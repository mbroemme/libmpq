#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

set -euo pipefail

: "${LIBMPQ_D_COMPILER_NAME:?LIBMPQ_D_COMPILER_NAME is required}"
: "${LIBMPQ_D_DUB_COMPILER:?LIBMPQ_D_DUB_COMPILER is required}"
: "${LIBMPQ_D_LIBC:?LIBMPQ_D_LIBC is required}"
: "${LIBMPQ_D_VERSION:?LIBMPQ_D_VERSION is required}"
: "${DC:?DC is required}"

readonly package_name="libmpq-d-${LIBMPQ_D_VERSION}"
readonly package_dir="release/${package_name}"
readonly interface_dir="release/interfaces"
readonly object_dir="release/objects"
readonly archive_name="${package_name}-${LIBMPQ_D_COMPILER_NAME}-linux-${LIBMPQ_D_LIBC}-x86_64.tar.gz"
readonly dub_platform="linux-x86_64-${LIBMPQ_D_COMPILER_NAME}"

mkdir -p "${package_dir}/source/libmpq" "${package_dir}/tests" \
	"${package_dir}/lib" "${interface_dir}" "${object_dir}"

"${DC}" -H -Hd="${interface_dir}" -od="${object_dir}" -c \
	bindings/d/source/libmpq/*.d
cp "${interface_dir}"/*.di "${package_dir}/source/libmpq/"
cp bindings/d/tests/main.d "${package_dir}/tests/"
cp bindings/d/README.md COPYING COPYING.LESSER "${package_dir}/"

compiler_version="$(${DC} --version | sed -n '1p')"
case "${LIBMPQ_D_COMPILER_NAME}" in
	dmd)
	toolchain_version="$(${DC} --version |
		sed -n 's/.*v\([0-9][0-9.]*\).*/\1/p')"
	;;
	ldc)
	toolchain_version="$(${DC} --version |
		grep -oE '\([0-9]+\.[0-9]+\.[0-9]+\)' |
		sed 's/[()]//g' | sed -n '1p')"
	;;
	*)
	echo "Unsupported compiler: ${LIBMPQ_D_COMPILER_NAME}" >&2
	exit 1
	;;
esac
test -n "${toolchain_version}"

dub convert --recipe=dub.sdl --format=json --stdout |
	jq --arg version "${LIBMPQ_D_VERSION}" \
		--arg compiler "${LIBMPQ_D_COMPILER_NAME}" \
		--arg platform "${dub_platform}" \
		--arg toolchain_version "${toolchain_version}" '
		.version = $version
		| .targetType = "sourceLibrary"
		| .sourcePaths = []
		| .importPaths = ["source"]
		| .sourceFiles = []
		| .["sourceFiles-" + $platform] = [
			("lib/libmpq-" + $compiler + ".a")
		  ]
		| .["lflags-" + $platform] = ["-L$PACKAGE_DIR/lib"]
		| .toolchainRequirements =
			if $compiler == "dmd" then
				{dmd: ("==" + $toolchain_version), ldc: "no", gdc: "no"}
			else
				{dmd: "no", ldc: ("==" + $toolchain_version), gdc: "no"}
			end
		| del(.configurations)
	' > "${package_dir}/dub.json"

d_library="$(find . -maxdepth 1 -type f \
	\( -name 'liblibmpq.a' -o -name 'libmpq.a' \) -print -quit)"
test -s "${d_library}"
test -s src/.libs/libmpq.so
cp "${d_library}" "${package_dir}/lib/libmpq-${LIBMPQ_D_COMPILER_NAME}.a"
cp -a src/.libs/libmpq.so* "${package_dir}/lib/"

soname="$(readelf -d "${package_dir}/lib/libmpq.so" |
	sed -n 's/.*SONAME.*\[\(.*\)\].*/\1/p')"
test -n "${soname}"
test -e "${package_dir}/lib/${soname}"

libc_build_version="$(ldd --version 2>&1 |
	grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' |
	sed -n '1p' || true)"
case "${LIBMPQ_D_LIBC}" in
	glibc)
	glibc_max_required_symbol="$(readelf --version-info \
		"${package_dir}/lib/${soname}" |
		grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -n 1 || true)"
	build_environment=ubuntu-24.04
	;;
	musl)
	glibc_max_required_symbol=none
	build_environment=alpine-3.22
	;;
	*)
	echo "Unsupported libc: ${LIBMPQ_D_LIBC}" >&2
	exit 1
	;;
esac
{
	echo "libmpq_version=${LIBMPQ_D_VERSION}"
	echo "compiler=${LIBMPQ_D_COMPILER_NAME}"
	echo "compiler_version=${compiler_version}"
	echo "architecture=x86_64"
	echo "os=linux"
	echo "libc=${LIBMPQ_D_LIBC}"
	echo "libc_build_version=${libc_build_version}"
	echo "build_environment=${build_environment}"
	echo "glibc_max_required_symbol=${glibc_max_required_symbol}"
} > "${package_dir}/BUILDINFO"

tar -czf "release/${archive_name}" -C release "${package_name}"

# Prove that a consumer selects the precompiled D archive and the bundled
# native library without source-tree linker paths.
extracted="$(mktemp -d)"
tar -xzf "release/${archive_name}" -C "${extracted}"
consumer="${extracted}/consumer"
mkdir -p "${consumer}/source"
cat > "${consumer}/dub.sdl" <<EOF
name "libmpq-consumer"
targetType "executable"
dependency "libmpq" path="../${package_name}"
EOF
cat > "${consumer}/source/app.d" <<'EOF'
import libmpq.mpq;
import std.stdio : writeln;

void main() { writeln(Mpq.version_()); }
EOF
consumer_dub_home="$(mktemp -d)"
trap 'rm -rf "${extracted}" "${consumer_dub_home}"' EXIT
describe="$(DUB_HOME="${consumer_dub_home}" \
	dub describe --root="${consumer}" --compiler="${LIBMPQ_D_DUB_COMPILER}" \
		--data=source-files,linker-files --data-list)"
grep -F "libmpq-${LIBMPQ_D_COMPILER_NAME}.a" <<<"${describe}"
if grep -F 'source/libmpq/mpq.d' <<<"${describe}"; then
	echo 'The binary package unexpectedly compiles D source.' >&2
	exit 1
fi
DUB_HOME="${consumer_dub_home}" \
	LD_LIBRARY_PATH="${extracted}/${package_name}/lib" \
	dub run --root="${consumer}" --compiler="${LIBMPQ_D_DUB_COMPILER}"
consumer_binary="${consumer}/libmpq-consumer"
test -x "${consumer_binary}"
LD_LIBRARY_PATH="${extracted}/${package_name}/lib" ldd "${consumer_binary}" |
	grep -F "${extracted}/${package_name}/lib/${soname}"
