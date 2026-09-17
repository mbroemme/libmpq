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
: "${LIBMPQ_D_OS:?LIBMPQ_D_OS is required}"
: "${LIBMPQ_D_VERSION:?LIBMPQ_D_VERSION is required}"
: "${DC:?DC is required}"
: "${LIBMPQ_D_ARCHITECTURE:?LIBMPQ_D_ARCHITECTURE is required}"

case "${LIBMPQ_D_OS}:${LIBMPQ_D_ARCHITECTURE}:$(uname -s)" in
	linux:x86_64:Linux|linux:aarch64:Linux)
	: "${LIBMPQ_D_LIBC:?LIBMPQ_D_LIBC is required}"
	package_platform="linux-${LIBMPQ_D_LIBC}-${LIBMPQ_D_ARCHITECTURE}"
	dub_os=linux
	dub_arch="${LIBMPQ_D_ARCHITECTURE}"
	elf_machine='Advanced Micro Devices X86-64'
	[[ "${dub_arch}" != aarch64 ]] || elf_machine=AArch64
	;;
	macos:x86_64:Darwin|macos:arm64:Darwin)
	: "${MACOSX_DEPLOYMENT_TARGET:?MACOSX_DEPLOYMENT_TARGET is required}"
	package_platform="macos-${LIBMPQ_D_ARCHITECTURE}"
	dub_os=osx
	dub_arch="${LIBMPQ_D_ARCHITECTURE}"
	[[ "${dub_arch}" != arm64 ]] || dub_arch=aarch64
	;;
	*) echo "Unsupported D package platform or host: ${LIBMPQ_D_OS}/${LIBMPQ_D_ARCHITECTURE}/$(uname -s)" >&2; exit 1 ;;
esac
if [[ "$(uname -m)" != "${LIBMPQ_D_ARCHITECTURE}" ]]; then
	echo "D package architecture ${LIBMPQ_D_ARCHITECTURE} does not match native host $(uname -m)" >&2
	exit 1
fi

# BFD handles DMD's archive format where readelf's archive reader does not.
# Inspect every member, while using ELF headers for libraries and executables.
validate_architecture() {
	local machines machine expected
	if [[ "${LIBMPQ_D_OS}" == macos ]]; then
		test "$(lipo -archs "$1")" = "${LIBMPQ_D_ARCHITECTURE}" || {
			echo "Unexpected or universal Mach-O architecture in $1" >&2; exit 1;
		}

		# otool prints each archive member's Mach header, including mixed members.
		machines="$(otool -hv "$1" | awk '$1 ~ /^MH_/ { print $2 }')"
		expected=X86_64
		[[ "${LIBMPQ_D_ARCHITECTURE}" != arm64 ]] || expected=ARM64
		test -n "${machines}"
		while IFS= read -r machine; do
			[[ "${machine}" == "${expected}" ]] || {
				echo "Unexpected Mach-O member in $1: ${machine}" >&2; exit 1;
			}
		done <<<"${machines}"
		return
	fi
	expected="${elf_machine}"
	case "$1" in
		*.a)
		machines="$(LC_ALL=C objdump -f "$1" | sed -n 's/^architecture: \([^,]*\),.*/\1/p')"
		case "${LIBMPQ_D_ARCHITECTURE}" in
			x86_64) expected='i386:x86-64' ;;
			aarch64) expected='aarch64' ;;
		esac
		;;
		*)
		machines="$(LC_ALL=C readelf -h "$1" | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')"
		;;
	esac
	test -n "${machines}"
	while IFS= read -r machine; do
		if [[ "${machine}" != "${expected}" ]]; then
			echo "Unexpected ELF architecture in $1: ${machine}; expected ${expected}" >&2
			exit 1
		fi
	done <<<"${machines}"
}

validate_macos_paths() {
	local paths
	paths="$(otool -L "$1" | sed '1d')"
	paths+="$(otool -l "$1" | awk '
		$1 == "cmd" { command = $2 }
		command == "LC_RPATH" && $1 == "path" { print $2 }
	')"
	if grep -Eq '(/opt/homebrew/|/usr/local/|/opt/local/|/Users/|/private/|/tmp/|/var/folders/)' <<<"${paths}"; then
		echo "Mach-O runtime path leaks a build or package-manager location in $1" >&2
		exit 1
	fi
}

readonly package_name="libmpq-d-${LIBMPQ_D_VERSION}"
readonly package_dir="release/${package_name}"
readonly interface_dir="release/interfaces"
readonly object_dir="release/objects"
readonly archive_name="${package_name}-${LIBMPQ_D_COMPILER_NAME}-${package_platform}.tar.gz"
readonly dub_platform="${dub_os}-${dub_arch}-${LIBMPQ_D_COMPILER_NAME}"

if [[ "${LIBMPQ_D_OS}" == macos ]]; then
	dub describe --compiler="${LIBMPQ_D_DUB_COMPILER}" |
		jq -e --arg arch "${dub_arch}" \
			'(.platform | index("osx")) != null and .architecture == [$arch]'
fi

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
cp "${d_library}" "${package_dir}/lib/libmpq-${LIBMPQ_D_COMPILER_NAME}.a"
if [[ "${LIBMPQ_D_OS}" == linux ]]; then
	test -s src/.libs/libmpq.so
	cp -a src/.libs/libmpq.so* "${package_dir}/lib/"
	validate_architecture "${package_dir}/lib/libmpq.so"

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
else
	native_sdk="release/libmpq-${LIBMPQ_D_VERSION}-macos-${LIBMPQ_D_ARCHITECTURE}"
	cp -a "${native_sdk}/lib/"libmpq*.dylib "${package_dir}/lib/"
	shared_library="${package_dir}/lib/libmpq.dylib"
	validate_architecture "${shared_library}"
	validate_macos_paths "${shared_library}"
	codesign --verify --strict "${shared_library}"
	dylib_id="$(otool -D "${shared_library}" | sed -n '2s/^[[:space:]]*//p')"
	[[ "${dylib_id}" == @rpath/libmpq.*.dylib ]]
	test -f "${package_dir}/lib/${dylib_id#@rpath/}"

	# The native SDK has already validated system dependencies, LC_RPATH,
	# the actual deployment target, and signatures before copying these files.
	grep -Fx "macos_deployment_target=${MACOSX_DEPLOYMENT_TARGET}" "${native_sdk}/BUILDINFO"
fi
validate_architecture "${package_dir}/lib/libmpq-${LIBMPQ_D_COMPILER_NAME}.a"
{
	echo "libmpq_version=${LIBMPQ_D_VERSION}"
	echo "compiler=${LIBMPQ_D_COMPILER_NAME}"
	echo "compiler_version=${compiler_version}"
	echo "architecture=${LIBMPQ_D_ARCHITECTURE}"
	echo "os=${LIBMPQ_D_OS}"
	if [[ "${LIBMPQ_D_OS}" == linux ]]; then
		echo "libc=${LIBMPQ_D_LIBC}"
		echo "libc_build_version=${libc_build_version}"
		echo "build_environment=${build_environment}"
		echo "glibc_max_required_symbol=${glibc_max_required_symbol}"
	else
		echo "macos_deployment_target=${MACOSX_DEPLOYMENT_TARGET}"
		echo "dylib_id=${dylib_id}"
	fi
} > "${package_dir}/BUILDINFO"

tar -czf "release/${archive_name}" -C release "${package_name}"

# Prove that a consumer selects the precompiled D archive and the bundled
# native library without source-tree linker paths.
extracted="$(mktemp -d)"
if [[ "${LIBMPQ_D_OS}" == macos ]]; then
	extracted="$(cd "${extracted}" && pwd -P)"
fi
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
if [[ "${LIBMPQ_D_OS}" == linux ]]; then
	DUB_HOME="${consumer_dub_home}" \
		LD_LIBRARY_PATH="${extracted}/${package_name}/lib" \
		dub run --root="${consumer}" --compiler="${LIBMPQ_D_DUB_COMPILER}"
	consumer_binary="${consumer}/libmpq-consumer"
	test -x "${consumer_binary}"
	validate_architecture "${consumer_binary}"
	test "$(LD_LIBRARY_PATH="${extracted}/${package_name}/lib" "${consumer_binary}")" = "${LIBMPQ_D_VERSION}"
	LD_LIBRARY_PATH="${extracted}/${package_name}/lib" ldd "${consumer_binary}" |
		grep -F "${extracted}/${package_name}/lib/${soname}"
else
	# Only the extracted package may satisfy the libmpq runtime dependency.
	unset LIBRARY_PATH LD_LIBRARY_PATH DYLD_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH
	DUB_HOME="${consumer_dub_home}" \
		dub build --root="${consumer}" --compiler="${LIBMPQ_D_DUB_COMPILER}"
	consumer_binary="${consumer}/libmpq-consumer"
	validate_architecture "${consumer_binary}"
	otool -L "${consumer_binary}" | grep -F "${dylib_id}"
	validate_macos_paths "${consumer_binary}"

	# arch sets these variables in the child, after macOS SIP handling of
	# system launchers. Trace loading to prove the extracted dylib was used.
	test "$(/usr/bin/arch -"${LIBMPQ_D_ARCHITECTURE}" \
		-e "DYLD_LIBRARY_PATH=${extracted}/${package_name}/lib" \
		-e DYLD_PRINT_LIBRARIES=1 "${consumer_binary}" \
		2> "${consumer}/loaded-libraries")" = "${LIBMPQ_D_VERSION}"
	grep -F "${extracted}/${package_name}/lib/libmpq" "${consumer}/loaded-libraries"
fi
