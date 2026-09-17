#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.

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
	;;
	macos:x86_64:Darwin|macos:arm64:Darwin)
	: "${MACOSX_DEPLOYMENT_TARGET:?MACOSX_DEPLOYMENT_TARGET is required}"
	;;
	*) echo "Unsupported D package platform or host: ${LIBMPQ_D_OS}/${LIBMPQ_D_ARCHITECTURE}/$(uname -s)" >&2; exit 1 ;;
esac
if [[ "$(uname -m)" != "${LIBMPQ_D_ARCHITECTURE}" ]]; then
	echo "D package architecture ${LIBMPQ_D_ARCHITECTURE} does not match native host $(uname -m)" >&2
	exit 1
fi

readonly project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${project_root}"

readonly temporary="$(mktemp -d)"
trap 'rm -rf -- "${temporary}"' EXIT
export DUB_HOME="${DUB_HOME:-${temporary}/dub}"

if command -v nproc >/dev/null 2>&1; then
	jobs="$(nproc)"
else
	jobs="$(getconf _NPROCESSORS_ONLN)"
fi

sh autogen.sh
if [[ "${LIBMPQ_D_OS}" == macos ]]; then
	./configure --prefix=/usr --enable-shared --disable-static
	/usr/bin/make -j"${jobs}" V=1
	/usr/bin/make check
	export LIBMPQ_NATIVE_ARCHITECTURE="${LIBMPQ_D_ARCHITECTURE}"
	export LIBMPQ_NATIVE_VERSION="${LIBMPQ_D_VERSION}"
	export LIBMPQ_NATIVE_BUILD_ENVIRONMENT="macos-$(sw_vers -productVersion)-${LIBMPQ_D_ARCHITECTURE}"

	# Reuse SDK installation, @rpath normalization, signing, and validation.
	bash scripts/package-macos-binary.sh
	bash scripts/test-macos-package.sh \
		"release/libmpq-${LIBMPQ_D_VERSION}-macos-${LIBMPQ_D_ARCHITECTURE}.tar.gz" \
		tests/fixtures/mpq-v1-features.mpq "${LIBMPQ_D_ARCHITECTURE}"
	export LIBRARY_PATH="${project_root}/release/libmpq-${LIBMPQ_D_VERSION}-macos-${LIBMPQ_D_ARCHITECTURE}/lib"
	export DYLD_LIBRARY_PATH="${LIBRARY_PATH}"

	# DUB's DMD --arch handling lacks aarch64. Include -marm64 even in its
	# compiler probe so DUB selects osx-aarch64 metadata, not Rosetta's host.
	if [[ "${LIBMPQ_D_COMPILER_NAME}:${LIBMPQ_D_ARCHITECTURE}" == dmd:arm64 ]]; then
		export LIBMPQ_D_REAL_COMPILER="$(command -v "${DC}")"
		cat > "${temporary}/dmd-arm64" <<'EOF'
#!/usr/bin/env bash
exec "${LIBMPQ_D_REAL_COMPILER}" -marm64 "$@"
EOF
		chmod +x "${temporary}/dmd-arm64"
		export DC="${temporary}/dmd-arm64"
		export LIBMPQ_D_DUB_COMPILER="${DC}"
	fi
	dub_arch="${LIBMPQ_D_ARCHITECTURE}"
	[[ "${dub_arch}" != arm64 ]] || dub_arch=aarch64
	dub describe --compiler="${LIBMPQ_D_DUB_COMPILER}" |
		jq -e --arg arch "${dub_arch}" \
			'(.platform | index("osx")) != null and .architecture == [$arch]'
	dub build --config=tests --compiler="${LIBMPQ_D_DUB_COMPILER}"
	test "$(lipo -archs libmpq)" = "${LIBMPQ_D_ARCHITECTURE}"
	/usr/bin/arch -"${LIBMPQ_D_ARCHITECTURE}" \
		-e "DYLD_LIBRARY_PATH=${LIBRARY_PATH}" ./libmpq
else
	./configure --prefix=/usr
	make -j"${jobs}" V=1
	export LIBRARY_PATH="${project_root}/src/.libs"
	export LD_LIBRARY_PATH="${project_root}/src/.libs"
	dub run --config=tests --compiler="${LIBMPQ_D_DUB_COMPILER}"
fi
dub build --config=library --compiler="${LIBMPQ_D_DUB_COMPILER}" --build=release
bash scripts/package-d-binary.sh
