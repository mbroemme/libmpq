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
: "${LIBMPQ_D_LIBC:?LIBMPQ_D_LIBC is required}"
: "${LIBMPQ_D_VERSION:?LIBMPQ_D_VERSION is required}"
: "${DC:?DC is required}"

readonly project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${project_root}"

if [[ -z "${DUB_HOME:-}" ]]; then
	readonly dub_home="$(mktemp -d)"
	trap 'rm -rf -- "${dub_home}"' EXIT
	export DUB_HOME="${dub_home}"
fi

if command -v nproc >/dev/null 2>&1; then
	jobs="$(nproc)"
else
	jobs="$(getconf _NPROCESSORS_ONLN)"
fi

sh autogen.sh
./configure --prefix=/usr
make -j"${jobs}" V=1
export LIBRARY_PATH="${project_root}/src/.libs"
export LD_LIBRARY_PATH="${project_root}/src/.libs"
dub run --config=tests --compiler="${LIBMPQ_D_DUB_COMPILER}"
dub build --config=library --compiler="${LIBMPQ_D_DUB_COMPILER}" --build=release
bash scripts/package-d-binary.sh
