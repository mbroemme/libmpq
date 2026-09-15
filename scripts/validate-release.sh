#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

set -euo pipefail

tag="${GITHUB_REF_NAME:-}"
if [[ ! "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ || "${GITHUB_REF:-}" != "refs/tags/${tag}" ]]; then
	printf 'Release requires an exact vX.Y.Z tag.\n' >&2
	exit 1
fi
version="${tag#v}"
autoconf_version="$(sed -nE 's/^AC_INIT\(\[libmpq\],[[:space:]]*\[([^]]+)\].*/\1/p' configure.ac)"
cmake_version="$(sed -nE 's/^project\(libmpq VERSION ([0-9.]+) LANGUAGES C\).*/\1/p' CMakeLists.txt)"
if [[ "${version}" == "${autoconf_version}" && "${version}" == "${cmake_version}" ]]; then
	printf 'version=%s\n' "${version}" >> "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
	printf 'Validated release %s\n' "${tag}"
else
	printf 'Tag %s must match AC_INIT (%s) and CMake (%s).\n' \
		"${tag}" "${autoconf_version}" "${cmake_version}" >&2
	exit 1
fi
