#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.

set -euo pipefail

: "${LIBMPQ_D_VERSION:?LIBMPQ_D_VERSION is required}"

readonly project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly package_name="libmpq-d-${LIBMPQ_D_VERSION}"
readonly package_dir="${project_root}/release/${package_name}"
readonly archive="${project_root}/release/${package_name}-source.tar.gz"
readonly extracted="$(mktemp -d)"
readonly source_dub_home="$(mktemp -d)"
trap 'rm -rf -- "${extracted}" "${source_dub_home}"' EXIT

cd "${project_root}"
mkdir -p "${package_dir}/source" "${package_dir}/tests"
cp -a bindings/d/source/. "${package_dir}/source/"
cp bindings/d/tests/main.d "${package_dir}/tests/"
cp bindings/d/README.md COPYING COPYING.LESSER "${package_dir}/"
dub convert --recipe=dub.sdl --format=json --stdout |
	jq --arg version "${LIBMPQ_D_VERSION}" '
		.version = $version
		| .sourcePaths = ["source"]
		| .importPaths = ["source"]
		| .configurations |= map(
			if .name == "tests" then
				.sourcePaths = ["source", "tests"]
				| .importPaths = ["source", "tests"]
				| .mainSourceFile = "tests/main.d"
			else . end
		)
	' > "${package_dir}/dub.json"
tar -czf "${archive}" -C "${project_root}/release" "${package_name}"
tar -tzf "${archive}" |
	grep -E "^${package_name}/(dub\.json|source/libmpq/mpq\.d|tests/main\.d)$" >/dev/null
tar -xzf "${archive}" -C "${extracted}"
readonly source_root="${extracted}/${package_name}"
jq -e --arg version "${LIBMPQ_D_VERSION}" \
	'.name == "libmpq" and .version == $version' \
	"${source_root}/dub.json" >/dev/null
DUB_HOME="${source_dub_home}" dub describe --root="${source_root}" --compiler=dmd
DUB_HOME="${source_dub_home}" \
	LIBRARY_PATH="${project_root}/src/.libs" \
	LD_LIBRARY_PATH="${project_root}/src/.libs" \
	dub run --root="${source_root}" --config=tests --compiler=dmd
