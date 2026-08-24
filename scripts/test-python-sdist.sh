#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

set -euo pipefail

readonly project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly python_bin="${PYTHON:-python}"
readonly output_dir="${1:-${project_root}/bindings/python/dist}"
readonly temporary="$(mktemp -d -t libmpq-python-sdist.XXXXXX)"
trap 'rm -rf "${temporary}"' EXIT

build_options=()
if [[ "${PYTHON_BUILD_NO_ISOLATION:-0}" == 1 ]]; then
	build_options+=(--no-isolation)
fi

is_forbidden_native_file() {
	local member="$1"

	case "${member}" in
		*.so|*.so.*|*.a|*.la|*.lo|*.o)
			return 0
			;;
	esac

	case "/${member}/" in
		*/.libs/*|*/.deps/*)
			return 0
			;;
	esac

	return 1
}

rm -rf "${output_dir}"
mkdir -p "${output_dir}"

"${python_bin}" -m build "${build_options[@]}" --sdist \
	--outdir "${output_dir}" "${project_root}/bindings/python"

mapfile -t sdists < <(
	find "${output_dir}" -maxdepth 1 -type f -name 'libmpq-*.tar.gz' -print
)
test "${#sdists[@]}" -eq 1
sdist="${sdists[0]}"

mapfile -t members < <(tar -tzf "${sdist}")
printf '%s\n' "${members[@]}" | grep -E '/native/src/[^/]+\.c$' >/dev/null
printf '%s\n' "${members[@]}" | grep -E '/native/src/[^/]+\.h$' >/dev/null
printf '%s\n' "${members[@]}" | grep -E '/native/include/.+\.h$' >/dev/null

for member in "${members[@]}"; do
	if is_forbidden_native_file "${member}"; then
		printf 'sdist contains native build product: %s\n' "${member}" >&2
		exit 1
	fi
done

tar -xzf "${sdist}" -C "${temporary}"
source_dir="$(find "${temporary}" -mindepth 1 -maxdepth 1 \
	-type d -name 'libmpq-*' -print -quit)"
test -n "${source_dir}"

"${python_bin}" -m build "${build_options[@]}" --wheel "${source_dir}" \
	--outdir "${temporary}/wheelhouse"
if [[ "${PYTHON_TEST_SYSTEM_SITE_PACKAGES:-0}" == 1 ]]; then
	"${python_bin}" -m venv --system-site-packages "${temporary}/venv"
else
	"${python_bin}" -m venv "${temporary}/venv"
	"${temporary}/venv/bin/python" -m pip install --upgrade pip pytest
fi
"${temporary}/venv/bin/python" -m pip install \
	"${temporary}/wheelhouse/"*.whl
(
	cd /tmp
	env -u LIBMPQ_LIBRARY -u PYTHONPATH \
		LIBMPQ_EXPECT_BUNDLED=1 \
		"${temporary}/venv/bin/python" -m pytest \
		"${source_dir}/tests" -k 'not fixture_metadata_and_extraction'
)
