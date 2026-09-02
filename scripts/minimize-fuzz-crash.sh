#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.

set -euo pipefail

if (($# != 3)); then
	printf 'Usage: %s <target> <crash-input> <output-seed>\n' "${0##*/}" >&2
	exit 2
fi

readonly target="$1"
readonly crash_input="$2"
readonly output_seed="$3"

if [[ ! -x "fuzz/${target}" ]]; then
	printf 'Unknown or unbuilt fuzz target: %s\n' "${target}" >&2
	exit 2
fi
if [[ ! -f "${crash_input}" ]]; then
	printf 'Crash input does not exist: %s\n' "${crash_input}" >&2
	exit 2
fi

mkdir -p "$(dirname -- "${output_seed}")"
"fuzz/${target}" -minimize_crash=1 -exact_artifact_path="${output_seed}" "${crash_input}"
