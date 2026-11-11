#!/usr/bin/env bash

# Copyright (c) 2026-2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this file; if not, see <https://www.gnu.org/licenses/>.

set -euo pipefail
export LC_ALL=C

if [[ $# -ne 2 ]]; then
	printf 'Usage: %s INSTALLED_HEADER SHARED_LIBRARY\n' "${BASH_SOURCE[0]}" >&2
	exit 2
fi

header=$1
library=$2
for file in "${header}" "${library}"; do
	if [[ ! -f "${file}" ]]; then
		printf 'Required file does not exist: %s\n' "${file}" >&2
		exit 1
	fi
done
temporary="$(mktemp -d)"
trap 'rm -rf -- "${temporary}"' EXIT

# A semicolon terminates each declaration, including multiline prototypes.
awk '
	BEGIN { RS = ";" }
	match($0, /(^|\n)[[:blank:]]*extern[[:space:]]+LIBMPQ_API[[:space:]]+/) {
		declaration = substr($0, RSTART + RLENGTH)
		if (match(declaration, /libmpq__[[:alnum:]_]+[[:space:]]*\(/)) {
			name = substr(declaration, RSTART, RLENGTH)
			sub(/[[:space:]]*\($/, "", name)
			print name
		}
	}
' "${header}" >"${temporary}/declarations"
sort -u "${temporary}/declarations" >"${temporary}/expected"
if (( $(wc -l <"${temporary}/declarations") != 97 || $(wc -l <"${temporary}/expected") != 97 )); then
	printf 'Expected 97 distinct public declarations in %s\n' "${header}" >&2
	exit 1
fi

platform="$(uname -s)"
case "${platform}" in
	Linux)
		nm -D --defined-only --format=posix -- "${library}" |
			awk 'NF { sub(/@.*/, "", $1); print $1 }'
		;;
	Darwin)
		xcrun dyld_info -exports "${library}" |
			awk '$1 ~ /^0x[[:xdigit:]]+$/ || $1 == "[re-export]" {
				sub(/^_/, "", $2)
				print $2
			}'
		;;
	*)
		printf 'No export inspection tool configured for %s\n' "${platform}" >&2
		exit 1
		;;
esac >"${temporary}/exports"

sort -u "${temporary}/exports" >"${temporary}/actual"
if ! cmp -s "${temporary}/expected" "${temporary}/actual"; then
	printf '%s: public C export set differs\nMissing names:\n' "${library}" >&2
	comm -23 "${temporary}/expected" "${temporary}/actual" >&2
	printf 'Extra names:\n' >&2
	comm -13 "${temporary}/expected" "${temporary}/actual" >&2
	exit 1
fi
printf '%s: exact 97-function public C export set\n' "${library}"
