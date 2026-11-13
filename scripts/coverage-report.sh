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

readonly maximum_counter=1000000000

die() {
	printf 'coverage-report.sh: %s\n' "$1" >&2
	exit 1
}

usage() {
	printf 'Usage: %s badge --input SUMMARY --output SVG\n' "${0##*/}" >&2
	exit 1
}

format_percentage() {
	local covered="$1"
	local total="$2"

	awk -v covered="${covered}" -v total="${total}" 'BEGIN {
		if (total == 0) {
			printf "0.00"
		} else {
			printf "%.2f", 100 * covered / total
		}
	}'
}

load_line_counts() {
	local input_path="$1"

	[[ -f "${input_path}" ]] || die "coverage summary does not exist: ${input_path}"
	jq -ers --argjson maximum_counter "${maximum_counter}" '
		if length == 1 then .[0] else error("expected one gcovr coverage summary") end
		| [.line_covered, .line_total]
		| if all(.[]; type == "number" and floor == . and . >= 0 and . <= $maximum_counter)
		     and .[0] <= .[1] then @tsv
		  else error("invalid line coverage counters") end
	' "${input_path}"
}

badge_color() {
	local percentage="$1"

	if awk -v percentage="${percentage}" 'BEGIN { exit !(percentage >= 90) }'; then
		printf '4c1'
	elif awk -v percentage="${percentage}" 'BEGIN { exit !(percentage >= 75) }'; then
		printf '97ca00'
	elif awk -v percentage="${percentage}" 'BEGIN { exit !(percentage >= 60) }'; then
		printf 'dfb317'
	else
		printf 'e05d44'
	fi
}

render_badge() {
	local input_path="$1"
	local output_path="$2"
	local counts covered total
	local percentage
	local color

	counts="$(load_line_counts "${input_path}")" || die "invalid coverage summary: ${input_path}"
	IFS=$'\t' read -r covered total <<< "${counts}"
	percentage="$(format_percentage "${covered}" "${total}")"
	color="$(badge_color "${percentage}")"

	cat > "${output_path}" <<EOF
<svg xmlns="http://www.w3.org/2000/svg" width="124" height="20" role="img" aria-label="coverage: ${percentage}%">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a"><rect width="124" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#a)">
    <path fill="#555" d="M0 0h68v20H0z"/>
    <path fill="#${color}" d="M68 0h56v20H68z"/>
    <path fill="url(#b)" d="M0 0h124v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">
    <text x="34" y="15" fill="#010101" fill-opacity=".3">coverage</text>
    <text x="34" y="14">coverage</text>
    <text x="96" y="15" fill="#010101" fill-opacity=".3">${percentage}%</text>
    <text x="96" y="14">${percentage}%</text>
  </g>
</svg>
EOF
}

[[ "${1:-}" == badge ]] || usage
shift

input_path=''
output_path=''
while (($# > 0)); do
	[[ $# -ge 2 ]] || usage
	case "$1" in
		--input) input_path="$2" ;;
		--output) output_path="$2" ;;
		*) usage ;;
	esac
	shift 2
done

[[ -n "${input_path}" && -n "${output_path}" ]] || usage
render_badge "${input_path}" "${output_path}"
