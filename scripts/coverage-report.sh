#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

set -euo pipefail

readonly maximum_counter=1000000000

die() {
	printf 'coverage-report.sh: %s\n' "$1" >&2
	exit 1
}

usage() {
	printf 'Usage: %s badge --input SUMMARY --output SVG\n' "${0##*/}" >&2
	printf '       %s comment --current SUMMARY --head-sha SHA --report-url URL --output MARKDOWN [--base SUMMARY --base-sha SHA]\n' \
		"${0##*/}" >&2
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

format_delta() {
	local base_covered="$1"
	local base_total="$2"
	local current_covered="$3"
	local current_total="$4"

	awk -v base_covered="${base_covered}" -v base_total="${base_total}" \
		-v current_covered="${current_covered}" -v current_total="${current_total}" 'BEGIN {
		base = base_total == 0 ? 0 : 100 * base_covered / base_total
		current = current_total == 0 ? 0 : 100 * current_covered / current_total
		printf "%+.2f", current - base
	}'
}

load_summary() {
	local input_path="$1"
	local output_name="$2"
	local rendered_metrics
	local -n output="${output_name}"

	[[ -f "${input_path}" ]] || die "coverage summary does not exist: ${input_path}"
	if ! rendered_metrics="$(jq -er --argjson maximum_counter "${maximum_counter}" '
		def valid_counter:
			if type == "number" then
				floor == . and . >= 0 and . <= $maximum_counter
			else
				false
			end;
		def metric($name; $covered_name; $total_name):
			.[$covered_name] as $covered |
			.[$total_name] as $total |
			if ($covered | valid_counter) and ($total | valid_counter) and
				$covered <= $total then
				[$name, $covered, $total] | @tsv
			else
				error("invalid " + $name + " coverage counters")
			end;
		metric("Lines"; "line_covered"; "line_total"),
		metric("Functions"; "function_covered"; "function_total"),
		metric("Branches"; "branch_covered"; "branch_total")
	' "${input_path}")"; then
		die "invalid coverage summary: ${input_path}"
	fi

	readarray -t "${output_name}" <<< "${rendered_metrics}"
	[[ "${#output[@]}" -eq 3 ]] || die "invalid coverage summary: ${input_path}"
}

metric_fields() {
	local metric="$1"
	local output_name="$2"
	local -n output="${output_name}"
	local name
	local covered
	local total

	IFS=$'\t' read -r name covered total <<< "${metric}"
	output=("${name}" "${covered}" "${total}")
	[[ -n "${output[0]}" && "${output[1]}" =~ ^[0-9]+$ && "${output[2]}" =~ ^[0-9]+$ ]] ||
		die 'invalid parsed coverage metric'
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
	local -a metrics
	local -a line_metric
	local percentage
	local color

	load_summary "${input_path}" metrics
	metric_fields "${metrics[0]}" line_metric
	percentage="$(format_percentage "${line_metric[1]}" "${line_metric[2]}")"
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

render_comment() {
	local current_path="$1"
	local head_sha="$2"
	local report_url="$3"
	local output_path="$4"
	local base_path="${5:-}"
	local base_sha="${6:-}"
	local -a current_metrics
	local -a base_metrics
	local -a current_metric
	local -a base_metric
	local index
	local percentage
	local delta
	local line_delta=''

	load_summary "${current_path}" current_metrics
	if [[ -n "${base_path}" ]]; then
		load_summary "${base_path}" base_metrics
	fi

	{
		printf '## Coverage report\n\n'
		if [[ -z "${base_path}" ]]; then
			printf 'Current CI run: `%s`.\n\n' "${head_sha:0:12}"
			printf 'An exact base-commit coverage artifact is unavailable, so no delta is reported.\n\n'
			printf '| Metric | PR |\n| --- | ---: |\n'
			for metric in "${current_metrics[@]}"; do
				metric_fields "${metric}" current_metric
				percentage="$(format_percentage "${current_metric[1]}" "${current_metric[2]}")"
				printf '| %s | %s%% |\n' "${current_metric[0]}" "${percentage}"
			done
		else
			printf 'Base: `%s`. Current CI run: `%s`.\n\n' "${base_sha:0:12}" "${head_sha:0:12}"
			printf '| Metric | Base | PR | Delta |\n| --- | ---: | ---: | ---: |\n'
			for index in "${!current_metrics[@]}"; do
				metric_fields "${base_metrics[index]}" base_metric
				metric_fields "${current_metrics[index]}" current_metric
				percentage="$(format_percentage "${base_metric[1]}" "${base_metric[2]}")"
				delta="$(format_delta "${base_metric[1]}" "${base_metric[2]}" "${current_metric[1]}" "${current_metric[2]}")"
				printf '| %s | %s%% | %s%% | %s pp |\n' \
					"${current_metric[0]}" "${percentage}" \
					"$(format_percentage "${current_metric[1]}" "${current_metric[2]}")" "${delta}"
				if [[ "${current_metric[0]}" == 'Lines' ]]; then
					line_delta="${delta}"
				fi
			done
			printf '\n'
			if awk -v delta="${line_delta}" 'BEGIN { exit !(delta > 0) }'; then
				printf '✅ Line coverage increased by %s percentage points.\n' "${line_delta}"
			elif awk -v delta="${line_delta}" 'BEGIN { exit !(delta == 0) }'; then
				printf '✅ Line coverage is unchanged by %s percentage points.\n' "${line_delta}"
			else
				printf '⚠️ Line coverage decreased by %s percentage points.\n' "${line_delta}"
			fi
		fi
		printf '\n[Detailed coverage report](%s)\n' "${report_url}"
	} > "${output_path}"
}

[[ $# -ge 1 ]] || usage
readonly command="$1"
shift

input_path=''
output_path=''
base_path=''
base_sha=''
current_path=''
head_sha=''
report_url=''

while (($# > 0)); do
	case "$1" in
		--base|--base-sha|--current|--head-sha|--input|--output|--report-url)
			[[ $# -ge 2 ]] || usage
			case "$1" in
				--base) base_path="$2" ;;
				--base-sha) base_sha="$2" ;;
				--current) current_path="$2" ;;
				--head-sha) head_sha="$2" ;;
				--input) input_path="$2" ;;
				--output) output_path="$2" ;;
				--report-url) report_url="$2" ;;
			esac
			shift 2
			;;
		*) usage ;;
	esac
done

case "${command}" in
	badge)
		[[ -n "${input_path}" && -n "${output_path}" ]] || usage
		render_badge "${input_path}" "${output_path}"
		;;
	comment)
		[[ -n "${current_path}" && -n "${head_sha}" && -n "${report_url}" && -n "${output_path}" ]] || usage
		if [[ -n "${base_path}" && -z "${base_sha}" ]] || [[ -z "${base_path}" && -n "${base_sha}" ]]; then
			die '--base and --base-sha must be provided together'
		fi
		render_comment "${current_path}" "${head_sha}" "${report_url}" "${output_path}" \
			"${base_path}" "${base_sha}"
		;;
	*) usage ;;
esac
