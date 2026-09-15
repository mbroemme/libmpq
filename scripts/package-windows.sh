#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

# Complete an installed shared SDK before its consumer test, then archive it.
# Build configuration and installation remain the workflows' responsibility.
set -euo pipefail
export LC_ALL=C
shopt -s nullglob nocaseglob

fail()
{
	printf '%s\n' "$*" >&2
	exit 1
}

unix_path()
{
	if command -v cygpath >/dev/null; then cygpath -au "$1"; else realpath -m -- "$1"; fi
}

native_path()
{
	if command -v cygpath >/dev/null; then cygpath -aw "$1"; else printf '%s\n' "$1"; fi
}

# Index actual filenames without assuming Windows filesystem case sensitivity.
index_dlls()
{
	local -n index="$1"
	local path base
	index=()
	[[ -d "$2" ]] || fail "Missing DLL directory: $2"
	for path in "$2"/*.dll; do
		[[ -f "${path}" ]] || continue
		base="${path##*/}"

		# This assignment updates the caller's associative array through a nameref.
		# shellcheck disable=SC2034
		index["${base,,}"]="${path}"
	done
}

imports()
{
	local output names
	if [[ "${toolchain}" == msvc ]]; then
		# Pass native paths and preserve dumpbin's slash options in MSYS/Git Bash.
		output="$(MSYS2_ARG_CONV_EXCL='*' MSYS_NO_PATHCONV=1 \
			dumpbin.exe /nologo /dependents "$(native_path "$1")")" || fail "Cannot inspect $1"
		names="$(printf '%s\n' "${output}" | tr -d '\r' | \
			sed -nE 's/^[[:space:]]+([^[:space:]]+\.[dD][lL][lL])[[:space:]]*$/\1/p')"
	else
		output="$(objdump -p "$1")" || fail "Cannot inspect $1"
		names="$(printf '%s\n' "${output}" | tr -d '\r' | \
			sed -nE 's/^[[:space:]]*DLL Name:[[:space:]]*([^[:space:]]+\.[dD][lL][lL])[[:space:]]*$/\1/p')"
	fi
	[[ -n "${names}" ]] || fail "No PE imports found in $1"
	printf '%s\n' "${names,,}" | sort -u
}

copy_license()
{
	local path="$1" base="${1##*/}" owner='' listing relative text target count=0
	if [[ "${toolchain}" == msvc ]]; then
		relative="${runtime##*/}/bin/${base}"
		for listing in "${runtime}/../vcpkg/info/"*.list; do
			text="$(tr -d '\r' < "${listing}")"
			if grep -Fqx -- "${relative,,}" <<< "${text,,}"; then
				owner="${listing##*/}"
				owner="${owner%%_*}"
				count=$((count + 1))
			fi
		done
		[[ "${count}" == 1 ]] || fail "Cannot identify vcpkg license owner for ${path}"
		[[ -f "${runtime}/share/${owner}/copyright" ]] || fail "Missing license for ${owner}"
		mkdir -p "${stage}/licenses/${owner}"
		cp "${runtime}/share/${owner}/copyright" "${stage}/licenses/${owner}/"
	else
		owner="$(pacman -Qqo "${path}")"
		[[ -n "${owner}" && "${owner}" != *$'\n'* ]] || fail "Invalid package owner for ${path}"
		listing="$(pacman -Qlq "${owner}")"
		while IFS= read -r path; do
			path="${path%$'\r'}"
			[[ "${path}" == */share/licenses/* && "${path}" != */ ]] || continue
			relative="${path#*/share/licenses/}"
			target="${stage}/licenses/${owner}/${relative}"
			mkdir -p "${target%/*}"
			cp "${path}" "${target}"
			count=$((count + 1))
		done <<< "${listing}"
		((count > 0)) || fail "No installed license files for ${owner} (${base})"
	fi
}

# The validation pass deliberately has no toolchain/PATH lookup. System DLLs
# are those actually installed in System32, plus Windows API-set contracts.
dependency_closure()
{
	local copy="$1" path name dependency listing position=0
	local -A staged=() available=() system_dlls=() visited=()
	local -a pending=()
	index_dlls staged "${stage}/bin"
	index_dlls system_dlls "${system}"
	if [[ "${copy}" == yes ]]; then index_dlls available "${runtime}/bin"; fi
	pending=("${staged[@]}")
	while ((position < ${#pending[@]})); do
		path="${pending[position]}"
		position=$((position + 1))
		name="${path##*/}"
		name="${name,,}"
		[[ -z "${visited[${name}]:-}" ]] || continue
		visited["${name}"]=1
		listing="$(imports "${path}")"
		while IFS= read -r dependency; do
			if [[ "${dependency}" == api-ms-* || "${dependency}" == ext-ms-* || \
				-n "${system_dlls[${dependency}]:-}" ]]; then continue; fi
			if [[ -z "${staged[${dependency}]:-}" ]]; then
				[[ -n "${available[${dependency}]:-}" ]] || fail "Missing dependency ${dependency} required by ${path}"
				name="${available[${dependency}]##*/}"
				cp "${available[${dependency}]}" "${stage}/bin/${name}"
				copy_license "${available[${dependency}]}"
				staged["${dependency}"]="${stage}/bin/${name}"
			fi
			pending+=("${staged[${dependency}]}")
		done <<< "${listing}"
	done
}

mode="${1:-}"
[[ $# -gt 0 ]] && shift
toolchain='' stage='' runtime='' output='' version='' source="${PWD}"
while (($#)); do
	[[ $# -ge 2 ]] || fail "Missing option value: $1"
	case "$1" in
		--toolchain) toolchain="$2" ;;
		--stage) stage="$(unix_path "$2")" ;;
		--runtime) runtime="$(unix_path "$2")" ;;
		--source) source="$(unix_path "$2")" ;;
		--output) output="$(unix_path "$2")" ;;
		--version) version="$2" ;;
		*) fail "Unknown option: $1" ;;
	esac
	shift 2
done
[[ "${mode}" == prepare || "${mode}" == archive ]] || fail "Usage: $0 prepare|archive --toolchain msvc|mingw --stage DIR --runtime DIR --output ZIP --version X.Y.Z"
[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'Expected a numeric X.Y.Z version'
case "${toolchain}" in
	msvc) suffix=msvc-x64; library=libmpq.lib ;;
	mingw) suffix=mingw-x86_64; library=libmpq.dll.a ;;
	*) fail 'Expected msvc or mingw toolchain' ;;
esac
name="libmpq-${version}-windows-${suffix}"
[[ "${stage##*/}" == "${name}" && "${output##*/}" == "${name}.zip" ]] || fail 'Invalid SDK directory or ZIP name'
[[ -f "${stage}/include/libmpq/mpq.h" && -f "${stage}/lib/${library}" ]] || fail 'Missing installed header or import library'
roots=("${stage}/bin/"libmpq*.dll)
[[ ${#roots[@]} == 1 && -f "${roots[0]}" ]] || fail 'Expected exactly one libmpq DLL'
[[ -z "$(find "${stage}" -name libmpq.a -print)" ]] || fail 'Static libmpq archive must not be published'
[[ -z "$(find "${stage}" -type l -print)" ]] || fail 'Unexpected SDK symlink'
system="$(unix_path "${SystemRoot:-${SYSTEMROOT:?SystemRoot is required}}")/System32"

if [[ "${mode}" == prepare ]]; then
	for path in "${stage}/bin/"*.dll; do
		base="${path##*/}"
		[[ "${base,,}" == libmpq* ]] || fail 'Prepare requires a clean install without runtime DLLs'
	done
	dependency_closure yes
	cp "${source}/README.md" "${source}/COPYING" "${source}/COPYING.LESSER" "${stage}/"
	if [[ "${toolchain}" == mingw ]]; then
		pc="${stage}/lib/pkgconfig/libmpq.pc"
		config="${stage}/bin/libmpq-config"
		grep -q '^prefix=' "${pc}" || fail 'Missing installed pkg-config prefix'
		grep -q '^prefix=' "${config}" || fail 'Missing installed config-script prefix'

		# Keep these expressions literal for expansion by the installed consumers.
		# shellcheck disable=SC2016
		sed -i 's|^prefix=.*|prefix=${pcfiledir}/../..|' "${pc}"

		# shellcheck disable=SC2016
		sed -i 's|^prefix=.*|prefix="$(CDPATH= cd -- "$(dirname -- "$0")/.." \&\& pwd)"|' "${config}"

		# Libtool's development-only archive records the original install path.
		rm -f "${stage}/lib/libmpq.la"
	fi
fi
dependency_closure no

if [[ "${mode}" == archive ]]; then
	[[ ! -e "${output}" ]] || fail "Refusing to overwrite ${output}"
	mkdir -p "${output%/*}"
	if [[ "${toolchain}" == msvc ]]; then
		# 7-Zip is supplied by the Windows runner. Avoid MSYS path rewriting.
		native_output="$(native_path "${output}")"
		(cd "${stage%/*}" && MSYS2_ARG_CONV_EXCL='*' MSYS_NO_PATHCONV=1 \
			7z.exe a -tzip "${native_output}" "${name}")
		MSYS2_ARG_CONV_EXCL='*' MSYS_NO_PATHCONV=1 7z.exe t "${native_output}"
		entries="$(MSYS2_ARG_CONV_EXCL='*' MSYS_NO_PATHCONV=1 7z.exe l -slt -ba "${native_output}" | \
			tr -d '\r' | sed -n 's/^Path = //p')"
	else
		(cd "${stage%/*}" && zip -qr "${output}" "${name}")
		unzip -t "${output}"
		entries="$(unzip -Z1 "${output}")"
	fi
	[[ -n "${entries}" ]] || fail 'Empty SDK ZIP'
	while IFS= read -r entry; do
		entry="${entry//\\//}"
		[[ "${entry}" == "${name}" || "${entry}" == "${name}/"* ]] || fail "Unexpected ZIP entry: ${entry}"
	done <<< "${entries}"
fi
