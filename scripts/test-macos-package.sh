#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

set -euo pipefail

if (($# != 3)); then
	printf 'Usage: %s PACKAGE_ARCHIVE FIXTURE_ARCHIVE ARCHITECTURE\n' \
		"${0##*/}" >&2
	exit 1
fi

readonly package_archive="$1"
readonly fixture_archive="$2"
readonly architecture="$3"
readonly project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly temporary="$(mktemp -d -t libmpq-macos-test.XXXXXX)"
readonly consumer_source="${temporary}/consumer.c"

cleanup()
{
	rm -rf "${temporary}"
}
trap cleanup EXIT

buildinfo_value()
{
	sed -n "s/^$1=//p" "${sdk_root}/BUILDINFO"
}

minimum_macos_version()
{
	otool -l "$1" | awk '
		$1 == "cmd" {
			command = $2
			next
		}
		command == "LC_BUILD_VERSION" && $1 == "minos" {
			print $2
			exit
		}
		command == "LC_VERSION_MIN_MACOSX" && $1 == "version" {
			print $2
			exit
		}
	'
}

mach_o_rpaths()
{
	otool -l "$1" | awk '
		$1 == "cmd" {
			command = $2
			next
		}
		command == "LC_RPATH" && $1 == "path" {
			print $2
			command = ""
		}
	'
}

assert_no_mach_o_path_leaks()
{
	local binary expected_rpath rpath

	binary="$1"
	expected_rpath="${2:-}"
	if otool -L "${binary}" | sed '1d' | grep -Eq \
		'(/opt/homebrew/|/usr/local/|/opt/local/|/Users/|/private/|/tmp/|/var/folders/)'; then
		printf 'Mach-O dependency path leaks a build or package-manager location.\n' >&2
		exit 1
	fi
	while IFS= read -r rpath; do
		if [[ -n "${expected_rpath}" && "${rpath}" == "${expected_rpath}" ]]; then
			continue
		fi
		if [[ "${rpath}" =~ ^(/opt/homebrew/|/usr/local/|/opt/local/|/Users/|/private/|/tmp/|/var/folders/) ]]; then
			printf 'Mach-O runtime search path leaks a build or package-manager location.\n' >&2
			exit 1
		fi
	done < <(mach_o_rpaths "${binary}")
}

assert_manpage_set()
{
	local section source_manpages package_manpages page
	local -a source_pages package_pages

	section="$1"
	shopt -s nullglob
	source_pages=("${project_root}/docs/${section}"/*."${section#man}")
	package_pages=("${sdk_root}/share/man/${section}"/*."${section#man}")
	shopt -u nullglob
	source_manpages="$({
		for page in "${source_pages[@]}"; do
			[[ -f "${page}" ]] && basename -- "${page}"
		done
	} | sort)"
	package_manpages="$({
		for page in "${package_pages[@]}"; do
			[[ -f "${page}" ]] && basename -- "${page}"
		done
	} | sort)"
	if [[ "${source_manpages}" != "${package_manpages}" ]]; then
		printf 'macOS package %s pages do not match the canonical source set.\n' \
			"${section}" >&2
		exit 1
	fi
}

compile_consumer()
{
	local output cflags libs
	local -a cflags_array libs_array

	output="$1"
	cflags="$2"
	libs="$3"
	read -r -a cflags_array <<< "${cflags}"
	read -r -a libs_array <<< "${libs}"
	"${CC:-cc}" -std=c99 -Wall -Wextra -Werror "${cflags_array[@]}" "${consumer_source}" \
		-o "${output}" "${libs_array[@]}" "-Wl,-rpath,${library_dir}"
}

validate_sdk()
{
	local config_cflags config_libs dylib_id minimum_version pkgconfig_cflags
	local pkgconfig_libs
	local -a config_link_flags pkgconfig_link_flags

	for path in \
		"${sdk_root}/include/libmpq/mpq.h" \
		"${sdk_root}/bin/libmpq-config" \
		"${pkgconfig_dir}/libmpq.pc" \
		"${sdk_root}/share/man/man1/libmpq-config.1" \
		"${sdk_root}/share/man/man3/libmpq.3" \
		"${sdk_root}/README.md" \
		"${sdk_root}/DEVELOPER.md" \
		"${sdk_root}/MPQ.md" \
		"${sdk_root}/COPYING" \
		"${sdk_root}/COPYING.LESSER" \
		"${sdk_root}/BUILDINFO"; do
		if [[ ! -f "${path}" ]]; then
			printf 'macOS package is missing: %s\n' "${path}" >&2
			exit 1
		fi
	done

	if [[ "$(buildinfo_value libmpq_version)" != "${package_name#libmpq-}" ]] ||
		[[ "$(buildinfo_value architecture)" != "${architecture}" ]] ||
		[[ "$(buildinfo_value os)" != macos ]] ||
		[[ -z "$(buildinfo_value macos_deployment_target)" ]] ||
		[[ -z "$(buildinfo_value build_environment)" ]]; then
		printf 'macOS package has inconsistent BUILDINFO metadata.\n' >&2
		exit 1
	fi

	if find "${sdk_root}" \( -type f \( -name '*.a' -o -name '*.la' -o \
		-name '*.o' -o -name '*.lo' \) -o -type d \( -name .libs -o -name .deps \) \) \
		-print -quit | grep -q .; then
		printf 'macOS package must not include static, libtool, or build artifacts.\n' >&2
		exit 1
	fi

	assert_manpage_set man1
	assert_manpage_set man3

	shopt -s nullglob
	shared_libraries=()
	for shared_library in "${library_dir}"/libmpq.*.dylib; do
		if [[ -f "${shared_library}" && ! -L "${shared_library}" ]]; then
			shared_libraries+=("${shared_library}")
		fi
	done
	shopt -u nullglob
	if ((${#shared_libraries[@]} != 1)); then
		printf 'macOS package has an invalid concrete dylib set.\n' >&2
		exit 1
	fi
	shared_library="${shared_libraries[0]}"
	dylib_name="$(basename -- "${shared_library}")"
	if [[ ! -L "${library_dir}/libmpq.dylib" ]] ||
		[[ ! -e "${library_dir}/libmpq.dylib" ]]; then
		printf 'macOS package has no usable libmpq.dylib symlink.\n' >&2
		exit 1
	fi
	if [[ "$(lipo -archs "${shared_library}")" != "${architecture}" ]] ||
		! file "${shared_library}" | grep -Fq "${architecture}"; then
		printf 'macOS package dylib has the wrong architecture.\n' >&2
		exit 1
	fi
	dylib_id="$(otool -D "${shared_library}" | sed -n '2s/^[[:space:]]*//p')"
	if [[ "${dylib_id}" != "@rpath/${dylib_name}" ]] ||
		[[ "$(buildinfo_value dylib_id)" != "${dylib_id}" ]]; then
		printf 'macOS package dylib ID is not relocatable.\n' >&2
		exit 1
	fi
	if ! codesign --verify --strict "${shared_library}"; then
		printf 'macOS package dylib has an invalid code signature.\n' >&2
		exit 1
	fi
	minimum_version="$(minimum_macos_version "${shared_library}")"
	if [[ -z "${minimum_version}" ]] ||
		[[ "${minimum_version}" != "$(buildinfo_value macos_deployment_target)" ]]; then
		printf 'macOS package dylib deployment target does not match BUILDINFO.\n' >&2
		exit 1
	fi
	assert_no_mach_o_path_leaks "${shared_library}"
	if ! otool -L "${shared_library}" | sed '1d' | grep -Eq \
		'^[[:space:]]*/usr/lib/liblzma[^/[:space:]]*\.dylib[[:space:]]'; then
		printf 'macOS package dylib must link against system liblzma in /usr/lib/.\n' >&2
		exit 1
	fi

	config_cflags="$("${sdk_root}/bin/libmpq-config" \
		--prefix="${sdk_root}" --cflags)"
	config_libs="$("${sdk_root}/bin/libmpq-config" \
		--prefix="${sdk_root}" --libs)"
	if [[ "${config_cflags}" != "-I${sdk_root}/include" ]] ||
		[[ "${config_libs}" != "-L${sdk_root}/lib -lmpq "* ]]; then
		printf 'Packaged libmpq-config does not describe the extracted SDK layout.\n' >&2
		exit 1
	fi

	export PKG_CONFIG_PATH="${pkgconfig_dir}"
	export PKG_CONFIG_LIBDIR="${pkgconfig_dir}"
	pkgconfig_cflags="$(pkg-config --cflags libmpq)"
	pkgconfig_libs="$(pkg-config --libs libmpq)"
	read -r -a config_link_flags <<< "${config_libs}"
	read -r -a pkgconfig_link_flags <<< "$(pkg-config \
		--define-variable=prefix="${sdk_root}" --static --libs libmpq)"
	if [[ "${config_link_flags[*]}" != "${pkgconfig_link_flags[*]}" ]]; then
		printf 'Packaged link dependency metadata is inconsistent.\n' >&2
		exit 1
	fi
	if [[ "${pkgconfig_cflags}" != *"-I${sdk_root}/"* ]] ||
		[[ "${pkgconfig_libs}" != *"-L${sdk_root}/"* ]]; then
		printf 'Packaged libmpq.pc does not describe the extracted SDK layout.\n' >&2
		exit 1
	fi

	compile_consumer "${temporary}/consumer-pkgconfig" \
		"${pkgconfig_cflags}" "${pkgconfig_libs}"
	compile_consumer "${temporary}/consumer-config" \
		"${config_cflags}" "${config_libs}"
	for consumer in "${temporary}/consumer-pkgconfig" \
		"${temporary}/consumer-config"; do
		if ! otool -L "${consumer}" | sed '1d' |
			grep -Fq "@rpath/${dylib_name}"; then
			printf 'External consumer does not use the relocatable libmpq dylib ID.\n' >&2
			exit 1
		fi
		assert_no_mach_o_path_leaks "${consumer}" "${library_dir}"
	done
	"${temporary}/consumer-pkgconfig" "${fixture_archive}"
	"${temporary}/consumer-config" "${fixture_archive}"
}

case "${architecture}" in
	arm64|x86_64) ;;
	*)
		printf 'Unsupported macOS architecture: %s\n' "${architecture}" >&2
		exit 1
		;;
esac
if [[ "$(uname -s)" != Darwin ]]; then
	printf 'macOS package tests require Darwin.\n' >&2
	exit 1
fi
for path in "${package_archive}" "${fixture_archive}"; do
	if [[ ! -f "${path}" ]]; then
		printf 'Required file does not exist: %s\n' "${path}" >&2
		exit 1
	fi
done

cat > "${consumer_source}" <<'EOF'
#include <libmpq/mpq.h>

#include <stddef.h>
#include <stdint.h>

int
main(int argc, char **argv)
{
    mpq_archive_s *archive = NULL;
    uint32_t files = 0;

    if (argc != 2)
        return 2;
    if (libmpq__archive_open(&archive, argv[1], 0) != 0)
        return 3;
    if (libmpq__archive_files(archive, &files) != 0 || files == 0) {
        libmpq__archive_close(archive);
        return 4;
    }
    return libmpq__archive_close(archive) == 0 ? 0 : 5;
}
EOF

for location in first relocated; do
	extraction_dir="${temporary}/${location}"
	mkdir -p "${extraction_dir}"
	tar -xzf "${package_archive}" -C "${extraction_dir}"
	shopt -s dotglob nullglob
	package_entries=("${extraction_dir}"/*)
	shopt -u dotglob nullglob
	for package_entry in "${!package_entries[@]}"; do
		package_entries[${package_entry}]="${package_entries[${package_entry}]##*/}"
	done
	if ((${#package_entries[@]} != 1)) ||
		[[ ! "${package_entries[0]}" =~ ^libmpq-[0-9] ]]; then
		printf 'macOS package must contain exactly one top-level version directory.\n' >&2
		exit 1
	fi
	package_name="${package_entries[0]}"
	sdk_root="${extraction_dir}/${package_name}"
	library_dir="${sdk_root}/lib"
	pkgconfig_dir="${library_dir}/pkgconfig"
	validate_sdk
done
