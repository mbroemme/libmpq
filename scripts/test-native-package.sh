#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

set -euo pipefail

if (($# != 2)); then
	printf 'Usage: %s PACKAGE_ARCHIVE FIXTURE_ARCHIVE\n' "${0##*/}" >&2
	exit 1
fi

readonly package_archive="$1"
readonly fixture_archive="$2"
readonly project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly temporary="$(mktemp -d -t libmpq-native-test.XXXXXX)"
readonly extraction_dir="${temporary}/package"
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

glibc_requirement()
{
	local requirement

	requirement="$(readelf --version-info "$1" |
		grep -o 'GLIBC_[0-9][0-9.]*' | sort -Vu | tail -n 1 || true)"
	printf '%s\n' "${requirement:-none}"
}

assert_manpage_set()
{
	local section source_manpages package_manpages

	section="$1"
	source_manpages="$(find "${project_root}/docs/${section}" -maxdepth 1 -type f \
		-name "*.${section#man}" -print | sed 's#.*/##' | sort)"
	package_manpages="$(find "${sdk_root}/share/man/${section}" -maxdepth 1 -type f \
		-name "*.${section#man}" -print | sed 's#.*/##' | sort)"
	if [[ "${source_manpages}" != "${package_manpages}" ]]; then
		printf 'Native package %s pages do not match the canonical source set.\n' \
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
	cc -std=c99 -Wall -Wextra -Werror "${cflags_array[@]}" "${consumer_source}" \
		-o "${output}" "${libs_array[@]}"
}

for path in "${package_archive}" "${fixture_archive}"; do
	if [[ ! -f "${path}" ]]; then
		printf 'Required file does not exist: %s\n' "${path}" >&2
		exit 1
	fi
done

mkdir -p "${extraction_dir}"
tar -xzf "${package_archive}" -C "${extraction_dir}"

mapfile -t package_entries < <(
	find "${extraction_dir}" -mindepth 1 -maxdepth 1 -print | sed 's#.*/##'
)
if ((${#package_entries[@]} != 1)) || [[ ! "${package_entries[0]}" =~ ^libmpq-[0-9] ]]; then
	printf 'Native package must contain exactly one top-level libmpq version directory.\n' >&2
	exit 1
fi

readonly sdk_root="${extraction_dir}/${package_entries[0]}"
readonly library_dir="${sdk_root}/lib"
readonly pkgconfig_dir="${library_dir}/pkgconfig"
for path in \
	"${sdk_root}/include/libmpq/mpq.h" \
	"${sdk_root}/bin/libmpq-config" \
	"${pkgconfig_dir}/libmpq.pc" \
	"${sdk_root}/share/man/man1/libmpq-config.1" \
	"${sdk_root}/share/man/man3/libmpq.3" \
	"${sdk_root}/README.md" \
	"${sdk_root}/COPYING" \
	"${sdk_root}/COPYING.LESSER" \
	"${sdk_root}/BUILDINFO"; do
	if [[ ! -f "${path}" ]]; then
		printf 'Native package is missing: %s\n' "${path}" >&2
		exit 1
	fi
done

if [[ "$(buildinfo_value libmpq_version)" != "${package_entries[0]#libmpq-}" ]] ||
	[[ "$(buildinfo_value architecture)" != x86_64 ]] ||
	[[ "$(buildinfo_value os)" != linux ]] ||
	[[ -z "$(buildinfo_value build_environment)" ]]; then
	printf 'Native package has inconsistent basic BUILDINFO metadata.\n' >&2
	exit 1
fi

if find "${sdk_root}" \( -type f \( -name '*.a' -o -name '*.la' -o \
	-name '*.o' -o -name '*.lo' \) -o -type d \( -name .libs -o -name .deps \) \) \
	-print -quit | grep -q .; then
	printf 'Native package must not include static, libtool, or build artifacts.\n' >&2
	exit 1
fi

assert_manpage_set man1
assert_manpage_set man3

mapfile -t shared_libraries < <(
	find "${library_dir}" -maxdepth 1 -type f -name 'libmpq.so.*' -print | sort
)
if ((${#shared_libraries[@]} != 1)); then
	printf 'Native package has an invalid concrete shared library set.\n' >&2
	exit 1
fi

readonly shared_library="${shared_libraries[0]}"
readonly soname="$(readelf -d "${shared_library}" |
	sed -n 's/.*SONAME.*\[\(.*\)\].*/\1/p')"
if [[ "${soname}" != libmpq.so.1 ]] || [[ ! -e "${library_dir}/libmpq.so" ]] ||
	[[ ! -e "${library_dir}/${soname}" ]] ||
	[[ "$(buildinfo_value soname)" != "${soname}" ]]; then
	printf 'Native package shared library SONAME set is invalid.\n' >&2
	exit 1
fi

case "$(buildinfo_value libc)" in
	glibc)
		readonly glibc_baseline="$(buildinfo_value glibc_baseline)"
		readonly recorded_requirement="$(buildinfo_value glibc_max_required_symbol)"
		readonly observed_requirement="$(glibc_requirement "${shared_library}")"
		if [[ -z "${glibc_baseline}" ]] ||
			[[ "${recorded_requirement}" != "${observed_requirement}" ]]; then
			printf 'Native package GLIBC metadata does not match the packaged ELF.\n' >&2
			exit 1
		fi
		if [[ "${observed_requirement}" != none ]] &&
			[[ "$(printf '%s\n%s\n' "${observed_requirement#GLIBC_}" \
				"${glibc_baseline}" | sort -V | head -n 1)" != \
				"${observed_requirement#GLIBC_}" ]]; then
			printf 'Native package exceeds the GLIBC %s compatibility baseline.\n' \
				"${glibc_baseline}" >&2
			exit 1
		fi
		;;
	musl)
		if [[ -z "$(buildinfo_value musl_baseline)" ]] ||
			[[ -z "$(buildinfo_value libc_build_version)" ]]; then
			printf 'Native package has incomplete musl compatibility metadata.\n' >&2
			exit 1
		fi
		;;
	*)
		printf 'Native package has an unsupported libc declaration.\n' >&2
		exit 1
		;;
esac

readonly config_cflags="$("${sdk_root}/bin/libmpq-config" \
	--prefix="${sdk_root}" --cflags)"
readonly config_libs="$("${sdk_root}/bin/libmpq-config" \
	--prefix="${sdk_root}" --libs)"
if [[ "${config_cflags}" != "-I${sdk_root}/include" ]] ||
	[[ "${config_libs}" != "-L${sdk_root}/lib -lmpq -lbz2 -lz" ]]; then
	printf 'Packaged libmpq-config does not describe the extracted SDK layout.\n' >&2
	exit 1
fi

export PKG_CONFIG_PATH="${pkgconfig_dir}"
export PKG_CONFIG_LIBDIR="${pkgconfig_dir}"
readonly pkgconfig_cflags="$(pkg-config --cflags libmpq)"
readonly pkgconfig_libs="$(pkg-config --libs libmpq)"
if [[ "${pkgconfig_cflags}" != *"-I${sdk_root}/"* ]] ||
	[[ "${pkgconfig_libs}" != *"-L${sdk_root}/"* ]]; then
	printf 'Packaged libmpq.pc does not describe the extracted SDK layout.\n' >&2
	exit 1
fi

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

readonly pkgconfig_consumer="${temporary}/consumer-pkgconfig"
readonly config_consumer="${temporary}/consumer-config"
compile_consumer "${pkgconfig_consumer}" "${pkgconfig_cflags}" "${pkgconfig_libs}"
compile_consumer "${config_consumer}" "${config_cflags}" "${config_libs}"

if ! readelf -d "${pkgconfig_consumer}" | grep -Fq 'Shared library: [libmpq.so.1]'; then
	printf 'pkg-config consumer does not use libmpq.so.1.\n' >&2
	exit 1
fi
if ! LD_LIBRARY_PATH="${library_dir}" ldd "${pkgconfig_consumer}" |
	grep -F 'libmpq.so.1 =>' | grep -Fq "${library_dir}/"; then
	printf 'pkg-config consumer does not resolve libmpq.so.1 from the SDK.\n' >&2
	exit 1
fi
LD_LIBRARY_PATH="${library_dir}" "${pkgconfig_consumer}" "${fixture_archive}"
LD_LIBRARY_PATH="${library_dir}" "${config_consumer}" "${fixture_archive}"
