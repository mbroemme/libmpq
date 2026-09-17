#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

set -euo pipefail

: "${LIBMPQ_NATIVE_ARCHITECTURE:?LIBMPQ_NATIVE_ARCHITECTURE is required}"
: "${LIBMPQ_NATIVE_BUILD_ENVIRONMENT:?LIBMPQ_NATIVE_BUILD_ENVIRONMENT is required}"
: "${LIBMPQ_NATIVE_VERSION:?LIBMPQ_NATIVE_VERSION is required}"
: "${MACOSX_DEPLOYMENT_TARGET:?MACOSX_DEPLOYMENT_TARGET is required}"

readonly project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly package_name="libmpq-${LIBMPQ_NATIVE_VERSION}-macos-${LIBMPQ_NATIVE_ARCHITECTURE}"
readonly archive_name="${package_name}.tar.gz"
readonly package_dir="${project_root}/release/${package_name}"
readonly archive_path="${project_root}/release/${archive_name}"
readonly temporary="$(mktemp -d -t libmpq-macos-package.XXXXXX)"
readonly install_root="${temporary}/install"
readonly installed_usr="${install_root}/usr"

cleanup()
{
	rm -rf "${temporary}"
}
trap cleanup EXIT

case "${LIBMPQ_NATIVE_ARCHITECTURE}" in
	arm64|x86_64) ;;
	*)
		printf 'Unsupported macOS architecture: %s\n' \
			"${LIBMPQ_NATIVE_ARCHITECTURE}" >&2
		exit 1
		;;
esac

if [[ "$(uname -s)" != Darwin ]]; then
	printf 'macOS package builds require Darwin.\n' >&2
	exit 1
fi
if [[ "$(uname -m)" != "${LIBMPQ_NATIVE_ARCHITECTURE}" ]]; then
	printf 'Native package architecture mismatch: expected %s, found %s\n' \
		"${LIBMPQ_NATIVE_ARCHITECTURE}" "$(uname -m)" >&2
	exit 1
fi

cd "${project_root}"
rm -rf "${package_dir}"
mkdir -p "${package_dir}" "${installed_usr}"

/usr/bin/make DESTDIR="${install_root}" install

for directory in bin include lib share; do
	if [[ -e "${installed_usr}/${directory}" ]]; then
		cp -a "${installed_usr}/${directory}" "${package_dir}/"
	fi
done
cp README.md DEVELOPER.md MPQ.md COPYING COPYING.LESSER "${package_dir}/"

readonly package_config="${package_dir}/bin/libmpq-config"
if [[ ! -f "${package_config}" ]]; then
	printf 'macOS package is missing libmpq-config.\n' >&2
	exit 1
fi
sed \
	-e 's|^      includes=.*|      includes="-I${prefix}/include"|' \
	-e 's|^      libdirs=.*|      libdirs="-L${exec_prefix}/lib"|' \
	"${package_config}" > "${package_config}.new"
chmod +x "${package_config}.new"
mv "${package_config}.new" "${package_config}"

find "${package_dir}" -type f -name '*.la' -delete
if find "${package_dir}" \( -type f \( -name '*.a' -o -name '*.la' -o \
	-name '*.o' -o -name '*.lo' \) -o -type d \( -name .libs -o -name .deps \) \) \
	-print -quit | grep -q .; then
	printf 'macOS package contains a static, libtool, or build artifact.\n' >&2
	exit 1
fi

shopt -s nullglob
shared_libraries=()
for shared_library in "${package_dir}/lib"/libmpq.*.dylib; do
	if [[ -f "${shared_library}" && ! -L "${shared_library}" ]]; then
		shared_libraries+=("${shared_library}")
	fi
done
shopt -u nullglob
if ((${#shared_libraries[@]} != 1)); then
	printf 'Expected exactly one concrete libmpq dylib.\n' >&2
	exit 1
fi

readonly shared_library="${shared_libraries[0]}"
readonly library_dir="$(dirname -- "${shared_library}")"
readonly dylib_name="$(basename -- "${shared_library}")"
install_name_tool -id "@rpath/${dylib_name}" "${shared_library}"
codesign --force --sign - "${shared_library}"
codesign --verify --strict "${shared_library}"

readonly package_pc="${library_dir}/pkgconfig/libmpq.pc"
if [[ ! -f "${package_pc}" ]]; then
	printf 'macOS package is missing libmpq.pc.\n' >&2
	exit 1
fi
{
	printf '%s\n' 'prefix=${pcfiledir}/../..'
	printf '%s\n' 'exec_prefix=${prefix}'
	printf '%s\n' 'libdir=${prefix}/lib'
	printf '%s\n\n' 'includedir=${prefix}/include'
	sed -n '/^Name:/,$p' "${package_pc}"
} > "${package_pc}.new"
mv "${package_pc}.new" "${package_pc}"

if otool -L "${shared_library}" | sed '1d' | grep -Eq \
	'(/opt/homebrew/|/usr/local/|/opt/local/|/Users/|/private/|/tmp/|/var/folders/)'; then
	printf 'macOS package dylib has a non-relocatable dependency path.\n' >&2
	exit 1
fi

{
	printf 'libmpq_version=%s\n' "${LIBMPQ_NATIVE_VERSION}"
	printf 'architecture=%s\n' "${LIBMPQ_NATIVE_ARCHITECTURE}"
	printf 'os=macos\n'
	printf 'macos_deployment_target=%s\n' "${MACOSX_DEPLOYMENT_TARGET}"
	printf 'build_environment=%s\n' "${LIBMPQ_NATIVE_BUILD_ENVIRONMENT}"
	printf 'dylib_id=@rpath/%s\n' "${dylib_name}"
} > "${package_dir}/BUILDINFO"

tar -czf "${archive_path}" -C "${project_root}/release" "${package_name}"
