#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

set -euo pipefail

: "${LIBMPQ_NATIVE_LIBC:?LIBMPQ_NATIVE_LIBC is required}"
: "${LIBMPQ_NATIVE_VERSION:?LIBMPQ_NATIVE_VERSION is required}"
: "${LIBMPQ_NATIVE_BUILD_ENVIRONMENT:?LIBMPQ_NATIVE_BUILD_ENVIRONMENT is required}"

readonly project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly package_name="libmpq-${LIBMPQ_NATIVE_VERSION}"
readonly archive_name="${package_name}-linux-${LIBMPQ_NATIVE_LIBC}-x86_64.tar.gz"
readonly package_dir="${project_root}/release/${package_name}"
readonly archive_path="${project_root}/release/${archive_name}"
readonly temporary="$(mktemp -d -t libmpq-native-package.XXXXXX)"
readonly install_root="${temporary}/install"
readonly installed_usr="${install_root}/usr"

cleanup()
{
	rm -rf "${temporary}"
}
trap cleanup EXIT

glibc_requirement()
{
	local requirement

	requirement="$(readelf --version-info "$1" |
		grep -o 'GLIBC_[0-9][0-9.]*' | sort -Vu | tail -n 1 || true)"
	printf '%s\n' "${requirement:-none}"
}

musl_build_version()
{
	local version

	version="$(ldd --version 2>&1 |
		sed -n 's/.*Version \([0-9][0-9.]*\).*/\1/p' | head -n 1)"
	if [[ -z "${version}" ]]; then
		printf 'Unable to determine the musl build version from ldd --version.\n' >&2
		exit 1
	fi
	printf '%s\n' "${version}"
}

case "${LIBMPQ_NATIVE_LIBC}" in
	glibc)
		: "${LIBMPQ_NATIVE_GLIBC_BASELINE:?LIBMPQ_NATIVE_GLIBC_BASELINE is required for glibc packages}"
		;;
	musl)
		: "${LIBMPQ_NATIVE_MUSL_BASELINE:?LIBMPQ_NATIVE_MUSL_BASELINE is required for musl packages}"
		;;
	*)
		printf 'Unsupported libc: %s\n' "${LIBMPQ_NATIVE_LIBC}" >&2
		exit 1
		;;
esac

if [[ "$(uname -m)" != x86_64 ]]; then
	printf 'Native package builds require x86_64, found: %s\n' "$(uname -m)" >&2
	exit 1
fi

cd "${project_root}"
rm -rf "${package_dir}"
mkdir -p "${package_dir}" "${installed_usr}"

make DESTDIR="${install_root}" install

for directory in bin include lib share; do
	if [[ -e "${installed_usr}/${directory}" ]]; then
		cp -a "${installed_usr}/${directory}" "${package_dir}/"
	fi
done
cp README.md COPYING COPYING.LESSER "${package_dir}/"

readonly package_config="${package_dir}/bin/libmpq-config"
if [[ ! -f "${package_config}" ]]; then
	printf 'Native package is missing libmpq-config.\n' >&2
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
	printf 'Native package contains a static, libtool, or build artifact.\n' >&2
	exit 1
fi

mapfile -t shared_libraries < <(
	find "${package_dir}/lib" -maxdepth 1 -type f -name 'libmpq.so.*' -print | sort
)
if ((${#shared_libraries[@]} != 1)); then
	printf 'Expected exactly one concrete libmpq shared library.\n' >&2
	exit 1
fi

readonly shared_library="${shared_libraries[0]}"
readonly library_dir="$(dirname -- "${shared_library}")"
readonly soname="$(readelf -d "${shared_library}" |
	sed -n 's/.*SONAME.*\[\(.*\)\].*/\1/p')"
if [[ "${soname}" != libmpq.so.1 ]] || [[ ! -e "${library_dir}/${soname}" ]] ||
	[[ ! -e "${library_dir}/libmpq.so" ]]; then
	printf 'Native package shared library has no usable libmpq.so.1 SONAME set.\n' >&2
	exit 1
fi

readonly package_pc="${library_dir}/pkgconfig/libmpq.pc"
if [[ ! -f "${package_pc}" ]]; then
	printf 'Native package is missing libmpq.pc.\n' >&2
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

{
	printf 'libmpq_version=%s\n' "${LIBMPQ_NATIVE_VERSION}"
	printf 'architecture=x86_64\n'
	printf 'os=linux\n'
	printf 'libc=%s\n' "${LIBMPQ_NATIVE_LIBC}"
	if [[ "${LIBMPQ_NATIVE_LIBC}" == glibc ]]; then
		printf 'glibc_baseline=%s\n' "${LIBMPQ_NATIVE_GLIBC_BASELINE}"
		printf 'glibc_max_required_symbol=%s\n' "$(glibc_requirement "${shared_library}")"
	else
		printf 'musl_baseline=%s\n' "${LIBMPQ_NATIVE_MUSL_BASELINE}"
		printf 'libc_build_version=%s\n' "$(musl_build_version)"
	fi
	printf 'build_environment=%s\n' "${LIBMPQ_NATIVE_BUILD_ENVIRONMENT}"
	printf 'soname=%s\n' "${soname}"
} > "${package_dir}/BUILDINFO"

tar -czf "${archive_path}" -C "${project_root}/release" "${package_name}"
