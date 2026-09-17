#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

# Exercise packaging policy with text import lists, not pretend PE binaries.
# The Windows jobs still inspect real imports and execute installed consumers.
# Fixture expressions are deliberately written and checked without expansion.
# shellcheck disable=SC2016
set -euo pipefail
project="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(sed -nE 's/^AC_INIT\(\[libmpq\],[[:space:]]*\[([^]]+)\].*/\1/p' "${project}/configure.ac")"
if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	printf 'Cannot determine release version from configure.ac: %s\n' "${version}" >&2
	exit 1
fi
mismatched_version="${version%.*}.$((10#${version##*.} + 1))"
temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT
root="${temporary}/paths with spaces"
mkdir -p "${root}/tools" "${root}/Windows/System32" "${root}/project"
export SystemRoot="${root}/Windows"
touch "${SystemRoot}/System32/KERNEL32.DLL"

cat > "${root}/tools/objdump" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
	-f)
		machine="${TEST_MACHINE}"
		if [[ "${2##*/}" != libmpq.dll ]]; then machine="${TEST_RUNTIME_MACHINE:-${machine}}"; fi
		case "${machine}" in
			8664) format=pei-x86-64 ;;
			AA64) format=coff-arm64 ;;
			*) format=unknown ;;
		esac
		printf '%s: file format %s\r\n' "$2" "${format}"
		;;
	-p)
		while IFS= read -r dependency; do printf '    DLL Name: %s\n' "${dependency}"; done < "$2"
		;;
	*) exit 1 ;;
esac
exit "${TEST_INSPECT_STATUS:-0}"
EOF
cat > "${root}/tools/dumpbin.exe" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${MSYS2_ARG_CONV_EXCL}" == '*' && "${MSYS_NO_PATHCONV}" == 1 ]]
[[ "$1" == /nologo ]]
case "$2" in
	/headers)
		machine="${TEST_MACHINE}"
		if [[ "${3##*/}" != libmpq.dll ]]; then machine="${TEST_RUNTIME_MACHINE:-${machine}}"; fi
		printf '    %s machine (mock architecture)\r\n' "${machine}"
		;;
	/dependents)
		while IFS= read -r dependency; do printf '    %s\r\n' "${dependency}"; done < "$3"
		;;
	*) exit 1 ;;
esac
exit "${TEST_INSPECT_STATUS:-0}"
EOF
cat > "${root}/tools/pacman" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
	-Qqo) printf 'codec\n' ;;
	-Qlq) printf '%s\n' "${TEST_RUNTIME}/bin/Codec.DLL" "${TEST_RUNTIME}/share/licenses/codec/LICENSE" ;;
	*) exit 1 ;;
esac
EOF
chmod +x "${root}/tools/objdump" "${root}/tools/dumpbin.exe" "${root}/tools/pacman"
ln -s "$(command -v 7z)" "${root}/tools/7z.exe"
export PATH="${root}/tools:${PATH}"

expect_failure()
{
	if "$@" > "${temporary}/failure.log" 2>&1; then
		printf 'Unexpected success: %s\n' "$*" >&2
		exit 1
	fi
}

reset_stage()
{
	rm -rf "${stage}"
	mkdir -p "${stage}/bin" "${stage}/lib/pkgconfig" "${stage}/include/libmpq"
	touch "${stage}/include/libmpq/mpq.h" "${stage}/lib/${library}"
	printf 'CODEC.DLL\nKERNEL32.dll\napi-ms-win-crt-runtime-l1-1-0.dll\n' > "${stage}/bin/libmpq.dll"
	printf 'prefix=/usr\n' > "${stage}/lib/pkgconfig/libmpq.pc"
	printf '#!/bin/sh\nprefix=/usr\nprintf "%%s\\n" "${prefix}"\n' > "${stage}/bin/libmpq-config"
}

for combination in msvc:x64 msvc:arm64 mingw:x86_64 mingw:aarch64; do
	toolchain="${combination%:*}"
	architecture="${combination#*:}"
	export TEST_MACHINE=8664
	if [[ "${architecture}" == arm64 || "${architecture}" == aarch64 ]]; then TEST_MACHINE=AA64; fi
	export TEST_RUNTIME="${root}/installed/${architecture}-windows"
	mkdir -p "${TEST_RUNTIME}/bin" "${TEST_RUNTIME}/share/codec" \
		"${TEST_RUNTIME}/share/licenses/codec" "${TEST_RUNTIME}/../vcpkg/info"
	printf 'kernel32.dll\n' > "${TEST_RUNTIME}/bin/helper.dll"
	printf 'HELPER.DLL\ncodec.dll\n' > "${TEST_RUNTIME}/bin/Codec.DLL"
	printf 'Original dependency license\n' > "${TEST_RUNTIME}/share/codec/copyright"
	cp "${TEST_RUNTIME}/share/codec/copyright" "${TEST_RUNTIME}/share/licenses/codec/LICENSE"
	printf '%s/bin/Codec.DLL\n%s/bin/helper.dll\n' "${architecture}-windows" \
		"${architecture}-windows" > "${TEST_RUNTIME}/../vcpkg/info/codec_1_${architecture}.list"
	if [[ "${toolchain}" == msvc ]]; then
		suffix="msvc-${architecture}"; library=libmpq.lib
	else
		suffix="mingw-${architecture}"; library=libmpq.dll.a
	fi
	stage="${root}/libmpq-${version}-windows-${suffix}"
	output="${root}/dist/${stage##*/}.zip"
	options=(--toolchain "${toolchain}" --architecture "${architecture}" --stage "${stage}" --runtime "${TEST_RUNTIME}" \
		--source "${project}" --output "${output}" --version "${version}")
	reset_stage
	expect_failure bash "${project}/scripts/package-windows.sh" prepare "${options[@]}" --architecture unsupported
	grep -q 'Unsupported Windows toolchain/architecture' "${temporary}/failure.log"

	# MinGW uses aarch64, not the MSVC arm64 spelling.
	expect_failure bash "${project}/scripts/package-windows.sh" prepare "${options[@]}" --toolchain mingw --architecture arm64
	grep -q 'Unsupported Windows toolchain/architecture' "${temporary}/failure.log"
	wrong_machine=AA64
	if [[ "${TEST_MACHINE}" == AA64 ]]; then wrong_machine=8664; fi
	expect_failure env TEST_MACHINE="${wrong_machine}" bash "${project}/scripts/package-windows.sh" prepare "${options[@]}"
	grep -q 'PE architecture mismatch' "${temporary}/failure.log"
	expect_failure env TEST_RUNTIME_MACHINE="${wrong_machine}" bash "${project}/scripts/package-windows.sh" prepare "${options[@]}"
	grep -q 'PE architecture mismatch' "${temporary}/failure.log"
	reset_stage
	bash "${project}/scripts/package-windows.sh" prepare "${options[@]}"
	for document in README.md DEVELOPER.md MPQ.md; do
		cmp "${project}/${document}" "${stage}/${document}"
	done
	[[ -f "${stage}/bin/Codec.DLL" && -f "${stage}/bin/helper.dll" ]]
	[[ ! -e "${stage}/bin/KERNEL32.DLL" && ! -e "${stage}/runtime-dependencies.json" ]]
	if [[ "${toolchain}" == msvc ]]; then
		cmp "${TEST_RUNTIME}/share/codec/copyright" "${stage}/licenses/codec/copyright"
	else
		cmp "${TEST_RUNTIME}/share/licenses/codec/LICENSE" "${stage}/licenses/codec/codec/LICENSE"
		grep -Fx 'prefix=${pcfiledir}/../..' "${stage}/lib/pkgconfig/libmpq.pc"
		[[ "$(sh "${stage}/bin/libmpq-config")" == "${stage}" ]]
	fi
	expect_failure env TEST_RUNTIME_MACHINE="${wrong_machine}" bash "${project}/scripts/package-windows.sh" archive "${options[@]}"
	grep -q 'PE architecture mismatch' "${temporary}/failure.log"
	bash "${project}/scripts/package-windows.sh" archive "${options[@]}" > "${temporary}/zip.log"
	unzip -t "${output}" > /dev/null
	for document in README.md DEVELOPER.md MPQ.md; do
		unzip -p "${output}" "${stage##*/}/${document}" | cmp "${project}/${document}" -
	done
	expect_failure bash "${project}/scripts/package-windows.sh" archive "${options[@]}"
	grep -q 'Refusing to overwrite' "${temporary}/failure.log"

	# The final scan must fail even though the missing DLL exists in the runtime.
	rm "${stage}/bin/helper.dll"
	expect_failure bash "${project}/scripts/package-windows.sh" archive "${options[@]}"
	grep -q 'Missing dependency helper.dll' "${temporary}/failure.log"
	reset_stage
	mv "${TEST_RUNTIME}/bin/helper.dll" "${TEST_RUNTIME}/helper.saved"
	expect_failure bash "${project}/scripts/package-windows.sh" prepare "${options[@]}"
	grep -q 'Missing dependency helper.dll' "${temporary}/failure.log"
	mv "${TEST_RUNTIME}/helper.saved" "${TEST_RUNTIME}/bin/helper.dll"
	reset_stage
	touch "${stage}/lib/libmpq.a"
	expect_failure bash "${project}/scripts/package-windows.sh" prepare "${options[@]}"
	grep -q 'Static libmpq archive' "${temporary}/failure.log"
	reset_stage
	mv "${TEST_RUNTIME}/share" "${TEST_RUNTIME}/share.saved"
	expect_failure bash "${project}/scripts/package-windows.sh" prepare "${options[@]}"
	mv "${TEST_RUNTIME}/share.saved" "${TEST_RUNTIME}/share"
	reset_stage
	expect_failure env TEST_INSPECT_STATUS=1 bash "${project}/scripts/package-windows.sh" prepare "${options[@]}"
	grep -q 'Cannot inspect' "${temporary}/failure.log"
	: > "${stage}/bin/libmpq.dll"
	expect_failure bash "${project}/scripts/package-windows.sh" prepare "${options[@]}"
	grep -q 'No PE imports' "${temporary}/failure.log"
done

cd "${root}/project"
printf 'AC_INIT([libmpq],[%s],[mail],[libmpq])\n' "${version}" > configure.ac
printf 'project(libmpq VERSION %s LANGUAGES C)\n' "${version}" > CMakeLists.txt
export GITHUB_REF="refs/tags/v${version}" GITHUB_REF_NAME="v${version}" GITHUB_OUTPUT="${temporary}/output"
bash "${project}/scripts/validate-release.sh"
grep -Fx "version=${version}" "${GITHUB_OUTPUT}"
expect_failure env GITHUB_REF="refs/heads/v${version}" bash "${project}/scripts/validate-release.sh"
for tag in "v${mismatched_version}" "v${version}-rc1" "v${version};false"; do
	expect_failure env GITHUB_REF="refs/tags/${tag}" GITHUB_REF_NAME="${tag}" \
		bash "${project}/scripts/validate-release.sh"
done
printf 'project(libmpq VERSION %s LANGUAGES C)\n' "${mismatched_version}" > CMakeLists.txt
expect_failure bash "${project}/scripts/validate-release.sh"

# Exercise sorted checksum generation on the four test ZIPs, not release assets.
cd "${root}/dist"
printf '%s\n' *.zip | LC_ALL=C sort | while IFS= read -r asset; do
	sha256sum "${asset}"
done > SHA256SUMS
sha256sum --check SHA256SUMS
printf 'Release helper tests passed.\n'
