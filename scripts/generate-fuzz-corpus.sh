#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.

set -euo pipefail

if (($# != 1)); then
	printf 'Usage: %s <output-directory>\n' "${0##*/}" >&2
	exit 2
fi

readonly project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly output_root="$1"
readonly archive_output="${output_root}/archive-open"
readonly sector_output="${output_root}/sector-decode"

mkdir -p "${archive_output}" "${sector_output}"

cp "${project_root}/tests/fixtures/mpq-v1-features.mpq" "${archive_output}/fixture-v1.mpq"
cp "${project_root}/tests/fixtures/mpq-v2-features.mpq" "${archive_output}/fixture-v2.mpq"

write_v1_header()
{
	printf '\x4d\x50\x51\x1a\x20\x00\x00\x00\x20\x00\x00\x00\x00\x00\x03\x00\x20\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
}

write_v2_header()
{
	printf '\x4d\x50\x51\x1a\x2c\x00\x00\x00\x2c\x00\x00\x00\x01\x00\x03\x00\x2c\x00\x00\x00\x2c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
}

write_v1_header > "${archive_output}/minimal-v1-empty.mpq"
write_v2_header > "${archive_output}/minimal-v2-empty.mpq"
dd if=/dev/zero bs=512 count=1 status=none > "${archive_output}/embedded-v1-header.bin"
write_v1_header >> "${archive_output}/embedded-v1-header.bin"

printf '\x00\x00\x00' > "${sector_output}/multi-empty"
printf '\x01\x00\x00' > "${sector_output}/pkware-empty"
printf '\x00\xfd\xff\x03' > "${sector_output}/multi-zlib-empty-large"
for mask in 01 02 08 10 40 80 03 04; do
	printf '%b' "\\x00\\x00\\x00\\x${mask}" > "${sector_output}/multi-mask-${mask}"
done
