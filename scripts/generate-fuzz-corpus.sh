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
readonly encrypted_output="${output_root}/encrypted-archive"
readonly file_read_output="${output_root}/file-read"
readonly sector_output="${output_root}/sector-decode"
readonly writer_output="${output_root}/writer-roundtrip"
readonly pkware_output="${output_root}/pkware-decode"
readonly huffman_output="${output_root}/huffman-decode"
readonly zlib_output="${output_root}/zlib-decode"
readonly bzip2_output="${output_root}/bzip2-decode"
readonly wave_output="${output_root}/wave-decode"

mkdir -p \
	"${archive_output}" \
	"${encrypted_output}" \
	"${file_read_output}" \
	"${sector_output}" \
	"${writer_output}" \
	"${pkware_output}" \
	"${huffman_output}" \
	"${zlib_output}" \
	"${bzip2_output}" \
	"${wave_output}"

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

# Create a valid-sized v1 header with fuzzer-interesting empty table locations.
write_v1_empty_tables_header()
{
	printf '\x4d\x50\x51\x1a\x20\x00\x00\x00\x20\x00\x00\x00\x00\x00\x03\x00\x20\x00\x00\x00\x20\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00'
}

# Create a v1 header whose table fields test oversized and wrapped offsets.
write_v1_oversized_tables_header()
{
	printf '\x4d\x50\x51\x1a\x20\x00\x00\x00\xff\xff\xff\x7f\x00\x00\x03\x00\xff\xff\xff\xff\xfe\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f'
}

write_v1_header > "${archive_output}/minimal-v1-empty.mpq"
write_v2_header > "${archive_output}/minimal-v2-empty.mpq"
write_v1_empty_tables_header > "${archive_output}/v1-empty-tables.mpq"
write_v1_oversized_tables_header > "${archive_output}/v1-oversized-tables.mpq"
dd if=/dev/zero bs=512 count=1 status=none > "${archive_output}/embedded-v1-header.bin"
write_v1_header >> "${archive_output}/embedded-v1-header.bin"
dd if="${project_root}/tests/fixtures/mpq-v1-features.mpq" \
	bs=1 count=31 status=none > "${archive_output}/truncated-v1-header.mpq"
dd if="${project_root}/tests/fixtures/mpq-v2-features.mpq" \
	bs=1 count=44 status=none > "${archive_output}/truncated-v2-header.mpq"

# Seed valid archive reader paths with known names, bad indexes, and long names.
printf '\x00\x00\x00\x00\x00' > "${file_read_output}/known-file-and-zero-index"
printf '\x01../../not-a-member' > "${file_read_output}/mutated-path"
printf '\x01dir\\entry.txt\xff\xff\xff\xff' > "${file_read_output}/separator-and-index"
printf '%.0sA' {1..255} > "${file_read_output}/maximum-name"

# Seed bounded archive creation with raw and supported compressed payloads.
printf '\x00\x00hello writer' > "${writer_output}/v1-raw"
printf '\x01\x01compressed writer payload compressed writer payload' > "${writer_output}/v2-zlib"
printf '\x00\x03bzip2 candidate payload bzip2 candidate payload' > "${writer_output}/v1-bzip2"

# Select encrypted seed header, hash/block table, and known-key mutation offsets.
printf '\x00' > "${encrypted_output}/unmodified-seed"
printf '\x03\x00\x00\x00\xff\x10\x00\x00\x00\x80\x20\x00\x00\x00\x01' > \
	"${encrypted_output}/header-and-table-mutations"
printf '\x04\xff\xff\xff\xff\xff\x40\x00\x00\x00\x7f\x80\x00\x00\x00\x55' > \
	"${encrypted_output}/wrapped-offset-mutations"

printf '\x00\x00\x00' > "${sector_output}/multi-empty"
printf '\x01\x00\x00' > "${sector_output}/pkware-empty"
printf '\x00\xfd\xff\x03' > "${sector_output}/multi-zlib-empty-large"
for mask in 01 02 08 10 40 80 03 04; do
	printf '%b' "\\x00\\x00\\x00\\x${mask}" > "${sector_output}/multi-mask-${mask}"
done

# Frame focused decoder inputs as output-size-minus-one followed by codec data.
printf '\x00\x00\x00' > "${pkware_output}/empty"
printf '\x00\x00\x00\x00\x00' > "${huffman_output}/empty"
printf '\x00\x00\x78\x9c\x73\x04\x00\x00\x42\x00\x42' > "${zlib_output}/single-byte"
printf '\x00\x00BZh' > "${bzip2_output}/truncated-header"
printf '\x00\x00\x00\x00' > "${wave_output}/mono-empty"
printf '\x01\x00\x00\x00' > "${wave_output}/stereo-empty"
