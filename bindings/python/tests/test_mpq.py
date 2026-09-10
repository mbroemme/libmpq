# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

"""End-to-end tests for the public Python binding and native libmpq ABI."""

import ctypes
import hashlib
import os
import zlib
from pathlib import Path

import pytest

import mpq


FIXTURES = Path(__file__).resolve().parent / "fixtures"
if not FIXTURES.is_dir():
    FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures"

SPARSE_TEXT = "This text uses SPARSE compression and decompression.\n" * 16
SPARSE_BYTES = b"\xff\xfe\x00\x00" + SPARSE_TEXT.encode("utf-32-le")


@pytest.mark.parametrize("layout,size,fields", [
    (mpq.ArchiveCreateOptions, 20, [
        ("version", 0, 4), ("max_files", 4, 4), ("sector_size", 8, 4),
        ("flags", 12, 4), ("attributes", 16, 4),
    ]),
    (mpq.FileCreateOptions, 16, [
        ("flags", 0, 4), ("compression_first", 4, 4), ("compression_next", 8, 4),
        ("locale", 12, 2), ("platform", 14, 2),
    ]),
    (mpq._FileAttributes, 40, [
        ("flags", 0, 4), ("crc32", 4, 4), ("filetime", 8, 8),
        ("md5", 16, 16), ("patch_bit", 32, 4), ("reserved", 36, 4),
    ]),
])
def test_native_struct_layouts(layout, size, fields):
    """All public value layouts match C, including explicit reserved bytes."""
    assert ctypes.sizeof(layout) == size
    for name, offset, field_size in fields:
        field = getattr(layout, name)
        assert field.offset == offset
        assert field.size == field_size
    assert mpq._FileAttributes.filetime.offset % ctypes.alignment(ctypes.c_uint64) == 0


def test_version_errors_and_hashes():
    """Version, diagnostics, and Storm hashing work without an archive handle."""
    assert mpq.version()
    assert "format" in mpq.strerror(mpq.ERROR_FORMAT)
    assert len(mpq.file_hash("overview.txt")) == 3
    query = mpq.libmpq.libmpq__archive_compression_allowed
    assert query.restype == ctypes.c_int32
    assert query.argtypes == [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int32]
    assert not mpq.archive_compression_allowed(mpq.ARCHIVE_VERSION_TWO, mpq.COMPRESSION_HUFFMAN)
    assert mpq.archive_compression_allowed(mpq.ARCHIVE_VERSION_TWO, mpq.COMPRESSION_HUFFMAN,
                                     mpq.COMPRESSION_POLICY_EXTENDED)
    for version in (mpq.ARCHIVE_VERSION_ONE, mpq.ARCHIVE_VERSION_TWO):
        for policy in (mpq.COMPRESSION_POLICY_STANDARD, mpq.COMPRESSION_POLICY_EXTENDED):
            for method in (mpq.COMPRESSION_SPARSE,
                           mpq.COMPRESSION_SPARSE | mpq.COMPRESSION_ZLIB,
                           mpq.COMPRESSION_SPARSE | mpq.COMPRESSION_BZIP2):
                assert mpq.archive_compression_allowed(version, method, policy)
            assert not mpq.archive_compression_allowed(
                version, mpq.COMPRESSION_SPARSE | mpq.COMPRESSION_WAVE_MONO, policy)


def test_wheel_uses_bundled_library():
    """Wheel tests must load the private library shipped in mpq_libs."""
    if not os.environ.get("LIBMPQ_EXPECT_BUNDLED"):
        pytest.skip("only required for installed wheel tests")
    native = Path(mpq.libmpq._name).resolve()
    assert native.name == "libmpq.so"
    assert native.parent.name == "mpq_libs"
    assert mpq.version() == mpq.__version__


@pytest.mark.parametrize("name,version", [
    ("mpq-v1-features.mpq", 1),
    ("mpq-v2-features.mpq", 2),
])
def test_fixture_metadata_and_extraction(name, version):
    """Both tracked fixture formats open, resolve names, and extract bytes."""
    with mpq.Archive(FIXTURES / name, offset=0) as archive:
        assert archive.version == version
        assert "overview.txt" in archive
        entry = archive["overview.txt"]
        attributes = entry.attributes()
        assert archive.attributes_flags() == (7 if version == 1 else 15)
        assert attributes.crc32 == zlib.crc32(entry.read())
        assert attributes.md5 == hashlib.md5(entry.read()).digest()
        assert attributes.filetime == 132537600000000000
        assert not attributes.patch_bit
        assert b"libmpq" in entry.read()
        assert archive.metadata().files == archive.files
        assert entry.metadata().unpacked_size == entry.unpacked_size
        for member in ("sparse.txt", "sparse-zlib.txt", "sparse-bzip2.txt"):
            assert archive[member].read() == SPARSE_BYTES
            assert archive[member].read().decode("utf-32") == SPARSE_TEXT


@pytest.mark.parametrize("name,version,offset", [
    ("mpq-v1-features.mpqe", 1, 0),
    ("mpq-v2-features.mpqe", 2, -1),
])
def test_mpqe_fixture_metadata_extraction_and_clone(name, version, offset):
    """MPQE opening uses borrowed credentials and supports independent clones."""
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    with mpq.Archive.open_mpqe(FIXTURES / name, memoryview(code), offset) as archive:
        assert archive.attributes_flags() == (7 if version == 1 else 15)
        assert archive.version == version
        assert b"libmpq" in archive["overview.txt"].read()
        clone = archive.clone()
        try:
            assert clone["overview.txt"].attributes() == archive["overview.txt"].attributes()
            assert clone["overview.txt"].read() == archive["overview.txt"].read()
            for member in ("sparse.txt", "sparse-zlib.txt", "sparse-bzip2.txt"):
                assert clone[member].read() == archive[member].read() == SPARSE_BYTES
        finally:
            clone.close()
    with pytest.raises(mpq.LibmpqDecryptError):
        mpq.Archive.open_mpqe(FIXTURES / name, code[:-1], offset)


def test_mpqe_creation_replaces_destination(tmp_path):
    """MPQE creation publishes a complete archive over an existing target."""
    path = tmp_path / "created.mpqe"
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    path.write_bytes(b"previous destination")
    with mpq.Writer.create_mpqe(path, code, version=mpq.ARCHIVE_VERSION_TWO,
                                attributes=mpq.ATTRIBUTE_CRC32) as writer:
        writer.add("payload.txt", b"Python MPQE writer regression\n")
    with mpq.Archive.open_mpqe(path, code, offset=0) as archive:
        assert archive.version == 2
        assert archive.attributes_flags() == mpq.ATTRIBUTE_CRC32
        assert archive["payload.txt"].read() == b"Python MPQE writer regression\n"
    with pytest.raises(mpq.LibmpqDecryptError):
        mpq.Writer.create_mpqe(path, code[:-1])
    with pytest.raises(mpq.LibmpqFormatError):
        mpq.Writer.create_mpqe(path, code, attributes=0x10)
    with pytest.raises(mpq.LibmpqFormatError):
        mpq.Writer(tmp_path / "invalid.mpq", attributes=0x10)


def test_creation_streaming_compression_clone_and_blocks(tmp_path):
    """Creation APIs round-trip raw, compressed, path, stream, clone, and blocks."""
    archive_path = tmp_path / "created.mpq"
    source_path = tmp_path / "source.txt"
    source_path.write_bytes(b"path payload")
    repetitive = b"R" * 12000
    streamed = bytes(range(256)) * 20

    with mpq.Writer(archive_path, version=mpq.ARCHIVE_VERSION_TWO,
                    flags=mpq.ARCHIVE_CREATE_LISTFILE,
                    attributes=mpq.ATTRIBUTE_CRC32 |
                          mpq.ATTRIBUTE_FILETIME | mpq.ATTRIBUTE_MD5 |
                          mpq.ATTRIBUTE_PATCH_BIT) as writer:
        writer.add("raw.bin", b"raw payload")
        writer.add("compressed.bin", repetitive,
                   mpq.FileCreateOptions.compressed(mpq.COMPRESSION_ZLIB,
                                                    mpq.COMPRESSION_ZLIB))
        writer.add("lzma.bin", repetitive,
                   mpq.FileCreateOptions.compressed(mpq.COMPRESSION_LZMA,
                                                    mpq.COMPRESSION_LZMA))
        writer.add_path("path.txt", source_path)
        with writer.begin("stream.bin", len(streamed)) as stream:
            stream.set_filetime(0xfedcba9876543210)
            stream.write(streamed[:1000])
            stream.write(streamed[1000:])

    with mpq.Archive(archive_path, offset=0) as archive:
        clone = archive.clone()
        try:
            assert clone["raw.bin"].read() == b"raw payload"
            assert archive["compressed.bin"].read() == repetitive
            assert archive["lzma.bin"].read() == repetitive
            assert archive["path.txt"].read() == b"path payload"
            assert archive["stream.bin"].read() == streamed
            stored = archive["stream.bin"].attributes()
            assert stored.flags == 15
            assert stored.crc32 == zlib.crc32(streamed)
            assert stored.md5 == hashlib.md5(streamed).digest()
            assert stored.filetime == 0xfedcba9876543210
            assert archive["path.txt"].attributes().filetime == 0
            assert clone["stream.bin"].attributes() == stored
            assert archive["raw.bin"].read_block(0) == b"raw payload"
        finally:
            clone.close()
        assert archive["raw.bin"].read() == b"raw payload"


def test_errors_and_lifecycle(tmp_path):
    """Missing entries, oversized writes, and post-close use expose typed errors."""
    path = tmp_path / "errors.mpq"
    with mpq.Writer(path) as writer:
        with pytest.raises(ValueError):
            with writer.begin("too-large", 3) as stream:
                stream.write(b"1234")
    with mpq.Archive(path, offset=0) as archive:
        with pytest.raises(mpq.LibmpqNotFoundError) as error:
            archive["missing"]
        assert error.value.code == mpq.ERROR_EXIST
        archive.close()
        with pytest.raises(mpq.LibmpqStateError):
            archive[0]
