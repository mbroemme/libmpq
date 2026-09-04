# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

"""End-to-end tests for the public Python binding and native libmpq ABI."""

import os
from pathlib import Path

import pytest

import mpq


ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests" / "fixtures"


def test_version_errors_and_hashes():
    """Version, diagnostics, and Storm hashing work without an archive handle."""
    assert mpq.version()
    assert "format" in mpq.strerror(mpq.ERROR_FORMAT)
    assert len(mpq.file_hash("overview.txt")) == 3


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
        assert b"libmpq" in entry.read()
        assert archive.metadata().files == archive.files
        assert entry.metadata().unpacked_size == entry.unpacked_size


@pytest.mark.parametrize("name,version,offset", [
    ("mpq-v1-features.mpqe", 1, 0),
    ("mpq-v2-features.mpqe", 2, -1),
])
def test_mpqe_fixture_metadata_extraction_and_clone(name, version, offset):
    """MPQE opening uses borrowed credentials and supports independent clones."""
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    with mpq.Archive.open_mpqe(FIXTURES / name, memoryview(code), offset) as archive:
        assert archive.version == version
        assert b"libmpq" in archive["overview.txt"].read()
        clone = archive.clone()
        try:
            assert clone["overview.txt"].read() == archive["overview.txt"].read()
        finally:
            clone.close()
    with pytest.raises(mpq.LibmpqDecryptError):
        mpq.Archive.open_mpqe(FIXTURES / name, code[:-1], offset)


def test_creation_streaming_compression_clone_and_blocks(tmp_path):
    """Creation APIs round-trip raw, compressed, path, stream, clone, and blocks."""
    archive_path = tmp_path / "created.mpq"
    source_path = tmp_path / "source.txt"
    source_path.write_bytes(b"path payload")
    repetitive = b"R" * 12000
    streamed = bytes(range(256)) * 20

    with mpq.Writer(archive_path, version=mpq.ARCHIVE_VERSION_TWO,
                    flags=mpq.ARCHIVE_CREATE_LISTFILE) as writer:
        writer.add("raw.bin", b"raw payload")
        writer.add("compressed.bin", repetitive,
                   mpq.FileCreateOptions.compressed(mpq.COMPRESSION_ZLIB,
                                                    mpq.COMPRESSION_ZLIB))
        writer.add_path("path.txt", source_path)
        with writer.begin("stream.bin", len(streamed)) as stream:
            stream.write(streamed[:1000])
            stream.write(streamed[1000:])

    with mpq.Archive(archive_path, offset=0) as archive:
        clone = archive.clone()
        try:
            assert clone["raw.bin"].read() == b"raw payload"
            assert archive["compressed.bin"].read() == repetitive
            assert archive["path.txt"].read() == b"path payload"
            assert archive["stream.bin"].read() == streamed
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
