# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

"""End-to-end tests for the public Python binding and native libmpq ABI."""

import array
import ctypes
import concurrent.futures
import gc
import hashlib
import io
import inspect
import mmap
import os
import struct
import sys
import weakref
import zlib
from pathlib import Path

import pytest

import mpq


FIXTURES = Path(__file__).resolve().parent / "fixtures"
if not FIXTURES.is_dir():
    FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures"

SPARSE_TEXT = "This text uses SPARSE compression and decompression.\n" * 16
SPARSE_BYTES = b"\xff\xfe\x00\x00" + SPARSE_TEXT.encode("utf-32-le")
WEAK_PUBLIC_KEY = bytes.fromhex("a13dab4de25f08acc393e15923b73aed2554013742f1079c1f1e6011c566948e5f0267ddf51175169e7bbeed8efe9ee8b6f63c4602f5089e97b02e1fe00ce8a700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001")
WEAK_PRIVATE_KEY = bytes.fromhex("a13dab4de25f08acc393e15923b73aed2554013742f1079c1f1e6011c566948e5f0267ddf51175169e7bbeed8efe9ee8b6f63c4602f5089e97b02e1fe00ce8a748315364c0c92a1a284b2ae77d5d49adea3bad7bafa639710661d443c0ad882f6c8d6787affd7f68145217cde42cf4dc2acb0ca2aeca535baf894084e590d719")
STRONG_PUBLIC_KEY = (
    bytes.fromhex("b76f7dc7cdd3a083b2e52f39a5b7d58f181ab7bc03c1eaa0931744f0218bf74397b68481776a3f49f7b9a7ea08abf1c3a9802b54ee75661190e521453f6e125cdaca5d4b5cb52c84a158f1bb1b51bb9138acc55b45a083d3dde6e9e9cc4cb03adf4dda27a4a673993ebddfefd06e7c8c976387df92ba92d6392b9baf1a40f7b39d3c0ad1a4e2d685b46caea30863c9055d8e0a151d2e5adf5b79c69cc849c8b879ecc53be1207334d60b4194583b44129f272fe4790570ba530df485e2188932d79abb5b3b8713fd2d16de821048328e9ae93da8de983519033806fbd55591ebf5542641af669ad73e7c0f01b2dea45040f6658d2c6ca0f55f8d91c482f81617")
    + bytes(253)
    + b"\x01\x00\x01"
)
STRONG_PRIVATE_KEY = STRONG_PUBLIC_KEY[:256] + bytes.fromhex(
    "14c9759f7c1ba1f24ab0de0bd253bac7b470e7fbf911088844783bea5a62da15"
    "0c24356fd670712b98a9aea03ecb52b7b18597637b2cf7f16afcb6d5cf67a727"
    "b9437abf078a75b907450fb4fc56396dd8d650a71484d4163641eca554997c29"
    "afbf201c4df444354c29882ef797b85580f259260f77efc686eeacd31da3d9c3"
    "37897433f8ef833890a04d55cbfc53f2dd8f96bd9b93e28fc6f022786b36e51d"
    "e38ec0d5d41aba3eed9647831fb16fcbc3b16eaca91e60894aa772b02b22a3ff"
    "b7042e52531163d089209df6412098613ef59664ed70884e33f3e3056ccfb911"
    "bcc04d2c73142996946d88be0daa29aafa1bab3d10ff4d52295880c8fad6d641"
)


@pytest.mark.parametrize("version,wire", [
    (1, "505443485400000088010000100000004d44355f28000000f5e506c1646586cd587606b06204f1edbd9130574d913d6ccec47d341a29d0625846524d1c000000434f50595061746368206c61796572206f6e650a"),
    (2, "505443485600000088010000120000004d44355f28000000f5e506c1646586cd587606b06204f1ed78a901df03758fa62e8d0471968d79345846524d1e000000434f505956657273696f6e2074776f2070617463680a"),
])
def test_patch_payload_fixtures(version, wire):
    expected = bytes.fromhex(wire)
    with mpq.Archive(FIXTURES / f"mpq-v{version}-features-patch.mpq") as archive:
        entry = archive["overview.txt"]
        assert entry.flags & mpq.FILE_FLAG_PATCH_FILE
        assert archive["pkware.txt"].flags & mpq.FILE_FLAG_DELETE_MARKER
        assert mpq.FILE_FLAG_PATCH_FILE == 0x00100000
        assert mpq.FILE_FLAG_DELETE_MARKER == 0x02000000
        assert entry.patch_payload_size == len(expected)
        assert entry.patch_payload_size != entry.unpacked_size
        assert entry.read_patch_payload() == expected
        assert archive[entry.number].read_patch_payload("overview.txt") == expected
        assert expected[:4] == b"PTCH"
        for action in (lambda: archive["patch-only.txt"].patch_payload_size,
                       lambda: archive["patch-only.txt"].read_patch_payload()):
            with pytest.raises(mpq.LibmpqNotFoundError):
                action()
        with pytest.raises(mpq.LibmpqNotFoundError):
            mpq.libmpq.libmpq__patch_payload_size(
                archive._mpq, 0xffffffff, ctypes.byref(mpq._OFF_T()))
    with pytest.raises(mpq.LibmpqStateError):
        entry.read_patch_payload()


def test_patch_payload_integrity():
    wire = bytearray((FIXTURES / "mpq-v1-features-patch.mpq").read_bytes())
    payload_start = wire.index(b"PTCH")
    wire[payload_start - 16] ^= 1  # Patch-info MD5, not PTCH contents.
    with mpq.Archive.open_io(io.BytesIO(wire), len(wire)) as archive:
        entry = archive["overview.txt"]
        assert entry.patch_payload_size == 84
        with pytest.raises(mpq.LibmpqFormatError):
            entry.read_patch_payload()
        destination = bytearray(b"!" * 84)
        with pytest.raises(mpq.LibmpqFormatError) as caught:
            entry.read_patch_payload_into(destination)
        assert caught.value.code == mpq.ERROR_FORMAT
        assert not hasattr(caught.value, "transferred")
        assert destination == b"!" * 84


@pytest.mark.parametrize("kind", ["file", "block", "patch_payload", "stream"])
def test_caller_owned_read_buffer(kind, monkeypatch, tmp_path):
    """Exercise the public operation with real buffers and the original native function."""
    path = tmp_path / "mapped.mpq"
    with mpq.Archive(FIXTURES / "mpq-v1-features.mpq") as archive, \
         mpq.Archive(FIXTURES / "mpq-v1-features-patch.mpq") as patch, \
         archive.open_stream("overview.txt") as stream:
        entry = archive["overview.txt"]
        patch_entry = patch["overview.txt"]
        reads = {
            "file": (entry.read_into, entry.read),
            "block": (lambda buffer: entry.read_block_into(0, buffer), lambda: entry.read_block(0)),
            "patch_payload": (patch_entry.read_patch_payload_into, patch_entry.read_patch_payload),
            "stream": (stream.read_into, stream.read),
        }
        read, read_bytes = reads[kind]
        expected = read_bytes()
        size = len(expected)
        calls = []
        symbol = f"libmpq__{kind}_read"
        native = getattr(mpq.libmpq, symbol)

        def spy(*args):
            calls.append((ctypes.cast(args[-3], ctypes.c_void_p).value, args[-2]))
            return native(*args)

        def unexpected(*args):
            pytest.fail("unexpected native metadata or verification call")

        monkeypatch.setattr(mpq.libmpq, symbol, spy)
        for extra in ("patch_payload_size", "block_size_unpacked", "block_verify"):
            monkeypatch.setattr(mpq.libmpq, f"libmpq__{extra}", unexpected)

        for capacity in (size, size + 7):
            destination = bytearray(b"!" * capacity)
            stream.seek(0)
            assert read(destination) == size
            assert destination == expected + b"!" * (capacity - size)
            assert calls.pop() == (ctypes.addressof(ctypes.c_uint8.from_buffer(destination)), capacity)
            assert not calls
            destination.extend(b"!")  # The temporary exports have been released.

        backing = bytearray(b"!" * (size + 7))
        with memoryview(backing)[3:-4] as view:
            stream.seek(0)
            assert read(view) == size
            assert calls.pop() == (ctypes.addressof(ctypes.c_uint8.from_buffer(backing)) + 3, size)
            assert not calls
            assert not view.readonly  # The caller's view remains usable.
        assert backing == b"!!!" + expected + b"!!!!"

        words = array.array("I", [0])
        words *= (size + words.itemsize - 1) // words.itemsize
        stream.seek(0)
        assert read(words) == size
        assert words.tobytes()[:size] == expected
        assert calls.pop()[1] == len(words) * words.itemsize
        assert not calls

        with path.open("w+b") as file:
            file.truncate(size + 1)
            with mmap.mmap(file.fileno(), size + 1, access=mmap.ACCESS_WRITE) as mapped:
                mapped[size:] = b"!"
                stream.seek(0)
                assert read(mapped) == size
                assert mapped[:] == expected + b"!"
                assert calls.pop()[1] == size + 1
                assert not calls

        released = memoryview(backing)
        released.release()
        with memoryview(bytes(backing)) as readonly, memoryview(backing)[::2] as strided:
            for invalid in (bytes(backing), readonly, strided, object()):
                with pytest.raises(TypeError):
                    read(invalid)
            with pytest.raises(ValueError):
                read(released)
        assert not calls

        with mmap.mmap(-1, size - 1) as short:
            stream.seek(0)
            if kind == "stream":
                assert read(short) == size - 1
                assert short[:] == expected[:-1]
                assert stream.tell() == size - 1
            else:
                with pytest.raises(mpq.LibmpqSizeError) as caught:
                    read(short)
                assert caught.value.code == mpq.ERROR_SIZE
                assert not hasattr(caught.value, "transferred")
            assert calls.pop()[1] == size - 1
            assert not calls
        # Closing the mmap succeeded even while the exception traceback lived.

        if kind == "stream":
            assert read(bytearray(3)) == 1
            assert read(bytearray(3)) == 0
            assert stream.tell() == size
            assert read(bytearray()) == 0
            assert [capacity for _, capacity in calls] == [3, 3, 0]
            calls.clear()
        else:
            with pytest.raises(mpq.LibmpqSizeError) as caught:
                read(bytearray())
            assert caught.value.code == mpq.ERROR_SIZE
            assert calls.pop()[1] == 0
            assert not calls

        stream.close()
        patch.close()
        archive.close()
        with pytest.raises(mpq.LibmpqStateError) as caught:
            read(bytearray(size))
        assert caught.value.code == mpq.ERROR_NOT_INITIALIZED
        assert not calls


def test_read_patch_payload_into_name_context(tmp_path, monkeypatch):
    base, output = tmp_path / "base.mpq", tmp_path / "patch.mpq"
    name = b"physical-\xff"
    with mpq.Writer(base) as writer:
        writer.add_data(name, b"original")
    with mpq.Patch.begin(base, output) as patch:
        options = mpq.FileCreateOptions(mpq.FILE_FLAG_SINGLE | mpq.FILE_FLAG_ENCRYPTED, 0, 0, 0, 0)
        patch.replace_data(name, b"replacement", options)
        patch.finish()

    with mpq.Archive(output) as archive:
        entry = archive[name]
        expected = entry.read_patch_payload(name)
        destination = bytearray(b"!" * len(expected))
        assert expected.startswith(b"PTCH")
        assert len(expected) != entry.unpacked_size
        native = mpq.libmpq.libmpq__patch_payload_read
        calls = []

        def spy(*args):
            calls.append(args[2])
            return native(*args)

        monkeypatch.setattr(mpq.libmpq, "libmpq__patch_payload_read", spy)
        for invalid in ("bad\0name", b"bad\0name"):
            with pytest.raises(ValueError, match="NUL"):
                entry.read_patch_payload_into(destination, invalid)
        assert not calls
        for spelling in (None, b""):
            with pytest.raises(mpq.LibmpqError) as caught:
                entry.read_patch_payload_into(destination, spelling)
            with pytest.raises(mpq.LibmpqError) as legacy:
                entry.read_patch_payload(spelling)
            assert caught.value.code == legacy.value.code
            assert destination == b"!" * len(expected)
        assert entry.read_patch_payload_into(destination, filename=name) == len(expected)
        assert destination == expected
        assert calls == [None, None, b"", b"", name]

    with mpq.Archive(base) as archive:
        with pytest.raises(mpq.LibmpqNotFoundError) as caught:
            archive[name].read_patch_payload_into(bytearray(100))
        assert caught.value.code == mpq.ERROR_EXIST


def test_patch_payload_allocation_bounds(monkeypatch):
    with mpq.Archive(FIXTURES / "mpq-v1-features-patch.mpq") as archive:
        entry = archive["overview.txt"]
        for size in (-1, sys.maxsize + 1):
            monkeypatch.setattr(mpq.File, "patch_payload_size", property(lambda self: size))
            with pytest.raises(mpq.LibmpqSizeError):
                entry.read_patch_payload()
        monkeypatch.setattr(mpq.File, "patch_payload_size", property(lambda self: 0))

        def empty_read(handle, number, name, buffer, capacity, transferred):
            assert buffer is None and capacity == 0 and name is None
            ctypes.cast(transferred, ctypes.POINTER(mpq._OFF_T))[0] = 0

        monkeypatch.setattr(mpq.libmpq, "libmpq__patch_payload_read", empty_read)
        assert entry.read_patch_payload() == b""

        def invalid_count(*args):
            ctypes.cast(args[-1], ctypes.POINTER(mpq._OFF_T))[0] = 1

        monkeypatch.setattr(mpq.libmpq, "libmpq__patch_payload_read", invalid_count)
        with pytest.raises(mpq.LibmpqSizeError):
            entry.read_patch_payload()


def test_strong_signature():
    """Verify independently signed test data through the public signature selector."""
    assert len(STRONG_PUBLIC_KEY) == 512
    with mpq.Archive(FIXTURES / "mpq-v1-features.mpq") as archive:
        assert archive.signatures() == mpq.SIGNATURE_WEAK | mpq.SIGNATURE_STRONG
        assert archive.verify(STRONG_PUBLIC_KEY, signature_type=mpq.SIGNATURE_STRONG) == 0


def test_logical_stream_lifetime_seek_and_eof():
    """Native streams remain valid after their originating archive closes."""
    archive = mpq.Archive(FIXTURES / "mpq-v1-features.mpq")
    stream = archive.open_stream("overview.txt")
    expected = archive["overview.txt"].read()
    assert stream.size == len(expected)
    assert stream.read(2) == expected[:2]
    assert stream.tell() == 2
    stream.seek(-1, os.SEEK_CUR)
    assert stream.read(3) == expected[1:4]
    stream.seek(-1, os.SEEK_END)
    assert stream.read() == expected[-1:]
    assert stream.read() == b""
    archive.close()
    stream.seek(0)
    assert stream.read() == expected
    stream.close()
    stream.close()
    with pytest.raises(mpq.LibmpqStateError):
        stream.tell()


@pytest.mark.parametrize("version", [mpq.ARCHIVE_VERSION_1, mpq.ARCHIVE_VERSION_2, mpq.ARCHIVE_VERSION_3,
                                     mpq.ARCHIVE_VERSION_4])
def test_transactional_update_binding(tmp_path, version):
    """All staged operations commit or abort without reusing consumed handles."""
    path = tmp_path / "update.mpq"
    source = tmp_path / "replacement.bin"
    source.write_bytes(b"from path")
    original = b"A" * 9000
    with mpq.Writer(path, version=version, max_files=16, flags=mpq.ARCHIVE_CREATE_LISTFILE,
                    attributes=mpq.ATTRIBUTE_CRC32 | mpq.ATTRIBUTE_MD5) as writer:
        writer.add("data", original)
        writer.add("path", b"old path")
        writer.add("remove", b"remove me")
        writer.add("rename", b"rename me")
        writer.add("secret", b"encrypted payload",
                   mpq.FileCreateOptions.raw().encrypted())

    options = mpq.FileCreateOptions.compressed(mpq.COMPRESSION_ZLIB,
                                                mpq.COMPRESSION_BZIP2)
    with mpq.Update.begin(path) as update:
        update.add_data("added", b"added")
        with pytest.raises(mpq.LibmpqNotFoundError):
            update.add_data("ADDED", b"duplicate")
        update.add_path("added-path", source)
        update.remove("added")
        update.add_data("added", b"re-added")
        update.replace_data("data", memoryview(b"B" * 9000), options)
        update.replace_path("path", source,
                            mpq.FileCreateOptions.raw().encrypted())
        update.remove("remove")
        update.rename("rename", "renamed")
        update.rename("secret", "secret-new")
        with mpq.Archive(path) as archive:
            assert archive["data"].read() == original
        update.commit()
    with mpq.Archive(path) as archive:
        assert archive["data"].read() == b"B" * 9000
        assert archive.version == version + 1
        assert archive["added"].read() == b"re-added"
        assert archive["added-path"].read() == b"from path"
        assert archive["data"].block_compression(0) == mpq.COMPRESSION_ZLIB
        assert archive["data"].block_compression(1) == mpq.COMPRESSION_BZIP2
        with archive.open_stream("path") as stream:
            assert stream.read() == b"from path"
        assert "remove" not in archive and "rename" not in archive
        assert archive["renamed"].read() == b"rename me"
        with archive.open_stream("secret-new") as stream:
            assert stream.read() == b"encrypted payload"
    with pytest.raises(mpq.LibmpqStateError):
        update.remove("path")

    with mpq.Update.begin(path) as update:
        update.replace_data("data", bytearray(b"rollback"))
        update.remove("path")
        update.rename("renamed", "rollback-name")
    with mpq.Archive(path) as archive:
        assert archive["data"].read() == b"B" * 9000
        with archive.open_stream("path") as stream:
            assert stream.read() == b"from path"
        assert archive["renamed"].read() == b"rename me"

    with pytest.raises(RuntimeError, match="caller failure"):
        with mpq.Update.begin(path) as update:
            update.remove("path")
            raise RuntimeError("caller failure")
    with mpq.Archive(path) as archive:
        with archive.open_stream("path") as stream:
            assert stream.read() == b"from path"

    update = mpq.Update.begin(path)
    with pytest.raises(mpq.LibmpqNotFoundError):
        update.remove("missing")
    update.abort()
    update.close()
    with pytest.raises(mpq.LibmpqStateError):
        update.commit()

    update = mpq.Update.begin(path)
    mismatched = mpq.FileCreateOptions.raw()
    mismatched.locale = 1
    with pytest.raises(mpq.LibmpqError):
        update.replace_data("data", b"no", mismatched)
    update.abort()

    update = mpq.Update.begin(path)
    replacement = tmp_path / "external.mpq"
    replacement.write_bytes(path.read_bytes())
    os.replace(replacement, path)
    with pytest.raises(mpq.LibmpqError):
        update.commit()
    with pytest.raises(mpq.LibmpqStateError):
        update.abort()


def test_update_localized_member_defaults(tmp_path):
    """Omitted options preserve nonzero locale/platform; explicit raw does not."""
    path = tmp_path / "localized.mpq"
    source = tmp_path / "replacement.bin"
    source.write_bytes(b"from path")
    identity = mpq.FileCreateOptions.raw()
    identity.locale, identity.platform = 0x409, 1
    with mpq.Writer(path, max_files=8) as writer:
        writer.add("localized", b"original", identity)

    with mpq.Update.begin(path) as update:
        update.replace_data("localized", b"new data")
        update.commit()
    with mpq.Archive(path) as archive:
        assert archive["localized"].read() == b"new data"

    with mpq.Update.begin(path) as update:
        with pytest.raises(mpq.LibmpqFormatError):
            update.replace_data("localized", b"wrong", mpq.FileCreateOptions.raw())
        with pytest.raises(mpq.LibmpqFormatError):
            update.replace_path("localized", source, mpq.FileCreateOptions.raw())
        update.replace_data("localized", b"matching", identity)
        update.commit()

    with mpq.Update.begin(path) as update:
        update.replace_path("localized", source)
        update.commit()
    with mpq.Archive(path) as archive:
        assert archive["localized"].read() == b"from path"
    with mpq.Update.begin(path) as update:
        update.replace_path("localized", source, identity)
        update.abort()


@pytest.mark.parametrize("version", [mpq.ARCHIVE_VERSION_1, mpq.ARCHIVE_VERSION_2, mpq.ARCHIVE_VERSION_3,
                                     mpq.ARCHIVE_VERSION_4])
def test_authenticated_mpqe_update(tmp_path, version):
    """MPQE uses the ordinary Update operations and consuming lifecycle."""
    path = tmp_path / "update.mpqe"
    source = tmp_path / "replacement.bin"
    source.write_bytes(b"from path")
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    with mpq.Writer.create_mpqe(path, code, version=version, max_files=16,
                                flags=mpq.ARCHIVE_CREATE_LISTFILE) as writer:
        writer.add("data", b"original")
        writer.add("path", b"old path")
        writer.add("remove", b"remove me")
        writer.add("secret", b"encrypted payload",
                   mpq.FileCreateOptions.raw().encrypted())
    original = path.read_bytes()
    with pytest.raises(mpq.LibmpqError):
        mpq.Update.begin(path)
    for invalid in (None, b"", code[:31], b"X" + code[1:]):
        with pytest.raises((TypeError, mpq.LibmpqError)):
            mpq.Update.begin_mpqe(path, invalid)
    assert path.read_bytes() == original

    with mpq.Update.begin_mpqe(path, code) as update:
        update.replace_data("data", b"rollback")
        update.remove("path")
    assert path.read_bytes() == original
    update = mpq.Update.begin_mpqe(path, code)
    update.rename("secret", "unused")
    update.abort()
    assert path.read_bytes() == original
    with pytest.raises(mpq.LibmpqStateError):
        update.commit()

    borrowed = bytearray(code)
    with mpq.Update.begin_mpqe(path, borrowed) as update:
        borrowed[:] = b"\0" * len(borrowed)
        update.replace_data("data", b"new data")
        update.replace_path("path", source)
        update.remove("remove")
        update.rename("secret", "secret-new")
        with mpq.Archive.open_mpqe(path, code) as archive:
            assert archive["data"].read() == b"original"
        update.commit()
    with pytest.raises(mpq.LibmpqStateError):
        update.remove("data")
    with mpq.Archive.open_mpqe(path, code) as archive:
        assert archive["data"].read() == b"new data"
        assert archive["path"].read() == b"from path"
        assert "remove" not in archive and "secret" not in archive
        with archive.open_stream("secret-new") as stream:
            assert stream.read() == b"encrypted payload"

    committed = path.read_bytes()
    with mpq.Update.begin_mpqe(path, code) as update:
        with pytest.raises(mpq.LibmpqNotFoundError):
            update.remove("missing")
        update.abort()
    assert path.read_bytes() == committed


@pytest.mark.parametrize("version", [mpq.ARCHIVE_VERSION_1, mpq.ARCHIVE_VERSION_4])
def test_patch_creation_binding(tmp_path, version):
    """Patch creation stages replacements and deletion without changing the base."""
    base = tmp_path / "base.mpq"
    output = tmp_path / "changes.mpq"
    source = tmp_path / "replacement.bin"
    source.write_bytes(b"from path")
    identity = mpq.FileCreateOptions.raw()
    identity.locale, identity.platform = 0x409, 1
    with mpq.Writer(base, version=version, max_files=8, flags=mpq.ARCHIVE_CREATE_LISTFILE) as writer:
        writer.add("data", b"original", identity)
        writer.add("path", b"old path", identity)
        writer.add("remove", b"remove me")

    options = mpq.FileCreateOptions.compressed(mpq.COMPRESSION_ZLIB,
                                                mpq.COMPRESSION_BZIP2)
    options.locale, options.platform = identity.locale, identity.platform
    options = options.encrypted()
    with mpq.Patch.begin(base, output) as patch:
        with pytest.raises(mpq.LibmpqFormatError):
            patch.replace_data("data", b"wrong", mpq.FileCreateOptions.raw())
        with pytest.raises(mpq.LibmpqFormatError):
            patch.replace_path("path", source, mpq.FileCreateOptions.raw())
        with pytest.raises(mpq.LibmpqNotFoundError):
            patch.remove("missing")
        patch.replace_data("data", memoryview(b"replacement"))
        patch.replace_path("path", source, options)
        patch.remove("remove")
        assert not output.exists()
        patch.finish()
    assert output.is_file()
    with mpq.Archive(base) as archive:
        assert archive["data"].read() == b"original"
        assert archive["path"].read() == b"old path"
        assert archive["remove"].read() == b"remove me"
    with mpq.Archive(output) as archive:
        assert archive.version == version + 1
        assert "data" in archive and "path" in archive and "remove" in archive
        entry = archive["path"]
        assert entry.flags & mpq.FILE_FLAG_ENCRYPTED
        payload = entry.read_patch_payload("path")
        assert payload[:4] == b"PTCH" and payload[68:] == b"from path"
        assert len(payload) == entry.patch_payload_size
        with pytest.raises(mpq.LibmpqError):
            entry.read_patch_payload("wrong-name")
    with pytest.raises(mpq.LibmpqStateError):
        patch.replace_data("data", b"again")
    with pytest.raises(mpq.LibmpqStateError):
        patch.abort()

    output.unlink()
    with mpq.Patch.begin(base, output) as patch:
        patch.replace_path("path", source)
    assert not output.exists()
    patch = mpq.Patch.begin(base, output)
    patch.replace_data("data", b"aborted")
    patch.abort()
    patch.close()
    assert not output.exists()
    with pytest.raises(mpq.LibmpqStateError):
        patch.finish()

    patch = mpq.Patch.begin(base, output)
    patch.replace_data("data", b"garbage collected")
    del patch
    gc.collect()
    assert not output.exists()

    patch = mpq.Patch.begin(base, output)
    output.mkdir()
    with pytest.raises(mpq.LibmpqError):
        patch.finish()
    with pytest.raises(mpq.LibmpqStateError):
        patch.remove("data")


@pytest.mark.parametrize("version", [mpq.ARCHIVE_VERSION_1, mpq.ARCHIVE_VERSION_4])
def test_mpqe_patch_creation_binding(tmp_path, version):
    """The MPQE factory retains the ordinary Patch lifecycle and borrows auth bytes."""
    base = tmp_path / "base.mpq"
    output = tmp_path / "changes.mpqe"
    code = b"LIBMPQ-MPQE-PATCH-AUTH-CODE-00002"
    with mpq.Writer(base, version=version, max_files=8) as writer:
        writer.add("replace", b"old")
        writer.add("remove", b"old")

    with pytest.raises(mpq.LibmpqDecryptError):
        mpq.Patch.begin_mpqe(base, output, b"")
    with pytest.raises(mpq.LibmpqDecryptError):
        mpq.Patch.begin_mpqe(base, output, code[:31])
    with pytest.raises(TypeError):
        mpq.Patch.begin_mpqe(base, output, None)
    assert not output.exists()

    with mpq.Patch.begin_mpqe(base, output, code) as patch:
        patch.replace_data("replace", b"new")
        patch.remove("remove")
        assert not output.exists()
        patch.finish()
    assert output.is_file()
    with pytest.raises(mpq.LibmpqFormatError):
        mpq.Archive(output)
    with pytest.raises(mpq.LibmpqError):
        mpq.Archive.open_mpqe(output, b"X" + code[1:])
    with mpq.Archive.open_mpqe(output, code) as archive:
        assert "replace" in archive and "remove" in archive
    with pytest.raises(mpq.LibmpqStateError):
        patch.abort()

    output.unlink()
    with mpq.Patch.begin_mpqe(base, output, code) as patch:
        patch.replace_data("replace", b"discarded")
    assert not output.exists()
    patch = mpq.Patch.begin_mpqe(base, output, code)
    patch.remove("remove")
    patch.abort()
    assert not output.exists()
    with pytest.raises(mpq.LibmpqStateError):
        patch.finish()


@pytest.mark.parametrize("signature_types", [mpq.SIGNATURE_WEAK, mpq.SIGNATURE_STRONG,
                                            mpq.SIGNATURE_WEAK | mpq.SIGNATURE_STRONG])
def test_patch_signing(tmp_path, signature_types):
    """Patch signing shares the archive key convention and verifies after finish."""
    base = tmp_path / "base.mpq"
    output = tmp_path / "signed-patch.mpq"
    with mpq.Writer(base, max_files=8) as writer:
        writer.add("data", b"original")
    with mpq.Patch.begin(base, output) as patch:
        with pytest.raises(mpq.LibmpqFormatError):
            patch.sign(b"invalid")
        if signature_types & mpq.SIGNATURE_WEAK:
            patch.sign(WEAK_PRIVATE_KEY)
            with pytest.raises(mpq.LibmpqFormatError):
                patch.sign(WEAK_PRIVATE_KEY)
        if signature_types & mpq.SIGNATURE_STRONG:
            patch.sign(STRONG_PRIVATE_KEY, mpq.SIGNATURE_STRONG)
        patch.replace_data("data", b"replacement")
        assert not output.exists()
        patch.finish()
    with mpq.Archive(output) as archive:
        assert archive.signatures() == signature_types
        if signature_types & mpq.SIGNATURE_WEAK:
            assert archive.verify(WEAK_PUBLIC_KEY) == 0
        if signature_types & mpq.SIGNATURE_STRONG:
            assert archive.verify(STRONG_PUBLIC_KEY,
                                  signature_type=mpq.SIGNATURE_STRONG) == 0
    with pytest.raises(mpq.LibmpqStateError):
        patch.sign(WEAK_PRIVATE_KEY)


def test_mpqe_patch_signing(tmp_path):
    """Rejected strong signing leaves the MPQE patch active for weak signing."""
    base = tmp_path / "base.mpq"
    output = tmp_path / "signed-patch.mpqe"
    code = b"LIBMPQ-MPQE-PATCH-AUTH-CODE-00002"
    with mpq.Writer(base, max_files=8) as writer:
        writer.add("data", b"original")
    with mpq.Patch.begin_mpqe(base, output, code) as patch:
        with pytest.raises(mpq.LibmpqFormatError):
            patch.sign(STRONG_PRIVATE_KEY, mpq.SIGNATURE_STRONG)
        patch.sign(WEAK_PRIVATE_KEY)
        patch.replace_data("data", b"replacement")
        patch.finish()
    with mpq.Archive.open_mpqe(output, code) as archive:
        assert archive.signatures() == mpq.SIGNATURE_WEAK
        assert archive.verify(WEAK_PUBLIC_KEY) == 0
    output.unlink()
    with mpq.Patch.begin_mpqe(base, output, code) as patch:
        patch.sign(WEAK_PRIVATE_KEY)
        patch.abort()
    assert not output.exists()


def test_logical_stream_encrypted_numeric_and_mpqe_lifetime():
    """Name-derived keys, numeric opens, and MPQE clones cross the binding boundary."""
    with mpq.Archive(FIXTURES / "mpq-v1-features.mpq") as archive:
        expected = archive["encrypted-compress.txt"].read()
        with archive.open_stream("encrypted-compress.txt") as stream:
            assert stream.read() == expected
        with archive.open_stream(archive["overview.txt"].number) as stream:
            assert stream.read() == archive["overview.txt"].read()

    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    archive = mpq.Archive.open_mpqe(FIXTURES / "mpq-v1-features.mpqe", code, 0)
    expected = archive["overview.txt"].read()
    stream = archive.open_stream("overview.txt")
    archive.close()
    try:
        assert stream.read() == expected
    finally:
        stream.close()


@pytest.fixture
def embedded_archive_paths(tmp_path):
    paths = []
    for label, payload in [("actual", b"actual"), ("decoy", b"decoy!")]:
        inner = tmp_path / f"{label}-inner.mpq"
        with mpq.Writer(inner) as writer:
            writer.add("payload", payload)
        outer = tmp_path / f"{label}-outer.mpq"
        with mpq.Writer(outer, flags=mpq.ARCHIVE_CREATE_LISTFILE) as writer:
            writer.add("nested.mpq", inner.read_bytes())
        paths.append((outer, payload))
    return paths


def test_embedded_archive_path_and_clone(embedded_archive_paths, monkeypatch):
    (actual, expected), (decoy, _) = embedded_archive_paths
    monkeypatch.chdir(actual.parent)
    with mpq.Archive.open(actual.name) as parent:
        entry = parent["nested.mpq"]
        with mpq.Archive(entry) as nested:
            assert nested.offset == parent.offset + entry.offset
            assert nested["payload"].read() == expected
        clone = parent.clone()
    with clone:
        monkeypatch.chdir(actual.parent.parent)
        with mpq.Archive(clone["nested.mpq"]) as nested:
            assert nested["payload"].read() == expected
        clone.filename = decoy
        with mpq.Archive(clone["nested.mpq"]) as nested:
            assert nested["payload"].read() == expected
    with pytest.raises(mpq.LibmpqStateError, match="archive is closed"):
        mpq.Archive(entry)


def test_embedded_archive_cumulative_offsets(tmp_path, embedded_archive_paths):
    (outer, expected), _ = embedded_archive_paths
    container = tmp_path / "container.mpq"
    with mpq.Writer(container) as writer:
        writer.add("outer.mpq", outer.read_bytes())
    wrapped = tmp_path / "container.w3x"
    prefix = b"HM3W" + bytes(508)
    wrapped.write_bytes(prefix + container.read_bytes())
    with mpq.Archive(wrapped, offset=len(prefix)) as parent:
        outer_entry = parent["outer.mpq"]
        with mpq.Archive(outer_entry) as middle:
            assert middle.offset == len(prefix) + outer_entry.offset
            inner_entry = middle["nested.mpq"]
            with mpq.Archive(inner_entry) as inner:
                assert inner.offset == len(prefix) + outer_entry.offset + inner_entry.offset
                assert inner["payload"].read() == expected


@pytest.mark.parametrize("use_existing_path", [False, True])
def test_embedded_archive_rejects_callback_display_path(
    embedded_archive_paths, monkeypatch, use_existing_path
):
    (actual, expected), (decoy, other) = embedded_archive_paths
    data = actual.read_bytes()
    with mpq.Archive(actual) as actual_archive, mpq.Archive(decoy) as decoy_archive:
        actual_member = actual_archive["nested.mpq"]
        decoy_member = decoy_archive["nested.mpq"]
        assert (actual_member.offset, actual_member.packed_size) == (
            decoy_member.offset, decoy_member.packed_size
        )
        offset = actual_archive.offset + actual_member.offset
        with mpq.Archive(decoy_member) as nested:
            assert nested["payload"].read() == other != expected
    with mpq.Archive.open_io(io.BytesIO(data), len(data), offset=offset) as nested:
        assert nested["payload"].read() == expected

    def unexpected_open(*args):
        pytest.fail("embedded constructor attempted native path open")

    display = str(decoy) if use_existing_path else "<callback display name>"
    with mpq.Archive.open_io(io.BytesIO(data), len(data), source_name=display) as parent:
        assert parent["nested.mpq"].read() == data[offset:offset + actual_member.packed_size]
        clone = parent.clone()
        with monkeypatch.context() as patch:
            patch.setattr(mpq.libmpq, "libmpq__archive_open", unexpected_open)
            with pytest.raises(ValueError, match="embedded path reopening"):
                mpq.Archive(parent["nested.mpq"])
    with clone:
        monkeypatch.setattr(mpq.libmpq, "libmpq__archive_open", unexpected_open)
        with pytest.raises(ValueError, match="embedded path reopening"):
            mpq.Archive(clone["nested.mpq"])


@pytest.mark.parametrize("source_kind", ["mpqe", "mpqe_io", "patch"])
def test_embedded_archive_rejects_other_parent_sources(
    tmp_path, embedded_archive_paths, monkeypatch, source_kind
):
    (outer, _), _ = embedded_archive_paths
    with mpq.Archive(outer) as base:
        contents = base["nested.mpq"].read()
        if source_kind == "patch":
            parent = mpq.Archive.open_patch(base, [])
        else:
            path = tmp_path / "outer.mpqe"
            code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
            with mpq.Writer.create_mpqe(path, code) as writer:
                writer.add("nested.mpq", contents)
            if source_kind == "mpqe":
                parent = mpq.Archive.open_mpqe(path, code)
            else:
                data = path.read_bytes()
                parent = mpq.Archive.open_mpqe_io(io.BytesIO(data), len(data), code,
                                                  source_name=str(outer))
    with parent:
        entry = parent["nested.mpq"]
        assert entry.read() == contents

        def unexpected_open(*args):
            pytest.fail("embedded constructor attempted native path open")

        monkeypatch.setattr(mpq.libmpq, "libmpq__archive_open", unexpected_open)
        with pytest.raises(ValueError, match="embedded path reopening"):
            mpq.Archive(entry)


def test_embedded_archive_requires_raw_members(tmp_path, embedded_archive_paths):
    (outer, _), _ = embedded_archive_paths
    data = outer.read_bytes()
    path = tmp_path / "nonraw.mpq"
    with mpq.Writer(path) as writer:
        compression = mpq.COMPRESSION_ZLIB
        writer.add("compressed", data, mpq.FileCreateOptions.compressed(compression, compression))
        writer.add("encrypted", data, mpq.FileCreateOptions.raw().encrypted())
    with mpq.Archive(path) as parent:
        for name in ("compressed", "encrypted"):
            with pytest.raises(ValueError, match="must be stored raw"):
                mpq.Archive(parent[name])
    with mpq.Archive(FIXTURES / "mpq-v1-features-patch.mpq") as parent:
        entry = parent["overview.txt"]
        assert entry.flags & mpq.FILE_FLAG_PATCH_FILE
        with pytest.raises(ValueError, match="must be stored raw"):
            mpq.Archive(entry)


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux sparse-file semantics")
def test_large_file_embedded_archive(tmp_path):
    name = b"member-\xff"
    payload = b"embedded payload"
    standalone = tmp_path / "archive.mpq"
    with mpq.Writer(standalone) as writer:
        writer.add_data(name, payload)

    origin = (1 << 32) + 512
    path = tmp_path / "sparse.mpq"
    with path.open("wb") as output:
        output.seek(origin)
        output.write(standalone.read_bytes())

    with mpq.Archive(path, offset=origin) as archive:
        assert archive.offset == origin
        assert archive.file_identity(name, 0).file_number == archive[name].number
        buffer = bytearray(len(payload))
        assert archive[name].read_into(buffer) == len(payload)
        assert buffer == payload
        with pytest.raises(mpq.LibmpqError) as error:
            archive.file_identity(name, 1)
        assert error.value.code == mpq.ERROR_EXIST

    with path.open("rb") as source:
        source.seek(7)
        with mpq.Archive.open_io(source, path.stat().st_size, offset=origin) as archive:
            assert archive[name].read() == payload
        assert source.tell() == 7


def test_custom_io_sources_and_stream_lifetime():
    """Borrowed BytesIO sources stay alive for archive clones owned by streams."""
    data = (FIXTURES / "mpq-v1-features.mpq").read_bytes()
    source = io.BytesIO(data)
    archive = mpq.Archive.open_io(source, len(data), source_name="fixture.mpq")
    expected = archive["overview.txt"].read()
    stream = archive.open_stream("overview.txt")
    archive.close()
    assert stream.read() == expected
    stream.close()
    assert not source.closed

    mpqe_data = (FIXTURES / "mpq-v1-features.mpqe").read_bytes()
    source = io.BytesIO(mpqe_data)
    archive = mpq.Archive.open_mpqe_io(
        source, len(mpqe_data), b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001", source_name="fixture.mpqe"
    )
    stream = archive.open_stream("overview.txt")
    expected = archive["overview.txt"].read()
    archive.close()
    assert stream.read() == expected
    stream.close()
    assert not source.closed


@pytest.mark.parametrize("failing_block", [0, 1, 2])
@pytest.mark.parametrize("into", [False, True])
def test_stream_read_preserves_partial_result(tmp_path, failing_block, into, monkeypatch):
    sector = 4096
    payload = b"A" * sector + b"B" * sector + b"C" * sector + b"D" * 23
    path = tmp_path / "partial.mpq"
    with mpq.Writer(path, sector_size=sector) as writer:
        writer.add("payload", payload)

    class FaultSource(io.BytesIO):
        fault = None
        failures = 0

        def read(self, size=-1):
            if self.tell() == self.fault:
                self.failures += 1
                raise OSError("injected sector read failure")
            return super().read(size)

    wire = path.read_bytes()
    source = FaultSource(wire)
    with mpq.Archive.open_io(source, len(wire)) as archive:
        transferred = sector * failing_block
        source.fault = archive["payload"].offset + transferred
        stream = archive.open_stream("payload")
    with stream:
        assert stream.read(0) == b""
        assert stream.tell() == source.failures == 0
        if into:
            destination = bytearray(b"!" * len(payload))
            native = mpq.libmpq.libmpq__stream_read
            calls = []

            def spy(*args):
                calls.append(args[-2])
                return native(*args)

            with monkeypatch.context() as guard:
                guard.setattr(mpq.libmpq, "libmpq__stream_read", spy)
                with pytest.raises(mpq.LibmpqIOError) as caught:
                    stream.read_into(destination)
            assert calls == [len(payload)]
            assert destination == payload[:transferred] + b"!" * (len(payload) - transferred)
            destination.extend(b"!")
            assert not hasattr(caught.value, "partial_data")
        else:
            with pytest.raises(mpq.LibmpqIOError) as caught:
                stream.read(len(payload))
            assert caught.value.partial_data == payload[:transferred]
        error = caught.value
        assert error.code == mpq.ERROR_READ
        assert error.transferred == stream.tell() == transferred
        assert source.failures == 1

        source.fault = None
        assert stream.read() == payload[transferred:]
        assert stream.read(1) == b""
        stream.seek(-11, os.SEEK_END)
        assert stream.read(32) == payload[-11:]
        assert stream.read(1) == b""
        stream.seek(0)
        assert stream.read(len(payload)) == payload


def test_custom_io_short_and_failing_reads():
    """Short reads and source exceptions become the binding's normal read error."""
    data = (FIXTURES / "mpq-v1-features.mpq").read_bytes()

    class ShortSource(io.BytesIO):
        def read(self, size=-1):
            return super().read(max(0, size - 1))

    class FailingSource(io.BytesIO):
        def read(self, size=-1):
            raise OSError("read failure")

    with pytest.raises(mpq.LibmpqIOError):
        mpq.Archive.open_io(ShortSource(data), len(data))
    with pytest.raises(mpq.LibmpqIOError):
        mpq.Archive.open_io(FailingSource(data), len(data))


def test_custom_io_shared_source_serializes_positional_reads():
    """Streams derived from one archive cannot race seek/read/restore operations."""
    data = (FIXTURES / "mpq-v1-features.mpq").read_bytes()
    source = io.BytesIO(data)
    with mpq.Archive.open_io(source, len(data)) as archive:
        expected = archive["overview.txt"].read()
        with archive.open_stream("overview.txt") as first, archive.open_stream("overview.txt") as second:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                actual = list(executor.map(lambda stream: stream.read(), (first, second)))
    assert actual == [expected, expected]


def test_custom_io_source_is_released_after_last_derived_handle():
    """Closed wrappers do not retain a caller source after its final stream closes."""
    source = io.BytesIO((FIXTURES / "mpq-v1-features.mpq").read_bytes())
    reference = weakref.ref(source)
    archive = mpq.Archive.open_io(source, source.getbuffer().nbytes)
    stream = archive.open_stream("overview.txt")
    del source
    archive.close()
    gc.collect()
    assert reference() is not None
    stream.close()
    gc.collect()
    assert reference() is None


def test_weak_signature(tmp_path):
    """Test-only RSA key, round trip, and independent integer verification."""
    public = WEAK_PUBLIC_KEY
    private = WEAK_PRIVATE_KEY
    path = tmp_path / "signed.mpq"
    with mpq.Writer(path, max_files=8, flags=mpq.ARCHIVE_CREATE_LISTFILE,
                    attributes=mpq.ATTRIBUTE_MD5 | mpq.ATTRIBUTE_CRC32) as writer:
        writer.sign(private)
        writer.add("payload", b"signature binding test")
    with mpq.Archive(path) as archive:
        assert archive.signatures() == mpq.SIGNATURE_WEAK
        assert archive.verify(public) == 0
        with pytest.raises(mpq.LibmpqError):
            archive.verify(public[:-1])
        offset = archive["(signature)"].offset
    data = bytearray(path.read_bytes())
    signature = int.from_bytes(data[offset + 8:offset + 72], "little")
    data[offset:offset + 72] = bytes(72)
    digest = hashlib.md5(data).digest()
    expected = b"\0\1" + b"\xff" * 27 + b"\0" + bytes.fromhex("3020300c06082a864886f70d020505000410") + digest
    assert pow(signature, int.from_bytes(public[64:], "big"),
               int.from_bytes(public[:64], "big")).to_bytes(64, "big") == expected
    data = bytearray(path.read_bytes())
    data[offset + 8] ^= 1
    path.write_bytes(data)
    with mpq.Archive(path) as archive:
        assert archive.verify(public) == mpq.SIGNATURE_WEAK


@pytest.mark.parametrize("version", [mpq.ARCHIVE_VERSION_1, mpq.ARCHIVE_VERSION_2])
def test_strong_signature_round_trip(tmp_path, version):
    """Writer strong signing emits a plain NGIS trailer that verifies after reopening."""
    path = tmp_path / f"strong-v{version}.mpq"
    with mpq.Writer(path, version=version, max_files=8) as writer:
        writer.sign(STRONG_PRIVATE_KEY, signature_type=mpq.SIGNATURE_STRONG)
        writer.add("payload", b"strong signature binding test")
    with mpq.Archive(path) as archive:
        assert archive.signatures() == mpq.SIGNATURE_STRONG
        assert archive.verify(STRONG_PUBLIC_KEY, signature_type=mpq.SIGNATURE_STRONG) == 0


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


def test_fixture_canonical_names_and_explicit_text_decoding(monkeypatch):
    """Use canonical metadata names; string conversion must not extract data."""
    with mpq.Archive(FIXTURES / "mpq-v1-features.mpq") as archive:
        entry = archive["overview.txt"]
        for value in (archive, entry):
            assert not hasattr(value, "size_packed")
            assert not hasattr(value, "size_unpacked")
            assert value.metadata().packed_size == value.packed_size
            assert value.metadata().unpacked_size == value.unpacked_size
        assert not hasattr(entry, "read_bytes")
        assert bytes(entry) == entry.read()
        assert entry.read().decode("utf-8")

        def unexpected_read():
            pytest.fail("string conversion must not read the payload")

        monkeypatch.setattr(entry, "read", unexpected_read)
        assert str(entry) == repr(entry)


def test_version_errors_and_hashes():
    """Version, diagnostics, and Storm hashing work without an archive handle."""
    assert mpq.version()
    assert "format" in mpq.strerror(mpq.ERROR_FORMAT)
    assert len(mpq.file_hash("overview.txt")) == 3
    query = mpq.libmpq.libmpq__archive_compression_allowed
    assert query.restype == ctypes.c_int32
    assert query.argtypes == [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int32]
    verify = mpq.libmpq.libmpq__file_verify
    assert verify.restype == ctypes.c_int32
    assert (mpq.VERIFY_SECTOR_CRC, mpq.VERIFY_FILE_CRC32, mpq.VERIFY_FILE_MD5) == (1, 2, 4)
    assert mpq.VERIFY_RAW_MD5 == 8
    assert mpq.VERIFY_ALL == 15
    assert mpq.FILE_FLAG_SECTOR_CRC == 0x04000000
    assert verify.argtypes == [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                               ctypes.POINTER(ctypes.c_uint32)]
    block_verify = mpq.libmpq.libmpq__block_verify
    assert block_verify.restype == ctypes.c_int32
    packed_size = mpq.libmpq.libmpq__block_size_packed
    compression = mpq.libmpq.libmpq__block_compression
    assert compression.restype == ctypes.c_int32
    assert compression.argtypes == [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                    ctypes.POINTER(ctypes.c_uint32)]
    assert packed_size.restype == ctypes.c_int32
    assert packed_size.argtypes == [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                   ctypes.POINTER(ctypes.c_int64)]
    assert block_verify.argtypes == [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                    ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
    assert not mpq.archive_compression_allowed(mpq.ARCHIVE_VERSION_2, mpq.COMPRESSION_HUFFMAN)
    assert mpq.archive_compression_allowed(mpq.ARCHIVE_VERSION_2, mpq.COMPRESSION_HUFFMAN,
                                     mpq.COMPRESSION_POLICY_EXTENDED)
    for version in (mpq.ARCHIVE_VERSION_1, mpq.ARCHIVE_VERSION_2, mpq.ARCHIVE_VERSION_3):
        for policy in (mpq.COMPRESSION_POLICY_STANDARD, mpq.COMPRESSION_POLICY_EXTENDED):
            for method in (mpq.COMPRESSION_SPARSE,
                           mpq.COMPRESSION_SPARSE | mpq.COMPRESSION_ZLIB,
                           mpq.COMPRESSION_SPARSE | mpq.COMPRESSION_BZIP2):
                assert mpq.archive_compression_allowed(version, method, policy)
            assert not mpq.archive_compression_allowed(
                version, mpq.COMPRESSION_SPARSE | mpq.COMPRESSION_WAVE_MONO, policy)


def test_file_number_from_hash_classic():
    hashes = mpq.file_hash("overview.txt")
    with mpq.Archive(FIXTURES / "mpq-v1-features.mpq") as archive:
        expected = archive.file_number("overview.txt")
        number = archive.file_number_from_hash(hashes)
        assert type(number) is int and number == expected
        assert archive.file_number_from_hash(hashes) == expected
        assert archive.file_number_from_hash(list(hashes)) == expected
        with pytest.raises(mpq.LibmpqNotFoundError) as error:
            archive.file_number_from_hash(mpq.file_hash("no-such-member.bin"))
        assert error.value.code == mpq.ERROR_EXIST


def test_file_number_from_hash_mixed_tables():
    with mpq.Archive(FIXTURES / "mpq-v3-features.mpq") as archive:
        assert archive.file_number_from_hash(mpq.file_hash("overview.txt")) == (
            archive.file_number("overview.txt")
        )
        (identity,) = archive.variants("zero.bin")
        assert identity.flags == mpq.IDENTITY_BET
        assert archive.file_number("zero.bin") == identity.file_number
        assert archive.file_number("zero.bin", locale=0, platform=0) == identity.file_number
        with pytest.raises(mpq.LibmpqNotFoundError) as error:
            archive.file_number_from_hash(mpq.file_hash("zero.bin"))
        assert error.value.code == mpq.ERROR_EXIST


def test_file_number_from_hash_without_classic_tables():
    wire = bytearray((FIXTURES / "mpq-v3-features.mpq").read_bytes())
    # The fixture stores HET/BET before the two classic tables at the end.
    classic_start, = struct.unpack_from("<I", wire, 16)
    del wire[classic_start:]
    # Clear classic offsets/counts and update both declared archive sizes.
    struct.pack_into("<IIIIQHH", wire, 16, 0, 0, 0, 0, 0, 0, 0)
    struct.pack_into("<I", wire, 8, len(wire))
    struct.pack_into("<Q", wire, 44, len(wire))
    with mpq.Archive.open_io(io.BytesIO(wire), len(wire)) as archive:
        (identity,) = archive.variants("overview.txt")
        assert identity.flags == mpq.IDENTITY_BET
        assert archive.file_number("overview.txt") == identity.file_number
        with pytest.raises(mpq.LibmpqNotFoundError) as error:
            archive.file_number_from_hash(mpq.file_hash("overview.txt"))
        assert error.value.code == mpq.ERROR_EXIST


@pytest.mark.parametrize("hashes,error", [
    ((), ValueError),
    ((1, 2), ValueError),
    ([1, 2, 3, 4], ValueError),
    ((-1, 2, 3), ValueError),
    ((1, 0x100000000, 3), ValueError),
    ((1, 2, 3.0), TypeError),
    ((1, "2", 3), TypeError),
    (b"abc", TypeError),
    ("123", TypeError),
    ({1: 0, 2: 0, 3: 0}, TypeError),
    (None, TypeError),
])
def test_file_number_from_hash_invalid_input(hashes, error):
    with mpq.Archive(FIXTURES / "mpq-v1-features.mpq") as archive:
        with pytest.raises(error) as caught:
            archive.file_number_from_hash(hashes)
        assert type(caught.value) is error


def test_file_number_from_hash_closed_archive():
    archive = mpq.Archive(FIXTURES / "mpq-v1-features.mpq")
    archive.close()
    with pytest.raises(mpq.LibmpqStateError) as error:
        archive.file_number_from_hash(mpq.file_hash("overview.txt"))
    assert error.value.code == mpq.ERROR_NOT_INITIALIZED


def test_wheel_uses_bundled_library():
    """Wheel tests must load the private library shipped in mpq_libs."""
    if not os.environ.get("LIBMPQ_EXPECT_BUNDLED"):
        pytest.skip("only required for installed wheel tests")
    native = Path(mpq.libmpq._name).resolve()
    name = {"win32": "mpq.dll", "darwin": "libmpq.dylib"}.get(sys.platform, "libmpq.so")
    assert native.name == name
    assert native.parent.name == "mpq_libs"
    assert native.parent.parent == Path(mpq.__file__).resolve().parent
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
        assert archive["overview.txt"].verify() == 0
        entry = archive["overview.txt"]
        assert entry.block_compression(0) == 0
        methods = {"implode.txt": 0x08, "huffman.txt": 0x01, "zlib.txt": 0x02,
                   "pkware.txt": 0x08, "bzip2.txt": 0x10, "chain.txt": 0x03,
                   "encrypted-compress.txt": 0x02, "sparse.txt": 0x20,
                   "sparse-zlib.txt": 0x22, "sparse-bzip2.txt": 0x30}
        if version == 2:
            methods["lzma.txt"] = 0x12
        for member, method in methods.items():
            assert archive[member].block_compression(0) == method
            flags = archive[member].flags
            assert flags & (mpq.FILE_FLAG_IMPLODE if member == "implode.txt" else mpq.FILE_FLAG_COMPRESS)
            assert bool(flags & mpq.FILE_FLAG_ENCRYPTED) == (member == "encrypted-compress.txt")
        with pytest.raises(mpq.LibmpqNotFoundError):
            entry.block_compression(0xffffffff)
        with pytest.raises(ValueError):
            entry.block_compression(-1)
        attributes = entry.attributes()
        assert archive.attributes() == (7 if version == 1 else 15)
        assert attributes.crc32 == zlib.crc32(entry.read())
        assert attributes.md5 == hashlib.md5(entry.read()).digest()
        assert attributes.filetime == 132537600000000000
        assert not attributes.patch_bit
        assert b"libmpq" in entry.read()
        assert archive.metadata().files == archive.files
        assert entry.metadata().unpacked_size == entry.unpacked_size
        assert entry.compressed == bool(entry.flags & mpq.FILE_FLAG_COMPRESS)
        assert entry.encrypted == bool(entry.flags & mpq.FILE_FLAG_ENCRYPTED)
        assert entry.imploded == bool(entry.flags & mpq.FILE_FLAG_IMPLODE)
        for member in ("sparse.txt", "sparse-zlib.txt", "sparse-bzip2.txt"):
            assert archive[member].read() == SPARSE_BYTES
            assert archive[member].read().decode("utf-32") == SPARSE_TEXT
            stored, mismatches = archive[member].verify_block(0)
            assert 0 < stored < 0xffffffff and mismatches == 0
            assert 0 < archive[member].block_size_packed(0) < archive[member].block_size_unpacked(0)
        assert entry.block_size_packed(0) == entry.block_size_unpacked(0)
        with pytest.raises(mpq.LibmpqNotFoundError):
            archive["sparse.txt"].block_size_packed(0xffffffff)
        with pytest.raises(ValueError):
            archive["sparse.txt"].block_size_packed(-1)
        with pytest.raises(mpq.LibmpqNotFoundError):
            entry.verify_block(0)
        with pytest.raises(mpq.LibmpqNotFoundError):
            archive["sparse.txt"].verify_block(0xffffffff)
        with pytest.raises(ValueError):
            archive["sparse.txt"].verify_block(-1)


@pytest.mark.parametrize("name,version,offset", [
    ("mpq-v1-features.mpqe", 1, 0),
    ("mpq-v2-features.mpqe", 2, -1),
])
def test_mpqe_fixture_metadata_extraction_and_clone(name, version, offset):
    """MPQE opening uses borrowed credentials and supports independent clones."""
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    with mpq.Archive.open_mpqe(FIXTURES / name, memoryview(code), offset) as archive:
        assert archive.attributes() == (7 if version == 1 else 15)
        assert archive.version == version
        assert b"libmpq" in archive["overview.txt"].read()
        assert archive["overview.txt"].verify() == 0
        stored, mismatches = archive["sparse.txt"].verify_block(0)
        assert 0 < stored < 0xffffffff and mismatches == 0
        assert 0 < archive["sparse.txt"].block_size_packed(0) < archive["sparse.txt"].block_size_unpacked(0)
        clone = archive.clone()
        try:
            assert clone["overview.txt"].attributes() == archive["overview.txt"].attributes()
            assert clone["overview.txt"].verify() == 0
            assert clone["overview.txt"].read() == archive["overview.txt"].read()
            for member in ("sparse.txt", "sparse-zlib.txt", "sparse-bzip2.txt"):
                assert clone[member].read() == archive[member].read() == SPARSE_BYTES
        finally:
            clone.close()
    with pytest.raises(mpq.LibmpqDecryptError):
        mpq.Archive.open_mpqe(FIXTURES / name, code[:-1], offset)


@pytest.mark.parametrize("version", [mpq.ARCHIVE_VERSION_2, mpq.ARCHIVE_VERSION_3,
                                     mpq.ARCHIVE_VERSION_4])
def test_mpqe_creation_replaces_destination(tmp_path, version):
    """MPQE creation publishes a complete archive over an existing target."""
    path = tmp_path / "created.mpqe"
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    path.write_bytes(b"previous destination")
    with mpq.Writer.create_mpqe(path, code, version=version,
                                attributes=mpq.ATTRIBUTE_CRC32) as writer:
        writer.add("payload.txt", b"Python MPQE writer regression\n")
    with mpq.Archive.open_mpqe(path, code, offset=0) as archive:
        assert archive.version == version + 1
        assert archive.attributes() == mpq.ATTRIBUTE_CRC32
        assert archive["payload.txt"].read() == b"Python MPQE writer regression\n"
        assert archive["payload.txt"].verify(mpq.VERIFY_RAW_MD5) == 0
    with pytest.raises(mpq.LibmpqDecryptError):
        mpq.Writer.create_mpqe(path, code[:-1])
    with pytest.raises(mpq.LibmpqFormatError):
        mpq.Writer.create_mpqe(path, code, attributes=0x10)
    with pytest.raises(mpq.LibmpqFormatError):
        mpq.Writer(tmp_path / "invalid.mpq", attributes=0x10)


@pytest.mark.parametrize("version", [mpq.ARCHIVE_VERSION_2, mpq.ARCHIVE_VERSION_3,
                                     mpq.ARCHIVE_VERSION_4])
def test_creation_streaming_compression_clone_and_blocks(tmp_path, version):
    """Creation APIs round-trip raw, compressed, path, stream, clone, and blocks."""
    archive_path = tmp_path / "created.mpq"
    source_path = tmp_path / "source.txt"
    source_path.write_bytes(b"path payload")
    repetitive = b"R" * 12000
    streamed = bytes(range(256)) * 20

    with mpq.Writer(archive_path, version=version,
                    flags=mpq.ARCHIVE_CREATE_LISTFILE,
                    attributes=mpq.ATTRIBUTE_CRC32 |
                          mpq.ATTRIBUTE_FILETIME | mpq.ATTRIBUTE_MD5 |
                          mpq.ATTRIBUTE_PATCH_BIT) as writer:
        writer.add("raw.bin", b"raw payload")
        checksummed = mpq.FileCreateOptions.compressed(mpq.COMPRESSION_ZLIB,
                                                       mpq.COMPRESSION_ZLIB)
        checksummed.flags |= mpq.FILE_FLAG_SECTOR_CRC
        writer.add("compressed.bin", repetitive, checksummed)
        writer.add("lzma.bin", repetitive,
                   mpq.FileCreateOptions.compressed(mpq.COMPRESSION_LZMA,
                                                    mpq.COMPRESSION_LZMA))
        writer.add_path("path.txt", source_path)
        with writer.begin("stream.bin", len(streamed)) as stream:
            stream.timestamp(0xfedcba9876543210)
            stream.write(streamed[:1000])
            stream.write(streamed[1000:])

    if version == mpq.ARCHIVE_VERSION_4:
        wire = archive_path.read_bytes()
        assert struct.unpack_from("<I", wire, 4)[0] == 0xd0
        assert struct.unpack_from("<H", wire, 12)[0] == 3
        assert struct.unpack_from("<I", wire, 0x6c)[0] == 0x4000
        assert wire[0xc0:0xd0] == hashlib.md5(wire[:0xc0]).digest()
    with mpq.Archive(archive_path, offset=0) as archive:
        assert archive.version == version + 1
        clone = archive.clone()
        try:
            assert clone["raw.bin"].read() == b"raw payload"
            assert archive["compressed.bin"].read() == repetitive
            assert archive["compressed.bin"].verify(mpq.VERIFY_SECTOR_CRC) == 0
            assert archive["compressed.bin"].verify() == 0
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


@pytest.mark.parametrize("method", [mpq.Writer.add_data, mpq.Writer.add])
def test_writer_add_data_alias(tmp_path, monkeypatch, method):
    assert str(inspect.signature(method)) == "(self, name, data, options=None)"
    path = tmp_path / "add-data.mpq"
    source = tmp_path / "source"
    source.write_bytes(b"path payload")
    calls = []
    native_data = mpq.libmpq.libmpq__archive_add_data
    native_path = mpq.libmpq.libmpq__archive_add_path

    def add_data(*args):
        calls.append("data")
        return native_data(*args)

    def add_path(*args):
        calls.append("path")
        return native_path(*args)

    monkeypatch.setattr(mpq.libmpq, "libmpq__archive_add_data", add_data)
    monkeypatch.setattr(mpq.libmpq, "libmpq__archive_add_path", add_path)
    with mpq.Writer(path) as writer:
        method(writer, "default", bytearray(b"payload"))
        assert calls == ["data"]
        method(writer, name="empty", data=b"", options=None)
        assert calls == ["data"] * 2
        options = mpq.FileCreateOptions(mpq.FILE_FLAG_SINGLE, 0, 0, 1033, 2)
        method(writer, "custom", memoryview(b"payload"), options)
        assert calls == ["data"] * 3
        with pytest.raises(mpq.LibmpqNotFoundError) as missing:
            method(writer, "", b"payload")
        assert missing.value.code == mpq.ERROR_EXIST
        assert calls == ["data"] * 4
        for bad_name in ("bad\0name", b"bad\0name"):
            with pytest.raises(ValueError, match="NUL"):
                method(writer, bad_name, b"payload")
        assert calls == ["data"] * 4
        writer.add_path("from-path", source)
    with pytest.raises(mpq.LibmpqStateError) as closed:
        method(writer, "closed", b"payload")
    assert closed.value.code == mpq.ERROR_NOT_INITIALIZED
    assert calls == ["data"] * 4 + ["path"]
    with mpq.Archive(path) as archive:
        assert archive["default"].read() == b"payload"
        assert not archive["default"].flags & mpq.FILE_FLAG_SINGLE
        assert archive["empty"].read() == b""
        custom = archive[archive.file_number("custom", locale=1033, platform=2)]
        assert custom.read() == b"payload"
        assert custom.flags & mpq.FILE_FLAG_SINGLE
        assert archive["from-path"].read() == b"path payload"


@pytest.mark.parametrize("corrupt", [
    0, mpq.VERIFY_FILE_CRC32, mpq.VERIFY_FILE_MD5,
    mpq.VERIFY_FILE_CRC32 | mpq.VERIFY_FILE_MD5,
])
def test_explicit_verification_mismatches(tmp_path, corrupt):
    """Explicit mismatches stay bit-based; complete reads reject bad metadata."""
    path = tmp_path / "verify.mpq"
    payload = b"verification payload\n" * 100
    crc = zlib.crc32(payload) ^ bool(corrupt & mpq.VERIFY_FILE_CRC32)
    digest = bytearray(hashlib.md5(payload).digest())
    digest[0] ^= bool(corrupt & mpq.VERIFY_FILE_MD5)
    metadata = struct.pack("<IIII", 100, mpq.ATTRIBUTE_CRC32 | mpq.ATTRIBUTE_MD5,
                           crc, 0) + digest + bytes(16)
    with mpq.Writer(path, max_files=2) as writer:
        writer.add("payload", payload)
        writer.add("(attributes)", metadata)
    with mpq.Archive(path, offset=0) as archive:
        entry = archive["payload"]
        for request in range(mpq.VERIFY_ALL + 1):
            mismatches = entry.verify(request)
            assert mismatches == (request & corrupt)
            assert mismatches & ~request == 0
        if corrupt:
            with pytest.raises(mpq.LibmpqIOError):
                entry.read()
            with pytest.raises(mpq.LibmpqIOError) as caught:
                entry.read_into(bytearray(len(payload)))
            assert caught.value.code == mpq.ERROR_READ
            assert not hasattr(caught.value, "transferred")
        else:
            assert entry.read() == payload
            buffer = bytearray(len(payload))
            assert entry.read_into(buffer) == len(payload)
            assert buffer == payload


def test_read_block_into_actual_decoded_size(tmp_path, monkeypatch):
    path = tmp_path / "reader-blocks.mpq"
    single = mpq.FileCreateOptions.compressed(mpq.COMPRESSION_ZLIB, mpq.COMPRESSION_ZLIB)
    single.flags |= mpq.FILE_FLAG_SINGLE
    multi = b"A" * 512 + b"B" * 23
    with mpq.Writer(path, sector_size=512) as writer:
        writer.add_data("sectorized", multi)
        writer.add_data("single", b"J" * 4000, single)
        writer.add_data("empty", b"", mpq.FileCreateOptions(flags=mpq.FILE_FLAG_SINGLE))
    with mpq.Archive(path) as archive:
        entry = archive["sectorized"]
        for block, expected in enumerate((multi[:512], multi[512:])):
            buffer = bytearray(b"!" * 520)
            assert entry.read_block_into(block, buffer) == len(expected)
            assert buffer == expected + b"!" * (len(buffer) - len(expected))
        with pytest.raises(mpq.LibmpqNotFoundError) as caught:
            entry.read_block_into(0xffffffff, bytearray(512))
        assert caught.value.code == mpq.ERROR_EXIST
        with monkeypatch.context() as guard:
            def unexpected(*args):
                pytest.fail("invalid block index reached C")

            guard.setattr(mpq.libmpq, "libmpq__block_read", unexpected)
            for invalid in (-1, 1 << 32):
                with pytest.raises(ValueError):
                    entry.read_block_into(invalid, bytearray(512))
            with pytest.raises(TypeError):
                entry.read_block_into(0.0, bytearray(512))
        entry = archive["empty"]
        assert entry.read_block_into(0, bytearray()) == entry.read_into(bytearray()) == 0
        assert entry.read_block(0) == entry.read() == b""
        entry = archive["single"]
        offset = archive.offset + entry.offset
        packed_size = entry.block_size_packed(0)
        buffer = bytearray(4000)
        assert entry.read_block_into(0, buffer) == len(buffer)
        assert buffer == b"J" * 4000

    wire = bytearray(path.read_bytes())
    for expected in (b"short block", b""):
        # Change the zlib payload while preserving the nominal size in the tables.
        packed = bytes([mpq.COMPRESSION_ZLIB]) + zlib.compress(expected)
        assert len(packed) <= packed_size
        wire[offset:offset + packed_size] = packed.ljust(packed_size, b"\0")
        path.write_bytes(wire)
        with mpq.Archive(path) as archive:
            entry = archive["single"]
            assert entry.block_size_unpacked(0) == 4000
            assert entry.read_block(0) == expected
            buffer = bytearray(b"!" * 4001)
            assert entry.read_block_into(0, buffer) == len(expected)
            assert buffer == expected + b"!" * (len(buffer) - len(expected))
            with pytest.raises(mpq.LibmpqSizeError) as caught:
                entry.read_block_into(0, bytearray(3999))
            assert caught.value.code == mpq.ERROR_SIZE

    wire[offset + 1:offset + packed_size] = bytes(packed_size - 1)
    path.write_bytes(wire)
    with mpq.Archive(path) as archive:
        with pytest.raises(mpq.LibmpqUnpackError) as caught:
            archive["single"].read_block_into(0, bytearray(4000))
        assert caught.value.code == mpq.ERROR_UNPACK
        assert not hasattr(caught.value, "transferred")


@pytest.mark.parametrize("chunk_size", [0, 1, 2, 3])
def test_v4_raw_md5(tmp_path, chunk_size):
    """Reuse writer-produced classic tables; independently hash raw v4 bytes."""
    path = tmp_path / "raw-md5.mpq"
    with mpq.Writer(path, version=mpq.ARCHIVE_VERSION_2, max_files=8) as writer:
        writer.add("raw", b"abc")
    with mpq.Archive(path, offset=0) as archive:
        offset = archive["raw"].offset
    original = path.read_bytes()
    _, _, _, _, shift, hash_pos, block_pos, hashes, blocks = struct.unpack_from(
        "<IIIHHIIII", original)
    hash_table = original[hash_pos:hash_pos + hashes * 16]
    block_table = original[block_pos:block_pos + blocks * 16]
    assert offset >= 0xd0 and original[offset:offset + 3] == b"abc"
    image = bytearray(original[:offset + 3])
    digest_pos = len(image)
    if chunk_size:
        for start in range(0, 3, chunk_size):
            image.extend(hashlib.md5(b"abc"[start:start + chunk_size]).digest())
    hash_pos = len(image)
    image.extend(hash_table)
    block_pos = len(image)
    image.extend(block_table)
    struct.pack_into("<IIIHHIIII", image, 0, 0x1a51504d, 0xd0, 1, 3, shift,
                     hash_pos, block_pos, hashes, blocks)
    struct.pack_into("<QHHQQQ", image, 32, 0, 0, 0, len(image), 0, 0)
    struct.pack_into("<QQQQQI", image, 68, len(hash_table), len(block_table),
                     0, 0, 0, chunk_size)
    image[112:208] = bytes(96)
    image[112:128] = hashlib.md5(block_table).digest()
    image[128:144] = hashlib.md5(hash_table).digest()
    image[192:208] = hashlib.md5(image[:192]).digest()
    path.write_bytes(image)
    with mpq.Archive(path, offset=0) as archive:
        assert archive.version == 4
        assert archive["raw"].verify(mpq.VERIFY_RAW_MD5) == 0
        assert archive["raw"].read() == b"abc"
    if chunk_size:
        image[digest_pos] ^= 1
        path.write_bytes(image)
        with mpq.Archive(path, offset=0) as archive:
            assert archive["raw"].read() == b"abc"
            assert archive["raw"].verify(mpq.VERIFY_RAW_MD5) == mpq.VERIFY_RAW_MD5


def test_errors_and_lifecycle(tmp_path):
    """Missing entries, oversized writes, and post-close use expose typed errors."""
    path = tmp_path / "errors.mpq"
    with mpq.Writer(path) as writer:
        writer.add("raw", b"abc")
        with pytest.raises(ValueError):
            with writer.begin("too-large", 3) as stream:
                stream.write(b"1234")
    with mpq.Archive(path, offset=0) as archive:
        assert archive["raw"].verify(0) == 0
        assert archive["raw"].verify(mpq.VERIFY_SECTOR_CRC) == 0
        assert archive["raw"].verify(mpq.VERIFY_RAW_MD5) == 0
        with pytest.raises(mpq.LibmpqNotFoundError):
            archive["raw"].verify()
        with pytest.raises(mpq.LibmpqError) as invalid:
            archive["raw"].verify(16)
        assert invalid.value.code == mpq.ERROR_FORMAT
        with pytest.raises(mpq.LibmpqNotFoundError) as error:
            archive["missing"]
        assert error.value.code == mpq.ERROR_EXIST
        archive.close()
        with pytest.raises(mpq.LibmpqStateError):
            archive[0]


def _v4_stored_layout(wire):
    """Check committed wire bytes with hashlib and an independent table decoder."""
    assert wire[:4] == b"MPQ\x1a"
    assert struct.unpack_from("<I", wire, 4)[0] == 0xd0
    assert struct.unpack_from("<H", wire, 12)[0] == 3
    assert struct.unpack_from("<Q", wire, 44)[0] == len(wire)
    assert hashlib.md5(wire[:0xc0]).digest() == wire[0xc0:0xd0]
    chunk_size = struct.unpack_from("<I", wire, 108)[0]
    assert chunk_size == 0x4000
    positions = [struct.unpack_from("<I", wire, 16)[0] |
                 (struct.unpack_from("<H", wire, 40)[0] << 32),
                 struct.unpack_from("<I", wire, 20)[0] |
                 (struct.unpack_from("<H", wire, 42)[0] << 32),
                 struct.unpack_from("<Q", wire, 32)[0],
                 struct.unpack_from("<Q", wire, 60)[0],
                 struct.unpack_from("<Q", wire, 52)[0]]
    sizes = struct.unpack_from("<5Q", wire, 68)
    digest_offsets = [128, 112, 144, 176, 160]
    ranges = [(0, 0xd0)]
    for position, size, digest_offset in zip(positions, sizes, digest_offsets):
        digest = wire[digest_offset:digest_offset + 16]
        if size == 0:
            assert position == 0 and digest == bytes(16)
        else:
            assert 0xd0 <= position < position + size <= len(wire)
            assert hashlib.md5(wire[position:position + size]).digest() == digest
            ranges.append((position, position + size))
    # Extended-table raw arrays are outside their stored-envelope extents.
    for position, size in zip(positions[3:], sizes[3:]):
        if size == 0:
            continue
        chunks = (size - 1) // chunk_size + 1
        end = position + size + 16 * chunks
        assert end <= len(wire)
        for index in range(chunks):
            start = position + index * chunk_size
            stop = min(start + chunk_size, position + size)
            offset = position + size + index * 16
            assert hashlib.md5(wire[start:stop]).digest() == wire[offset:offset + 16]
        ranges.append((position + size, end))
    assert all(sizes[i] > 0 for i in (0, 1, 3, 4))
    count = struct.unpack_from("<I", wire, 28)[0]
    assert sizes[1] == count * 16
    # Decode the encrypted classic block table independently of native code.
    table = [0] * 0x500
    seed = 0x100001
    for low in range(256):
        for high in range(5):
            seed = (seed * 125 + 3) % 0x2aaaab
            upper = (seed & 0xffff) << 16
            seed = (seed * 125 + 3) % 0x2aaaab
            table[low + high * 256] = upper | (seed & 0xffff)
    key, seed = 0xec83b3a3, 0xeeeeeeee
    decoded = []
    for (word,) in struct.iter_unpack("<I", wire[positions[1]:positions[1] + sizes[1]]):
        seed = (seed + table[0x400 + (key & 0xff)]) & 0xffffffff
        value = word ^ ((key + seed) & 0xffffffff)
        key = (((~key & 0xffffffff) << 21) + 0x11111111 | (key >> 11)) & 0xffffffff
        seed = (value + seed + (seed << 5) + 3) & 0xffffffff
        decoded.append(value)
    entries = []
    for i in range(0, len(decoded), 4):
        position, size, logical, flags = decoded[i:i + 4]
        if not flags & 0x80000000:
            continue
        entries.append((position, size, logical, flags))
        if size == 0:
            continue
        chunks = (size + chunk_size - 1) // chunk_size
        end = position + size + 16 * chunks
        assert 0xd0 <= position < end <= len(wire)
        for chunk in range(chunks):
            start = position + chunk * chunk_size
            stop = min(start + chunk_size, position + size)
            offset = position + size + chunk * 16
            assert hashlib.md5(wire[start:stop]).digest() == wire[offset:offset + 16]
        ranges.append((position, end))
    ranges.sort()
    assert all(left[1] <= right[0] for left, right in zip(ranges, ranges[1:]))
    return positions, entries


@pytest.mark.parametrize("name", ["mpq-v4-features.mpq", "mpq-v4-features-patch.mpq"])
def test_v4_fixture_wire_integrity(name):
    positions, entries = _v4_stored_layout((FIXTURES / name).read_bytes())
    assert positions and entries
    if name == "mpq-v4-features.mpq":
        assert any(size == 16421 and logical == size for _, size, logical, _ in entries)


@pytest.mark.parametrize("encrypted", [False, True])
def test_v4_fixture_read_update(tmp_path, encrypted):
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    source = FIXTURES / ("mpq-v4-features.mpqe" if encrypted else "mpq-v4-features.mpq")
    expected = {
        "overview.txt": b"Synthetic MPQ v4 overview.\n",
        "large.bin": bytes((i * 37 + 11) & 255 for i in range(16421)),
        "folder/sector.txt": bytes(65 + i % 23 for i in range(8192)),
        "remove.txt": b"Delete this synthetic member.\n",
        "empty.bin": b"",
    }
    opener = (lambda path: mpq.Archive.open_mpqe(path, code)) if encrypted else mpq.Archive
    with opener(source) as archive:
        assert archive.version == 4 and archive.files == 7
        for name, payload in expected.items():
            entry = archive[name]
            with archive.open_stream(name) as stream:
                assert stream.read() == payload
                assert entry.verify(mpq.VERIFY_RAW_MD5 if entry.encrypted else mpq.VERIFY_ALL) == 0
        assert archive["large.bin"].flags & mpq.FILE_FLAG_KEY
        with archive.open_stream("folder/sector.txt") as stream:
            stream.seek(4090)
            assert stream.read(32) == expected["folder/sector.txt"][4090:4122]
    path = tmp_path / source.name
    path.write_bytes(source.read_bytes())
    begin = (lambda: mpq.Update.begin_mpqe(path, code)) if encrypted else lambda: mpq.Update.begin(path)
    with begin() as update:
        update.remove("large.bin")
        update.abort()
    assert path.read_bytes() == source.read_bytes()
    with begin() as update:
        update.replace_data("overview.txt", b"fixture update\n")
        update.add_data("added.txt", b"added\n")
        update.rename("empty.bin", "renamed.bin")
        update.remove("remove.txt")
        update.commit()
    with opener(path) as archive:
        assert archive.version == 4
        assert archive["overview.txt"].read() == b"fixture update\n"
        assert archive["added.txt"].read() == b"added\n"
        assert archive["renamed.bin"].read() == b"" and "remove.txt" not in archive
        with archive.open_stream("large.bin") as stream:
            assert stream.read() == expected["large.bin"]
            assert archive["large.bin"].verify(mpq.VERIFY_RAW_MD5) == 0
    if not encrypted:
        _v4_stored_layout(path.read_bytes())


@pytest.mark.parametrize("target", ["header", "hash", "block", "het", "bet"])
def test_v4_fixture_corrupt_metadata(target):
    wire = bytearray((FIXTURES / "mpq-v4-features.mpq").read_bytes())
    positions, _ = _v4_stored_layout(wire)
    offset = 0xc0 if target == "header" else positions[{"hash": 0, "block": 1, "het": 3, "bet": 4}[target]]
    wire[offset] ^= 1
    with pytest.raises(mpq.LibmpqFormatError):
        mpq.Archive.open_io(io.BytesIO(wire), len(wire))


@pytest.mark.parametrize("digest", [False, True])
def test_v4_fixture_corrupt_raw(digest):
    wire = bytearray((FIXTURES / "mpq-v4-features.mpq").read_bytes())
    _, entries = _v4_stored_layout(wire)
    position, size, _, _ = next(entry for entry in entries if entry[1] == 16421)
    wire[position + size if digest else position + 0x4000] ^= 1
    with mpq.Archive.open_io(io.BytesIO(wire), len(wire)) as archive:
        assert archive["large.bin"].verify(mpq.VERIFY_RAW_MD5) == mpq.VERIFY_RAW_MD5


@pytest.mark.parametrize("source_kind", ["path", "custom", "mpqe"])
@pytest.mark.parametrize("prefixes", [None, [None, None], ["", ""]])
def test_open_patch_owned(tmp_path, source_kind, prefixes):
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    base_path = FIXTURES / ("mpq-v4-features.mpqe" if source_kind == "mpqe"
                            else "mpq-v4-features.mpq")
    callback_source = None
    if source_kind == "custom":
        callback_source = io.BytesIO(base_path.read_bytes())
        base = mpq.Archive.open_io(callback_source, len(callback_source.getvalue()))
    elif source_kind == "mpqe":
        base = mpq.Archive.open_mpqe(base_path, code)
    else:
        base = mpq.Archive(base_path)
    patch = mpq.Archive(FIXTURES / "mpq-v4-features-patch.mpq")
    overlay_path = tmp_path / "addition.mpq"
    with mpq.Writer(overlay_path, version=mpq.ARCHIVE_VERSION_4,
                    flags=mpq.ARCHIVE_CREATE_LISTFILE) as writer:
        writer.add("addition.txt", b"ordinary addition")
    overlay = mpq.Archive(overlay_path)
    snapshot = mpq.Archive.open_patch(base, [])
    assert snapshot.version == 4
    result = mpq.Archive.open_patch(base, [patch, overlay], prefixes)
    base.close()
    patch.close()
    overlay.close()
    if callback_source is not None:
        reference = weakref.ref(callback_source)
        callback_source.close()
        del callback_source
        gc.collect()
        assert reference() is None
    with snapshot.open_stream("large.bin") as stream:
        assert len(stream.read()) == 16421
    snapshot.close()
    assert result["overview.txt"].read() == b"Version four patch\n"
    assert result["addition.txt"].read() == b"ordinary addition"
    assert "remove.txt" not in result
    clone = result.clone()
    stream = result.open_stream("folder/sector.txt")
    result.close()
    assert clone["overview.txt"].read() == b"Version four patch\n"
    clone.close()
    expected = bytearray(65 + i % 23 for i in range(8192))
    expected[17] ^= 0x5a
    assert stream.read() == expected
    stream.close()


def test_open_patch_stream_detached(tmp_path):
    name = "folder/sector.txt"
    first_path = FIXTURES / "mpq-v4-features-patch.mpq"
    middle_path = tmp_path / "middle.mpq"
    last_path = tmp_path / "last.mpq"
    middle = bytearray(65 + i % 23 for i in range(8192))
    middle[17] ^= 0x5a
    with mpq.Writer(middle_path, version=mpq.ARCHIVE_VERSION_2,
                    flags=mpq.ARCHIVE_CREATE_LISTFILE) as writer:
        writer.add(name, middle)
        writer.add("empty", b"")
        writer.add("voice", b"localized", mpq.FileCreateOptions(locale=1033, platform=2))
        writer.add("voice", b"neutral")
    with mpq.Patch.begin(middle_path, last_path) as patch:
        patch.replace_data(name, b"done")
        patch.finish()
    with mpq.Archive(middle_path) as archive:
        with archive.open_patch_stream("empty", []) as empty:
            assert empty.size == 0
            assert empty.read() == b""
        with archive.open_patch_stream("voice", [], locale=1033, platform=2) as localized:
            assert localized.read() == b"localized"
        with archive.open_patch_stream("voice", [], locale=0, platform=0) as neutral:
            assert neutral.read() == b"neutral"

    paths = [FIXTURES / "mpq-v4-features.mpq", first_path, last_path]
    sources = [io.BytesIO(path.read_bytes()) for path in paths]
    references = [weakref.ref(source) for source in sources]
    archives = [mpq.Archive.open_io(source, len(source.getvalue())) for source in sources]
    base, first, last = archives
    with base, first, last:
        assert first[name].read_patch_payload()[64:68] == b"BSD0"
        assert last[name].read_patch_payload()[64:68] == b"COPY"
        with pytest.raises(ValueError):
            base.open_patch_stream(name, [first], [])
        with pytest.raises(ValueError):
            base.open_patch_stream(name, [first], ["bad\0prefix"])
        with pytest.raises(ValueError):
            base.open_patch_stream(name, [], locale=65536)
        for absent in ("remove.txt", "missing"):
            with pytest.raises(mpq.LibmpqError):
                base.open_patch_stream(absent, [first, last])
        with pytest.raises(RuntimeError, match="consumer failed"):
            with base.open_patch_stream(name, [first, last]) as interrupted:
                raise RuntimeError("consumer failed")
        with pytest.raises(mpq.LibmpqStateError):
            interrupted.read()
        regular = base.open_patch_stream(name, [first, last], [None, ""])
        with regular:
            exact = base.open_patch_stream(name, [first, last], locale=0, platform=0)
            with exact:
                for archive in archives:
                    archive.close()
                for source in sources:
                    source.close()
                del source, sources
                gc.collect()
                assert all(reference() is None for reference in references)
                assert exact.size == 4
                assert regular.read(2) == b"do"
                assert exact.tell() == 0
                assert exact.seek(-2, os.SEEK_END) == 2
                assert exact.read() == b"ne"
                assert exact.read() == b""
                assert exact.seek(0) == 0
                assert exact.read() == b"done"
                assert regular.read() == b"ne"
    with pytest.raises(mpq.LibmpqStateError):
        base.open_patch_stream(name, [])
    with pytest.raises(mpq.LibmpqStateError):
        exact.read()


def test_open_patch_arguments():
    with mpq.Archive(FIXTURES / "mpq-v4-features.mpq") as base:
        with pytest.raises(ValueError):
            mpq.Archive.open_patch(base, [], [None])
        with pytest.raises(ValueError):
            mpq.Archive.open_patch(base, [base], ["bad\0prefix"])
        with pytest.raises(TypeError):
            mpq.Archive.open_patch(base, [None])
        with pytest.raises(TypeError):
            mpq.Archive.open_patch(None, [])
        with mpq.Archive(FIXTURES / "mpq-v4-features-patch.mpq") as patch:
            with pytest.raises(mpq.LibmpqFormatError):
                mpq.Archive.open_patch(base, [patch, patch])
            assert base["overview.txt"].read() == b"Synthetic MPQ v4 overview.\n"
    with pytest.raises(mpq.LibmpqStateError):
        mpq.Archive.open_patch(base, [])


def test_open_patch_namespace(tmp_path):
    path = tmp_path / "namespaced.mpq"
    with mpq.Writer(path, version=mpq.ARCHIVE_VERSION_4,
                    flags=mpq.ARCHIVE_CREATE_LISTFILE) as writer:
        writer.add("Base\\extra.txt", b"prefix payload")
        writer.add("Base\\(patch_metadata)", b"namespace marker")
    with mpq.Archive(FIXTURES / "mpq-v4-features.mpq") as base, mpq.Archive(path) as patch:
        for prefixes in (None, [None], ["Base"]):
            with mpq.Archive.open_patch(base, [patch], prefixes) as result:
                assert result["extra.txt"].read() == b"prefix payload"
        for prefixes in ([""], ["Other"]):
            with pytest.raises(mpq.LibmpqFormatError):
                mpq.Archive.open_patch(base, [patch], prefixes)


@pytest.mark.parametrize("version", [mpq.ARCHIVE_VERSION_1, mpq.ARCHIVE_VERSION_4])
@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("mixed", [False, True])
def test_patch_ordinary_additions(tmp_path, version, wrapped, mixed):
    base_path, output, source = (tmp_path / name for name in ("base.mpq", "patch.mpq", "source.bin"))
    payload = bytes((i * 37 + 11) & 255 for i in range(17003))
    source.write_bytes(payload)
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    with mpq.Writer(base_path, version=version, max_files=8,
                    flags=mpq.ARCHIVE_CREATE_LISTFILE) as writer:
        writer.add("existing.txt", b"before")
        writer.add("remove.txt", b"remove")
    original = base_path.read_bytes()
    secure = mpq.FileCreateOptions.compressed(mpq.COMPRESSION_ZLIB, mpq.COMPRESSION_ZLIB)
    secure.flags |= mpq.FILE_FLAG_ENCRYPTED | mpq.FILE_FLAG_KEY | mpq.FILE_FLAG_SECTOR_CRC
    opener = (lambda: mpq.Patch.begin_mpqe(base_path, output, code)) if wrapped else lambda: mpq.Patch(base_path, output)
    with opener() as patch:
        with pytest.raises(mpq.LibmpqNotFoundError):
            patch.add_data("existing.txt", b"not an addition")
        with pytest.raises(ValueError):
            patch.add_data("bad\0name", b"payload")
        with pytest.raises(ValueError):
            patch.add_path("bad", "bad\0source")
        patch.add_data("new.bin", payload)
        patch.add_path("path.bin", source, secure)
        patch.add_data("empty.bin", b"")
        with pytest.raises(mpq.LibmpqNotFoundError):
            patch.add_data("NEW.BIN", b"duplicate")
        with pytest.raises(mpq.LibmpqNotFoundError):
            patch.replace_data("new.bin", b"not a base member")
        with pytest.raises(mpq.LibmpqNotFoundError):
            patch.remove("new.bin")
        if mixed:
            patch.replace_data("existing.txt", b"after")
            patch.remove("remove.txt")
            with pytest.raises(mpq.LibmpqNotFoundError):
                patch.add_data("remove.txt", b"use replace")
        patch.finish()
    assert base_path.read_bytes() == original
    open_layer = mpq.Archive.open_mpqe(output, code) if wrapped else mpq.Archive(output)
    with mpq.Archive(base_path) as base, open_layer as layer:
        assert not layer["new.bin"].flags & (mpq.FILE_FLAG_PATCH_FILE | mpq.FILE_FLAG_DELETE_MARKER)
        assert layer["new.bin"].verify(mpq.VERIFY_ALL) == 0
        with mpq.Archive.open_patch(base, [layer]) as result:
            assert result["new.bin"].read() == payload
            with result.open_stream("path.bin") as stream:
                assert stream.read() == payload
            assert result["empty.bin"].read() == b""
            assert result["existing.txt"].read() == (b"after" if mixed else b"before")
            assert ("remove.txt" in result) is not mixed
    output.unlink()
    with opener() as patch:
        patch.add_data("aborted.txt", b"unpublished")
        patch.abort()
    assert not output.exists() and base_path.read_bytes() == original


@pytest.mark.parametrize("chunk", [0, 1, 17, 0x4000, 0xffffffff])
@pytest.mark.parametrize("wrapped", [False, True])
def test_raw_chunk_configuration(tmp_path, chunk, wrapped):
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    path = tmp_path / "raw-policy.mpq"
    create = (lambda: mpq.Writer.create_mpqe(path, code, version=mpq.ARCHIVE_VERSION_4,
                                            flags=mpq.ARCHIVE_CREATE_LISTFILE)) if wrapped else lambda: mpq.Writer(
        path, version=mpq.ARCHIVE_VERSION_4, flags=mpq.ARCHIVE_CREATE_LISTFILE)
    with create() as writer:
        assert writer.raw_chunk_size == 0x4000
        for invalid in (-1, 0x100000000, 1.5, "17"):
            with pytest.raises((ValueError, TypeError)):
                writer.raw_chunk_size = invalid
            assert writer.raw_chunk_size == 0x4000
        options = mpq.FileCreateOptions.raw()
        options.flags = mpq.FILE_FLAG_COMPRESS | mpq.FILE_FLAG_IMPLODE
        with pytest.raises(mpq.LibmpqFormatError):
            writer.add("bad", b"x", options)
        writer.raw_chunk_size = 1
        writer.raw_chunk_size = chunk
        with writer.begin("data", 3) as member:
            with pytest.raises(mpq.LibmpqStateError):
                writer.raw_chunk_size = 0
            member.write(b"abc")
        with pytest.raises(mpq.LibmpqStateError):
            writer.raw_chunk_size = 0
        assert writer.raw_chunk_size == chunk
        writer.add("empty", b"")
    with (mpq.Archive.open_mpqe(path, code) if wrapped else mpq.Archive(path)) as archive:
        assert archive.raw_chunk_size == chunk
        with pytest.raises(AttributeError):
            archive.raw_chunk_size = 17
        assert archive["data"].read() == b"abc"
        assert archive["empty"].read() == b""
        assert archive["data"].verify(mpq.VERIFY_RAW_MD5) == 0


@pytest.mark.parametrize("wrapped", [False, True])
def test_raw_chunk_signing_and_patch(tmp_path, wrapped):
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    path, output = tmp_path / "raw-signing.mpq", tmp_path / "patch.mpq"
    create = (lambda: mpq.Writer.create_mpqe(path, code, version=mpq.ARCHIVE_VERSION_4)) if wrapped else lambda: mpq.Writer(path, version=mpq.ARCHIVE_VERSION_4)
    with create() as writer:
        with pytest.raises(mpq.LibmpqFormatError):
            writer.sign(WEAK_PRIVATE_KEY)
        writer.raw_chunk_size = 0
        with pytest.raises(mpq.LibmpqFormatError):
            writer.sign(b"invalid")
        writer.raw_chunk_size = 17
        writer.raw_chunk_size = 0
        writer.sign(WEAK_PRIVATE_KEY)
        with pytest.raises(mpq.LibmpqStateError):
            writer.raw_chunk_size = 17
        writer.add("signed", b"data")
    with (mpq.Archive.open_mpqe(path, code) if wrapped else mpq.Archive(path)) as archive:
        assert archive.raw_chunk_size == 0
        assert archive.signatures() == mpq.SIGNATURE_WEAK
        assert archive.verify(WEAK_PUBLIC_KEY) == 0
    base = tmp_path / "base.mpq"
    with mpq.Writer(base, version=mpq.ARCHIVE_VERSION_4, flags=mpq.ARCHIVE_CREATE_LISTFILE) as writer:
        writer.add("base", b"base")
    for chunk in (0, 1, 17, 0x4000, 0xffffffff):
        begin = (lambda: mpq.Patch.begin_mpqe(base, output, code)) if wrapped else lambda: mpq.Patch.begin(base, output)
        with begin() as patch:
            with pytest.raises(ValueError):
                patch.raw_chunk_size = -1
            assert patch.raw_chunk_size == 0x4000
            patch.raw_chunk_size = 1
            assert patch.raw_chunk_size == 1
            patch.raw_chunk_size = chunk
            assert patch.raw_chunk_size == chunk
            if chunk == 0:
                patch.sign(WEAK_PRIVATE_KEY)
                with pytest.raises(mpq.LibmpqStateError):
                    patch.raw_chunk_size = 17
                assert patch.raw_chunk_size == chunk
            patch.add_data("new", b"new")
            with pytest.raises(mpq.LibmpqStateError):
                patch.raw_chunk_size = 0
            assert patch.raw_chunk_size == chunk
            patch.finish()
        with (mpq.Archive.open_mpqe(output, code) if wrapped else mpq.Archive(output)) as archive:
            assert archive.raw_chunk_size == chunk
            assert archive["new"].read() == b"new"
    with mpq.Writer(tmp_path / "older.mpq") as writer:
        assert writer.raw_chunk_size == 0
        with pytest.raises(mpq.LibmpqFormatError):
            writer.raw_chunk_size = 17


def test_file_identity_single_native_call(tmp_path, monkeypatch):
    class SecondOrdinal:
        def __index__(self):
            return 1

    path = tmp_path / "ordinals.mpq"
    name = "voice.bin"
    raw_name = b"member-\xff"
    selectors = [(0xffff, 0xffff), (0, 0)]
    with mpq.Writer(path, max_files=16) as writer:
        for locale, platform in selectors:
            writer.add_data(name, b"voice", mpq.FileCreateOptions(0, 0, 0, locale, platform))
        writer.add_data(raw_name, b"raw")

    # The first name takes its home slot. Its second identity takes the next
    # slot. The native result uses ascending slot numbers, even after wrap.
    count, = struct.unpack_from("<I", path.read_bytes(), 24)
    if mpq.file_hash(name)[0] % count == count - 1:
        selectors.reverse()

    native = mpq.libmpq.libmpq__file_identity
    calls = []

    def spy(handle, encoded, ordinal, output):
        calls.append((encoded, ordinal))
        return native(handle, encoded, ordinal, output)

    def unexpected_lookup(*args):
        pytest.fail("identity lookup dispatched through a different native operation")

    with mpq.Archive(path) as archive:
        expected = tuple(
            mpq.FileIdentity(archive.file_number(name, locale=locale, platform=platform),
                             mpq.IDENTITY_CLASSIC, locale, platform)
            for locale, platform in selectors
        )
        raw_number = archive.file_number(raw_name)
        monkeypatch.setattr(mpq.libmpq, "libmpq__file_identity", spy)
        monkeypatch.setattr(mpq.libmpq, "libmpq__file_number", unexpected_lookup)
        monkeypatch.setattr(mpq.libmpq, "libmpq__file_number_from_identity", unexpected_lookup)

        for ordinal, index in enumerate((0, SecondOrdinal())):
            identity = archive.file_identity(name, index)
            assert type(identity) is mpq.FileIdentity
            assert identity == expected[ordinal]
            assert calls == [(b"voice.bin", ordinal)]
            calls.clear()
        assert archive.file_identity(raw_name, 0) == (
            mpq.FileIdentity(raw_number, mpq.IDENTITY_CLASSIC, 0, 0)
        )
        assert calls == [(raw_name, 0)]
        calls.clear()

        for missing_name, ordinal in ((name, 2), (name, 100), (name, 0xffffffff), ("absent", 0)):
            with pytest.raises(mpq.LibmpqNotFoundError) as caught:
                archive.file_identity(missing_name, ordinal)
            assert caught.value.code == mpq.ERROR_EXIST
            assert calls == [(missing_name.encode(), ordinal)]
            calls.clear()
        assert archive.variants(name) == expected
        assert calls == [(b"voice.bin", ordinal) for ordinal in range(3)]
        calls.clear()
        assert archive.variants("absent") == ()
        assert calls == [(b"absent", 0)]
        calls.clear()

        for invalid_name in ("voice.bin\x00suffix", b"voice.bin\x00suffix"):
            with pytest.raises(ValueError, match="NUL"):
                archive.file_identity(invalid_name, 0)
        for invalid in (-1, 0x100000000):
            with pytest.raises(ValueError, match="identity index"):
                archive.file_identity(name, invalid)
        for invalid in (1.0, "1", None):
            with pytest.raises(TypeError):
                archive.file_identity(name, invalid)
        assert not calls

    with pytest.raises(mpq.LibmpqStateError) as caught:
        archive.file_identity(name, 0)
    assert caught.value.code == mpq.ERROR_NOT_INITIALIZED
    with pytest.raises(mpq.LibmpqStateError):
        archive.variants(name)
    assert not calls


def test_file_identity_bet_only_and_format_error(monkeypatch):
    native = mpq.libmpq.libmpq__file_identity
    calls = []

    def spy(handle, encoded, ordinal, output):
        calls.append((encoded, ordinal))
        return native(handle, encoded, ordinal, output)

    with mpq.Archive(FIXTURES / "mpq-v3-features.mpq") as archive:
        monkeypatch.setattr(mpq.libmpq, "libmpq__file_identity", spy)
        assert archive.file_identity("zero.bin", 0) == mpq.FileIdentity(
            archive.file_number("zero.bin"), mpq.IDENTITY_BET, 0, 0
        )
        assert calls == [(b"zero.bin", 0)]
        calls.clear()
        # Exact extended identity lookup rejects names beyond the HET limit.
        name = b"x" * 265
        with pytest.raises(mpq.LibmpqFormatError) as caught:
            archive.file_identity(name, 0)
        assert caught.value.code == mpq.ERROR_FORMAT
        assert calls == [(name, 0)]


@pytest.mark.parametrize("version", [mpq.ARCHIVE_VERSION_1, mpq.ARCHIVE_VERSION_2])
@pytest.mark.parametrize("wrapped", [False, True])
def test_exact_identities(tmp_path, version, wrapped):
    path = tmp_path / "identities.mpq"
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    create = (lambda: mpq.Writer.create_mpqe(path, code, version=version)) if wrapped else lambda: mpq.Writer(path, version=version)
    options = mpq.FileCreateOptions(mpq.FILE_FLAG_COMPRESS | mpq.FILE_FLAG_ENCRYPTED | mpq.FILE_FLAG_KEY,
                                    mpq.COMPRESSION_ZLIB, mpq.COMPRESSION_ZLIB, 0, 0)
    with create() as writer:
        writer.add("dir/voice.bin", b"neutral", options)
        options.locale, options.platform = 0x409, 1
        writer.add("dir/voice.bin", b"localized", options)
    archive = mpq.Archive.open_mpqe(path, code) if wrapped else mpq.Archive(path)
    identities = archive.variants("dir/voice.bin")
    assert {(i.locale, i.platform) for i in identities} == {(0, 0), (0x409, 1)}
    assert all(i.flags == mpq.IDENTITY_CLASSIC for i in identities)
    with pytest.raises(AttributeError):
        identities[0].locale = 7
    assert archive.variants("absent") == ()
    assert archive.file_number("dir/voice.bin", locale=0x409, platform=1) in {i.file_number for i in identities}
    with pytest.raises(mpq.LibmpqNotFoundError):
        archive.file_number("dir/voice.bin", locale=0x409, platform=0)
    for invalid in (-1, 65536, 1.5):
        with pytest.raises((ValueError, TypeError)):
            archive.open_stream("dir/voice.bin", locale=invalid, platform=0)
    assert archive.file_number("dir/voice.bin") == archive["dir/voice.bin"].number
    with archive.open_stream("dir/voice.bin", locale=0, platform=0) as neutral:
        assert neutral.read() == b"neutral"
    for keyword in ({"locale": 0}, {"platform": 0}, {"locale": None, "platform": 0}):
        with pytest.raises(ValueError):
            archive.file_number("dir/voice.bin", **keyword)
        with pytest.raises(ValueError):
            archive.open_stream("dir/voice.bin", **keyword)
    with pytest.raises(ValueError):
        archive.open_stream(identities[0].file_number, locale=0, platform=0)
    with pytest.raises(TypeError):
        archive.file_number("dir/voice.bin", locale="0", platform=0)
    stream = archive.open_stream("dir/voice.bin", locale=0x409, platform=1)
    archive.close()
    assert stream.read() == b"localized"
    stream.close()


@pytest.mark.parametrize("version", [mpq.ARCHIVE_VERSION_3, mpq.ARCHIVE_VERSION_4])
@pytest.mark.parametrize("wrapped", [False, True])
def test_exact_extended_identity_sources(tmp_path, version, wrapped):
    path = tmp_path / "exact-source.mpq"
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    create = (lambda: mpq.Writer.create_mpqe(path, code, version=version, sector_size=512)) if wrapped else lambda: mpq.Writer(path, version=version, sector_size=512)
    options = mpq.FileCreateOptions(mpq.FILE_FLAG_COMPRESS | mpq.FILE_FLAG_ENCRYPTED | mpq.FILE_FLAG_KEY,
                                    mpq.COMPRESSION_ZLIB, mpq.COMPRESSION_ZLIB, 0, 0)
    payload = b"exact neutral content" * 100
    with create() as writer:
        writer.add("nested/content.bin", payload, options)
    wire = path.read_bytes()
    archive = mpq.Archive.open_mpqe(path, code) if wrapped else mpq.Archive.open_io(io.BytesIO(wire), len(wire))
    identities = archive.variants("nested/content.bin")
    assert len(identities) == 1 and identities[0].flags == mpq.IDENTITY_CLASSIC | mpq.IDENTITY_BET
    assert archive.file_number("nested/content.bin", locale=0, platform=0) == identities[0].file_number
    with pytest.raises(mpq.LibmpqNotFoundError):
        archive.file_number("nested/content.bin", locale=1, platform=0)
    stream = archive.open_stream("nested/content.bin", locale=0, platform=0)
    archive.close()
    assert stream.read() == payload
    stream.close()


@pytest.mark.parametrize("version", [mpq.ARCHIVE_VERSION_1, mpq.ARCHIVE_VERSION_2,
                                     mpq.ARCHIVE_VERSION_3, mpq.ARCHIVE_VERSION_4])
@pytest.mark.parametrize("wrapped", [False, True])
def test_exact_update_stages(tmp_path, version, wrapped):
    path = tmp_path / "exact-update.mpq"
    source = tmp_path / "replacement.bin"
    source.write_bytes(b"path bytes")
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    classic = version in (mpq.ARCHIVE_VERSION_1, mpq.ARCHIVE_VERSION_2)
    locale, platform = (0x409, 1) if classic else (0, 0)
    filetime = 0xfedcba9876543210
    options = mpq.FileCreateOptions.raw()
    options.locale, options.platform = locale, platform
    create = (mpq.Writer.create_mpqe(path, code, version=version, attributes=mpq.ATTRIBUTE_FILETIME)
              if wrapped else mpq.Writer(path, version=version, attributes=mpq.ATTRIBUTE_FILETIME))
    with create as writer:
        writer.add("voice", b"selected", options)
        if classic:
            writer.add("voice", b"neutral")
    original = path.read_bytes()
    begin = lambda: (mpq.Update.begin_mpqe(path, code) if wrapped else mpq.Update.begin(path))
    with begin() as update:
        update.timestamp("voice", filetime, locale=locale, platform=platform)
        update.replace_data("voice", b"bytes", locale=locale, platform=platform)
        for invalid in (-1, 65536, 1.5):
            with pytest.raises((ValueError, TypeError)):
                update.remove("voice", locale=invalid, platform=0)
        with pytest.raises(mpq.LibmpqNotFoundError):
            update.remove("voice", locale=locale, platform=platform + 1)
        update.rename("voice", "renamed", locale=locale, platform=platform)
        with pytest.raises(mpq.LibmpqNotFoundError):
            update.replace_data("voice", b"stale", locale=locale, platform=platform)
        update.replace_path("renamed", source, locale=locale, platform=platform)
        update.replace_ranges("renamed", [(0, bytearray(b"XY")), (1, memoryview(b"Z"))])
        update.replace_ranges("renamed", [(0, b"pa")], locale=locale, platform=platform)
        with pytest.raises(OverflowError):
            update.replace_ranges("renamed", [(1 << 63, b"X")])
        assert path.read_bytes() == original
        update.commit()
    with (mpq.Archive.open_mpqe(path, code) if wrapped else mpq.Archive(path)) as archive:
        with archive.open_stream("renamed", locale=locale, platform=platform) as stream:
            assert stream.read() == b"path bytes"
        selected = archive.file_number("renamed", locale=locale, platform=platform)
        assert archive[selected].attributes().filetime == filetime
        if classic:
            with archive.open_stream("voice", locale=0, platform=0) as stream:
                assert stream.read() == b"neutral"
            neutral = archive.file_number("voice", locale=0, platform=0)
            assert archive[neutral].attributes().filetime == 0
    committed = path.read_bytes()
    with begin() as update:
        update.remove("renamed", locale=locale, platform=platform)
    assert path.read_bytes() == committed
    with begin() as update:
        update.remove("renamed", locale=locale, platform=platform)
        update.commit()
    with (mpq.Archive.open_mpqe(path, code) if wrapped else mpq.Archive(path)) as archive:
        assert archive.variants("renamed") == ()


@pytest.mark.parametrize("version", [mpq.ARCHIVE_VERSION_1, mpq.ARCHIVE_VERSION_2,
                                     mpq.ARCHIVE_VERSION_3, mpq.ARCHIVE_VERSION_4])
@pytest.mark.parametrize("wrapped", [False, True])
def test_change_identity(tmp_path, version, wrapped):
    path = tmp_path / "change-identity.mpq"
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    classic = version <= mpq.ARCHIVE_VERSION_2
    create = (mpq.Writer.create_mpqe(path, code, version=version) if wrapped
              else mpq.Writer(path, version=version))
    with create as writer:
        options = mpq.FileCreateOptions.raw()
        options.flags = mpq.FILE_FLAG_ENCRYPTED | mpq.FILE_FLAG_KEY
        writer.add("voice", b"neutral", options)
        writer.add("other", b"other")
        if classic:
            options.locale, options.platform = 0x411, 2
            writer.add("voice", b"other locale", options)
    begin = lambda: (mpq.Update.begin_mpqe(path, code) if wrapped else mpq.Update.begin(path))
    original = path.read_bytes()
    with begin() as update:
        for operation in (
                lambda: update.remove("voice", locale=0),
                lambda: update.rename("voice", "other", platform=0),
                lambda: update.replace_data("voice", b"bad", locale=65536, platform=0),
                lambda: update.replace_path("voice", path, locale=0)):
            with pytest.raises(ValueError):
                operation()
        update.change_identity("voice", 0, 0, 0, 0)
        update.commit()
    assert path.read_bytes() == original
    with begin() as update:
        for invalid in (-1, 65536, 1.5):
            for index in range(4):
                selectors = [0, 0, 0, 0]
                selectors[index] = invalid
                with pytest.raises((ValueError, TypeError)):
                    update.change_identity("voice", *selectors)
        with pytest.raises(mpq.LibmpqNotFoundError):
            update.change_identity("voice", 0, 1, 0, 1)
        if classic:
            with pytest.raises(mpq.LibmpqNotFoundError):
                update.change_identity("voice", 0, 0, 0x411, 2)
        update.change_identity("voice", 0, 0, 0x409, 0)
        with pytest.raises(mpq.LibmpqNotFoundError):
            update.change_identity("voice", 0, 0, 0, 0)
        update.change_identity("voice", 0x409, 0, 0x409, 3)
        update.rename("voice", "renamed", locale=0x409, platform=3)
        update.change_identity("renamed", 0x409, 3, 0, 0)
        update.replace_data("renamed", b"updated", locale=0, platform=0)
        update.remove("other", locale=0, platform=0)
        update.change_identity("renamed", 0, 0, 65535, 65535)
        assert path.read_bytes() == original
        update.commit()
    with pytest.raises(mpq.LibmpqStateError):
        update.change_identity("renamed", 65535, 65535, 0, 0)
    with (mpq.Archive.open_mpqe(path, code) if wrapped else mpq.Archive(path)) as archive:
        with archive.open_stream("renamed", locale=65535, platform=65535) as stream:
            assert stream.read() == b"updated"
        if classic:
            with archive.open_stream("voice", locale=0x411, platform=2) as stream:
                assert stream.read() == b"other locale"
        assert archive.variants("other") == ()
    committed = path.read_bytes()
    with begin() as update:
        update.change_identity("renamed", 65535, 65535, 0, 0)
    assert path.read_bytes() == committed


@pytest.mark.parametrize("version", [mpq.ARCHIVE_VERSION_1, mpq.ARCHIVE_VERSION_2,
                                     mpq.ARCHIVE_VERSION_3, mpq.ARCHIVE_VERSION_4])
@pytest.mark.parametrize("wrapped", [False, True])
def test_transactional_timestamps(tmp_path, version, wrapped):
    path = tmp_path / "timestamp.mpq"
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    create = (mpq.Writer.create_mpqe(path, code, version=version, attributes=mpq.ATTRIBUTE_FILETIME)
              if wrapped else mpq.Writer(path, version=version, attributes=mpq.ATTRIBUTE_FILETIME))
    with create as writer:
        writer.add("voice", b"payload")
        writer.add("other", b"unchanged")
    original = path.read_bytes()
    begin = lambda: (mpq.Update.begin_mpqe(path, code) if wrapped else mpq.Update.begin(path))
    with begin() as update:
        assert update.timestamp("voice", 0) is None
        for invalid in (-1, 1 << 64):
            with pytest.raises(ValueError):
                update.timestamp("voice", invalid)
        for invalid in (1.5, "bad", None):
            with pytest.raises(TypeError):
                update.timestamp("voice", invalid)
        for selectors in [dict(locale=1), dict(platform=0), dict(locale=-1, platform=0),
                          dict(locale=0, platform=65536)]:
            with pytest.raises(ValueError):
                update.timestamp("voice", 1, **selectors)
        with pytest.raises(mpq.LibmpqNotFoundError):
            update.timestamp("voice", 1, locale=1, platform=0)
        update.timestamp("voice", 0xffffffffffffffff, locale=0, platform=0)
        update.replace_data("voice", b"new", locale=0, platform=0)
        assert path.read_bytes() == original
        update.commit()
    archive = mpq.Archive.open_mpqe(path, code) if wrapped else mpq.Archive(path)
    with archive:
        assert archive["voice"].attributes().filetime == 0xffffffffffffffff
        assert archive["other"].attributes().filetime == 0
        assert archive["voice"].read() == b"new"
    committed = path.read_bytes()
    with begin() as update:
        update.timestamp("voice", 1)
    assert path.read_bytes() == committed


@pytest.mark.parametrize("version", [0, 1, 2, 3])
@pytest.mark.parametrize("wrapped,embedded", [(False, False), (True, False), (False, True)])
def test_transactional_compaction(tmp_path, version, wrapped, embedded):
    path = tmp_path / "compact.mpq"
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    create = (mpq.Writer.create_mpqe(path, code, version=version, max_files=8, attributes=mpq.ATTRIBUTE_FILETIME)
              if wrapped else mpq.Writer(path, version=version, max_files=8, attributes=mpq.ATTRIBUTE_FILETIME))
    with create as writer:
        writer.add("voice", b"payload")
        writer.add("discard", bytes(32768))
    prefix = bytes(512) if embedded else b""
    if embedded:
        path.write_bytes(prefix + path.read_bytes())
    before = path.read_bytes()
    begin = lambda: mpq.Update.begin_mpqe(path, code) if wrapped else mpq.Update(path)
    with begin() as update:
        update.remove("discard")
        update.replace_data("voice", b"new")
        update.rename("voice", "renamed")
        update.change_identity("renamed", 0, 0, 1033, 2)
        update.timestamp("renamed", 17, locale=1033, platform=2)
        assert update.compact() is None
        assert update.compact() is None
        update.add_data("added", b"addition")
        assert update.compact() is None
        assert path.read_bytes() == before
        update.commit()
    opened = mpq.Archive.open_mpqe(path, code) if wrapped else mpq.Archive(path)
    with opened as archive:
        assert archive["renamed"].read() == b"new"
        assert archive["renamed"].attributes().filetime == 17
        assert "discard" not in archive
    after = path.read_bytes()
    assert after[:len(prefix)] == prefix
    with begin() as update:
        update.compact()
    assert path.read_bytes() == after
    with pytest.raises(mpq.LibmpqStateError):
        update.compact()


@pytest.mark.parametrize("version", [0, 1, 2, 3])
@pytest.mark.parametrize("embedded,wrapped", [(False, False), (True, False), (False, True)])
def test_transactional_signing(tmp_path, version, embedded, wrapped):
    path = tmp_path / "sign.mpq"
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    create = (mpq.Writer.create_mpqe(path, code, version=version, max_files=8,
                                   attributes=mpq.ATTRIBUTE_FILETIME)
              if wrapped else mpq.Writer(path, version=version, max_files=8,
                                         attributes=mpq.ATTRIBUTE_FILETIME))
    with create as writer:
        if version == 3:
            writer.raw_chunk_size = 0
        writer.add("voice", b"original")
    prefix = b"HM3W" + bytes(508) if embedded else b""
    if embedded:
        path.write_bytes(prefix + path.read_bytes())
    original = path.read_bytes()
    begin = lambda: mpq.Update.begin_mpqe(path, code) if wrapped else mpq.Update(path)
    private = bytearray(WEAK_PRIVATE_KEY)
    with begin() as update:
        update.replace_data("voice", b"replacement")
        update.timestamp("voice", 17)
        update.compact()
        with pytest.raises(mpq.LibmpqError):
            update.sign(private[:-1])
        assert update.sign(private) is None
        assert private == WEAK_PRIVATE_KEY
        if wrapped:
            with pytest.raises(mpq.LibmpqError):
                update.sign(STRONG_PRIVATE_KEY, mpq.SIGNATURE_STRONG)
        else:
            update.sign(STRONG_PRIVATE_KEY, mpq.SIGNATURE_STRONG)
        assert path.read_bytes() == original
        update.commit()
    opened = mpq.Archive.open_mpqe(path, code) if wrapped else mpq.Archive(path)
    with opened as archive:
        assert archive.verify(WEAK_PUBLIC_KEY) == 0
        assert archive.signatures() == (mpq.SIGNATURE_WEAK if wrapped else
                                        mpq.SIGNATURE_WEAK | mpq.SIGNATURE_STRONG)
        if not wrapped:
            assert archive.verify(STRONG_PUBLIC_KEY, mpq.SIGNATURE_STRONG) == 0
        assert archive["voice"].read() == b"replacement"
        assert archive["voice"].attributes().filetime == 17
    if embedded:
        assert path.read_bytes()[:512] == prefix
    committed = path.read_bytes()
    with begin() as update:
        update.sign(private)
    assert path.read_bytes() == committed
    with pytest.raises(mpq.LibmpqStateError):
        update.sign(private)


@pytest.mark.parametrize("failure", [False, True])
def test_update_sign_clears_native_key_copy(tmp_path, monkeypatch, failure):
    path = tmp_path / "sign-key-copy.mpq"
    with mpq.Writer(path) as writer:
        writer.add("voice", b"payload")
    captured = []
    key = bytearray(WEAK_PRIVATE_KEY)

    def signer(handle, signature_type, pointer, size):
        assert handle and signature_type == mpq.SIGNATURE_WEAK
        assert size == len(key) and bytes(pointer) == key
        captured.append(pointer)
        if failure:
            raise RuntimeError("synthetic signer failure")

    monkeypatch.setattr(mpq.libmpq, "libmpq__update_sign", signer)
    with mpq.Update(path) as update:
        if failure:
            with pytest.raises(RuntimeError, match="synthetic signer failure"):
                update.sign(key)
        else:
            update.sign(key)
    assert key == WEAK_PRIVATE_KEY
    assert len(captured) == 1 and bytes(captured[0]) == bytes(len(key))


def test_member_verification_coverage():
    with mpq.Archive(FIXTURES / "mpq-v1-features.mpq") as archive:
        entry = archive["overview.txt"]
        for flags in range(16):
            result = entry.verify_result(flags, filename="overview.txt")
            assert result.checked == flags & 6
            assert result.unavailable == flags & 9
            assert result.mismatches == 0
            assert entry.verify(flags) == result.mismatches
        result = archive["(attributes)"].verify_result(6)
        assert result == mpq.VerificationResult(0, 6, 0)
        with pytest.raises(mpq.LibmpqNotFoundError):
            entry.verify_result(filename="sparse.txt")
        with pytest.raises(ValueError):
            entry.verify_result(-1)
        with pytest.raises(ValueError):
            entry.verify_result(filename="bad\0name")
        with pytest.raises(mpq.LibmpqFormatError):
            entry.verify_result(16)


@pytest.mark.parametrize("version", range(4))
def test_verification_filename_key_context(tmp_path, version):
    path = tmp_path / "verify-key.mpq"
    payload = bytes((i * 71 + i // 3) % 256 for i in range(64))
    storage = mpq.FileCreateOptions(
        mpq.FILE_FLAG_SINGLE | mpq.FILE_FLAG_ENCRYPTED | mpq.FILE_FLAG_KEY, 0, 0, 1033, 2)
    with mpq.Writer(path, version=version, max_files=4,
                    attributes=mpq.ATTRIBUTE_CRC32 | mpq.ATTRIBUTE_MD5) as writer:
        writer.add("voice.bin", payload, storage)
    with mpq.Archive(path) as archive:
        entry = archive[archive.file_number("voice.bin", locale=1033, platform=2)]
        with pytest.raises(mpq.LibmpqDecryptError):
            entry.verify_result(6)
        assert entry.verify_result(6, filename="voice.bin") == mpq.VerificationResult(6, 0, 0)
        with pytest.raises(mpq.LibmpqDecryptError):
            entry.verify(6)


@pytest.mark.parametrize("version", range(1, 5))
def test_archive_verification_result(version):
    source = io.BytesIO((FIXTURES / f"mpq-v{version}-features.mpq").read_bytes())
    with mpq.Archive.open_io(source, source.getbuffer().nbytes) as archive:
        result = archive.verify_ex()
        assert result.checked | result.unavailable == mpq.VERIFY_METADATA_ALL
        assert not result.checked & result.unavailable
        assert result.mismatches == 0
        if version < 4:
            assert result.checked == 0
        else:
            assert result.checked & mpq.VERIFY_METADATA_HEADER_MD5
            source.getbuffer()[192] ^= 1
            changed = archive.verify_ex(mpq.VERIFY_METADATA_HEADER_MD5)
            assert changed == mpq.VerificationResult(0x100, 0, 0x100)
            source.getbuffer()[192] ^= 1
        assert archive.verify_ex(0) == mpq.VerificationResult(0, 0, 0)
        with pytest.raises(mpq.LibmpqFormatError):
            archive.verify_ex(mpq.VERIFY_ALL)
        with pytest.raises(ValueError):
            archive.verify_ex(-1)
    with pytest.raises(mpq.LibmpqError):
        archive.verify_ex()


def test_archive_metadata_independent_md5():
    wire = (FIXTURES / "mpq-v4-features.mpq").read_bytes()
    assert hashlib.md5(wire[:192]).digest() == wire[192:208]
    hash_low, block_low = struct.unpack_from("<II", wire, 16)
    high_offset, hash_high, block_high = struct.unpack_from("<QHH", wire, 32)
    bet, het = struct.unpack_from("<QQ", wire, 52)
    positions = [hash_low | hash_high << 32, block_low | block_high << 32,
                 high_offset, het, bet]
    sizes = struct.unpack_from("<QQQQQ", wire, 68)
    reference_offsets = [128, 112, 144, 176, 160]
    expected_checked = mpq.VERIFY_METADATA_HEADER_MD5
    raw_size = struct.unpack_from("<I", wire, 108)[0]
    for index, (position, size, reference) in enumerate(zip(positions, sizes, reference_offsets)):
        expected = wire[reference:reference + 16]
        if position and expected != bytes(16):
            assert hashlib.md5(wire[position:position + size]).digest() == expected
            expected_checked |= 0x200 << index
        if index >= 3 and position and size and raw_size:
            for chunk_index, offset in enumerate(range(0, size, raw_size)):
                actual = hashlib.md5(wire[position + offset:position + min(size, offset + raw_size)]).digest()
                reference = position + size + 16 * chunk_index
                assert actual == wire[reference:reference + 16]
            expected_checked |= 0x4000 << (index - 3)
    with mpq.Archive.open_io(io.BytesIO(wire), len(wire)) as archive:
        assert archive.verify_ex() == mpq.VerificationResult(
            expected_checked, mpq.VERIFY_METADATA_ALL & ~expected_checked, 0)
    # Explicit optional hi-block storage yields all eight available checks.
    extended = bytearray(wire)
    high_position = len(extended)
    high_table = bytes(2 * struct.unpack_from("<I", wire, 28)[0])
    extended.extend(high_table)
    struct.pack_into("<Q", extended, 32, high_position)
    struct.pack_into("<Q", extended, 44, len(extended))
    struct.pack_into("<Q", extended, 84, len(high_table))
    extended[144:160] = hashlib.md5(high_table).digest()
    extended[192:208] = hashlib.md5(extended[:192]).digest()
    with mpq.Archive.open_io(io.BytesIO(extended), len(extended)) as archive:
        assert archive.verify_ex() == mpq.VerificationResult(mpq.VERIFY_METADATA_ALL, 0, 0)


def test_key_flag_constant():
    assert mpq.FILE_FLAG_KEY == 0x00020000


@pytest.mark.parametrize("version", range(4))
def test_transaction_filename_provenance(tmp_path, version):
    path = tmp_path / "provenance.mpq"
    payload = bytes((i * 71 + i // 3) & 255 for i in range(403))
    flags = mpq.FILE_FLAG_SINGLE | mpq.FILE_FLAG_ENCRYPTED | mpq.FILE_FLAG_KEY
    options = mpq.FileCreateOptions(flags, 0, 0, 0, 0)
    with mpq.Writer(path, version=version, max_files=8,
                    attributes=mpq.ATTRIBUTE_FILETIME) as writer:
        writer.add("voice", payload, options)
        writer.add("other", b"unchanged")
    with mpq.Update.begin(path) as update:
        update.replace_data("voice", payload, options)
        update.change_identity("other", 0, 0, 1033, 2)
        update.rename("voice", "renamed", locale=0, platform=0)
        update.timestamp("other", 17, locale=1033, platform=2)
        update.compact()
        update.commit()
    with mpq.Archive(path) as archive:
        with archive.open_stream("renamed", locale=0, platform=0) as stream:
            assert stream.read() == payload


@pytest.mark.parametrize("version", range(4))
@pytest.mark.parametrize("wrapped", [False, True])
def test_compact_external_filenames(tmp_path, version, wrapped):
    path = tmp_path / "compact-names.mpq"
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    payload = bytes((i * 71 + i // 3) & 255 for i in range(403))
    options = mpq.FileCreateOptions(
        mpq.FILE_FLAG_SINGLE | mpq.FILE_FLAG_ENCRYPTED | mpq.FILE_FLAG_KEY, 0, 0, 1033, 2)
    create = (mpq.Writer.create_mpqe(path, code, version=version, max_files=8,
                                    attributes=mpq.ATTRIBUTE_FILETIME | mpq.ATTRIBUTE_MD5)
              if wrapped else mpq.Writer(path, version=version, max_files=8,
                                        attributes=mpq.ATTRIBUTE_FILETIME | mpq.ATTRIBUTE_MD5))
    with create as writer:
        writer.add("obsolete", bytes(32768))
        writer.add("voice", payload, options)
    begin = lambda: (mpq.Update.begin_mpqe(path, code) if wrapped else mpq.Update.begin(path))
    with begin() as preparation:
        preparation.remove("obsolete")
        preparation.commit()
    before = path.read_bytes()
    update = begin()
    try:
        for empty in [None, []]:
            with pytest.raises(mpq.LibmpqDecryptError):
                update.compact(empty)
        for scalar in ["voice", b"voice", Path("voice")]:
            with pytest.raises(TypeError):
                update.compact(scalar)
        for invalid in [["voice", None], ["voice", ""], ["voice", "bad\0name"]]:
            with pytest.raises(ValueError):
                update.compact(invalid)
        with pytest.raises(TypeError):
            update.compact(["voice", object()])
        with pytest.raises(mpq.LibmpqNotFoundError):
            update.compact(["voice", "missing"])
        # A failed late element must not have installed the preceding valid name.
        with pytest.raises(mpq.LibmpqDecryptError):
            update.compact()
        class Once:
            calls = 0
            def __iter__(self):
                self.calls += 1
                assert self.calls == 1
                yield Path("voice")
                yield "VOICE"
                yield b"voice"
        names = Once()
        assert update.compact(names) is None
        assert names.calls == 1
        del names
        gc.collect()
        assert update.compact([]) is None
        assert update.compact() is None
        assert path.read_bytes() == before
        update.commit()
        with pytest.raises(mpq.LibmpqStateError):
            update.compact(["voice"])
    finally:
        update.close()
    with (mpq.Archive.open_mpqe(path, code) if wrapped else mpq.Archive(path)) as archive:
        with archive.open_stream("voice", locale=1033, platform=2) as stream:
            assert stream.read() == payload
        number = archive.file_number("voice", locale=1033, platform=2)
        result = archive[number].verify_result(mpq.VERIFY_FILE_MD5, filename="voice")
        assert result == mpq.VerificationResult(mpq.VERIFY_FILE_MD5, 0, 0)


@pytest.mark.parametrize("version", range(4))
@pytest.mark.parametrize("wrapped", [False, True])
def test_oversized_single_writer(tmp_path, version, wrapped):
    path = tmp_path / "single.mpq"
    source = tmp_path / "input.bin"
    payload = bytes((i * 71 + i // 3) & 255 for i in range(9001))
    source.write_bytes(payload)
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    options = mpq.FileCreateOptions(
        mpq.FILE_FLAG_SINGLE | mpq.FILE_FLAG_ENCRYPTED | mpq.FILE_FLAG_KEY |
        mpq.FILE_FLAG_COMPRESS, mpq.COMPRESSION_ZLIB, mpq.COMPRESSION_ZLIB)
    create = (mpq.Writer.create_mpqe(path, code, version=version, max_files=8)
              if wrapped else mpq.Writer(path, version=version, max_files=8))
    with create as writer:
        writer.add("data", payload, options)
        writer.add_path("path", source, options)
        stream = writer.begin("incremental", len(payload), options)
        for position in range(0, len(payload), 3):
            stream.write(payload[position:position + 3])
        with pytest.raises(ValueError):
            stream.write(b"excess")
        stream.finish()
        with pytest.raises(mpq.LibmpqStateError):
            stream.write(b"")
    with (mpq.Archive.open_mpqe(path, code) if wrapped else mpq.Archive(path)) as archive:
        for name in ["data", "path", "incremental"]:
            with archive.open_stream(name) as stream:
                assert stream.read() == payload
            number = archive.file_number(name)
            assert archive[number].blocks == 1
    # Incomplete finish consumes the stream and retains native SIZE translation.
    writer = mpq.Writer(tmp_path / "incomplete.mpq", version=version, max_files=4)
    stream = writer.begin("incomplete", 9001, options)
    stream.write(payload[:4097])
    with pytest.raises(mpq.LibmpqSizeError):
        stream.finish()
    if version == mpq.ARCHIVE_VERSION_4:
        with pytest.raises(mpq.LibmpqSizeError):
            writer.close()
    else:
        writer.close()


def test_create_io_writer_lifetime():
    class Sink:
        def __init__(self):
            self.data = io.BytesIO()
            self.flushes = 0

        def write_at(self, offset, data):
            self.data.seek(offset)
            return self.data.write(data)

        def read_at(self, offset, size):
            self.data.seek(offset)
            return self.data.read(size)

        def flush(self):
            self.flushes += 1

    sink = Sink()
    payload = b"callback storage" * 1000
    with mpq.Writer.create_io(sink, version=mpq.ARCHIVE_VERSION_4) as archive:
        with archive.begin("hello", len(payload)) as writer:
            writer.write(payload[:4321])
            writer.write(payload[4321:])
    assert sink.flushes == 1
    wire = sink.data.getvalue()
    with mpq.Archive.open_io(io.BytesIO(wire), len(wire)) as archive:
        with archive.open_stream("hello") as reader:
            assert reader.read() == payload

    sink = Sink()
    archive = mpq.Writer.create_io(sink)
    member = archive.begin("incomplete", 100)
    with pytest.raises(mpq.LibmpqError) as caught:
        archive.close()
    assert caught.value.code == mpq.ERROR_SIZE
    member.close()
    archive.close()
    assert sink.flushes == 0

    class FailingSink(Sink):
        def flush(self):
            raise OSError("controlled flush failure")

    archive = mpq.Writer.create_io(FailingSink())
    with pytest.raises(mpq.LibmpqError) as caught:
        archive.close()
    assert caught.value.code == mpq.ERROR_CLOSE
    archive.close()


def test_create_mpqe_io_writer_lifetime():
    code = bytearray(b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001")
    expected_code = bytes(code)
    batch = 16 * 1024
    payload = b"MPQE positioned output" * 4000

    class Sink:
        def __init__(self, fault=None):
            self.data = io.BytesIO()
            self.writes = self.flushes = 0
            self.fault = fault
            self.transfers = []

        def write_at(self, offset, data):
            self.writes += 1
            self.transfers.append((offset, len(data)))
            self.data.seek(offset)
            if self.fault == "write" and self.writes == 2:
                return self.data.write(data[:1])
            return self.data.write(data)

        def flush(self):
            self.flushes += 1
            if self.fault == "flush":
                raise OSError("controlled flush failure")

    sink = Sink()
    with pytest.raises(mpq.LibmpqError) as caught:
        mpq.Writer.create_mpqe_io(sink, expected_code[:-1])
    assert caught.value.code == mpq.ERROR_DECRYPT
    assert sink.writes == sink.flushes == 0

    with mpq.Writer.create_mpqe_io(sink, code, version=mpq.ARCHIVE_VERSION_4) as archive:
        code[:] = b"x" * len(code)
        with archive.begin("hello", len(payload)) as writer:
            writer.write(payload[:4321])
            writer.write(payload[4321:])
        assert sink.writes == sink.flushes == 0
    assert sink.flushes == 1
    wire = sink.data.getvalue()
    assert sink.writes == (len(wire) + batch - 1) // batch
    assert sink.transfers == [
        (at, min(batch, len(wire) - at)) for at in range(0, len(wire), batch)
    ]
    assert not wire.startswith(b"MPQ\x1a")
    with mpq.Archive.open_mpqe_io(io.BytesIO(wire), len(wire), expected_code) as archive:
        with archive.open_stream("hello") as reader:
            assert reader.read() == payload

    for fault, error, flushes in (("write", mpq.ERROR_WRITE, 0), ("flush", mpq.ERROR_CLOSE, 1)):
        sink = Sink(fault)
        archive = mpq.Writer.create_mpqe_io(sink, expected_code)
        if fault == "write":
            archive.add("large", payload)
        with pytest.raises(mpq.LibmpqError) as caught:
            archive.close()
        assert caught.value.code == error
        writes = sink.writes
        archive.close()
        assert sink.writes == writes and sink.flushes == flushes
        if fault == "write":
            assert writes == 2 and len(sink.data.getvalue()) == batch + 1
            assert sink.transfers == [(0, batch), (batch, batch)]


def test_numeric_width_archive_and_stream(tmp_path, monkeypatch):
    class Integer:
        def __init__(self, value):
            self.value = value

        def __index__(self):
            return self.value

    path = tmp_path / "numeric.mpq"
    with mpq.Writer(path) as writer:
        writer.add("data", b"abcdef")
    wire = b"\0" * 512 + path.read_bytes()
    path.write_bytes(wire)
    for offset in (-1, Integer(512)):
        with mpq.Archive.open_io(io.BytesIO(wire), Integer(len(wire)), offset) as archive:
            assert archive.offset == 512
            member = archive["data"]
            assert member.block_size_unpacked(Integer(0)) == 6
            with archive.open_stream(Integer(member.number)) as stream:
                assert stream.seek(Integer(-2), Integer(os.SEEK_END)) == 4
                assert stream.seek(-1, os.SEEK_CUR) == 3
                for invalid in (1 << 63, -(1 << 63) - 1, 1 << 64):
                    with pytest.raises(ValueError):
                        stream.seek(invalid)
                for edge in (-(1 << 63), (1 << 63) - 1):
                    with pytest.raises(mpq.LibmpqIOError) as caught:
                        stream.seek(edge)
                    assert caught.value.code == mpq.ERROR_SEEK
                with pytest.raises(ValueError):
                    stream.seek(0, 1 << 32)
                with pytest.raises(TypeError):
                    stream.seek(1.5)
                with pytest.raises(ValueError):
                    stream.read(1 << 64)
                assert stream.tell() == 3
                assert stream.read() == b"def"
            for block in (-1, 1 << 32):
                with pytest.raises(ValueError):
                    member.block_size_unpacked(block)
            with pytest.raises(TypeError):
                member.block_size_unpacked(0.0)
            with pytest.raises(mpq.LibmpqError):
                member.block_size_unpacked(0xffffffff)
            with pytest.raises(ValueError):
                mpq.File(archive, 1 << 32)
            with pytest.raises(IndexError):
                archive.open_stream(1 << 32)
            member.number += 1 << 32
            with pytest.raises(ValueError):
                member.read()

    def unexpected(*args):
        pytest.fail("invalid input reached the native opener")

    with monkeypatch.context() as patch:
        for name in ("archive_open", "archive_open_mpqe", "archive_open_io", "archive_open_mpqe_io"):
            patch.setattr(mpq.libmpq, "libmpq__" + name, unexpected)
        for open_at in (
            lambda offset: mpq.Archive(path, offset),
            lambda offset: mpq.Archive.open_mpqe(path, b"", offset),
            lambda offset: mpq.Archive.open_io(io.BytesIO(wire), len(wire), offset),
            lambda offset: mpq.Archive.open_mpqe_io(io.BytesIO(wire), len(wire), b"", offset),
        ):
            with pytest.raises(ValueError):
                open_at(1 << 64)
            with pytest.raises(TypeError):
                open_at(0.0)
        for size in (-1, 1 << 63):
            with pytest.raises(ValueError):
                mpq.Archive.open_io(io.BytesIO(wire), size)


@pytest.mark.parametrize("options", [mpq.ArchiveCreateOptions, mpq.FileCreateOptions])
def test_numeric_width_option_fields(options):
    for position, (name, field_type) in enumerate(options._fields_):
        limit = 1 << (ctypes.sizeof(field_type) * 8)
        value = options(**{name: limit - 1})
        assert getattr(value, name) == limit - 1
        for invalid in (-1, limit):
            with pytest.raises(ValueError):
                setattr(value, name, invalid)
            with pytest.raises(ValueError):
                options(*([0] * position), **{name: invalid})
            with pytest.raises(ValueError):
                options(*([0] * position + [invalid]))
            assert getattr(value, name) == limit - 1
        with pytest.raises(TypeError):
            options(**{name: 0.0})


def test_numeric_width_mutations(tmp_path):
    path = tmp_path / "numeric-mutations.mpq"
    with pytest.raises(ValueError):
        mpq.Writer(path, version=1 << 32)
    assert not path.exists()

    with mpq.Writer(path, attributes=mpq.ATTRIBUTE_FILETIME | mpq.ATTRIBUTE_CRC32) as archive:
        for size in (-1, 1 << 63, 1 << 64):
            with pytest.raises(ValueError):
                archive.begin("unintended", size)
        with pytest.raises(ValueError):
            archive.sign(b"", (1 << 32) + mpq.SIGNATURE_WEAK)
        with pytest.raises(ValueError):
            archive.raw_chunk_size = 1 << 32
        options = mpq.FileCreateOptions(locale=0xffff, platform=0xffff)
        with archive.begin("data", 3, options) as writer:
            with pytest.raises(ValueError):
                writer.timestamp(1 << 64)
            writer.timestamp(1 << 63)
            writer.write(b"abc")

    with mpq.Archive(path) as archive:
        assert "unintended" not in archive
        assert archive["data"].attributes().filetime == 1 << 63
        assert archive["data"].verify(mpq.VERIFY_FILE_CRC32) == 0
        with pytest.raises(ValueError):
            archive["data"].verify(1 << 32)
        with pytest.raises(ValueError):
            archive.verify(b"", (1 << 32) + mpq.SIGNATURE_WEAK)
    original = path.read_bytes()
    with mpq.Update(path) as update:
        with pytest.raises(ValueError):
            update.replace_data("data", b"wrong", locale=0x1ffff, platform=0xffff)
        for offset in (1 << 63, -(1 << 63) - 1):
            with pytest.raises(OverflowError):
                update.replace_ranges("data", [(0, b"x"), (offset, b"a")],
                                      locale=0xffff, platform=0xffff)
        assert path.read_bytes() == original
        update.timestamp("data", 0xffffffffffffffff, locale=0xffff, platform=0xffff)
        update.replace_ranges("data", [(2, b"z")], locale=0xffff, platform=0xffff)
        update.commit()
    with mpq.Archive(path) as archive:
        assert archive["data"].attributes().filetime == 0xffffffffffffffff
        with archive.open_stream("data", locale=0xffff, platform=0xffff) as stream:
            assert stream.read() == b"abz"

    assert mpq.archive_compression_allowed(0, mpq.COMPRESSION_ZLIB)
    assert not mpq.archive_compression_allowed(0, 0xffffffff)
    for args in ((1 << 32, 0, 0), (0, -1, 0), (0, 0, 1 << 31), (0, 0, -(1 << 31) - 1)):
        with pytest.raises(ValueError):
            mpq.archive_compression_allowed(*args)
    with pytest.raises(ValueError):
        mpq.strerror(1 << 32)


def test_numeric_width_callback_counts():
    # size_t counts are normally derived from real buffers and containers.
    # Probe their endpoints without constructing a buffer of that size.
    limit = 1 << (ctypes.sizeof(ctypes.c_size_t) * 8)
    assert mpq._checked_int(limit - 1, ctypes.c_size_t, "test size") == limit - 1
    with pytest.raises(ValueError):
        mpq._checked_int(limit, ctypes.c_size_t, "test size")

    class Sink:
        def __init__(self):
            self.calls = []

        def write_at(self, offset, data):
            self.calls.append((offset, data))
            return len(data) + limit

        def read_at(self, offset, size):
            self.calls.append((offset, size))
            return b""

    sink = Sink()
    state = mpq._SinkState(sink)
    buffer = (ctypes.c_uint8 * 1)(42)
    assert state.read(None, -1, buffer, 1) == mpq.ERROR_READ
    assert state.write(None, -1, buffer, 1) == mpq.ERROR_WRITE
    assert state.write(None, (1 << 63) - 1, buffer, 1) == mpq.ERROR_WRITE
    assert not sink.calls
    assert state.write(None, 0, buffer, 1) == mpq.ERROR_WRITE
    assert sink.calls == [(0, b"*")]

    class FloatCount:
        def write_at(self, offset, data):
            return float(len(data))

    with pytest.raises(mpq.LibmpqIOError) as caught:
        with mpq.Writer.create_io(FloatCount()) as archive:
            archive.add("data", b"a")
    assert caught.value.code == mpq.ERROR_WRITE


def test_explicit_block_size_alias(monkeypatch):
    native = mpq.libmpq.libmpq__block_size_unpacked
    calls = []

    def count_query(archive, number, block, output):
        calls.append(block)
        return native(archive, number, block, output)

    monkeypatch.setattr(mpq.libmpq, "libmpq__block_size_unpacked", count_query)
    with mpq.Archive(FIXTURES / "mpq-v1-features.mpq") as archive:
        member = archive["encrypted-compress.txt"]
        assert 0 < member.block_size_packed(0) < 4096
        for size in (member.block_size_unpacked, member.block_size):
            calls.clear()
            assert size(0) == 4096
            assert size(block=1) == 1760
            assert calls == [0, 1]
            with pytest.raises(mpq.LibmpqNotFoundError) as caught:
                size(2)
            assert caught.value.code == mpq.ERROR_EXIST
            assert calls == [0, 1, 2]
            with pytest.raises(ValueError):
                size(1 << 32)
            assert calls == [0, 1, 2]

    for size in (member.block_size_unpacked, member.block_size):
        with pytest.raises(mpq.LibmpqNotFoundError) as caught:
            size(0)
        assert caught.value.code == mpq.ERROR_EXIST

    with mpq.Archive(FIXTURES / "mpq-v4-features.mpq") as archive:
        for name, expected in (("overview.txt", 27), ("empty.bin", 0)):
            entry = archive[name]
            assert entry.flags & mpq.FILE_FLAG_SINGLE
            assert entry.block_size_unpacked(0) == entry.block_size(0) == expected


@pytest.mark.parametrize("wrapped", [False, True])
def test_source_callback_status(wrapped):
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"
    wire = (FIXTURES / ("mpq-v1-features.mpqe" if wrapped else "mpq-v1-features.mpq")).read_bytes()

    class Source(io.BytesIO):
        fail = False
        restore_failure = False
        error = None

        def read(self, size):
            self.fail = True
            if self.error is not None:
                raise self.error
            return super().read(size - 1)

        def seek(self, offset, whence=0):
            if self.fail and self.restore_failure:
                raise OSError("cursor restore failed")
            return super().seek(offset, whence)

    for error, expected in (
        (mpq.LibmpqCallbackError(mpq.ERROR_MALLOC), mpq.ERROR_MALLOC),
        (mpq.LibmpqMemoryError(mpq.ERROR_MALLOC, "ordinary exception"), mpq.ERROR_READ),
        (None, mpq.ERROR_READ),
    ):
        source = Source(wire)
        source.seek(7)
        source.error = error
        source.restore_failure = isinstance(error, mpq.LibmpqCallbackError)
        with pytest.raises(mpq.LibmpqError) as caught:
            if wrapped:
                mpq.Archive.open_mpqe_io(source, len(wire), code, offset=0)
            else:
                mpq.Archive.open_io(source, len(wire), offset=0)
        assert caught.value.code == expected
        assert not source.closed
        assert source.fail
        if not source.restore_failure:
            assert source.tell() == 7


@pytest.mark.parametrize("wrapped,phase", [
    (False, "write"), (True, "write"), (False, "read"), (False, "flush"), (True, "flush"),
])
def test_sink_callback_status(wrapped, phase):
    code = b"LIBMPQ-MPQE-TEST-AUTH-CODE-00001"

    class Sink:
        data = bytearray()
        events = []
        active = False

        def visit(self, operation):
            self.events.append(operation)
            if self.active and phase == operation:
                raise mpq.LibmpqCallbackError(mpq.ERROR_MALLOC)

        def write_at(self, offset, payload):
            self.visit("write")
            end = offset + len(payload)
            if end > len(self.data):
                self.data.extend(bytes(end - len(self.data)))
            self.data[offset:end] = payload
            return len(payload)

        def read_at(self, offset, size):
            assert not wrapped
            self.visit("read")
            return self.data[offset:offset + size]

        def flush(self):
            self.visit("flush")

    sink = Sink()
    writer = mpq.Writer.create_mpqe_io(sink, code) if wrapped else mpq.Writer.create_io(sink)
    writer.add("payload", b"payload")
    if phase == "read":
        writer.sign(WEAK_PRIVATE_KEY)
    if wrapped:
        assert sink.events == []
    sink.active = True
    if phase == "write" and not wrapped:
        with pytest.raises(mpq.LibmpqMemoryError):
            writer.add("failed", b"more bytes")
        events = list(sink.events)
        sink.active = False
        with pytest.raises(mpq.LibmpqMemoryError):
            writer.add("retry", b"more bytes")
        assert sink.events == events
    with pytest.raises(mpq.LibmpqMemoryError) as caught:
        writer.close()
    assert caught.value.code == mpq.ERROR_MALLOC
    assert sink.events[-1] == phase
    if phase != "flush":
        assert "flush" not in sink.events
    elif wrapped:
        assert "read" not in sink.events
    events = list(sink.events)
    writer.close()
    assert sink.events == events


def test_callback_status_domain_and_short_write():
    for status in range(mpq.ERROR_UNPACK, mpq.ERROR_OPEN + 1):
        assert mpq.LibmpqCallbackError(status).code == status
    for status in (0, 1, mpq.ERROR_UNPACK - 1, 1 << 32):
        with pytest.raises(ValueError):
            mpq.LibmpqCallbackError(status)
    with pytest.raises(TypeError):
        mpq.LibmpqCallbackError(-6.0)

    invalid = mpq.LibmpqCallbackError(mpq.ERROR_MALLOC)
    invalid.code = 0

    class FailingSink:
        def write_at(self, offset, data):
            if error is not None:
                raise error
            return len(data) - 1

    for error in (None, OSError("ordinary write failure"), invalid):
        with pytest.raises(mpq.LibmpqIOError) as caught:
            with mpq.Writer.create_io(FailingSink()) as writer:
                writer.add("payload", b"payload")
        assert caught.value.code == mpq.ERROR_WRITE


@pytest.mark.parametrize("as_bytes", [False, True])
def test_nul_path_rejection(tmp_path, monkeypatch, as_bytes):
    path = tmp_path / "prefix.mpq"
    output = tmp_path / "patch.mpq"
    with mpq.Writer(path) as writer:
        writer.add("member", b"original")
    original = path.read_bytes()
    output.write_bytes(original)
    bad_path = str(path) + "\0ignored"
    bad_output = str(output) + "\0ignored"
    if as_bytes:
        bad_path, bad_output = bad_path.encode(), bad_output.encode()
    code = b"A" * 32

    with mpq.Update.begin(path) as update, mpq.Patch.begin(path, tmp_path / "stage.mpq") as patch:
        operations = [
            ("archive_open", lambda: mpq.Archive.open(bad_path)),
            ("archive_open_mpqe", lambda: mpq.Archive.open_mpqe(bad_path, code)),
            ("archive_create", lambda: mpq.Writer(bad_path)),
            ("archive_create_mpqe", lambda: mpq.Writer.create_mpqe(bad_path, code)),
            ("update_begin", lambda: mpq.Update.begin(bad_path)),
            ("patch_begin", lambda: mpq.Patch.begin(path, bad_output)),
            ("patch_begin_mpqe", lambda: mpq.Patch.begin_mpqe(path, bad_output, code)),
            ("update_replace_path_identity",
             lambda: update.replace_path("member", bad_path, locale=0, platform=0)),
            ("patch_add_path", lambda: patch.add_path("added", bad_path)),
            ("patch_replace_path", lambda: patch.replace_path("member", bad_path)),
        ]
        for native, call in operations:
            with monkeypatch.context() as guard:
                guard.setattr(mpq.libmpq, "libmpq__" + native,
                              lambda *args: pytest.fail("reached native operation"))
                with pytest.raises(ValueError, match="native string.*NUL"):
                    call()
    assert path.read_bytes() == output.read_bytes() == original


def test_nul_native_names(tmp_path, monkeypatch):
    path = tmp_path / "names.mpq"
    name, bad_name = b"raw-\xff", b"raw-\xff\0ignored"
    with mpq.Writer(path) as writer:
        with pytest.raises(ValueError, match="native string.*NUL"):
            writer.begin(bad_name, 0)
        writer.add(name, b"original")
    wire = path.read_bytes()

    with mpq.Archive.open(path) as archive, mpq.Update.begin(path) as update:
        number = archive.file_number(name, locale=0, platform=0)
        member = archive[number]
        assert member.read() == b"original"
        assert member.verify_result(filename=None).mismatches == 0
        operations = [
            ("file_hash", lambda: mpq.file_hash(bad_name)),
            ("file_number", lambda: archive[bad_name]),
            ("file_number_from_identity", lambda: archive.file_number(bad_name, locale=0, platform=0)),
            ("stream_open_name_identity", lambda: archive.open_stream(bad_name, locale=0, platform=0)),
            ("file_verify_ex", lambda: member.verify_result(filename=bad_name)),
            ("patch_payload_size", lambda: member.read_patch_payload(bad_name)),
            ("update_rename", lambda: update.rename(bad_name, "other")),
            ("update_rename_identity", lambda: update.rename(name, bad_name, locale=0, platform=0)),
            ("update_compact_ex", lambda: update.compact([name, bad_name])),
            ("archive_open_io", lambda: mpq.Archive.open_io(io.BytesIO(wire), len(wire),
                                                          source_name=bad_name)),
            ("archive_open_mpqe_io", lambda: mpq.Archive.open_mpqe_io(
                io.BytesIO(wire), len(wire), b"A" * 32, source_name=bad_name)),
            ("archive_open_patch", lambda: mpq.Archive.open_patch(archive, [archive], [bad_name])),
            ("stream_open_patch", lambda: archive.open_patch_stream(name, [archive], [bad_name])),
            ("stream_open_patch_identity", lambda: archive.open_patch_stream(
                bad_name, [], locale=0, platform=0)),
        ]
        for native, call in operations:
            with monkeypatch.context() as guard:
                guard.setattr(mpq.libmpq, "libmpq__" + native,
                              lambda *args: pytest.fail("reached native operation"))
                with pytest.raises(ValueError, match="native string.*NUL"):
                    call()
    assert path.read_bytes() == wire
