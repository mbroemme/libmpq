/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */

/** End-to-end D binding tests using deterministic native archives. */
module libmpq.d_tests;

import std.file : remove, write;
import std.path : buildPath;
import std.process : environment;
import libmpq.mpq;

private string temporaryArchive(string suffix) {
    auto root = environment.get("TMPDIR", "/tmp");
    auto path = buildPath(root, "libmpq-d-binding-" ~ suffix ~ ".mpq");
    try { remove(path); } catch (Exception) { }
    return path;
}

private void testVersionAndErrors() {
    assert(Mpq.version_().length > 0);
    assert(Mpq.strerror(ERROR_OPEN).length > 0);
    assert(Mpq.strerror(-999).length > 0);
}

private void testCreateReadAndMetadata(uint archiveVersion) {
    auto path = temporaryArchive(archiveVersion == ARCHIVE_VERSION_ONE ? "v1" : "v2");
    auto options = archiveVersion == ARCHIVE_VERSION_ONE ?
        ArchiveCreateOptions.v1() : ArchiveCreateOptions.v2();
    options.sectorSize = 4096;
    options.maxFiles = 16;
    auto archive = Archive.create(path, options);
    scope(exit) archive.close();

    const(ubyte)[] payload = cast(const(ubyte)[])"D binding regression\n";
    archive.add("hello.txt", payload);
    ubyte[] repetitive = new ubyte[](12000);
    repetitive[] = cast(ubyte) 'D';
    archive.add("compressed.txt", repetitive,
                FileOptions.compressed(COMPRESSION_ZLIB, COMPRESSION_ZLIB));
    auto sourcePath = path ~ ".source";
    write(sourcePath, cast(const(ubyte)[])"path payload");
    scope(exit) remove(sourcePath);
    archive.addPath("source.txt", sourcePath);
    auto writer = archive.begin("stream.bin", 6);
    writer.write(cast(const(ubyte)[])"abc");
    writer.write(cast(const(ubyte)[])"def");
    writer.finish();
    assert(writer.finished());

    archive.close();
    auto reopened = Archive.open(path);
    scope(exit) { reopened.close(); remove(path); }
    auto hello = reopened.file("hello.txt");
    assert(hello.read() == payload);
    assert(hello.unpackedSize() == payload.length);
    assert(hello.blockCount() > 0);
    auto hash = Mpq.fileHash("hello.txt");
    assert(reopened.fileNumber(hash) == hello.no());
    assert(reopened.metadata().version_ == (archiveVersion + 1));
    assert(reopened.fileCount() >= 4);
    assert(reopened.file("stream.bin").read() == cast(const(ubyte)[])"abcdef");
    assert(reopened.file("compressed.txt").read() == repetitive);
    assert(reopened.file("source.txt").read() == cast(const(ubyte)[])"path payload");
    auto clone = reopened.clone();
    scope(exit) clone.close();
    reopened.close();
    assert(clone.file("hello.txt").read() == payload);
}

private void testFailures() {
    bool failed;
    try { auto unused = Archive.open("/definitely/missing/libmpq.mpq"); }
    catch (MPQException error) { failed = error.code == ERROR_EXIST; }
    assert(failed);

    auto path = temporaryArchive("incomplete");
    auto archive = Archive.create(path, ArchiveCreateOptions.v1());
    auto writer = archive.begin("incomplete.bin", 6);
    writer.write(cast(const(ubyte)[])"abc");
    failed = false;
    try { writer.finish(); }
    catch (MPQException) { failed = true; }
    assert(failed);
    assert(writer.finished());
    writer.close();
    archive.close();
    remove(path);
}

private void testFixture() {
    auto root = environment.get("LIBMPQ_SOURCE_DIR", ".");
    auto path = buildPath(root, "tests", "fixtures", "mpq-v1-features.mpq");
    auto archive = Archive.open(path);
    scope(exit) archive.close();
    auto listfile = archive.file("(listfile)");
    assert(listfile.read().length > 0);
    assert(archive.fileNumber(Mpq.fileHash("(listfile)")) == listfile.no());
}

private void testMpqeFixture() {
    auto root = environment.get("LIBMPQ_SOURCE_DIR", ".");
    auto path = buildPath(root, "tests", "fixtures", "mpq-v1-features.mpqe");
    immutable ubyte[] authenticationCode =
        cast(immutable(ubyte)[])"LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
    auto archive = Archive.openMpqe(path, authenticationCode, 0);
    scope(exit) archive.close();
    assert(archive.version_() == 1);
    assert(archive.file("overview.txt").read().length > 0);

    bool failed;
    try {
        auto unused = Archive.openMpqe(path, authenticationCode[0 .. $ - 1], 0);
    } catch (MPQException error) {
        failed = error.code == ERROR_DECRYPT;
    }
    assert(failed);
}

private void testMpqeCreate() {
    auto path = temporaryArchive("created.mpqe");
    immutable ubyte[] authenticationCode =
        cast(immutable(ubyte)[])"LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
    write(path, cast(const(ubyte)[])"previous destination");
    auto archive = Archive.createMpqe(path, authenticationCode, ArchiveCreateOptions.v2());
    archive.add("payload.txt", cast(const(ubyte)[])"D MPQE writer regression\n");
    archive.close();
    auto reopened = Archive.openMpqe(path, authenticationCode, 0);
    scope(exit) { reopened.close(); remove(path); }
    assert(reopened.version_() == 2);
    assert(reopened.file("payload.txt").read() ==
           cast(const(ubyte)[])"D MPQE writer regression\n");
}

void main() {
    testVersionAndErrors();
    testCreateReadAndMetadata(ARCHIVE_VERSION_ONE);
    testCreateReadAndMetadata(ARCHIVE_VERSION_TWO);
    testFixture();
    testMpqeFixture();
    testMpqeCreate();
    testFailures();
}
