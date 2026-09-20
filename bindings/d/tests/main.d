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
import facade = libmpq.mpq;

static assert(__traits(compiles, &libmpq__writer_begin));
static assert(__traits(compiles, &libmpq__writer_write));
static assert(__traits(compiles, &libmpq__writer_finish));
static assert(__traits(compiles, &libmpq__writer_timestamp));

static foreach (name; ["libversion", "archive_open", "writer_begin", "writer_write",
                      "writer_finish", "writer_timestamp", "file_unpacked_size",
                      "MPQ_FUNC", "MPQ_CHECKERR", "FileWriter"]) {
    static assert(!__traits(hasMember, facade, name));
}
static foreach (name; ["cloneArchive", "files", "packed_size", "unpacked_size",
                      "archive", "filelist"]) {
    static assert(!__traits(hasMember, Archive, name));
}
static foreach (name; ["packed_size", "unpacked_size", "blocks", "fileno"]) {
    static assert(!__traits(hasMember, File, name));
}

private string temporaryArchive(string suffix) {
    auto root = environment.get("TMPDIR", "/tmp");
    auto path = buildPath(root, "libmpq-d-binding-" ~ suffix ~ ".mpq");
    try { remove(path); } catch (Exception) { }
    return path;
}

private void testVersionAndErrors() {
    const(ubyte)[] publicKey = cast(const(ubyte)[]) x"a13dab4de25f08acc393e15923b73aed2554013742f1079c1f1e6011c566948e5f0267ddf51175169e7bbeed8efe9ee8b6f63c4602f5089e97b02e1fe00ce8a700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
    const(ubyte)[] privateKey = cast(const(ubyte)[]) x"a13dab4de25f08acc393e15923b73aed2554013742f1079c1f1e6011c566948e5f0267ddf51175169e7bbeed8efe9ee8b6f63c4602f5089e97b02e1fe00ce8a748315364c0c92a1a284b2ae77d5d49adea3bad7bafa639710661d443c0ad882f6c8d6787affd7f68145217cde42cf4dc2acb0ca2aeca535baf894084e590d719";
    auto signaturePath = temporaryArchive("signature");
    scope(exit) remove(signaturePath);
    auto signedArchive = Archive.create(signaturePath, ArchiveCreateOptions.v1());
    signedArchive.sign(privateKey);
    signedArchive.close();
    auto verifiedArchive = new Archive(signaturePath);
    scope(exit) verifiedArchive.close();
    assert(verifiedArchive.signatures() == SIGNATURE_WEAK);
    assert(verifiedArchive.verify(publicKey) == 0);
    static assert(mpq_archive_create_options_s.sizeof == 20);
    assert(Mpq.version_().length > 0);
    assert(Mpq.strerror(ERROR_OPEN).length > 0);
    assert(Mpq.strerror(-999).length > 0);
    assert(!Mpq.archiveCompressionAllowed(ARCHIVE_VERSION_TWO, COMPRESSION_HUFFMAN));
    assert(Mpq.archiveCompressionAllowed(ARCHIVE_VERSION_TWO, COMPRESSION_HUFFMAN,
                                   COMPRESSION_POLICY_EXTENDED));
}

private void testCreateReadAndMetadata(uint archiveVersion) {
    auto path = temporaryArchive(archiveVersion == ARCHIVE_VERSION_ONE ? "v1" : "v2");
    auto options = archiveVersion == ARCHIVE_VERSION_ONE ?
        ArchiveCreateOptions.v1() : ArchiveCreateOptions.v2();
    options.sectorSize = 4096;
    options.maxFiles = 16;
    options.attributes = ATTRIBUTE_CRC32 | ATTRIBUTE_FILETIME |
                     ATTRIBUTE_MD5 | ATTRIBUTE_PATCH_BIT;
    auto archive = Archive.create(path, options);
    scope(exit) archive.close();

    const(ubyte)[] payload = cast(const(ubyte)[])"D binding regression\n";
    archive.add("hello.txt", payload);
    ubyte[] repetitive = new ubyte[](12000);
    repetitive[] = cast(ubyte) 'D';
    auto checksummed = FileOptions.compressed(COMPRESSION_ZLIB, COMPRESSION_ZLIB);
    checksummed.flags |= FILE_FLAG_SECTOR_CRC;
    archive.add("compressed.txt", repetitive, checksummed);
    if (archiveVersion == ARCHIVE_VERSION_TWO) {
        archive.add("lzma.txt", repetitive,
                    FileOptions.compressed(COMPRESSION_LZMA, COMPRESSION_LZMA));
    }
    auto sourcePath = path ~ ".source";
    write(sourcePath, cast(const(ubyte)[])"path payload");
    scope(exit) remove(sourcePath);
    archive.addPath("source.txt", sourcePath);
    auto writer = archive.begin("stream.bin", 6);
    writer.timestamp(0xfedcba9876543210UL);
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
    assert(reopened.attributes().get() == 15);
    assert(reopened.file("stream.bin").verify() == 0);
    assert(reopened.file("stream.bin").verify(VERIFY_FILE_CRC32) == 0);
    assert(reopened.file("stream.bin").verify(VERIFY_SECTOR_CRC) == 0);
    assert(reopened.file("compressed.txt").verify(VERIFY_SECTOR_CRC) == 0);
    assert(reopened.file("compressed.txt").verify() == 0);
    assert((reopened.file("compressed.txt").flags() &
            (FILE_FLAG_COMPRESS | FILE_FLAG_SECTOR_CRC)) ==
           (FILE_FLAG_COMPRESS | FILE_FLAG_SECTOR_CRC));
    auto blockResult = reopened.file("compressed.txt").verifyBlock(0);
    assert(blockResult.checksum != 0 && blockResult.checksum != uint.max);
    assert(blockResult.mismatches == 0);
    assert(reopened.file("compressed.txt").blockSizePacked(0) > 0);
    assert(reopened.file("compressed.txt").blockSizePacked(0) <
           reopened.file("compressed.txt").readBlock(0).length);
    assert(reopened.file("hello.txt").blockSizePacked(0) == payload.length);
    assert(reopened.file("hello.txt").blockCompression(0) == 0);
    assert(reopened.file("compressed.txt").blockCompression(0) == 0x02);
    bool invalidCompression = false;
    try { reopened.file("compressed.txt").blockCompression(uint.max); }
    catch (MPQException error) { invalidCompression = error.code == ERROR_EXIST; }
    assert(invalidCompression);
    bool noChecksum;
    try { reopened.file("hello.txt").verifyBlock(0); }
    catch (MPQException error) { noChecksum = error.code == ERROR_EXIST; }
    assert(noChecksum);
    noChecksum = false;
    try { reopened.file("compressed.txt").blockSizePacked(uint.max); }
    catch (MPQException error) { noChecksum = error.code == ERROR_EXIST; }
    assert(noChecksum);
    noChecksum = false;
    try { reopened.file("compressed.txt").verifyBlock(uint.max); }
    catch (MPQException error) { noChecksum = error.code == ERROR_EXIST; }
    assert(noChecksum);
    static assert(VERIFY_SECTOR_CRC == 1 && VERIFY_FILE_CRC32 == 2 && VERIFY_FILE_MD5 == 4);
    static assert(VERIFY_ALL == 7);
    static assert(FILE_FLAG_SECTOR_CRC == 0x04000000u);
    auto attributes = reopened.file("stream.bin").attributes();
    assert(attributes.flags == 15);
    assert(attributes.crc32 == 0x4b8e39ef);
    assert(attributes.filetime == 0xfedcba9876543210UL);
    assert(attributes.md5 == [0xe8, 0x0b, 0x50, 0x17, 0x09, 0x89, 0x50, 0xfc,
                              0x58, 0xaa, 0xd8, 0x3c, 0x8c, 0x14, 0x97, 0x8e]);
    assert(!attributes.patchBit);
    assert(reopened.file("compressed.txt").read() == repetitive);
    if (archiveVersion == ARCHIVE_VERSION_TWO)
        assert(reopened.file("lzma.txt").read() == repetitive);
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
    assert(archive.file("overview.txt").verify() == 0);
    assert(archive.file("(attributes)").verify(VERIFY_FILE_MD5) ==
           VERIFY_FILE_MD5);
    assert(archive.fileNumber(Mpq.fileHash("(listfile)")) == listfile.no());
}

private void testMpqeFixture() {
    auto root = environment.get("LIBMPQ_SOURCE_DIR", ".");
    auto path = buildPath(root, "tests", "fixtures", "mpq-v1-features.mpqe");
    immutable ubyte[] authCode =
        cast(immutable(ubyte)[])"LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
    auto archive = Archive.openMpqe(path, authCode, 0);
    scope(exit) archive.close();
    assert(archive.version_() == 1);
    assert(archive.file("overview.txt").read().length > 0);
    assert(archive.file("overview.txt").verify() == 0);

    bool failed;
    try {
        auto unused = Archive.openMpqe(path, authCode[0 .. $ - 1], 0);
    } catch (MPQException error) {
        failed = error.code == ERROR_DECRYPT;
    }
    assert(failed);
}

/** Verify UTF-32LE fixture bytes without using host-native character encoding. */
private void testSparseFixtures() {
    enum sentence = "This text uses SPARSE compression and decompression.\n";
    ubyte[] expected = [0xff, 0xfe, 0, 0];
    foreach (repetition; 0 .. 16)
        foreach (character; sentence)
            expected ~= [cast(ubyte) character, cast(ubyte) 0, cast(ubyte) 0, cast(ubyte) 0];
    auto root = environment.get("LIBMPQ_SOURCE_DIR", ".");
    immutable ubyte[] code = cast(immutable(ubyte)[])"LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
    foreach (archiveVersion; ["1", "2"]) {
        auto raw = Archive.open(buildPath(root, "tests", "fixtures",
                                         "mpq-v" ~ archiveVersion ~ "-features.mpq"));
        scope(exit) raw.close();
        auto encrypted = Archive.openMpqe(buildPath(root, "tests", "fixtures",
                                                   "mpq-v" ~ archiveVersion ~ "-features.mpqe"), code);
        scope(exit) encrypted.close();
        foreach (name; ["sparse.txt", "sparse-zlib.txt", "sparse-bzip2.txt"]) {
            assert(raw.file(name).read() == expected);
            assert(encrypted.file(name).read() == expected);
        }
    }
    foreach (archiveVersion; [ARCHIVE_VERSION_ONE, ARCHIVE_VERSION_TWO])
        foreach (policy; [COMPRESSION_POLICY_STANDARD, COMPRESSION_POLICY_EXTENDED]) {
            foreach (method; [COMPRESSION_SPARSE, COMPRESSION_SPARSE | COMPRESSION_ZLIB,
                              COMPRESSION_SPARSE | COMPRESSION_BZIP2])
                assert(Mpq.archiveCompressionAllowed(archiveVersion, method, policy));
            assert(!Mpq.archiveCompressionAllowed(archiveVersion,
                COMPRESSION_SPARSE | COMPRESSION_WAVE_MONO, policy));
        }
}

private void testMpqeCreate() {
    auto path = temporaryArchive("created.mpqe");
    immutable ubyte[] authCode =
        cast(immutable(ubyte)[])"LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
    write(path, cast(const(ubyte)[])"previous destination");
    auto options = ArchiveCreateOptions.v2();
    options.attributes = ATTRIBUTE_CRC32;
    auto archive = Archive.createMpqe(path, authCode, options);
    archive.add("payload.txt", cast(const(ubyte)[])"D MPQE writer regression\n");
    archive.close();
    auto reopened = Archive.openMpqe(path, authCode, 0);
    scope(exit) { reopened.close(); remove(path); }
    assert(reopened.version_() == 2);
    assert(reopened.attributes().get() == ATTRIBUTE_CRC32);
    assert(reopened.file("payload.txt").read() ==
           cast(const(ubyte)[])"D MPQE writer regression\n");
}

void main() {
    testVersionAndErrors();
    testCreateReadAndMetadata(ARCHIVE_VERSION_ONE);
    testCreateReadAndMetadata(ARCHIVE_VERSION_TWO);
    testFixture();
    testMpqeFixture();
    testSparseFixtures();
    testMpqeCreate();
    testFailures();
}
