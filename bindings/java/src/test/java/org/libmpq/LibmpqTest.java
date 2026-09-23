/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */
package org.libmpq;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.libmpq.ffi.LibmpqNative;

/**
 * End-to-end integration coverage for the public Java binding and native ABI.
 * Each test loads the freshly built shared library and exercises native file
 * creation or fixture reading rather than mocking the FFM calls.
 */
class LibmpqTest {
    /** Skips integration tests when no native library path was configured. */
    @BeforeAll
    static void requireNativeLibrary() {
        boolean explicitLibrary = System.getProperty("org.libmpq.library") != null;
        boolean loaderPathTest = Boolean.getBoolean("org.libmpq.test.loaderPath");
        Assumptions.assumeTrue(explicitLibrary || loaderPathTest,
                               "configure org.libmpq.library or "
                               + "org.libmpq.test.loaderPath to run native integration tests");
    }

    /** Verifies version reporting and translation of a documented error code. */
    @Test
    void exposesVersionAndErrorText() {
        assertTrue(!Mpq.version().isBlank());
        assertTrue(Mpq.strerror(Mpq.ERROR_FORMAT).contains("format"));
    }

    @Test
    void weakSignatureRoundTrip() throws Exception {
        byte[] publicKey = java.util.HexFormat.of().parseHex("a13dab4de25f08acc393e15923b73aed2554013742f1079c1f1e6011c566948e5f0267ddf51175169e7bbeed8efe9ee8b6f63c4602f5089e97b02e1fe00ce8a700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001");
        byte[] privateKey = java.util.HexFormat.of().parseHex("a13dab4de25f08acc393e15923b73aed2554013742f1079c1f1e6011c566948e5f0267ddf51175169e7bbeed8efe9ee8b6f63c4602f5089e97b02e1fe00ce8a748315364c0c92a1a284b2ae77d5d49adea3bad7bafa639710661d443c0ad882f6c8d6787affd7f68145217cde42cf4dc2acb0ca2aeca535baf894084e590d719");
        Path path = java.nio.file.Files.createTempFile("libmpq-signature", ".mpq");
        try {
            try (Archive archive = Archive.create(path, ArchiveCreateOptions.v1())) {
                archive.sign(privateKey);
            }
            try (Archive archive = Archive.open(path)) {
                assertEquals(Mpq.SIGNATURE_WEAK, archive.signatures());
                assertEquals(0, archive.verify(publicKey));
            }
        } finally {
            java.nio.file.Files.deleteIfExists(path);
        }
    }

    /** Verifies independently signed data through the existing native entry point. */
    @Test
    void strongSignatureFixture() throws Exception {
        Path root = Path.of(System.getProperty("libmpq.sourceDir", "."), "tests", "fixtures");
        byte[] publicKey = HexFormat.of().parseHex(
            "b76f7dc7cdd3a083b2e52f39a5b7d58f181ab7bc03c1eaa0931744f0218bf74397b68481776a3f49f7b9a7ea08abf1c3a9802b54ee75661190e521453f6e125cdaca5d4b5cb52c84a158f1bb1b51bb9138acc55b45a083d3dde6e9e9cc4cb03adf4dda27a4a673993ebddfefd06e7c8c976387df92ba92d6392b9baf1a40f7b39d3c0ad1a4e2d685b46caea30863c9055d8e0a151d2e5adf5b79c69cc849c8b879ecc53be1207334d60b4194583b44129f272fe4790570ba530df485e2188932d79abb5b3b8713fd2d16de821048328e9ae93da8de983519033806fbd55591ebf5542641af669ad73e7c0f01b2dea45040f6658d2c6ca0f55f8d91c482f81617" + "00".repeat(253) + "010001");
        assertEquals(512, publicKey.length);
        try (Archive archive = Archive.open(root.resolve("mpq-v1-features.mpq"))) {
            assertEquals(Mpq.SIGNATURE_WEAK | Mpq.SIGNATURE_STRONG, archive.signatures());
            assertEquals(0, archive.verify(Mpq.SIGNATURE_STRONG, publicKey));
        }
    }

    @Test
    void strongSignatureRoundTrip(@TempDir Path directory) throws Exception {
        byte[] publicKey = strongPublicKey();
        byte[] privateKey = java.util.Arrays.copyOf(publicKey, 512);
        byte[] exponent = HexFormat.of().parseHex(
            "14c9759f7c1ba1f24ab0de0bd253bac7b470e7fbf911088844783bea5a62da15"
            + "0c24356fd670712b98a9aea03ecb52b7b18597637b2cf7f16afcb6d5cf67a727"
            + "b9437abf078a75b907450fb4fc56396dd8d650a71484d4163641eca554997c29"
            + "afbf201c4df444354c29882ef797b85580f259260f77efc686eeacd31da3d9c3"
            + "37897433f8ef833890a04d55cbfc53f2dd8f96bd9b93e28fc6f022786b36e51d"
            + "e38ec0d5d41aba3eed9647831fb16fcbc3b16eaca91e60894aa772b02b22a3ff"
            + "b7042e52531163d089209df6412098613ef59664ed70884e33f3e3056ccfb911"
            + "bcc04d2c73142996946d88be0daa29aafa1bab3d10ff4d52295880c8fad6d641");
        System.arraycopy(exponent, 0, privateKey, 256, 256);
        Path path = directory.resolve("strong.mpq");
        try (Archive archive = Archive.create(path, ArchiveCreateOptions.v2())) {
            archive.sign(Mpq.SIGNATURE_STRONG, privateKey);
            archive.add("payload", "Java strong signing".getBytes(StandardCharsets.UTF_8), FileOptions.raw());
        }
        try (Archive archive = Archive.open(path)) {
            assertEquals(Mpq.SIGNATURE_STRONG, archive.signatures());
            assertEquals(0, archive.verify(Mpq.SIGNATURE_STRONG, publicKey));
        }
    }

    private static byte[] strongPublicKey() {
        return HexFormat.of().parseHex(
            "b76f7dc7cdd3a083b2e52f39a5b7d58f181ab7bc03c1eaa0931744f0218bf743"
            + "97b68481776a3f49f7b9a7ea08abf1c3a9802b54ee75661190e521453f6e125c"
            + "daca5d4b5cb52c84a158f1bb1b51bb9138acc55b45a083d3dde6e9e9cc4cb03a"
            + "df4dda27a4a673993ebddfefd06e7c8c976387df92ba92d6392b9baf1a40f7b3"
            + "9d3c0ad1a4e2d685b46caea30863c9055d8e0a151d2e5adf5b79c69cc849c8b8"
            + "79ecc53be1207334d60b4194583b44129f272fe4790570ba530df485e2188932"
            + "d79abb5b3b8713fd2d16de821048328e9ae93da8de983519033806fbd55591eb"
            + "f5542641af669ad73e7c0f01b2dea45040f6658d2c6ca0f55f8d91c482f81617"
            + "00".repeat(253) + "010001");
    }

    /** Ensures Java's native struct layouts match the C ABI sizes. */
    @Test
    void preservesNativeStructLayouts() {
        assertEquals(20, LibmpqNative.ARCHIVE_OPTIONS.byteSize());
        assertEquals(16, LibmpqNative.FILE_OPTIONS.byteSize());
        assertEquals(40, LibmpqNative.FILE_ATTRIBUTES_LAYOUT.byteSize());
        assertLayoutFields(LibmpqNative.ARCHIVE_OPTIONS,
            new String[] {"version", "max_files", "sector_size", "flags", "attributes"},
            new long[] {0, 4, 8, 12, 16}, new long[] {4, 4, 4, 4, 4});
        assertLayoutFields(LibmpqNative.FILE_OPTIONS,
            new String[] {"flags", "compression_first", "compression_next", "locale", "platform"},
            new long[] {0, 4, 8, 12, 14}, new long[] {4, 4, 4, 2, 2});
        assertLayoutFields(LibmpqNative.FILE_ATTRIBUTES_LAYOUT,
            new String[] {"flags", "crc32", "filetime", "md5", "patch_bit", "reserved"},
            new long[] {0, 4, 8, 16, 32, 36}, new long[] {4, 4, 8, 16, 4, 4});
        assertFalse(Mpq.archiveCompressionAllowed(Mpq.ARCHIVE_VERSION_TWO,
            Mpq.COMPRESSION_HUFFMAN, Mpq.COMPRESSION_POLICY_STANDARD));
        assertTrue(Mpq.archiveCompressionAllowed(Mpq.ARCHIVE_VERSION_TWO,
            Mpq.COMPRESSION_HUFFMAN, Mpq.COMPRESSION_POLICY_EXTENDED));
        for (int version : new int[] {Mpq.ARCHIVE_VERSION_ONE, Mpq.ARCHIVE_VERSION_TWO}) {
            for (int policy : new int[] {Mpq.COMPRESSION_POLICY_STANDARD, Mpq.COMPRESSION_POLICY_EXTENDED}) {
                for (int method : new int[] {0x20, 0x22, 0x30}) {
                    assertTrue(Mpq.archiveCompressionAllowed(version, method, policy));
                }
                assertFalse(Mpq.archiveCompressionAllowed(version,
                    Mpq.COMPRESSION_SPARSE | Mpq.COMPRESSION_WAVE_STEREO, policy));
            }
        }
    }

    /** Checks each field against the fixed native offsets and widths. */
    private static void assertLayoutFields(java.lang.foreign.MemoryLayout layout,
                                           String[] names, long[] offsets, long[] sizes) {
        for (int i = 0; i < names.length; ++i) {
            var field = java.lang.foreign.MemoryLayout.PathElement.groupElement(names[i]);
            assertEquals(offsets[i], layout.byteOffset(field), names[i]);
            assertEquals(sizes[i], layout.select(field).byteSize(), names[i]);
            assertEquals(0, offsets[i] % layout.select(field).byteAlignment(), names[i]);
        }
    }

    /** Extracts the same UTF-32LE bytes from every shared MPQ and MPQE fixture. */
    @Test
    void readsSparseFixtures() throws Exception {
        String text = "This text uses SPARSE compression and decompression.\n".repeat(16);
        byte[] body = text.getBytes(java.nio.charset.Charset.forName("UTF-32LE"));
        byte[] expected = new byte[body.length + 4];
        expected[0] = (byte) 0xff;
        expected[1] = (byte) 0xfe;
        System.arraycopy(body, 0, expected, 4, body.length);
        byte[] code = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001".getBytes(StandardCharsets.US_ASCII);
        Path root = Path.of(System.getProperty("libmpq.sourceDir", "."), "tests", "fixtures");
        for (int version : new int[] {1, 2}) {
            try (Archive raw = Archive.open(root.resolve("mpq-v" + version + "-features.mpq"));
                 Archive mpqe = Archive.openMpqe(root.resolve("mpq-v" + version + "-features.mpqe"), code)) {
                for (String member : new String[] {"sparse.txt", "sparse-zlib.txt", "sparse-bzip2.txt"}) {
                    assertArrayEquals(expected, raw.readFile(raw.fileNumber(member)));
                    assertEquals(raw.fileFlags(raw.fileNumber(member)),
                                 mpqe.fileFlags(mpqe.fileNumber(member)));
                    assertTrue((raw.fileFlags(raw.fileNumber(member)) & Mpq.FILE_FLAG_SECTOR_CRC) != 0);
                    assertArrayEquals(expected, mpqe.readFile(mpqe.fileNumber(member)));
                    Archive.BlockVerification sector = raw.verifyBlock(raw.fileNumber(member), 0);
                    assertTrue(sector.checksum() > 0 && sector.checksum() < 0xffffffffL);
                    assertEquals(0, sector.mismatches());
                    assertEquals(sector, mpqe.verifyBlock(mpqe.fileNumber(member), 0));
                    long packed = raw.blockSizePacked(raw.fileNumber(member), 0);
                    assertTrue(packed > 0 && packed < raw.blockSize(raw.fileNumber(member), 0));
                    assertEquals(packed, mpqe.blockSizePacked(mpqe.fileNumber(member), 0));
                    int method = member.equals("sparse.txt") ? 0x20 :
                                 member.equals("sparse-zlib.txt") ? 0x22 : 0x30;
                    assertEquals(method, raw.blockCompression(raw.fileNumber(member), 0));
                    assertEquals(method, mpqe.blockCompression(mpqe.fileNumber(member), 0));
                }
                assertEquals(Mpq.ERROR_EXIST, assertThrows(LibmpqException.class,
                    () -> raw.verifyBlock(raw.fileNumber("overview.txt"), 0)).code());
                assertEquals(Mpq.ERROR_EXIST, assertThrows(LibmpqException.class,
                    () -> raw.verifyBlock(raw.fileNumber("sparse.txt"), -1)).code());
                assertEquals(Mpq.ERROR_EXIST, assertThrows(LibmpqException.class,
                    () -> raw.blockSizePacked(raw.fileNumber("sparse.txt"), -1)).code());
                assertEquals(raw.blockSize(raw.fileNumber("overview.txt"), 0),
                             raw.blockSizePacked(raw.fileNumber("overview.txt"), 0));
                assertEquals(0, raw.blockCompression(raw.fileNumber("overview.txt"), 0));
                assertEquals(Mpq.ERROR_EXIST, assertThrows(LibmpqException.class,
                    () -> raw.blockCompression(raw.fileNumber("sparse.txt"), -1)).code());
                if (version == 2)
                    assertEquals(0x12, mpqe.blockCompression(mpqe.fileNumber("lzma.txt"), 0));
            }
        }
    }

    /** Resolves a Storm hash and reads a known fixture through the facade. */
    @Test
    void hashesAndReadsFixture() throws Exception {
        Mpq.StormHash hash = Mpq.fileHash("overview.txt");
        Path fixture = Path.of(System.getProperty("libmpq.sourceDir", "."), "tests", "fixtures",
                               "mpq-v1-features.mpq");
        try (Archive archive = Archive.open(fixture)) {
            int number = archive.fileNumber(hash);
            byte[] data = archive.readFile(number);
            assertEquals(7, archive.attributes().orElseThrow());
            FileAttributes attributes = archive.attributes(number);
            assertEquals(0, archive.verify(number));
            assertEquals(0, archive.verify(number, Mpq.VERIFY_FILE_MD5));
            assertEquals(0, archive.verify(number, Mpq.VERIFY_SECTOR_CRC));
            assertEquals(1, Mpq.VERIFY_SECTOR_CRC);
            assertEquals(2, Mpq.VERIFY_FILE_CRC32);
            assertEquals(4, Mpq.VERIFY_FILE_MD5);
            assertEquals(7, Mpq.VERIFY_ALL);
            assertEquals(0x04000000, Mpq.FILE_FLAG_SECTOR_CRC);
            assertEquals(Mpq.VERIFY_FILE_MD5,
                archive.verify(archive.fileNumber("(attributes)"), Mpq.VERIFY_FILE_MD5));
            java.util.zip.CRC32 crc = new java.util.zip.CRC32();
            crc.update(data);
            assertEquals(crc.getValue(), attributes.crc32());
            assertArrayEquals(java.security.MessageDigest.getInstance("MD5").digest(data), attributes.md5());
            assertEquals(132537600000000000L, attributes.filetime());
            assertFalse(attributes.patchBit());
            assertTrue(new String(data, StandardCharsets.UTF_8).contains("libmpq"));
            assertTrue(archive.fileCount() > 0);
        }
    }

    /** Logical streams retain their private native clone after archive close. */
    @Test
    void streamsFixtureIncrementally() throws Exception {
        Path fixture = Path.of(System.getProperty("libmpq.sourceDir", "."), "tests", "fixtures",
                               "mpq-v1-features.mpq");
        Archive archive = Archive.open(fixture);
        byte[] expected = archive.readFile(archive.fileNumber("overview.txt"));
        try (MpqStream stream = archive.openStream("overview.txt")) {
            assertEquals(expected.length, stream.size());
            byte[] first = new byte[2];
            assertEquals(2, stream.read(first));
            assertArrayEquals(java.util.Arrays.copyOf(expected, 2), first);
            stream.seek(-1, Mpq.SEEK_CUR);
            stream.seek(0, Mpq.SEEK_SET);
            archive.close();
            byte[] all = new byte[expected.length];
            assertEquals(expected.length, stream.read(all));
            assertArrayEquals(expected, all);
            assertEquals(-1, stream.read(new byte[1]));
        }
    }

    /** Name-derived encrypted keys, numeric opens, and MPQE lifetime reach streams. */
    @Test
    void streamsEncryptedAndMpqeFixtures() throws Exception {
        Path root = Path.of(System.getProperty("libmpq.sourceDir", "."), "tests", "fixtures");
        try (Archive archive = Archive.open(root.resolve("mpq-v1-features.mpq"))) {
            byte[] expected = archive.readFile(archive.fileNumber("encrypted-compress.txt"));
            try (MpqStream stream = archive.openStream("encrypted-compress.txt")) {
                byte[] actual = new byte[expected.length];
                assertEquals(expected.length, stream.read(actual));
                assertArrayEquals(expected, actual);
            }
            try (MpqStream stream = archive.openStream(archive.fileNumber("overview.txt"))) {
                assertTrue(stream.read(new byte[8]) > 0);
            }
        }
        byte[] code = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001".getBytes(StandardCharsets.US_ASCII);
        Archive archive = Archive.openMpqe(root.resolve("mpq-v1-features.mpqe"), code, 0);
        byte[] expected = archive.readFile(archive.fileNumber("overview.txt"));
        try (MpqStream stream = archive.openStream("overview.txt")) {
            archive.close();
            byte[] actual = new byte[expected.length];
            assertEquals(expected.length, stream.read(actual));
            assertArrayEquals(expected, actual);
        }
    }

    /** Borrowed seekable channels remain usable for archive-owned native clones. */
    @Test
    void opensCustomSourcesAndRetainsThemForStreams() throws Exception {
        Path root = Path.of(System.getProperty("libmpq.sourceDir", "."), "tests", "fixtures");
        try (SeekableByteChannel channel = Files.newByteChannel(root.resolve("mpq-v1-features.mpq"))) {
            channel.position(3);
            Archive archive = Archive.openSource(channel, "fixture.mpq");
            assertEquals(3, channel.position());
            byte[] expected = archive.readFile(archive.fileNumber("overview.txt"));
            assertEquals(3, channel.position());
            try (MpqStream stream = archive.openStream("overview.txt")) {
                archive.close();
                byte[] actual = new byte[expected.length];
                assertEquals(expected.length, stream.read(actual));
                assertArrayEquals(expected, actual);
            }
            assertTrue(channel.isOpen());
        }
        byte[] code = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001".getBytes(StandardCharsets.US_ASCII);
        try (SeekableByteChannel channel = Files.newByteChannel(root.resolve("mpq-v1-features.mpqe"))) {
            Archive archive = Archive.openMpqeSource(channel, code, "fixture.mpqe", 0);
            MpqStream stream = archive.openStream("overview.txt");
            archive.close();
            assertTrue(stream.read(new byte[8]) > 0);
            stream.close();
            assertTrue(channel.isOpen());
        }
        try (SeekableByteChannel channel = new FailingChannel(
                 Files.newByteChannel(root.resolve("mpq-v1-features.mpq")))) {
            assertThrows(LibmpqException.class, () -> Archive.openSource(channel, null));
        }
    }

    /** Channel wrapper that proves Java read failures do not escape the FFM upcall. */
    private static final class FailingChannel implements SeekableByteChannel {
        private final SeekableByteChannel delegate;

        FailingChannel(SeekableByteChannel delegate) { this.delegate = delegate; }
        @Override public int read(ByteBuffer target) throws IOException { throw new IOException("failure"); }
        @Override public int write(ByteBuffer source) throws IOException { return delegate.write(source); }
        @Override public long position() throws IOException { return delegate.position(); }
        @Override public SeekableByteChannel position(long value) throws IOException {
            delegate.position(value);
            return this;
        }
        @Override public long size() throws IOException { return delegate.size(); }
        @Override public SeekableByteChannel truncate(long size) throws IOException {
            delegate.truncate(size);
            return this;
        }
        @Override public boolean isOpen() { return delegate.isOpen(); }
        @Override public void close() throws IOException { delegate.close(); }
    }

    /** Exercises MPQE v1/v2 opening, credential validation, and independent cloning. */
    @Test
    void opensMpqeFixturesAndClones() throws Exception {
        byte[] code = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001".getBytes(StandardCharsets.US_ASCII);
        Path root = Path.of(System.getProperty("libmpq.sourceDir", "."), "tests", "fixtures");

        try (Archive v1 = Archive.openMpqe(root.resolve("mpq-v1-features.mpqe"), code);
             Archive v2 = Archive.openMpqe(root.resolve("mpq-v2-features.mpqe"), code, -1);
             Archive clone = v1.cloneArchive()) {
            assertEquals(1, v1.version());
            assertEquals(2, v2.version());
            assertArrayEquals(v1.readFile(v1.fileNumber("overview.txt")),
                              clone.readFile(clone.fileNumber("overview.txt")));
        }
        LibmpqException error = assertThrows(LibmpqException.class,
            () -> Archive.openMpqe(root.resolve("mpq-v1-features.mpqe"),
                                   java.util.Arrays.copyOf(code, code.length - 1)));
        assertEquals(Mpq.ERROR_DECRYPT, error.code());
    }

    /** Creates MPQE output, replaces an existing target, and reads it back. */
    @Test
    void createsMpqeArchive(@TempDir Path directory) throws Exception {
        Path path = directory.resolve("created.mpqe");
        byte[] code = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001".getBytes(StandardCharsets.US_ASCII);
        byte[] payload = "Java MPQE writer regression\n".getBytes(StandardCharsets.UTF_8);
        Files.write(path, "previous destination".getBytes(StandardCharsets.UTF_8));
        ArchiveCreateOptions options = new ArchiveCreateOptions(Mpq.ARCHIVE_VERSION_TWO,
            8, 4096, 0, Mpq.ATTRIBUTE_CRC32);
        try (Archive archive = Archive.createMpqe(path, code, options)) {
            archive.add("payload.txt", payload, FileOptions.raw());
        }
        try (Archive archive = Archive.openMpqe(path, code, 0)) {
            assertEquals(2, archive.version());
            assertEquals(Mpq.ATTRIBUTE_CRC32, archive.attributes().orElseThrow());
            assertEquals(0, archive.verify(archive.fileNumber("payload.txt")));
            assertArrayEquals(payload, archive.readFile(archive.fileNumber("payload.txt")));
        }
        LibmpqException error = assertThrows(LibmpqException.class,
            () -> Archive.createMpqe(path, java.util.Arrays.copyOf(code, code.length - 1),
                                     ArchiveCreateOptions.v1()));
        assertEquals(Mpq.ERROR_DECRYPT, error.code());
    }

    /** Exercises v2 creation, compression, path addition, cloning, and blocks. */
    @Test
    void createsReadsAndClonesArchive(@TempDir Path directory) throws Exception {
        Path path = directory.resolve("created.mpq");
        Path source = directory.resolve("source.txt");
        byte[] payload = "java binding payload".getBytes(StandardCharsets.UTF_8);
        byte[] repetitive = new byte[12000];
        java.util.Arrays.fill(repetitive, (byte) 'J');
        Files.write(source, "path payload".getBytes(StandardCharsets.UTF_8));
        try (Archive archive = Archive.create(path, ArchiveCreateOptions.v2())) {
            archive.add("payload.txt", payload, FileOptions.raw());
            archive.add("compressed.txt", repetitive,
                        new FileOptions(Mpq.FILE_FLAG_COMPRESS | Mpq.FILE_FLAG_SECTOR_CRC,
                            Mpq.COMPRESSION_ZLIB, Mpq.COMPRESSION_ZLIB, 0, 0));
            archive.add("lzma.txt", repetitive,
                        FileOptions.compressed(Mpq.COMPRESSION_LZMA, Mpq.COMPRESSION_LZMA));
            archive.addPath("source.txt", source, FileOptions.raw());
        }
        try (Archive archive = Archive.open(path); Archive clone = archive.cloneArchive()) {
            int number = archive.fileNumber("payload.txt");
            assertArrayEquals(payload, archive.readFile(number));
            assertArrayEquals(payload, clone.readFile(clone.fileNumber("payload.txt")));
            ArchiveMetadata metadata = archive.metadata();
            assertEquals(2, metadata.version());
            FileMetadata fileMetadata = archive.fileMetadata(number);
            assertEquals(payload.length, fileMetadata.unpackedSize());
            assertArrayEquals(payload, archive.readBlock(number, 0));
            assertArrayEquals(repetitive, archive.readFile(archive.fileNumber("compressed.txt")));
            assertEquals(0, archive.verify(archive.fileNumber("compressed.txt"), Mpq.VERIFY_SECTOR_CRC));
            assertArrayEquals(repetitive, archive.readFile(archive.fileNumber("lzma.txt")));
            assertArrayEquals("path payload".getBytes(StandardCharsets.UTF_8),
                              archive.readFile(archive.fileNumber("source.txt")));
        }
    }

    /** Exercises streaming finalization and missing-file error propagation. */
    @Test
    void streamsAndRejectsMissingFile(@TempDir Path directory) throws Exception {
        Path path = directory.resolve("stream.mpq");
        byte[] payload = "streamed".getBytes(StandardCharsets.UTF_8);
        ArchiveCreateOptions options = new ArchiveCreateOptions(Mpq.ARCHIVE_VERSION_ONE,
            8, 4096, 0, Mpq.ATTRIBUTE_CRC32 |
            Mpq.ATTRIBUTE_FILETIME | Mpq.ATTRIBUTE_MD5);
        try (Archive archive = Archive.create(path, options)) {
            try (MpqFileWriter writer = archive.begin("stream.txt", payload.length, FileOptions.raw())) {
                writer.timestamp(0xfedcba9876543210L);
                writer.write(payload);
            }
        }
        try (Archive archive = Archive.open(path)) {
            FileAttributes attributes = archive.attributes(archive.fileNumber("stream.txt"));
            assertEquals(7, attributes.flags());
            assertEquals(0xfedcba9876543210L, attributes.filetime());
            assertArrayEquals(java.security.MessageDigest.getInstance("MD5").digest(payload), attributes.md5());
            assertEquals(Mpq.ERROR_EXIST,
                         org.junit.jupiter.api.Assertions.assertThrows(
                             LibmpqException.class, () -> archive.fileNumber("missing"))
                             .code());
        }
    }
}
