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
import java.nio.file.Files;
import java.nio.file.Path;
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
                    assertArrayEquals(expected, mpqe.readFile(mpqe.fileNumber(member)));
                    Archive.BlockVerification sector = raw.verifyBlock(raw.fileNumber(member), 0);
                    assertTrue(sector.checksum() > 0 && sector.checksum() < 0xffffffffL);
                    assertEquals(0, sector.mismatches());
                    assertEquals(sector, mpqe.verifyBlock(mpqe.fileNumber(member), 0));
                }
                assertEquals(Mpq.ERROR_EXIST, assertThrows(LibmpqException.class,
                    () -> raw.verifyBlock(raw.fileNumber("overview.txt"), 0)).code());
                assertEquals(Mpq.ERROR_EXIST, assertThrows(LibmpqException.class,
                    () -> raw.verifyBlock(raw.fileNumber("sparse.txt"), -1)).code());
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
            assertEquals(7, archive.attributesFlags().orElseThrow());
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
            assertEquals(Mpq.ATTRIBUTE_CRC32, archive.attributesFlags().orElseThrow());
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
