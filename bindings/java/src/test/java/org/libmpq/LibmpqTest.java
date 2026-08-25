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
        assertEquals(16, LibmpqNative.ARCHIVE_OPTIONS.byteSize());
        assertEquals(16, LibmpqNative.FILE_OPTIONS.byteSize());
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
            assertTrue(new String(data, StandardCharsets.UTF_8).contains("libmpq"));
            assertTrue(archive.fileCount() > 0);
        }
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
                        FileOptions.compressed(Mpq.COMPRESSION_ZLIB, Mpq.COMPRESSION_ZLIB));
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
            assertArrayEquals("path payload".getBytes(StandardCharsets.UTF_8),
                              archive.readFile(archive.fileNumber("source.txt")));
        }
    }

    /** Exercises streaming finalization and missing-file error propagation. */
    @Test
    void streamsAndRejectsMissingFile(@TempDir Path directory) throws Exception {
        Path path = directory.resolve("stream.mpq");
        byte[] payload = "streamed".getBytes(StandardCharsets.UTF_8);
        try (Archive archive = Archive.create(path, ArchiveCreateOptions.v1())) {
            try (MpqFileWriter writer = archive.begin("stream.txt", payload.length, FileOptions.raw())) {
                writer.write(payload);
            }
        }
        try (Archive archive = Archive.open(path)) {
            assertEquals(Mpq.ERROR_EXIST,
                         org.junit.jupiter.api.Assertions.assertThrows(
                             LibmpqException.class, () -> archive.fileNumber("missing"))
                             .code());
        }
    }
}
