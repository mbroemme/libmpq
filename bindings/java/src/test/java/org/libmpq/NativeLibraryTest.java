/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */
package org.libmpq;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Linker;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercise library discovery in fresh JVMs because the FFM facade initializes once. */
class NativeLibraryTest {
    @Test
    void usesOneLogicalNameForEveryOs(@TempDir Path directory) throws Exception {
        Files.copy(configuredLibrary(), directory.resolve(System.mapLibraryName("mpq")));
        for (String osName : List.of("Linux", "Mac OS X", "Windows 11")) {
            assertLoaded(run(directory, osName, null));
        }
    }

    @Test
    void missingCanonicalLibraryDoesNotFallBack(@TempDir Path directory) throws Exception {
        Path library = configuredLibrary();
        Files.copy(library, directory.resolve(System.mapLibraryName("libmpq")));
        Files.copy(library, directory.resolve(System.mapLibraryName("libmpq-4")));
        Result result = run(directory, "Windows 11", null);
        assertNotEquals(0, result.exitCode(), result.output());
        assertTrue(result.output().contains("UnsatisfiedLinkError"), result.output());
        assertTrue(result.output().contains("no mpq in java.library.path"), result.output());
    }

    @Test
    void explicitPathTakesPrecedence(@TempDir Path directory) throws Exception {
        Path library = configuredLibrary();
        assertLoaded(run(directory, "Windows 11", library));

        Files.copy(library, directory.resolve(System.mapLibraryName("mpq")));
        Path missing = directory.resolve("missing-library");
        Result result = run(directory, "Windows 11", missing);
        assertNotEquals(0, result.exitCode(), result.output());
        assertTrue(result.output().contains("IllegalArgumentException"), result.output());
        assertTrue(result.output().contains(missing.toString()), result.output());
    }

    private static Path configuredLibrary() {
        String path = System.getProperty("org.libmpq.library");
        Assumptions.assumeTrue(path != null && !path.isBlank(), "requires org.libmpq.library");
        return Path.of(path).toAbsolutePath();
    }

    private static void assertLoaded(Result result) {
        assertEquals(0, result.exitCode(), result.output());
        assertTrue(result.output().lines().anyMatch(line -> line.equals("libmpq " + Mpq.version())),
                   result.output());
    }

    private static Result run(Path directory, String osName, Path explicit) throws Exception {
        String classPath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        var command = new ArrayList<>(List.of(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "--enable-native-access=ALL-UNNAMED", "-cp", classPath,
            "-Djava.library.path=" + directory
        ));
        if (explicit != null) {
            command.add("-Dorg.libmpq.library=" + explicit);
        }
        command.add(NativeLibraryTest.class.getName());
        command.add(osName);

        Path output = directory.resolve("loader.log");
        Process process = new ProcessBuilder(command).redirectErrorStream(true)
            .redirectOutput(output.toFile()).start();
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "library probe timed out");
            return new Result(process.exitValue(), Files.readString(output));
        } finally {
            process.destroyForcibly();
        }
    }

    private record Result(int exitCode, String output) { }

    public static void main(String[] args) {
        // Select the real host ABI before simulating the facade's OS selection.
        Linker.nativeLinker();
        System.setProperty("os.name", args[0]);
        System.out.println("libmpq " + Mpq.version());
    }
}
