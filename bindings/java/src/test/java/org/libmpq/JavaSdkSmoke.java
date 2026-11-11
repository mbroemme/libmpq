/* SPDX-License-Identifier: LGPL-2.1-or-later */

package org.libmpq;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

final class JavaSdkSmoke {
    private static final String MEMBER = "payload.txt";
    private static final byte[] PAYLOAD = "libmpq SDK smoke\n".getBytes(StandardCharsets.US_ASCII);

    public static void main(String[] args) throws Exception {
        String architecture = switch (System.getProperty("os.arch")) {
            case "amd64", "x64", "x86_64" -> "x86_64";
            case "arm64", "aarch64" -> "aarch64";
            default -> throw new AssertionError("Unexpected JVM architecture");
        };
        check(args[1].equals(architecture), "JVM architecture mismatch: " + architecture);
        String version = Mpq.version();
        check(args[0].equals(version), "Native version mismatch: " + version);

        Path path = Path.of("sdk-smoke.mpq");
        try {
            try (Archive writer = Archive.create(path,
                    new ArchiveCreateOptions(Mpq.ARCHIVE_VERSION_FOUR, 8, 4096, 0))) {
                writer.addData(MEMBER, PAYLOAD, null);
            }
            try (Archive archive = Archive.open(path)) {
                check(Arrays.equals(PAYLOAD, archive.readFile(archive.fileNumber(MEMBER))),
                        "Filesystem archive payload mismatch");
                try {
                    archive.fileNumber("missing.txt");
                    throw new AssertionError("Missing member lookup succeeded");
                } catch (LibmpqException error) {
                    check(error.code() == Mpq.ERROR_EXIST, "Wrong missing member status: " + error.code());
                }
            }
            try (SeekableByteChannel source = Files.newByteChannel(path)) {
                source.position(3);
                try (Archive archive = Archive.openSource(source, "positioned-sdk-source");
                        Arena arena = Arena.ofConfined()) {
                    MemorySegment destination = arena.allocate(PAYLOAD.length);
                    long transferred = archive.readFile(archive.fileNumber(MEMBER), destination);
                    check(transferred == PAYLOAD.length, "Wrong transfer count: " + transferred);
                    check(Arrays.equals(PAYLOAD, destination.toArray(ValueLayout.JAVA_BYTE)),
                            "Positioned source payload mismatch");
                }
                check(source.position() == 3, "Source cursor or ownership changed");
            }
        } finally {
            Files.deleteIfExists(path);
        }
        System.out.printf("libmpq %s %s SDK smoke passed%n", version, architecture);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
