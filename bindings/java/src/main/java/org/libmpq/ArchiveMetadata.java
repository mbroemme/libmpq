/*
 * Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */
package org.libmpq;

/**
 * Immutable snapshot of metadata obtained from one MPQ archive.  Sizes and
 * offsets are represented as Java {@code long} values because the native API
 * exposes 64-bit quantities; {@code version} and {@code fileCount} contain
 * unsigned 32-bit values widened to Java.
 *
 * @param packedSize sum of the stored file payload sizes
 * @param unpackedSize sum of the logical file sizes
 * @param offset archive header offset in the backing file
 * @param version public archive format version, normally one or two
 * @param fileCount number of public file entries
 */
public record ArchiveMetadata(long packedSize, long unpackedSize, long offset,
                              long version, long fileCount) { }
