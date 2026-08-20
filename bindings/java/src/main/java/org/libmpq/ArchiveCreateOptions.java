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
 * Immutable options passed to {@link Archive#create}.  The version field uses
 * libmpq's creation selectors: zero requests the v1 layout and one requests
 * the v2 layout.  The resulting archive reports its public format version as
 * one or two, respectively.
 */
public record ArchiveCreateOptions(int version, long maxFiles, long sectorSize, int flags) {
    /**
     * Returns options that let libmpq choose its default archive version,
     * hash-table capacity, sector size, and creation flags.
     */
    public static ArchiveCreateOptions defaults() {
        return new ArchiveCreateOptions(0, 0, 0, 0);
    }

    /**
     * Returns options for a v1 archive while retaining libmpq's default
     * capacity, sector size, and creation flags.
     */
    public static ArchiveCreateOptions v1() {
        return defaults();
    }

    /**
     * Returns options for a v2 archive while retaining libmpq's default
     * capacity, sector size, and creation flags.
     */
    public static ArchiveCreateOptions v2() {
        return new ArchiveCreateOptions(1, 0, 0, 0);
    }
}
