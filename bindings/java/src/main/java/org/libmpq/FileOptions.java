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
 * Immutable options controlling how one file is stored in an MPQ archive.
 * Compression masks use the native MPQ bit assignments exposed by
 * {@link Mpq}; the first mask applies to the first sector and the next mask
 * applies to subsequent sectors.
 *
 * @param flags MPQ file flags such as compression and encryption
 * @param compressionFirst compression mask for the first sector
 * @param compressionNext compression mask for later sectors
 * @param locale MPQ locale identifier stored in the block-table entry
 * @param platform MPQ platform identifier stored in the block-table entry
 */
public record FileOptions(int flags, int compressionFirst, int compressionNext,
                          int locale, int platform) {
    /**
     * Returns options for raw, unencrypted, sectorized storage.  This is the
     * safest default for payloads that do not require MPQ compression.
     */
    public static FileOptions raw() {
        return new FileOptions(0, 0, 0, 0, 0);
    }

    /**
     * Returns options requesting MPQ multi-compression for the first and
     * subsequent sectors.  The native writer may reject unsupported codec
     * combinations and reports the documented libmpq error code.
     *
     * @param firstMask compression mask for the first sector
     * @param nextMask compression mask for subsequent sectors
     */
    public static FileOptions compressed(int firstMask, int nextMask) {
        return new FileOptions(0x00000200, firstMask, nextMask, 0, 0);
    }

    /**
     * Returns a copy of these options with MPQ encryption enabled while
     * preserving compression, locale, and platform settings.
     */
    public FileOptions encrypted() {
        return new FileOptions(flags | 0x00010000, compressionFirst, compressionNext,
                               locale, platform);
    }
}
