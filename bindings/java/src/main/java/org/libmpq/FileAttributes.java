/* Copyright (c) 2026 Maik Broemme. LGPL-2.1-or-later. */
package org.libmpq;

/** Stored optional metadata. FILETIME is an unsigned 64-bit bit pattern, not Java time.
 * Flags distinguish unavailable values from zero; hashes are not authentication. */
public record FileAttributes(int flags, long crc32, long filetime, byte[] md5, boolean patchBit) {
    /** Retain owned bytes, never native memory or the caller's mutable array. */
    public FileAttributes {
        md5 = md5.clone();
    }

    /** Return an independent copy of the stored MD5 bytes. */
    @Override
    public byte[] md5() {
        return md5.clone();
    }
}
