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
 * Immutable snapshot of one public MPQ file entry.  The offset is relative
 * to the archive's backing file, while sizes describe the stored and logical
 * representations of the entry.
 *
 * @param packedSize stored payload size, including sector metadata where
 * applicable
 * @param unpackedSize logical file size after decompression
 * @param offset archive-relative payload offset
 * @param blocks number of logical sectors used by the file
 * @param encrypted whether the payload is encrypted
 * @param compressed whether MPQ multi-compression is enabled
 * @param imploded whether standalone PKWARE implode is enabled
 */
public record FileMetadata(long packedSize, long unpackedSize, long offset, long blocks,
                           boolean encrypted, boolean compressed, boolean imploded) { }
