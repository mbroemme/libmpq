/*
 *  test-mpq-consumer.c -- installed public library smoke test.
 *
 *  Copyright (c) 2003-2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This file is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this file; if not, see <https://www.gnu.org/licenses/>.
 */

#include <libmpq/mpq.h>
#include <stdio.h>
#include <string.h>

int
main(int argc, char **argv)
{
    const char *version = libmpq__version();
    libmpq__off_t payload_size = -1;
    libmpq__off_t transferred = -1;

    if (version == NULL || (argc != 2 && argc != 3) || strcmp(version, argv[1]) != 0)
        return 1;

    /* Exercise the import library, not private objects linked into native tests. */
    if (libmpq__patch_payload_size(NULL, 0, &payload_size) != LIBMPQ_ERROR_EXIST ||
        payload_size != 0 ||
        libmpq__patch_payload_read(NULL, 0, NULL, NULL, 0, &transferred) != LIBMPQ_ERROR_EXIST ||
        transferred != 0)
        return 1;
    if (argc == 3) {
        mpq_archive_s *archive = NULL;

        if (libmpq__archive_open(&archive, argv[2], -1) != 0)
            return 1;
        if (libmpq__archive_close(archive) != 0)
            return 1;
    }
    puts(version);
    return 0;
}
