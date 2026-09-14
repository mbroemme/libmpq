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

    if (version == NULL || argc != 2 || strcmp(version, argv[1]) != 0)
        return 1;
    puts(version);
    return 0;
}
