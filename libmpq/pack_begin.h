/*
 *  pack_begin.h -- header file for struct packing used by libmpq.
 *
 *  Copyright (c) 2010-2011 Georg Lukas <georg@op-co.de>
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

#ifndef _PACK_BEGIN
#define _PACK_BEGIN
#else
#error "pack_begin.h may not be included twice!"
#endif

#ifdef _MSC_VER
  #pragma pack(push,1)
  #define PACK_STRUCT
#else
  /* we assume GNU here */
  #define PACK_STRUCT __attribute__((packed))
#endif

