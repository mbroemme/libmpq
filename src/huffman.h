/*
 *  huffman.h -- adaptive Huffman decompression structures and helpers.
 *
 *  Copyright (c) 2003-2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This source was adapted from the C++ version of huffman.h included
 *  in stormlib. The C++ version belongs to the following authors:
 *
 *  Ladislav Zezula <ladik@zezula.net>
 *  ShadowFlare <BlakFlare@hotmail.com>
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

#ifndef _HUFFMAN_H
#define _HUFFMAN_H

/* Initialize the Huffman tree for decompression. */
#define LIBMPQ_HUFF_DECOMPRESS 0

/* Convert the encoded pointer values used by the original Huffman layout. */
#define PTR_NOT(ptr) (struct huffman_tree_item_s *)(~(unsigned long)(ptr))
#define PTR_PTR(ptr) ((struct huffman_tree_item_s *)(ptr))
#define PTR_INT(ptr) (long)(ptr)

/* Huffman linked-list update operations. */
#define INSERT_ITEM 1  /* Insert a new item into the list. */
#define SWITCH_ITEMS 2 /* Move an existing item inside the list. */

/* Bitstream cursor used by the adaptive Huffman decoder. */
struct huffman_input_stream_s
{
    uint8_t *in_buf;  /* 00 - next unread input bytes. */
    uint32_t bit_buf; /* 04 - pending bits. */
    uint32_t bits;    /* 08 - number of valid bits in bit_buf. */
};

/* Node stored in the adaptive Huffman tree and linked frequency list. */
struct huffman_tree_item_s
{
    struct huffman_tree_item_s *next;   /* 00 - next item in frequency order. */
    struct huffman_tree_item_s *prev;   /* 04 - previous item or encoded sentinel. */
    uint32_t dcmp_byte;                 /* 08 - decoded symbol represented by this node. */
    uint32_t byte_value;                /* 0C - adaptive symbol weight. */
    struct huffman_tree_item_s *parent; /* 10 - parent tree node. */
    struct huffman_tree_item_s *child;  /* 14 - first child tree node. */
};

/* Cache entry for resolving short Huffman prefixes without walking the tree. */
struct huffman_decompress_s
{
    uint32_t offs00; /* 00 - tree update generation for this cache entry. */
    uint32_t bits;   /* 04 - Bits represented by this entry. */
    union
    {
        uint32_t dcmp_byte;                 /* 08 - decoded symbol for short prefixes. */
        struct huffman_tree_item_s *p_item; /* 08 - resume node for longer prefixes. */
    };
};

/* Adaptive Huffman tree state and quick-decode cache. */
struct huffman_tree_s
{
    uint32_t cmp0;                                /* 0000 - true for compression type 0. */
    uint32_t offs0004;                            /* 0004 - tree update generation. */
    struct huffman_tree_item_s items0008[0x203];  /* 0008 - static node pool. */
    struct huffman_tree_item_s *item3050;         /* 3050 - encoded sentinel storage. */
    struct huffman_tree_item_s *item3054;         /* 3054 - current sentinel item. */
    struct huffman_tree_item_s *item3058;         /* 3058 - next reusable item or sentinel. */
    struct huffman_tree_item_s *item305C;         /* 305C - insertion scratch pointer. */
    struct huffman_tree_item_s *first;            /* 3060 - head sentinel for frequency list. */
    struct huffman_tree_item_s *last;             /* 3064 - tail sentinel for frequency list. */
    uint32_t items;                               /* 3068 - number of nodes used from the pool. */
    struct huffman_tree_item_s *items306C[0x102]; /* 306C - symbol-to-node lookup table. */
    struct huffman_decompress_s qd3474[0x80];     /* 3474 - seven-bit quick-decode cache. */
    uint8_t table_1502A630[];                     /* Initial weight table appended by layout. */
};

/* Insert or move an item inside the adaptive Huffman frequency list. */
void libmpq__huffman_insert_item(
    struct huffman_tree_item_s **p_item, struct huffman_tree_item_s *item, uint32_t where,
    struct huffman_tree_item_s *item2
);

/* Remove an item from the adaptive Huffman frequency list. */
void libmpq__huffman_remove_item(struct huffman_tree_item_s *hi);

/* Resolve the previous Huffman item, including encoded relative links. */
struct huffman_tree_item_s *
libmpq__huffman_previous_item(struct huffman_tree_item_s *hi, long value);

/* Read one bit from the Huffman input stream. */
uint32_t libmpq__huffman_get_1bit(struct huffman_input_stream_s *is);

/* Peek at the next seven bits without consuming them. */
uint32_t libmpq__huffman_get_7bit(struct huffman_input_stream_s *is);

/* Read one byte from the Huffman input stream. */
uint32_t libmpq__huffman_get_8bit(struct huffman_input_stream_s *is);

/* Allocate or recycle a Huffman tree item and move it to the front list. */
struct huffman_tree_item_s *libmpq__huffman_call_1500E740(struct huffman_tree_s *ht);

/* Increase adaptive Huffman weights and reorder affected items. */
void libmpq__huffman_call_1500E820(struct huffman_tree_s *ht, struct huffman_tree_item_s *p_item);

/* Initialize the adaptive Huffman tree and clear lookup tables. */
void libmpq__huffman_tree_init(struct huffman_tree_s *ht, uint32_t cmp);

/* Build the adaptive Huffman tree for the selected compression type. */
void libmpq__huffman_tree_build(struct huffman_tree_s *ht, uint32_t cmp_type);

/* Decode a Huffman bitstream into the caller-provided output buffer. */
int32_t libmpq__do_decompress_huffman(
    struct huffman_tree_s *ht, struct huffman_input_stream_s *is, uint8_t *out_buf,
    uint32_t out_length
);

#endif /* _HUFFMAN_H */
