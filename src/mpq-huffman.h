/*
 *  mpq-huffman.h -- adaptive Huffman decompression structures and helpers.
 *
 *  Copyright (c) 2003-2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This source was adapted from the C++ version of mpq-huffman.h included
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

#ifndef LIBMPQ_HUFFMAN_H
#define LIBMPQ_HUFFMAN_H

#include <stdint.h>

/*
 * Select the initial adaptive Huffman model. The value is passed to the tree
 * initializer and is not itself serialized as an MPQ compression mask: zero
 * selects the model used while decoding an archive stream, while one selects
 * the corresponding encoder model.
 */

/* Initialize the adaptive tree for decoding compressed input. */
#define LIBMPQ_HUFF_DECOMPRESS 0

/* Initialize the adaptive tree for encoding uncompressed input. */
#define LIBMPQ_HUFF_COMPRESS 1

/*
 * Convert the encoded pointer values used by the original Huffman layout.
 * The imported algorithm stores some linked-list references as either normal
 * pointers or bitwise-complemented pointer values. PTR_NOT restores or
 * creates the complemented representation, PTR_PTR preserves a normal
 * pointer representation, and PTR_INT exposes the encoded value for the
 * sign and sentinel tests used by the compatibility implementation.
 */
#define PTR_NOT(ptr) (struct huffman_tree_item_s *)(~(unsigned long)(ptr))
#define PTR_PTR(ptr) ((struct huffman_tree_item_s *)(ptr))
#define PTR_INT(ptr) (long)(ptr)

/*
 * Operations accepted by libmpq__huffman_insert_item(). The first operation
 * links a newly allocated node into the adaptive frequency list; the second
 * relocates an existing node after its weight changes. These values are
 * internal operation codes and are not part of the serialized stream.
 */

/* Insert a new item into the adaptive frequency list. */
#define INSERT_ITEM 1

/* Move an existing item to its new frequency-list position. */
#define SWITCH_ITEMS 2

/* Bitstream cursor used by the adaptive Huffman decoder. */
struct huffman_input_stream_s
{
    const uint8_t *in_buf; /* next unread input byte. */
    const uint8_t *in_end; /* one byte past the compressed input. */
    uint32_t bit_buf;      /* pending bits. */
    uint32_t bits;         /* number of valid bits in bit_buf. */
    int failed;            /* nonzero after input exhaustion. */
};

struct huffman_output_stream_s
{
    uint8_t *out_buf;
    uint32_t out_pos;
    uint32_t bit_buf;
    uint32_t bits;
    uint32_t capacity;
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
    uint32_t tree_update_generation; /* 00 - tree update generation for this cache entry. */
    uint32_t bits;                   /* 04 - Bits represented by this entry. */
    union huffman_decode_value_u
    {
        uint32_t dcmp_byte;                 /* 08 - decoded symbol for short prefixes. */
        struct huffman_tree_item_s *p_item; /* 08 - resume node for longer prefixes. */
    } value;
};

/* Adaptive Huffman tree state and quick-decode cache. */
struct huffman_tree_s
{
    uint32_t compression_type_zero;                 /* 0000 - true for compression type 0. */
    uint32_t tree_update_generation;                /* 0004 - tree update generation. */
    struct huffman_tree_item_s node_pool[0x203];    /* 0008 - static node pool. */
    struct huffman_tree_item_s *encoded_sentinel;   /* 3050 - encoded sentinel storage. */
    struct huffman_tree_item_s *current_sentinel;   /* 3054 - current sentinel item. */
    struct huffman_tree_item_s *next_reusable_item; /* 3058 - next reusable item or sentinel. */
    struct huffman_tree_item_s *insertion_scratch;  /* 305C - insertion scratch pointer. */
    struct huffman_tree_item_s *first;              /* 3060 - head sentinel for frequency list. */
    struct huffman_tree_item_s *last;               /* 3064 - tail sentinel for frequency list. */
    uint32_t items;                                 /* 3068 - number of nodes used from the pool. */
    struct huffman_tree_item_s *symbol_nodes[0x102];      /* 306C - symbol-to-node lookup table. */
    struct huffman_decompress_s quick_decode_cache[0x80]; /* 3474 - seven-bit quick-decode cache. */
    uint8_t huffman_initial_weights[]; /* Initial weight table appended by layout. */
};

/*
 * Insert or move item inside the adaptive Huffman frequency list. where is
 * INSERT_ITEM for a new node or SWITCH_ITEMS for an existing node; item2 is
 * the neighboring list item when required. The tree owns no heap storage for
 * item and the operation preserves the encoded sentinel links in ht.
 */
void libmpq__huffman_insert_item(
    struct huffman_tree_s *ht, struct huffman_tree_item_s *item, uint32_t where,
    struct huffman_tree_item_s *item2
);

/* Remove item from ht's frequency list without releasing its fixed-pool slot. */
void libmpq__huffman_remove_item(struct huffman_tree_s *ht, struct huffman_tree_item_s *hi);

/* Resolve a previous item from an encoded link and caller-supplied relative offset. */
struct huffman_tree_item_s *
libmpq__huffman_previous_item(struct huffman_tree_item_s *hi, long value);

/* Consume and return one low-order bit from the bounded input range. */
uint32_t libmpq__huffman_read_bit(struct huffman_input_stream_s *is);

/* Return the next seven low-order bits without advancing the input cursor. */
uint32_t libmpq__huffman_peek_seven_bits(struct huffman_input_stream_s *is);

/* Consume and return one low-order byte, refilling the bit accumulator as needed. */
uint32_t libmpq__huffman_read_byte(struct huffman_input_stream_s *is);

/* Acquire a fixed-pool node, recycle an exhausted node when necessary, and link it. */
struct huffman_tree_item_s *libmpq__huffman_acquire_item(struct huffman_tree_s *ht);

/* Increase item and ancestor weights while restoring frequency-list order. */
void libmpq__huffman_update_weights(struct huffman_tree_s *ht, struct huffman_tree_item_s *p_item);

/* Reset tree state, sentinels, node-pool cursors, and decoder cache for cmp. */
void libmpq__huffman_tree_init(struct huffman_tree_s *ht, uint32_t cmp);

/* Populate the adaptive tree from the initial weight table selected by cmp_type. */
void libmpq__huffman_tree_build(struct huffman_tree_s *ht, uint32_t cmp_type);

/*
 * Decode input into out_buf until the requested byte count or end marker is
 * reached. Buffers remain caller-owned; the return value is bytes written, or
 * zero when the stream cannot produce a valid symbol sequence.
 */
int32_t libmpq__huffman_decode(
    struct huffman_tree_s *ht, struct huffman_input_stream_s *is, uint8_t *out_buf,
    uint32_t out_length
);

/*
 * Encode in_buf into an MPQ adaptive-Huffman stream in os. The output stream
 * must provide at least four bytes of capacity and remains caller-owned; the
 * return value is bytes produced or a negative libmpq error on invalid input
 * or insufficient capacity.
 */
int32_t libmpq__huffman_encode(
    struct huffman_tree_s *ht, struct huffman_output_stream_s *os, const uint8_t *in_buf,
    uint32_t in_length
);

#endif /* LIBMPQ_HUFFMAN_H */
