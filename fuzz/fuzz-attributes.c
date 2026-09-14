/* Bounded parser and serializer coverage for optional MPQ attributes. */
#include "mpq-attributes.h"

#include <stdlib.h>
#include <string.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mpq_attributes_s view;
    mpq_file_attributes_s entries[32] = { 0 };
    uint8_t *serialized = NULL;
    size_t serialized_size = 0;
    uint32_t count;
    uint32_t self;
    uint32_t i;
    uint32_t flags;

    if (size < 2 || size > 4096)
        return 0;
    count = 1 + data[0] % 32;
    self = data[1] % count;
    if (libmpq__attributes_parse(data + 2, size - 2, count, self, &view) != 0)
        return 0;
    flags = view.flags;
    for (i = 0; i < count; ++i) {
        libmpq__attributes_get(&view, i, &entries[i]);
        entries[i].patch_bit = 0;
    }
    if (libmpq__attributes_serialize(entries, count, self, flags, &serialized, &serialized_size) !=
        0)
        abort();
    if (libmpq__attributes_parse(serialized, serialized_size, count, self, &view) != 0)
        abort();
    for (i = 0; i < count; ++i) {
        mpq_file_attributes_s actual;
        libmpq__attributes_get(&view, i, &actual);
        if (i != self &&
            ((flags & LIBMPQ_ATTRIBUTE_CRC32 && actual.crc32 != entries[i].crc32) ||
             (flags & LIBMPQ_ATTRIBUTE_FILETIME && actual.filetime != entries[i].filetime) ||
             (flags & LIBMPQ_ATTRIBUTE_MD5 && memcmp(actual.md5, entries[i].md5, 16) != 0)))
            abort();
    }
    free(serialized);
    return 0;
}
