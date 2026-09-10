/* Optional attributes, explicit metadata, and physical block indexing. */
#include "mpq-attributes.h"
#include "mpq-endian.h"
#include "mpq-internal.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            test_failure(__FILE__, __LINE__, #condition);                                          \
            result = 1;                                                                            \
            goto cleanup;                                                                          \
        }                                                                                          \
    } while (0)

static const uint8_t code[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
static const uint8_t digest_digits[16] = { 0x25, 0xf9, 0xe7, 0x94, 0x32, 0x3b, 0x45, 0x38,
                                           0x85, 0xf5, 0x18, 0x1f, 0x1b, 0x62, 0x4d, 0x0b };

static int
test_layouts(void)
{
    mpq_attributes_s view;
    mpq_file_attributes_s entry;
    uint8_t raw[1024] = { 0 };
    uint32_t flags;
    size_t length;

    for (flags = 0; flags < 16; ++flags) {
        libmpq__store_le32(raw, 100);
        libmpq__store_le32(raw + 4, flags);
        length = 8 + ((flags & 1) ? 36 : 0) + ((flags & 2) ? 72 : 0) + ((flags & 4) ? 144 : 0) +
                 ((flags & 8) ? 2 : 0);
        TEST_CHECK(libmpq__attributes_parse(raw, length, 9, 8, &view) == 0);
        TEST_CHECK(view.entries == 9 && view.flags == flags);
        TEST_CHECK(libmpq__attributes_parse(raw, length + 1, 9, 8, &view) == LIBMPQ_ERROR_FORMAT);
    }
    libmpq__store_le32(raw + 4, 8);
    raw[8] = 0x81;
    raw[9] = 0x80;
    TEST_CHECK(libmpq__attributes_parse(raw, 10, 9, 8, &view) == 0);
    libmpq__attributes_get(&view, 0, &entry);
    TEST_CHECK(entry.flags == 8 && entry.patch_bit == 1);
    libmpq__attributes_get(&view, 7, &entry);
    TEST_CHECK(entry.patch_bit == 1);
    libmpq__attributes_get(&view, 8, &entry);
    TEST_CHECK(entry.patch_bit == 1);
    TEST_CHECK(libmpq__attributes_parse(raw, 9, 9, 8, &view) == 0);
    libmpq__attributes_get(&view, 8, &entry);
    TEST_CHECK(entry.patch_bit == 0 && entry.flags == 8);

    /* Missing patch data and the historical all-zero DWORD region are not bits. */
    TEST_CHECK(libmpq__attributes_parse(raw, 8, 9, 8, &view) == 0);
    libmpq__attributes_get(&view, 0, &entry);
    TEST_CHECK(entry.flags == 0);
    memset(raw + 8, 0, sizeof(raw) - 8);
    TEST_CHECK(libmpq__attributes_parse(raw, 44, 9, 8, &view) == 0);
    libmpq__attributes_get(&view, 0, &entry);
    TEST_CHECK(entry.flags == 0);
    raw[10] = 1;
    TEST_CHECK(libmpq__attributes_parse(raw, 44, 9, 8, &view) == LIBMPQ_ERROR_FORMAT);
    memset(raw + 8, 0, sizeof(raw) - 8);
    libmpq__store_le32(raw + 4, 1);
    TEST_CHECK(libmpq__attributes_parse(raw, 40, 9, 8, &view) == 0);
    TEST_CHECK(view.entries == 8);
    libmpq__attributes_get(&view, 8, &entry);
    TEST_CHECK(entry.flags == 0);
    for (length = 0; length < 8; ++length)
        TEST_CHECK(libmpq__attributes_parse(raw, length, 9, 8, &view) == LIBMPQ_ERROR_FORMAT);
    libmpq__store_le32(raw, 1);
    TEST_CHECK(libmpq__attributes_parse(raw, 44, 9, 8, &view) == LIBMPQ_ERROR_FORMAT);
    libmpq__store_le32(raw, 100);
    libmpq__store_le32(raw + 4, 16);
    TEST_CHECK(libmpq__attributes_parse(raw, 44, 9, 8, &view) == LIBMPQ_ERROR_FORMAT);
    libmpq__store_le32(raw + 4, 7);
    TEST_CHECK(
        libmpq__attributes_parse(raw, sizeof(raw), UINT32_MAX, 0, &view) == LIBMPQ_ERROR_FORMAT
    );
    return 0;
}

static int
test_roundtrip(uint32_t version, uint32_t flags, int mpqe)
{
    mpq_archive_s *archive = NULL;
    mpq_archive_s *clone = NULL;
    mpq_writer_s *writer = NULL;
    mpq_archive_create_options_s options = { version, 9, 512, LIBMPQ_ARCHIVE_CREATE_LISTFILE,
                                             flags };
    mpq_file_options_s file = { LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED,
                                LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_file_attributes_s attributes;
    char path[256] = { 0 };
    uint8_t output[9];
    uint8_t *raw = NULL;
    size_t size;
    uint32_t number;
    uint32_t found;
    libmpq__off_t transferred = 0;
    int32_t status;
    int result = 0;

    REQUIRE(test_temp_path(path, sizeof(path), "attributes") == 0);
    if (mpqe)
        status = libmpq__archive_create_mpqe(&archive, path, code, sizeof(code) - 1, &options);
    else
        status = libmpq__archive_create(&archive, path, &options);
    REQUIRE(status == 0);
    REQUIRE(libmpq__archive_attributes_flags(archive, &found) == LIBMPQ_ERROR_NOT_INITIALIZED);
    REQUIRE(libmpq__file_begin(archive, "digits.txt", 9, &file, &writer) == 0);
    REQUIRE(
        libmpq__file_set_filetime(writer, UINT64_C(0xfedcba9876543210)) ==
        ((flags & 2) ? 0 : LIBMPQ_ERROR_FORMAT)
    );
    REQUIRE(libmpq__file_write(writer, (const uint8_t *)"1234", 4) == 0);
    REQUIRE(libmpq__file_write(writer, (const uint8_t *)"56789", 5) == 0);
    status = libmpq__file_finish(writer);
    writer = NULL;
    REQUIRE(status == 0);
    REQUIRE(libmpq__file_add(archive, "empty.txt", NULL, 0, NULL) == 0);
    if (flags != 0)
        REQUIRE(libmpq__file_add(archive, "(ATTRIBUTES)", NULL, 0, NULL) == LIBMPQ_ERROR_FORMAT);
    status = libmpq__archive_close(archive);
    archive = NULL;
    REQUIRE(status == 0);
    if (mpqe)
        status = libmpq__archive_open_mpqe(&archive, path, -1, code, sizeof(code) - 1);
    else
        status = libmpq__archive_open(&archive, path, -1);
    REQUIRE(status == 0);
    REQUIRE(libmpq__archive_attributes_flags(archive, &found) == (flags ? 0 : LIBMPQ_ERROR_EXIST));
    if (version == LIBMPQ_ARCHIVE_VERSION_ONE && flags != 0)
        REQUIRE(archive->mpq_header.hash_table_offset > archive->mpq_header.header_size);
    REQUIRE(found == flags);
    REQUIRE(libmpq__file_number(archive, "digits.txt", &number) == 0);
    REQUIRE(
        libmpq__file_attributes(archive, number, &attributes) == (flags ? 0 : LIBMPQ_ERROR_EXIST)
    );
    REQUIRE(attributes.flags == flags);
    REQUIRE(memcmp(attributes.reserved, "\0\0\0\0", sizeof(attributes.reserved)) == 0);
    if (flags & 1)
        REQUIRE(attributes.crc32 == 0xcbf43926u);
    if (flags & 2)
        REQUIRE(attributes.filetime == UINT64_C(0xfedcba9876543210));
    if (flags & 4)
        REQUIRE(memcmp(attributes.md5, digest_digits, 16) == 0);
    REQUIRE(attributes.patch_bit == 0);
    found = UINT32_MAX;
    REQUIRE(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &found) ==
        (flags ? 0 : LIBMPQ_ERROR_EXIST)
    );
    REQUIRE(found == 0);
    REQUIRE(libmpq__file_verify(archive, number, 0, &found) == 0 && found == 0);
    REQUIRE(libmpq__file_verify(archive, number, 8, &found) == LIBMPQ_ERROR_FORMAT && found == 0);
    REQUIRE(libmpq__file_read(archive, number, output, sizeof(output), &transferred) == 0);
    REQUIRE(transferred == 9 && memcmp(output, "123456789", 9) == 0);
    REQUIRE(libmpq__file_number(archive, "empty.txt", &number) == 0);
    found = UINT32_MAX;
    REQUIRE(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &found) ==
        (flags ? 0 : LIBMPQ_ERROR_EXIST)
    );
    REQUIRE(found == 0);
    REQUIRE(libmpq__file_number(archive, "digits.txt", &number) == 0);
    REQUIRE(libmpq__archive_clone(&clone, archive) == 0);
    REQUIRE(libmpq__archive_close(archive) == 0);
    archive = NULL;
    REQUIRE(
        libmpq__file_attributes(clone, number, &attributes) == (flags ? 0 : LIBMPQ_ERROR_EXIST)
    );
    if (flags != 0) {
        mpq_attributes_s view;
        REQUIRE(libmpq__file_number(clone, "(attributes)", &number) == 0);
        REQUIRE(test_archive_read(clone, number, &raw, &size) == 0);
        REQUIRE(libmpq__attributes_parse(raw, size, 9, 3, &view) == 0);
        for (number = 3; number < 9; ++number) {
            uint8_t zero[16] = { 0 };
            libmpq__attributes_get(&view, number, &attributes);
            REQUIRE(attributes.crc32 == 0 && attributes.filetime == 0 && attributes.patch_bit == 0);
            REQUIRE(memcmp(attributes.md5, zero, 16) == 0);
        }
    }
cleanup:
    free(raw);
    if (writer != NULL)
        (void)libmpq__file_finish(writer);
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (clone != NULL)
        (void)libmpq__archive_close(clone);
    if (path[0] != 0)
        unlink(path);
    return result;
}

/* Manually supplied metadata covers holes, encryption, and malformed optional files. */
static int
test_manual(int malformed, uint32_t storage)
{
    mpq_archive_create_options_s options = { 0, 4, 512, 0, 0 };
    mpq_file_options_s file = { storage, 2, 2, 0, 0 };
    mpq_archive_s *archive = NULL;
    mpq_file_attributes_s attributes;
    uint8_t raw[24] = { 0 };
    uint8_t output[3];
    libmpq__off_t transferred;
    char path[256] = { 0 };
    uint32_t number;
    uint32_t flags;
    int32_t status;
    int result = 0;

    libmpq__store_le32(raw, malformed ? 101 : 100);
    libmpq__store_le32(raw + 4, 1);
    libmpq__store_le32(raw + 12, 0x12345678);
    REQUIRE(test_temp_path(path, sizeof(path), "attributes-manual") == 0);
    REQUIRE(libmpq__archive_create(&archive, path, &options) == 0);
    REQUIRE(libmpq__file_add(archive, "hole", NULL, 0, NULL) == 0);
    REQUIRE(libmpq__file_add(archive, "live", (const uint8_t *)"abc", 3, NULL) == 0);
    REQUIRE(
        libmpq__file_add(
            archive, "(attributes)", raw, !malformed && storage == 0 ? 20 : sizeof(raw), &file
        ) == 0
    );
    REQUIRE(libmpq__file_add(archive, "tail", (const uint8_t *)"abc", 3, NULL) == 0);
    archive->mpq_block[0].flags = 0;
    status = libmpq__archive_close(archive);
    archive = NULL;
    REQUIRE(status == 0);
    REQUIRE(libmpq__archive_open(&archive, path, 0) == 0);
    if ((storage & (LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_COMPRESS)) ==
        (LIBMPQ_FILE_FLAG_SINGLE | LIBMPQ_FILE_FLAG_COMPRESS)) {
        REQUIRE(libmpq__file_number(archive, "(attributes)", &number) == 0);
        REQUIRE(libmpq__block_open_offset(archive, number) == 0);
    }
    REQUIRE(libmpq__file_number(archive, "live", &number) == 0 && number == 0);
    REQUIRE(
        libmpq__archive_attributes_flags(archive, &flags) == (malformed ? LIBMPQ_ERROR_FORMAT : 0)
    );
    REQUIRE(
        libmpq__file_attributes(archive, number, &attributes) ==
        (malformed ? LIBMPQ_ERROR_FORMAT : 0)
    );
    if (!malformed)
        REQUIRE(attributes.crc32 == 0x12345678);
    flags = UINT32_MAX;
    REQUIRE(
        libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &flags) ==
        (malformed ? LIBMPQ_ERROR_FORMAT : 0)
    );
    REQUIRE(flags == (malformed ? 0 : LIBMPQ_VERIFY_FILE_CRC32));
    REQUIRE(libmpq__file_read(archive, number, output, 3, &transferred) == 0);
    REQUIRE(transferred == 3 && memcmp(output, "abc", 3) == 0);
    if (!malformed && storage == 0) {
        REQUIRE(libmpq__file_number(archive, "tail", &number) == 0);
        REQUIRE(libmpq__file_attributes(archive, number, &attributes) == 0);
        REQUIRE(attributes.flags == 0);
        flags = UINT32_MAX;
        REQUIRE(libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &flags) == 0);
        REQUIRE(flags == 0);
    }
cleanup:
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (path[0] != 0)
        unlink(path);
    return result;
}

/* Store deliberately wrong metadata without corrupting readable file contents. */
static int
test_verify(uint32_t version, uint32_t storage, uint32_t corrupt)
{
    mpq_archive_create_options_s options = { version, 4, 512, 0,
                                             LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_MD5 };
    mpq_file_options_s file = { storage, LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB, 0, 0 };
    mpq_archive_s *archive = NULL;
    uint8_t payload[4097];
    uint8_t output[4097];
    uint32_t number;
    uint32_t request;
    uint32_t bits;
    libmpq__off_t transferred;
    int32_t status;
    int result = 0;
    char path[256] = { 0 };

    memset(payload, 'a', sizeof(payload));
    if ((storage & LIBMPQ_FILE_FLAG_SINGLE) != 0)
        options.sector_size = 8192;
    REQUIRE(test_temp_path(path, sizeof(path), "verify") == 0);
    REQUIRE(libmpq__archive_create(&archive, path, &options) == 0);
    bits = UINT32_MAX;
    REQUIRE(
        libmpq__file_verify(archive, 0, LIBMPQ_VERIFY_ALL, &bits) == LIBMPQ_ERROR_NOT_INITIALIZED &&
        bits == 0
    );
    REQUIRE(libmpq__file_add(archive, "payload", payload, sizeof(payload), &file) == 0);
    if (corrupt & LIBMPQ_VERIFY_FILE_CRC32)
        archive->write_attributes[0].crc32 ^= 1;
    if (corrupt & LIBMPQ_VERIFY_FILE_MD5)
        archive->write_attributes[0].md5[0] ^= 1;
    status = libmpq__archive_close(archive);
    archive = NULL;
    REQUIRE(status == 0);
    REQUIRE(libmpq__archive_open(&archive, path, 0) == 0);
    REQUIRE(libmpq__file_number(archive, "payload", &number) == 0);
    REQUIRE(libmpq__block_open_offset(archive, number) == 0);
    for (request = 0; request <= LIBMPQ_VERIFY_ALL; ++request) {
        bits = UINT32_MAX;
        REQUIRE(libmpq__file_verify(archive, number, request, &bits) == 0);
        REQUIRE(bits == (request & corrupt));
        REQUIRE((bits & ~request) == 0);
        REQUIRE(archive->mpq_file[number]->open_count == 1);
    }
    REQUIRE(libmpq__block_close_offset(archive, number) == 0);
    REQUIRE(archive->mpq_file[number] == NULL);
    REQUIRE(libmpq__file_read(archive, number, output, sizeof(output), &transferred) == 0);
    REQUIRE(transferred == sizeof(payload) && memcmp(payload, output, sizeof(payload)) == 0);
    if (storage == 0 || (storage & LIBMPQ_FILE_FLAG_SINGLE) != 0) {

        /* A CRC flag alone does not create a table for raw or single-unit files. */
        archive->mpq_block[archive->mpq_map[number].block_table_indices].flags |= LIBMPQ_FLAG_CRC;
        bits = UINT32_MAX;
        REQUIRE(libmpq__file_verify(archive, number, LIBMPQ_VERIFY_SECTOR_CRC, &bits) == 0);
        REQUIRE(bits == 0);
    }
    bits = UINT32_MAX;
    REQUIRE(
        libmpq__file_verify(
            archive, UINT32_MAX, LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5, &bits
        ) == LIBMPQ_ERROR_EXIST &&
        bits == 0
    );
    bits = UINT32_MAX;
    REQUIRE(
        libmpq__file_verify(NULL, 0, LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5, &bits) ==
            LIBMPQ_ERROR_EXIST &&
        bits == 0
    );
    REQUIRE(
        libmpq__file_verify(
            archive, number, LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5, NULL
        ) == LIBMPQ_ERROR_EXIST
    );

    /* An I/O failure must leave the result zero. */
    archive->mpq_block[archive->mpq_map[number].block_table_indices].offset = UINT32_MAX;
    bits = UINT32_MAX;
    REQUIRE(
        libmpq__file_verify(
            archive, number, LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5, &bits
        ) < 0 &&
        bits == 0
    );
    REQUIRE(archive->mpq_file[number] == NULL);
cleanup:
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (path[0] != 0)
        unlink(path);
    return result;
}

/* Exercise serializer sizes and availability around packed-byte boundaries. */
static int
test_serialization(void)
{
    mpq_file_attributes_s entries[33] = { 0 };
    mpq_file_attributes_s actual;
    mpq_attributes_s view;
    uint8_t *raw = NULL;
    size_t size;
    uint32_t count;
    uint32_t flags;
    uint32_t i;
    int result = 0;

    for (count = 1; count <= 33; ++count) {
        for (flags = 0; flags < 16; ++flags) {
            for (i = 0; i < count; ++i) {
                entries[i].crc32 = i + 1;
                entries[i].filetime = UINT64_C(0xfedcba9876543210) + i;
                memset(entries[i].md5, (int)i + 1, 16);
            }
            REQUIRE(
                libmpq__attributes_serialize(entries, count, count - 1, flags, &raw, &size) == 0
            );
            REQUIRE(libmpq__attributes_parse(raw, size, count, count - 1, &view) == 0);
            for (i = 0; i < count; ++i) {
                libmpq__attributes_get(&view, i, &actual);
                REQUIRE(actual.flags == flags);
                REQUIRE(actual.patch_bit == 0);
                if (flags & 1)
                    REQUIRE(actual.crc32 == (i == count - 1 ? 0 : entries[i].crc32));
                if (flags & 2)
                    REQUIRE(actual.filetime == (i == count - 1 ? 0 : entries[i].filetime));
            }
            free(raw);
            raw = NULL;
        }
    }
    entries[0].patch_bit = 1;
    REQUIRE(libmpq__attributes_serialize(entries, 1, 0, 8, &raw, &size) == LIBMPQ_ERROR_FORMAT);
    REQUIRE(raw == NULL && size == 0);
cleanup:
    free(raw);
    return result;
}

/* Attribute selections are independent of creation flags and reserve one slot. */
static int
test_creation_options(uint32_t version, int mpqe)
{
    mpq_archive_s *archive = NULL;
    mpq_archive_create_options_s options = { version, 2, 512, 0, 0 };
    uint32_t flags;
    uint32_t count;
    char path[256] = { 0 };
    int32_t status;
    int result = 0;

    REQUIRE(test_temp_path(path, sizeof(path), "attributes-options") == 0);
    for (flags = 0; flags < 16; ++flags) {
        options.attributes = flags;
        if (mpqe)
            status = libmpq__archive_create_mpqe(&archive, path, code, sizeof(code) - 1, &options);
        else
            status = libmpq__archive_create(&archive, path, &options);
        REQUIRE(status == 0);
        REQUIRE(libmpq__file_add(archive, "first.txt", (const uint8_t *)"a", 1, NULL) == 0);
        REQUIRE(
            libmpq__file_add(archive, "second.txt", (const uint8_t *)"b", 1, NULL) ==
            (flags ? LIBMPQ_ERROR_SIZE : 0)
        );
        status = libmpq__archive_close(archive);
        archive = NULL;
        REQUIRE(status == 0);
        if (mpqe)
            status = libmpq__archive_open_mpqe(&archive, path, 0, code, sizeof(code) - 1);
        else
            status = libmpq__archive_open(&archive, path, 0);
        REQUIRE(status == 0);
        REQUIRE(libmpq__archive_files(archive, &count) == 0 && count == 2);
        REQUIRE(
            libmpq__archive_attributes_flags(archive, &count) == (flags ? 0 : LIBMPQ_ERROR_EXIST)
        );
        REQUIRE(count == flags);
        REQUIRE(libmpq__archive_close(archive) == 0);
        archive = NULL;
    }
    options.attributes = LIBMPQ_ATTRIBUTE_CRC32 | 0x10u;
    if (mpqe)
        status = libmpq__archive_create_mpqe(&archive, path, code, sizeof(code) - 1, &options);
    else
        status = libmpq__archive_create(&archive, path, &options);
    REQUIRE(status == LIBMPQ_ERROR_FORMAT && archive == NULL);

cleanup:
    if (archive != NULL)
        (void)libmpq__archive_close(archive);
    if (path[0] != 0)
        unlink(path);
    return result;
}

int
main(void)
{
    uint32_t version;
    uint32_t flags;
    mpq_file_attributes_s unavailable;

    memset(&unavailable, 0xff, sizeof(unavailable));
    flags = UINT32_MAX;
    TEST_CHECK(libmpq__archive_attributes_flags(NULL, &flags) == LIBMPQ_ERROR_EXIST && flags == 0);
    TEST_CHECK(libmpq__file_attributes(NULL, 0, &unavailable) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(unavailable.flags == 0 && unavailable.crc32 == 0 && unavailable.filetime == 0);
    TEST_CHECK(memcmp(unavailable.reserved, "\0\0\0\0", sizeof(unavailable.reserved)) == 0);
    TEST_CHECK(libmpq__file_set_filetime(NULL, 0) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(test_layouts() == 0);
    TEST_CHECK(test_serialization() == 0);
    for (version = 0; version < 2; ++version) {
        TEST_CHECK(test_creation_options(version, 0) == 0);
        TEST_CHECK(test_creation_options(version, 1) == 0);
        for (flags = 0; flags < 16; ++flags)
            TEST_CHECK(test_roundtrip(version, flags, flags % 2) == 0);
    }
    TEST_CHECK(test_manual(1, 0) == 0);
    for (version = 0; version < 2; ++version) {
        const uint32_t corruptions[] = { 0, LIBMPQ_VERIFY_FILE_CRC32, LIBMPQ_VERIFY_FILE_MD5,
                                         LIBMPQ_VERIFY_FILE_CRC32 | LIBMPQ_VERIFY_FILE_MD5 };
        for (size_t i = 0; i < sizeof(corruptions) / sizeof(corruptions[0]); ++i) {
            uint32_t corrupt = corruptions[i];
            TEST_CHECK(test_verify(version, 0, corrupt) == 0);
            TEST_CHECK(
                test_verify(
                    version, LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_ENCRYPTED, corrupt
                ) == 0
            );
            TEST_CHECK(
                test_verify(
                    version, LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE, corrupt
                ) == 0
            );
        }
    }
    TEST_CHECK(test_manual(0, 0) == 0);
    TEST_CHECK(test_manual(0, LIBMPQ_FILE_FLAG_ENCRYPTED) == 0);
    TEST_CHECK(test_manual(0, LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_SINGLE) == 0);
    TEST_CHECK(test_manual(0, LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_COMPRESS) == 0);
    TEST_CHECK(
        test_manual(
            0, LIBMPQ_FILE_FLAG_ENCRYPTED | LIBMPQ_FILE_FLAG_COMPRESS | LIBMPQ_FILE_FLAG_SINGLE
        ) == 0
    );
    return 0;
}
