/* Verify every checked-in v1 and v2 fixture archive and extracted payload. */
#include "mpq-attributes.h"
#include "mpq-internal.h"
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Fixed source checksums independently calculated with Python zlib/hashlib. */
static const struct
{
    const char *name;
    uint32_t crc32;
    uint64_t filetime;
    uint8_t md5[16];
} fixture_attributes[] = {
    { "overview.txt",
      0xf71965bau,
      UINT64_C(132537600000000000),
      { 0xf5, 0xe5, 0x06, 0xc1, 0x64, 0x65, 0x86, 0xcd, 0x58, 0x76, 0x06, 0xb0, 0x62, 0x04, 0xf1,
        0xed } },
    { "implode.txt",
      0x2ce532adu,
      UINT64_C(132537600010000000),
      { 0xa0, 0x79, 0xd5, 0xed, 0x48, 0x9d, 0x59, 0xa9, 0xf4, 0x5c, 0x9f, 0x55, 0x8f, 0x1f, 0xd7,
        0xda } },
    { "huffman.txt",
      0x47235a97u,
      UINT64_C(132537600020000000),
      { 0xf6, 0x50, 0xc7, 0x98, 0x96, 0x89, 0xf9, 0x22, 0x71, 0xa3, 0x94, 0x3a, 0x3c, 0x25, 0xee,
        0xf7 } },
    { "zlib.txt",
      0xea5fc117u,
      UINT64_C(132537600030000000),
      { 0x3f, 0x05, 0x9e, 0xf6, 0x75, 0xa6, 0xfc, 0xe3, 0x9e, 0x54, 0x80, 0x6f, 0x26, 0xfe, 0x4c,
        0x72 } },
    { "pkware.txt",
      0x82285a55u,
      UINT64_C(132537600040000000),
      { 0x0a, 0x10, 0xc8, 0xf8, 0x6d, 0xf0, 0xd5, 0x2e, 0x36, 0x47, 0xe9, 0x09, 0x01, 0xfa, 0x90,
        0xd4 } },
    { "bzip2.txt",
      0x2be7a7e3u,
      UINT64_C(132537600050000000),
      { 0x78, 0x69, 0xaf, 0xe0, 0x13, 0x02, 0x71, 0xcd, 0x5b, 0x98, 0x11, 0x0d, 0x16, 0x84, 0x34,
        0x7e } },
    { "chain.txt",
      0x8372ab88u,
      UINT64_C(132537600060000000),
      { 0x79, 0xa4, 0x34, 0x56, 0x2e, 0xc2, 0xed, 0x83, 0xb8, 0x1e, 0xc2, 0x41, 0x0f, 0x67, 0x16,
        0xb0 } },
    { "encrypted-compress.txt",
      0xfbef4a69u,
      UINT64_C(132537600070000000),
      { 0x4b, 0xae, 0x0b, 0xc2, 0x36, 0xc5, 0x41, 0x7f, 0xff, 0xa3, 0x08, 0x7a, 0x95, 0xf2, 0xfb,
        0xc0 } },
    { "wave-mono.wav",
      0x59ffecd9u,
      UINT64_C(132537600080000000),
      { 0xe1, 0x8b, 0x97, 0xb6, 0xf3, 0x30, 0x2d, 0x25, 0xa3, 0x31, 0x87, 0x39, 0x89, 0xc0, 0x69,
        0x55 } },
    { "wave-stereo.wav",
      0x4d4cd05fu,
      UINT64_C(132537600090000000),
      { 0xfb, 0x82, 0x14, 0xa2, 0x6c, 0x59, 0x01, 0xda, 0xd6, 0xdd, 0x25, 0xf3, 0x69, 0xd2, 0xad,
        0xbc } },
    { "sparse.txt",
      0x44d36045u,
      UINT64_C(132537600100000000),
      { 0xe4, 0xb2, 0xc1, 0x4a, 0x6f, 0x59, 0xd0, 0x75, 0x2e, 0x0e, 0x59, 0xd2, 0xfe, 0x02, 0xb2,
        0xae } },
    { "sparse-zlib.txt",
      0x44d36045u,
      UINT64_C(132537600110000000),
      { 0xe4, 0xb2, 0xc1, 0x4a, 0x6f, 0x59, 0xd0, 0x75, 0x2e, 0x0e, 0x59, 0xd2, 0xfe, 0x02, 0xb2,
        0xae } },
    { "sparse-bzip2.txt",
      0x44d36045u,
      UINT64_C(132537600120000000),
      { 0xe4, 0xb2, 0xc1, 0x4a, 0x6f, 0x59, 0xd0, 0x75, 0x2e, 0x0e, 0x59, 0xd2, 0xfe, 0x02, 0xb2,
        0xae } },
    { "lzma.txt",
      0x458cb824u,
      UINT64_C(132537600130000000),
      { 0xd8, 0x47, 0x20, 0x00, 0x6b, 0x48, 0xd5, 0x23, 0x62, 0x09, 0x8d, 0x43, 0x60, 0x3f, 0x65,
        0x82 } },
};

/* The listfile names are the complete user-file corpus in insertion order. */
static const char *const fixture_names[] = {
    "overview.txt",     "implode.txt",     "huffman.txt", "zlib.txt",
    "pkware.txt",       "bzip2.txt",       "chain.txt",   "encrypted-compress.txt",
    "wave-mono.wav",    "wave-stereo.wav", "sparse.txt",  "sparse-zlib.txt",
    "sparse-bzip2.txt", "lzma.txt",
};

/* Verify the codec entries are stored with their intended serialized methods. */
static const uint8_t fixture_methods[] = {
    0, 0, 0x01, 0x02, 0x08, 0x10, 0x03, 0, 0x41, 0x81, 0x20, 0x22, 0x30, 0x12,
};

/* Load a serialized little-endian 32-bit sector-table offset. */
static uint32_t
load_le32(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

/* Confirm the fixture avoids raw fallback for every advertised codec entry. */
static int
test_fixture_storage(
    mpq_archive_s *archive, const uint8_t *archive_data, size_t archive_size, uint32_t number,
    size_t name_index
)
{
    libmpq__off_t offset;
    libmpq__off_t packed;
    libmpq__off_t unpacked;
    uint32_t flags;
    uint32_t compressed;
    uint32_t encrypted;
    uint32_t imploded;
    uint32_t blocks;
    uint8_t expected_method = fixture_methods[name_index];
    uint32_t method = UINT32_MAX;

    TEST_CHECK(libmpq__block_compression(archive, number, 0, &method) == 0);
    if (name_index != 8 && name_index != 9)
        TEST_CHECK(method == (name_index == 1 ? 0x08U : name_index == 7 ? 0x02U : expected_method));

    TEST_CHECK(libmpq__file_flags(archive, number, &flags) == 0);
    TEST_CHECK(flags == archive->mpq_block[archive->mpq_map[number].block_table_indices].flags);
    compressed = flags & LIBMPQ_FILE_FLAG_COMPRESS;
    encrypted = flags & LIBMPQ_FILE_FLAG_ENCRYPTED;
    imploded = flags & LIBMPQ_FILE_FLAG_IMPLODE;
    TEST_CHECK(libmpq__file_size_packed(archive, number, &packed) == 0);
    TEST_CHECK(libmpq__file_size_unpacked(archive, number, &unpacked) == 0);

    if (name_index == 1) {
        TEST_CHECK(imploded != 0 && packed < unpacked);
        return 0;
    }
    if (name_index == 7) {
        TEST_CHECK(compressed != 0 && encrypted != 0 && packed < unpacked);
        return 0;
    }
    if (expected_method == 0) {
        TEST_CHECK(compressed == 0 && imploded == 0);
        return 0;
    }

    TEST_CHECK(compressed != 0 && encrypted == 0 && packed < unpacked);
    if (name_index == 8 || name_index == 9) {

        /* test-wave checks every lossless/ADPCM sector and decoded PCM sample. */
        TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks > 1);
        return 0;
    }
    TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0 && blocks == 1);
    TEST_CHECK(libmpq__file_offset(archive, number, &offset) == 0 && offset >= 0);
    TEST_CHECK((uint64_t)offset <= archive_size && archive_size - (size_t)offset >= 13U);
    TEST_CHECK(load_le32(archive_data + offset) == 12U);
    TEST_CHECK(archive_data[(size_t)offset + 12U] == expected_method);
    return 0;
}

/* Pin checksum presence and table contents so skipped verification cannot pass. */
static int
test_fixture_checksums(mpq_archive_s *archive, const uint8_t *raw, size_t size, uint32_t version)
{
    uint32_t files;
    uint32_t number;
    uint32_t checked = 0;

    TEST_CHECK(libmpq__archive_files(archive, &files) == 0);
    for (number = 0; number < files; ++number) {
        mpq_block_s *entry = &archive->mpq_block[archive->mpq_map[number].block_table_indices];
        uint32_t verification = UINT32_MAX;
        int eligible = entry->unpacked_size != 0 && (entry->flags & LIBMPQ_FLAG_SINGLE) == 0 &&
                       (entry->flags & (LIBMPQ_FLAG_COMPRESSED | LIBMPQ_FLAG_COMPRESS_PKZIP));

        TEST_CHECK(((entry->flags & LIBMPQ_FLAG_CRC) != 0) == !!eligible);
        if (eligible) {
            uint32_t blocks;
            uint32_t i;
            uint32_t *offsets = NULL;
            TEST_CHECK(libmpq__file_blocks(archive, number, &blocks) == 0);
            TEST_CHECK(test_archive_offsets(archive, number, &offsets) == 0);
            TEST_CHECK(offsets[0] == (blocks + 2U) * 4U);
            TEST_CHECK(offsets[blocks + 1U] == entry->packed_size);

            /* These fixed tables are too small to benefit from compression. */
            TEST_CHECK(offsets[blocks + 1U] - offsets[blocks] == blocks * 4U);
            TEST_CHECK(entry->offset <= size && entry->packed_size <= size - entry->offset);
            for (i = 0; i < blocks; ++i) {
                uint32_t checksum = load_le32(raw + entry->offset + offsets[blocks] + i * 4U);
                TEST_CHECK(checksum != 0 && checksum != UINT32_MAX);
            }
            free(offsets);
            ++checked;
        }
        TEST_CHECK(
            libmpq__file_verify(archive, number, LIBMPQ_VERIFY_SECTOR_CRC, &verification) == 0
        );
        TEST_CHECK(verification == 0);
    }
    TEST_CHECK(checked == (version == 1 ? 13U : 14U));
    return 0;
}

/* The listfile is generated identically for both archive format versions. */
static const char fixture_listfile_v1[] = "overview.txt\n"
                                          "implode.txt\n"
                                          "huffman.txt\n"
                                          "zlib.txt\n"
                                          "pkware.txt\n"
                                          "bzip2.txt\n"
                                          "chain.txt\n"
                                          "encrypted-compress.txt\n"
                                          "wave-mono.wav\n"
                                          "wave-stereo.wav\n"
                                          "sparse.txt\n"
                                          "sparse-zlib.txt\n"
                                          "sparse-bzip2.txt\n"
                                          "(signature)\n"
                                          "(attributes)\n";
static const char fixture_listfile_v2[] = "overview.txt\n"
                                          "implode.txt\n"
                                          "huffman.txt\n"
                                          "zlib.txt\n"
                                          "pkware.txt\n"
                                          "bzip2.txt\n"
                                          "chain.txt\n"
                                          "encrypted-compress.txt\n"
                                          "wave-mono.wav\n"
                                          "wave-stereo.wav\n"
                                          "sparse.txt\n"
                                          "sparse-zlib.txt\n"
                                          "sparse-bzip2.txt\n"
                                          "lzma.txt\n"
                                          "(signature)\n"
                                          "(attributes)\n";

/* Archive and extracted-file hashes are the single fixture source of truth. */
static const char *const fixture_archive_hashes[] = {
    "930c17747f5d3a040c30a34e1c084c942ce55e4957ad003a5ecd1e7aec73b984",
    "de1a4324eff6043a4a2ed604fb93427e389346ad01096d2d9f8571e49c8e583a",
};

static const char *const fixture_file_hashes[2][15] = {
    {
        "722f1acc2acd306abaed0466ffbbfd568e09f5e7da8d63eba86f19c1c2adde73",
        "1ad8d61488c18eb2e0e12cc4306c3d0348edd6c1777c09c87e217c26963b2141",
        "8168cb4d878fe1a16587e9a118c026b5f6be7fa660030811a442a9e7c2072ef7",
        "89e5241816f19dd4d5566667a065e1d026697276d068d0656a5ec596645e13d4",
        "006806ff106cfe33cd8b52e3a9d12232860b9bdeb34d0bcf4692eac7eb8f59e9",
        "c4e6c57d3e5ab628c085aca85a943434381032b7da8f39045c97797ffb399fe7",
        "167de694bb690e3d03311689fcbd5ff7e7357f3e8dcd2cef867f4c7f40b42ff9",
        "def68c91e0a61582507c1199e134b230d193f6cd9625e898d70431239d1426a8",
        "32475acd7b286a3c19b3ac65bc919478900c25d688b6e925d1278384e0ae5450",
        "9256f5652671f4a608804432074d59afa94b74475a8bb34b5df8cf37e3488d40",
        "e4249a848cb3ae3cd031a01dcafa0f6f378b2542963035db8440e680f9d84381",
        "e4249a848cb3ae3cd031a01dcafa0f6f378b2542963035db8440e680f9d84381",
        "e4249a848cb3ae3cd031a01dcafa0f6f378b2542963035db8440e680f9d84381",
        "1c1c534fce9fe0fdd104a0ee14321741e84b51a7d6ec499de93bf5672bbe784d",
        NULL,
    },
    {
        "722f1acc2acd306abaed0466ffbbfd568e09f5e7da8d63eba86f19c1c2adde73",
        "1ad8d61488c18eb2e0e12cc4306c3d0348edd6c1777c09c87e217c26963b2141",
        "8168cb4d878fe1a16587e9a118c026b5f6be7fa660030811a442a9e7c2072ef7",
        "89e5241816f19dd4d5566667a065e1d026697276d068d0656a5ec596645e13d4",
        "006806ff106cfe33cd8b52e3a9d12232860b9bdeb34d0bcf4692eac7eb8f59e9",
        "c4e6c57d3e5ab628c085aca85a943434381032b7da8f39045c97797ffb399fe7",
        "167de694bb690e3d03311689fcbd5ff7e7357f3e8dcd2cef867f4c7f40b42ff9",
        "def68c91e0a61582507c1199e134b230d193f6cd9625e898d70431239d1426a8",
        "32475acd7b286a3c19b3ac65bc919478900c25d688b6e925d1278384e0ae5450",
        "9256f5652671f4a608804432074d59afa94b74475a8bb34b5df8cf37e3488d40",
        "e4249a848cb3ae3cd031a01dcafa0f6f378b2542963035db8440e680f9d84381",
        "e4249a848cb3ae3cd031a01dcafa0f6f378b2542963035db8440e680f9d84381",
        "e4249a848cb3ae3cd031a01dcafa0f6f378b2542963035db8440e680f9d84381",
        "da99ea7c15a1e60401f49c86b7d541714437891c4fc4a12d1dcff6674775e976",
        "5062529fc4cf90c04e97cff8971286d6546edcb22a550766e21b2daa406f5850",
    },
};

/* Verify one archive's bytes, version, listfile, and extracted payloads. */
static int
test_fixture(const char *path, uint32_t expected_version, size_t fixture_index)
{
    mpq_archive_s *archive = NULL;
    uint8_t *archive_data = NULL;
    uint8_t *file_data = NULL;
    size_t archive_size;
    size_t file_size;
    char hash[65];
    uint32_t archive_version;
    uint32_t file_count;
    uint32_t number;
    size_t i;
    size_t names_count = sizeof(fixture_names) / sizeof(fixture_names[0]) - (fixture_index == 0);
    const char *fixture_listfile = fixture_index == 0 ? fixture_listfile_v1 : fixture_listfile_v2;

    TEST_CHECK(test_read_path(path, &archive_data, &archive_size) == 0);
    TEST_CHECK(test_sha256(archive_data, archive_size, hash) == 0);
    TEST_CHECK(strcmp(hash, fixture_archive_hashes[fixture_index]) == 0);
    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__archive_version(archive, &archive_version) == 0);
    TEST_CHECK(archive_version == expected_version);
    TEST_CHECK(libmpq__archive_files(archive, &file_count) == 0);
    TEST_CHECK(file_count == names_count + 3);
    {
        uint32_t signatures = 0;
        uint32_t mismatches = UINT32_MAX;
        mpq_file_attributes_s attributes;
        TEST_CHECK(libmpq__archive_signatures(archive, &signatures) == 0);
        TEST_CHECK(signatures == LIBMPQ_SIGNATURE_WEAK);
        TEST_CHECK(
            libmpq__archive_verify(
                archive, signatures, test_signature_public_key, sizeof(test_signature_public_key),
                &mismatches
            ) == 0
        );
        TEST_CHECK(mismatches == 0);
        TEST_CHECK(libmpq__file_number(archive, "(signature)", &number) == 0);
        TEST_CHECK(libmpq__file_flags(archive, number, &signatures) == 0);
        TEST_CHECK(signatures == LIBMPQ_FLAG_EXISTS);
        TEST_CHECK(test_archive_read(archive, number, &file_data, &file_size) == 0);
        TEST_CHECK(file_size == 72 && memcmp(file_data, "\0\0\0\0\0\0\0\0", 8) == 0);
        free(file_data);
        file_data = NULL;
        TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
        TEST_CHECK(attributes.crc32 == 0 && attributes.filetime == 0 && attributes.patch_bit == 0);
        for (i = 0; i < sizeof(attributes.md5); ++i)
            TEST_CHECK(attributes.md5[i] == 0);
    }
    TEST_CHECK(test_fixture_checksums(archive, archive_data, archive_size, expected_version) == 0);

    /* Verify the generated listfile and resolve every name it advertises. */
    TEST_CHECK(libmpq__file_number(archive, "(listfile)", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &file_data, &file_size) == 0);
    TEST_CHECK(file_size == strlen(fixture_listfile));
    TEST_CHECK(memcmp(file_data, fixture_listfile, file_size) == 0);
    TEST_CHECK(test_sha256(file_data, file_size, hash) == 0);
    TEST_CHECK(strcmp(hash, fixture_file_hashes[fixture_index][names_count]) == 0);
    free(file_data);
    file_data = NULL;

    for (i = 0; i < names_count; ++i) {
        mpq_file_attributes_s attributes;
        TEST_CHECK(libmpq__file_number(archive, fixture_names[i], &number) == 0);
        TEST_CHECK(libmpq__file_attributes(archive, number, &attributes) == 0);
        TEST_CHECK(attributes.flags == (fixture_index == 0 ? 7u : 15u));
        TEST_CHECK(attributes.crc32 == fixture_attributes[i].crc32);
        TEST_CHECK(attributes.filetime == fixture_attributes[i].filetime);
        TEST_CHECK(memcmp(attributes.md5, fixture_attributes[i].md5, 16) == 0);
        TEST_CHECK(attributes.patch_bit == 0);
        if (strstr(fixture_names[i], ".wav") == NULL) {
            uint32_t verification = UINT32_MAX;
            TEST_CHECK(libmpq__file_verify(archive, number, LIBMPQ_VERIFY_ALL, &verification) == 0);
            TEST_CHECK(verification == 0);
        }
        TEST_CHECK(test_fixture_storage(archive, archive_data, archive_size, number, i) == 0);
        TEST_CHECK(test_archive_read(archive, number, &file_data, &file_size) == 0);
        if (i >= 10 && i <= 12) {
            uint8_t expected[TEST_SPARSE_FIXTURE_SIZE];
            test_sparse_payload(expected, sizeof(expected));
            TEST_CHECK(file_size == sizeof(expected));
            TEST_CHECK(memcmp(file_data, expected, sizeof(expected)) == 0);
        }
        TEST_CHECK(test_sha256(file_data, file_size, hash) == 0);
        TEST_CHECK(strcmp(hash, fixture_file_hashes[fixture_index][i]) == 0);
        free(file_data);
        file_data = NULL;
    }

    TEST_CHECK(libmpq__archive_close(archive) == 0);
    free(archive_data);
    return 0;
}

/* Refresh the canonical archives without decoding/re-encoding lossy samples.
 * Text comes from the canonical corpus; PCM is the original documented formula.
 * Private attribute serialization preserves this corpus's sector-CRC layout;
 * signing and MPQE finalization exercise the public writer APIs. */
static int
refresh_fixture(const char *path, uint32_t version, size_t fixture_index)
{
    static const uint8_t auth[] = "LIBMPQ-MPQE-TEST-AUTH-CODE-00001";
    mpq_archive_s *source = NULL;
    size_t count = sizeof(fixture_names) / sizeof(fixture_names[0]) - (fixture_index == 0);
    uint8_t *payloads[14] = { NULL };
    size_t sizes[14];
    mpq_file_options_s storage[14];
    char output[512];
    size_t i;
    unsigned encrypted;
    TEST_CHECK(libmpq__archive_open(&source, path, 0) == 0);
    for (i = 0; i < count; ++i) {
        uint32_t number;
        TEST_CHECK(libmpq__file_number(source, fixture_names[i], &number) == 0);
        TEST_CHECK(test_archive_read(source, number, &payloads[i], &sizes[i]) == 0);
        memset(&storage[i], 0, sizeof(storage[i]));
        TEST_CHECK(libmpq__file_flags(source, number, &storage[i].flags) == 0);
        storage[i].flags &= ~LIBMPQ_FLAG_EXISTS;
        storage[i].compression_first = i == 7 ? 2 : fixture_methods[i];
        storage[i].compression_next = storage[i].compression_first;
        if (i == 13)
            storage[i].compression_first = storage[i].compression_next = LIBMPQ_COMPRESSION_LZMA;
        if (i == 8 || i == 9) {
            size_t frame;
            size_t channels = i == 8 ? 1 : 2;
            storage[i].compression_first = LIBMPQ_COMPRESSION_ZLIB;
            for (frame = 0; frame < 7000; ++frame) {
                size_t channel;
                int32_t phase = (int32_t)((frame * 17) % 4096);
                int32_t base = phase < 2048 ? phase - 1024 : 3072 - phase;
                for (channel = 0; channel < channels; ++channel) {
                    uint16_t sample = (uint16_t)(base * 24 + (channel ? 1800 : 0));
                    size_t offset = 44 + (frame * channels + channel) * 2;
                    payloads[i][offset] = (uint8_t)sample;
                    payloads[i][offset + 1] = (uint8_t)(sample >> 8);
                }
            }
        }
    }
    TEST_CHECK(libmpq__archive_close(source) == 0);
    for (encrypted = 0; encrypted < 2; ++encrypted) {
        mpq_archive_s *writer = NULL;
        mpq_archive_create_options_s options = { version - 1, 32, 4096,
                                                 LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED,
                                                 fixture_index == 0 ? 7 : 15 };
        mpq_file_options_s list_storage = { LIBMPQ_FILE_FLAG_SINGLE, 0, 0, 0, 0 };
        mpq_file_options_s attribute_storage = { LIBMPQ_FILE_FLAG_COMPRESS |
                                                     LIBMPQ_FILE_FLAG_SECTOR_CRC,
                                                 LIBMPQ_COMPRESSION_ZLIB, LIBMPQ_COMPRESSION_ZLIB,
                                                 0, 0 };
        const char *list = fixture_index == 0 ? fixture_listfile_v1 : fixture_listfile_v2;
        uint8_t *attributes = NULL;
        size_t attribute_size;
        TEST_CHECK(snprintf(output, sizeof(output), "%s%s", path, encrypted ? "e" : "") > 0);
        if (encrypted)
            TEST_CHECK(
                libmpq__archive_create_mpqe(&writer, output, auth, sizeof(auth) - 1, &options) == 0
            );
        else
            TEST_CHECK(libmpq__archive_create(&writer, output, &options) == 0);
        for (i = 0; i < count; ++i) {
            mpq_writer_s *file = NULL;
            TEST_CHECK(
                libmpq__writer_begin(
                    writer, fixture_names[i], (libmpq__off_t)sizes[i], &storage[i], &file
                ) == 0
            );
            TEST_CHECK(libmpq__writer_timestamp(file, fixture_attributes[i].filetime) == 0);
            TEST_CHECK(libmpq__writer_write(file, payloads[i], (libmpq__off_t)sizes[i]) == 0);
            TEST_CHECK(libmpq__writer_finish(file) == 0);
        }
        TEST_CHECK(
            libmpq__archive_sign(
                writer, LIBMPQ_SIGNATURE_WEAK, test_signature_private_key,
                sizeof(test_signature_private_key)
            ) == 0
        );
        TEST_CHECK(
            libmpq__archive_add_data(
                writer, LIBMPQ_LISTFILE_NAME, (const uint8_t *)list, (libmpq__off_t)strlen(list),
                &list_storage
            ) == 0
        );
        TEST_CHECK(
            libmpq__attributes_serialize(
                writer->write_attributes, writer->write_capacity, writer->write_next_block,
                options.attributes, &attributes, &attribute_size
            ) == 0
        );

        /* Preserve the fixture's explicit checksummed attributes, not the default
         * generated storage. Its self row and the signature row remain zero. */
        writer->write_attributes_flags = 0;
        TEST_CHECK(
            libmpq__archive_add_data(
                writer, LIBMPQ_ATTRIBUTES_NAME, attributes, (libmpq__off_t)attribute_size,
                &attribute_storage
            ) == 0
        );
        free(attributes);
        TEST_CHECK(libmpq__archive_close(writer) == 0);
    }
    for (i = 0; i < count; ++i)
        free(payloads[i]);
    return 0;
}

/* Verify both deterministic fixture formats against the embedded manifest. */
int
main(int argc, char **argv)
{
    char path[512];
    size_t i;

    for (i = 0; i < 2; ++i) {
        TEST_CHECK(
            snprintf(path, sizeof(path), "%s/mpq-v%zu-features.mpq", FIXTURE_DIR, i + 1) > 0
        );
        if (argc == 2 && strcmp(argv[1], "--refresh") == 0) {
            TEST_CHECK(refresh_fixture(path, (uint32_t)(i + 1), i) == 0);
            continue;
        }
        TEST_CHECK(test_fixture(path, (uint32_t)(i + 1), i) == 0);
    }
    return 0;
}
