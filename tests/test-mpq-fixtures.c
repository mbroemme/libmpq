/* Verify every checked-in v1 and v2 fixture archive and extracted payload. */
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
    uint32_t compressed;
    uint32_t encrypted;
    uint32_t imploded;
    uint32_t blocks;
    uint8_t expected_method = fixture_methods[name_index];

    TEST_CHECK(libmpq__file_compressed(archive, number, &compressed) == 0);
    TEST_CHECK(libmpq__file_encrypted(archive, number, &encrypted) == 0);
    TEST_CHECK(libmpq__file_imploded(archive, number, &imploded) == 0);
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
    TEST_CHECK((uint64_t)offset <= archive_size && archive_size - (size_t)offset >= 5U);
    TEST_CHECK(load_le32(archive_data + offset) == 8U);
    TEST_CHECK(archive_data[(size_t)offset + 8U] == expected_method);
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
                                          "(attributes)\n";

/* Archive and extracted-file hashes are the single fixture source of truth. */
static const char *const fixture_archive_hashes[] = {
    "22998a47e57cc3e43357e6c96fc1a772e468f524b0bc8ee66bf6e88afc66efc0",
    "dc1d4c5b8cc39613f5f7940d97474a7a7a6b16c58aa4d642093380be64e62d0c",
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
        "d84a86a55ecb32cb95bfb4725ef156e3be8d14bdcb19e84a95c0a4463da0c61f",
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
        "23fad524da76451f14ceacbe6acaeb7ff7aaff39e3f8e0aa3963cf1bac3bc396",
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
    TEST_CHECK(file_count == names_count + 2);

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

/* Verify both deterministic fixture formats against the embedded manifest. */
int
main(void)
{
    char path[512];
    size_t i;

    for (i = 0; i < 2; ++i) {
        TEST_CHECK(
            snprintf(path, sizeof(path), "%s/mpq-v%zu-features.mpq", FIXTURE_DIR, i + 1) > 0
        );
        TEST_CHECK(test_fixture(path, (uint32_t)(i + 1), i) == 0);
    }
    return 0;
}
