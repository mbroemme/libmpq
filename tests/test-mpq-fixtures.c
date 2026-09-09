/* Verify every checked-in v1 and v2 fixture archive and extracted payload. */
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The listfile names are the complete user-file corpus in insertion order. */
static const char *const fixture_names[] = {
    "overview.txt",   "implode.txt", "huffman.txt", "zlib.txt",
    "pkware.txt",     "bzip2.txt",   "chain.txt",   "encrypted-compress.txt",
    "wave-adpcm.txt", "lzma.txt",
};

/* Verify the codec entries are stored with their intended serialized methods. */
static const uint8_t fixture_methods[] = {
    0, 0, 0x01, 0x02, 0x08, 0x10, 0x03, 0, 0, 0x12,
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
                                          "wave-adpcm.txt\n";
static const char fixture_listfile_v2[] = "overview.txt\n"
                                          "implode.txt\n"
                                          "huffman.txt\n"
                                          "zlib.txt\n"
                                          "pkware.txt\n"
                                          "bzip2.txt\n"
                                          "chain.txt\n"
                                          "encrypted-compress.txt\n"
                                          "wave-adpcm.txt\n"
                                          "lzma.txt\n";

/* Archive and extracted-file hashes are the single fixture source of truth. */
static const char *const fixture_archive_hashes[] = {
    "3ac655f1f6fc976cd3cb5a636142691a9ae31eeaa56d003b8c5dd256282106f5",
    "722c9e4b92c3767042e61c4954d617ec3c9b022f312461715fab9eb39c532949",
};

static const char *const fixture_file_hashes[2][11] = {
    {
        "722f1acc2acd306abaed0466ffbbfd568e09f5e7da8d63eba86f19c1c2adde73",
        "1ad8d61488c18eb2e0e12cc4306c3d0348edd6c1777c09c87e217c26963b2141",
        "8168cb4d878fe1a16587e9a118c026b5f6be7fa660030811a442a9e7c2072ef7",
        "89e5241816f19dd4d5566667a065e1d026697276d068d0656a5ec596645e13d4",
        "006806ff106cfe33cd8b52e3a9d12232860b9bdeb34d0bcf4692eac7eb8f59e9",
        "c4e6c57d3e5ab628c085aca85a943434381032b7da8f39045c97797ffb399fe7",
        "167de694bb690e3d03311689fcbd5ff7e7357f3e8dcd2cef867f4c7f40b42ff9",
        "def68c91e0a61582507c1199e134b230d193f6cd9625e898d70431239d1426a8",
        "3df96a6e5d56995da58118014e78c18d320c1b81886340000300af9e2fdea3aa",
        "058f38444a689f28623607b6c813b1b6a87ec18fe00af740cb873b4bd1fc9af2",
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
        "3df96a6e5d56995da58118014e78c18d320c1b81886340000300af9e2fdea3aa",
        "da99ea7c15a1e60401f49c86b7d541714437891c4fc4a12d1dcff6674775e976",
        "950e58d99261dbe85eb69a9bc5aae2c690f92f79edc8494c00c1802faf54550c",
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
    TEST_CHECK(file_count == names_count + 1);

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
        TEST_CHECK(libmpq__file_number(archive, fixture_names[i], &number) == 0);
        TEST_CHECK(test_fixture_storage(archive, archive_data, archive_size, number, i) == 0);
        TEST_CHECK(test_archive_read(archive, number, &file_data, &file_size) == 0);
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
