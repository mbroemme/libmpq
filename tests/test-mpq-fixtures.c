/* Verify every checked-in v1 and v2 fixture archive and extracted payload. */
#include "test-mpq-helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The listfile names are the complete user-file corpus in insertion order. */
static const char *const fixture_names[] = {
    "overview.txt",   "implode.txt", "huffman.txt", "zlib.txt",
    "pkware.txt",     "bzip2.txt",   "chain.txt",   "encrypted-compress.txt",
    "wave-adpcm.txt",
};

/* The listfile is generated identically for both archive format versions. */
static const char fixture_listfile[] = "overview.txt\n"
                                       "implode.txt\n"
                                       "huffman.txt\n"
                                       "zlib.txt\n"
                                       "pkware.txt\n"
                                       "bzip2.txt\n"
                                       "chain.txt\n"
                                       "encrypted-compress.txt\n"
                                       "wave-adpcm.txt\n";

/* Archive and extracted-file hashes are the single fixture source of truth. */
static const char *const fixture_archive_hashes[] = {
    "ed5b2a25a12fea90e78715eb248eecfbfbce08145f138777de5a24ee22e6976b",
    "62673b801eca32f451a4dc5f58e60f5a5b98ab581d7ba8416085848ee4b86829",
};

static const char *const fixture_file_hashes[2][10] = {
    {
        "c974912482320e001e3550b36f7eda21a8df2c57c9ef7c9fa84154579c21b8d9",
        "535ea832756a1294b29bdf6f37913234fa4c1b92b3a841aec26456a4fdbb4930",
        "93c7bdaceb3a5aa3969520c20a63e64d577227f51d2bbb6ee075c43ff8fa5b8e",
        "f6deaaceaff813f329e02724dff3f84826d151a441185b9c5e475684379f8adc",
        "8607ff190e40d16473329af9d9ab526246417580cfdade1ff894118efa70d7ab",
        "e8df388818ff333ef55e444a2990f9327efc9860fb2003953e52803dd7734fcd",
        "17450f13de9b5608b609a37edf0d6d9d71815e5c2db3269e083e1c8f6b991cbe",
        "a8f75fedaa13e64adabf9c2e47df77b905da142a9d8b2a818bd213533fe60241",
        "45a47477f2e70c65982c60f382681f3740a68d44c014b9cecb3df87df497f448",
        "058f38444a689f28623607b6c813b1b6a87ec18fe00af740cb873b4bd1fc9af2",
    },
    {
        "5b82917a5cb24bee72be9b0526c6f28b5a3e977d31156398b129502fd191ad0b",
        "535ea832756a1294b29bdf6f37913234fa4c1b92b3a841aec26456a4fdbb4930",
        "93c7bdaceb3a5aa3969520c20a63e64d577227f51d2bbb6ee075c43ff8fa5b8e",
        "f6deaaceaff813f329e02724dff3f84826d151a441185b9c5e475684379f8adc",
        "8607ff190e40d16473329af9d9ab526246417580cfdade1ff894118efa70d7ab",
        "e8df388818ff333ef55e444a2990f9327efc9860fb2003953e52803dd7734fcd",
        "17450f13de9b5608b609a37edf0d6d9d71815e5c2db3269e083e1c8f6b991cbe",
        "a8f75fedaa13e64adabf9c2e47df77b905da142a9d8b2a818bd213533fe60241",
        "45a47477f2e70c65982c60f382681f3740a68d44c014b9cecb3df87df497f448",
        "058f38444a689f28623607b6c813b1b6a87ec18fe00af740cb873b4bd1fc9af2",
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

    TEST_CHECK(test_read_path(path, &archive_data, &archive_size) == 0);
    TEST_CHECK(test_sha256(archive_data, archive_size, hash) == 0);
    TEST_CHECK(strcmp(hash, fixture_archive_hashes[fixture_index]) == 0);
    free(archive_data);

    TEST_CHECK(libmpq__archive_open(&archive, path, 0) == 0);
    TEST_CHECK(libmpq__archive_version(archive, &archive_version) == 0);
    TEST_CHECK(archive_version == expected_version);
    TEST_CHECK(libmpq__archive_files(archive, &file_count) == 0);
    TEST_CHECK(file_count == sizeof(fixture_names) / sizeof(fixture_names[0]) + 1);

    /* Verify the generated listfile and resolve every name it advertises. */
    TEST_CHECK(libmpq__file_number(archive, "(listfile)", &number) == 0);
    TEST_CHECK(test_archive_read(archive, number, &file_data, &file_size) == 0);
    TEST_CHECK(file_size == sizeof(fixture_listfile) - 1);
    TEST_CHECK(memcmp(file_data, fixture_listfile, file_size) == 0);
    TEST_CHECK(test_sha256(file_data, file_size, hash) == 0);
    TEST_CHECK(strcmp(hash, fixture_file_hashes[fixture_index][9]) == 0);
    free(file_data);
    file_data = NULL;

    for (i = 0; i < sizeof(fixture_names) / sizeof(fixture_names[0]); ++i) {
        TEST_CHECK(libmpq__file_number(archive, fixture_names[i], &number) == 0);
        TEST_CHECK(test_archive_read(archive, number, &file_data, &file_size) == 0);
        TEST_CHECK(test_sha256(file_data, file_size, hash) == 0);
        TEST_CHECK(strcmp(hash, fixture_file_hashes[fixture_index][i]) == 0);
        free(file_data);
        file_data = NULL;
    }

    TEST_CHECK(libmpq__archive_close(archive) == 0);
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
