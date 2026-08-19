/* Verify the checked-in fixture bytes and every listed extracted payload. */
#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    const char *name;
    const char *v1;
    const char *v2;
} fixture_entry;
static const fixture_entry entries[] = {
    { "(listfile)", "058f38444a689f28623607b6c813b1b6a87ec18fe00af740cb873b4bd1fc9af2",
      "058f38444a689f28623607b6c813b1b6a87ec18fe00af740cb873b4bd1fc9af2" },
    { "overview.txt", "c974912482320e001e3550b36f7eda21a8df2c57c9ef7c9fa84154579c21b8d9",
      "5b82917a5cb24bee72be9b0526c6f28b5a3e977d31156398b129502fd191ad0b" },
    { "implode.txt", "535ea832756a1294b29bdf6f37913234fa4c1b92b3a841aec26456a4fdbb4930",
      "535ea832756a1294b29bdf6f37913234fa4c1b92b3a841aec26456a4fdbb4930" },
    { "huffman.txt", "93c7bdaceb3a5aa3969520c20a63e64d577227f51d2bbb6ee075c43ff8fa5b8e",
      "93c7bdaceb3a5aa3969520c20a63e64d577227f51d2bbb6ee075c43ff8fa5b8e" },
    { "zlib.txt", "f6deaaceaff813f329e02724dff3f84826d151a441185b9c5e475684379f8adc",
      "f6deaaceaff813f329e02724dff3f84826d151a441185b9c5e475684379f8adc" },
    { "pkware.txt", "8607ff190e40d16473329af9d9ab526246417580cfdade1ff894118efa70d7ab",
      "8607ff190e40d16473329af9d9ab526246417580cfdade1ff894118efa70d7ab" },
    { "bzip2.txt", "e8df388818ff333ef55e444a2990f9327efc9860fb2003953e52803dd7734fcd",
      "e8df388818ff333ef55e444a2990f9327efc9860fb2003953e52803dd7734fcd" },
    { "chain.txt", "17450f13de9b5608b609a37edf0d6d9d71815e5c2db3269e083e1c8f6b991cbe",
      "17450f13de9b5608b609a37edf0d6d9d71815e5c2db3269e083e1c8f6b991cbe" },
    { "encrypted-compress.txt", "a8f75fedaa13e64adabf9c2e47df77b905da142a9d8b2a818bd213533fe60241",
      "a8f75fedaa13e64adabf9c2e47df77b905da142a9d8b2a818bd213533fe60241" },
    { "wave-adpcm.txt", "45a47477f2e70c65982c60f382681f3740a68d44c014b9cecb3df87df497f448",
      "45a47477f2e70c65982c60f382681f3740a68d44c014b9cecb3df87df497f448" }
};

static int
test_fixture(const char *path, uint32_t expected_version, const char *archive_hash)
{
    mpq_archive_s *archive = NULL;
    uint8_t *bytes = NULL;
    uint8_t *data = NULL;
    size_t bytes_size;
    size_t data_size;
    char hash[65];
    uint32_t files;
    uint32_t version;
    uint32_t number;
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    size_t i;
    TEST_CHECK(test_read_path(path, &bytes, &bytes_size) == 0);
    TEST_CHECK(test_sha256(bytes, bytes_size, hash) == 0 && strcmp(hash, archive_hash) == 0);
    free(bytes);
    TEST_CHECK(libmpq__archive_open(&archive, path, -1) == 0);
    TEST_CHECK(libmpq__archive_version(archive, &version) == 0 && version == expected_version);
    TEST_CHECK(libmpq__archive_files(archive, &files) == 0 && files == 10);
    for (i = 0; i < sizeof(entries) / sizeof(entries[0]); ++i) {
        const char *expected = expected_version == 1 ? entries[i].v1 : entries[i].v2;
        TEST_CHECK(libmpq__file_number(archive, entries[i].name, &number) == 0);
        libmpq__file_hash(entries[i].name, &h1, &h2, &h3);
        TEST_CHECK(libmpq__file_number_from_hash(archive, h1, h2, h3, &number) == 0);
        TEST_CHECK(test_archive_read(archive, number, &data, &data_size) == 0);
        TEST_CHECK(test_sha256(data, data_size, hash) == 0 && strcmp(hash, expected) == 0);
        free(data);
        data = NULL;
    }
    TEST_CHECK(libmpq__archive_close(archive) == 0);
    return 0;
}

int
main(void)
{
    char v1[512];
    char v2[512];
    TEST_CHECK(snprintf(v1, sizeof(v1), "%s/mpq-v1-features.mpq", FIXTURE_DIR) > 0);
    TEST_CHECK(snprintf(v2, sizeof(v2), "%s/mpq-v2-features.mpq", FIXTURE_DIR) > 0);
    TEST_CHECK(
        test_fixture(v1, 1, "ed5b2a25a12fea90e78715eb248eecfbfbce08145f138777de5a24ee22e6976b") == 0
    );
    TEST_CHECK(
        test_fixture(v2, 2, "62673b801eca32f451a4dc5f58e60f5a5b98ab581d7ba8416085848ee4b86829") == 0
    );
    return 0;
}
