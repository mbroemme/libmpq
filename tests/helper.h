/* Shared deterministic helpers for the libmpq C regression programs. */
#ifndef LIBMPQ_TEST_HELPER_H
#define LIBMPQ_TEST_HELPER_H

#include <libmpq/mpq.h>

#include <stddef.h>
#include <stdint.h>

#ifndef FIXTURE_DIR
#define FIXTURE_DIR "fixtures"
#endif

#define TEST_CHECK(condition)                                                                      \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            test_failure(__FILE__, __LINE__, #condition);                                          \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

void test_failure(const char *file, unsigned line, const char *condition);
int test_temp_path(char *path, size_t path_size, const char *tag);
int test_read_path(const char *path, uint8_t **data, size_t *size);
void test_payload(uint8_t *data, size_t size, uint32_t seed);
int test_sha256(const uint8_t *data, size_t size, char output[65]);
int test_archive_read(mpq_archive_s *archive, uint32_t number, uint8_t **data, size_t *size);
int test_add_archive(mpq_archive_s **archive, const char *path, uint32_t version, uint32_t flags);

#endif
