/* Exercise version, diagnostics, and invalid-handle error paths. */
#include "test.h"

#include <stdint.h>

int
main(void)
{
    unsigned error;

    TEST_CHECK(libmpq__version() != NULL && *libmpq__version() != '\0');
    TEST_CHECK(libmpq__strerror(0) != NULL && libmpq__strerror(12345) == NULL);
    for (error = 1; error <= 12; ++error)
        TEST_CHECK(libmpq__strerror(-(int32_t)error) != NULL);

    TEST_CHECK(libmpq__archive_clone(NULL, NULL) == LIBMPQ_ERROR_EXIST);
    TEST_CHECK(libmpq__archive_close(NULL) == LIBMPQ_ERROR_EXIST);
    return 0;
}
