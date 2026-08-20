/* Exercise the compiled little-endian serialization module. */
#include "helper.h"

#include "../src/endian.h"

/* Verify unaligned-safe little-endian loads and stores for all widths. */
int
main(void)
{
    uint8_t raw[16] = { 0 };

    TEST_CHECK(libmpq__load_le16((const uint8_t[]){ 0x78, 0x56 }) == 0x5678);
    TEST_CHECK(libmpq__load_le32((const uint8_t[]){ 0x78, 0x56, 0x34, 0x12 }) == 0x12345678);
    TEST_CHECK(
        libmpq__load_le64((const uint8_t[]){ 1, 2, 3, 4, 5, 6, 7, 8 }) ==
        UINT64_C(0x0807060504030201)
    );
    TEST_CHECK(libmpq__load_le16(NULL) == 0 && libmpq__load_le32(NULL) == 0);
    TEST_CHECK(libmpq__load_le64(NULL) == 0);
    libmpq__store_le16(raw, 0x5678);
    libmpq__store_le32(raw + 2, 0x12345678);
    libmpq__store_le64(raw + 6, UINT64_C(0x1122334455667788));
    TEST_CHECK(
        raw[0] == 0x78 && raw[1] == 0x56 && raw[2] == 0x78 && raw[5] == 0x12 && raw[6] == 0x88 &&
        raw[13] == 0x11
    );
    return 0;
}
