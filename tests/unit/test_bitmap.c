/**
 * @file tests/unit/test_bitmap.c
 * @brief Unit tests for bitmap utilities.
 */

#include <stdio.h>
#include <string.h>
#include "emv_kernel/bitmap.h"

static int g_tests_run = 0;
static int g_tests_fail = 0;

#define TEST(name) static void name(void)
#define RUN(test) do { \
    g_tests_run++; \
    printf("  TEST: %s ... ", #test); \
    (test)(); \
    printf("OK\n"); \
} while (0)

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("FAIL: %s (expected=%d, got=%d)\n", msg, (int)(b), (int)(a)); \
        g_tests_fail++; \
    } \
} while (0)

/* ---- Test: bitmap set/get ---- */
TEST(test_bitmap_set_get) {
    uint8_t buf[4] = {0};

    bitmap_set(buf, 0);   /* MSB of byte 0 */
    bitmap_set(buf, 7);   /* LSB of byte 0 */
    bitmap_set(buf, 8);   /* MSB of byte 1 */

    ASSERT_EQ(bitmap_get(buf, 0), 1, "bit 0 is set");
    ASSERT_EQ(bitmap_get(buf, 7), 1, "bit 7 is set");
    ASSERT_EQ(bitmap_get(buf, 8), 1, "bit 8 is set");
    ASSERT_EQ(bitmap_get(buf, 1), 0, "bit 1 not set");
    ASSERT_EQ(bitmap_get(buf, 15), 0, "bit 15 not set");
}

/* ---- Test: bitmap clear ---- */
TEST(test_bitmap_clear) {
    uint8_t buf[4] = {0xFF};

    bitmap_clear(buf, 0);
    ASSERT_EQ(buf[0], 0x7Fu, "clearing bit 0 masks correct");
}

/* ---- Test: AIP parse extracts SDA bit ---- */
TEST(test_aip_parse_sda) {
    uint8_t aip[] = {0x02, 0x00};  /* B3=1 → SDA capable */
    aip_fields_t fields;
    aip_parse(aip, sizeof(aip), &fields);

    ASSERT_EQ(fields.b1_sda_capable, 1, "SDA capable bit set");
}

/* ---- Test: TVR hex encoding ---- */
TEST(test_tvr_to_hex) {
    uint8_t tvr[] = {0xAB, 0xCD};
    char hex[16];
    int rc = tvr_to_hex(tvr, 2, hex, sizeof(hex));
    ASSERT_EQ(rc, 4, "hex output length");
    ASSERT_EQ(memcmp(hex, "ABCD", 4), 0, "hex value correct");
}

/* ---- Test: Terminal qualifiers parse ---- */
TEST(test_tq_parse) {
    uint8_t tq[4] = {0xFF, 0x00, 0x00, 0x00};
    terminal_qualifiers_t tqf;
    terminal_qualifiers_parse(tq, 4, &tqf);

    ASSERT_EQ(tqf.byte1_has_online_credentials, 1, "TQ byte1 bit0 set");
    ASSERT_EQ(tqf.byte2_default_term, 0, "TQ byte2 bit0 cleared");
}

int main(void)
{
    printf("\n=== Bitmap Utility Tests ===\n\n");

    RUN(test_bitmap_set_get);
    RUN(test_bitmap_clear);
    RUN(test_aip_parse_sda);
    RUN(test_tvr_to_hex);
    RUN(test_tq_parse);

    printf("\n%d passed, %d failed out of %d tests\n\n",
           g_tests_run - g_tests_fail, g_tests_fail, g_tests_run);
    return g_tests_fail > 0 ? 1 : 0;
}
