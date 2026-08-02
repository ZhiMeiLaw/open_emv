/**
 * @file tests/unit/test_tlv_encode.c
 * @brief Unit tests for BER-TLV encoding/decoding.
 */

#include <stdio.h>
#include <string.h>
#include "emv_kernel/types.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/errors.h"

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

#define ASSERT_GT(a, b, msg) do { \
    if ((a) <= (b)) { \
        printf("FAIL: %s (expected > %d, got=%d)\n", msg, (int)(b), (int)(a)); \
        g_tests_fail++; \
    } \
} while (0)

/* ---- Test: 1-byte tag encodes to 1 byte ---- */
TEST(test_tag_1byte_encode) {
    uint8_t out[4];
    uint8_t olen = 4;
    int rc = tlv_encode_tag(0x5A, out, &olen);
    ASSERT_EQ(rc, 0, "encode single byte tag");
    ASSERT_EQ(olen, 1, "tag length is 1");
    ASSERT_EQ(out[0], 0x5A, "tag value matches");
}

/* ---- Test: 2-byte tag encodes to 2 bytes ---- */
TEST(test_tag_2byte_encode) {
    uint8_t out[4];
    uint8_t olen = 4;
    int rc = tlv_encode_tag(0x9F02, out, &olen);
    ASSERT_EQ(rc, 0, "encode 2-byte tag");
    ASSERT_EQ(olen, 2, "tag length is 2");
    ASSERT_EQ(out[0], 0x9F, "high byte");
    ASSERT_EQ(out[1], 0x02, "low byte");
}

/* ---- Test: tag roundtrip decode == original ---- */
TEST(test_tag_roundtrip) {
    uint32_t orig = 0x9F66;
    uint8_t encoded[4];
    uint8_t elen = 4;
    tlv_encode_tag(orig, encoded, &elen);

    uint32_t decoded = 0;
    int consumed = tlv_decode_tag(encoded, elen, &decoded);
    ASSERT_EQ(consumed, 2, "decoded 2 tag bytes");
    ASSERT_EQ(decoded, orig, "decoded tag matches original");
}

/* ---- Test: dump_raw serializes warehouse correctly ---- */
TEST(test_dump_raw) {
    uint8_t pool[512];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    /* Store 2 simple tags */
    uint8_t v1[] = {0xAB, 0xCD};
    uint8_t v2[] = {0x01};
    tlv_store_set(&wh, 0x5A, v1, 2);
    tlv_store_set(&wh, 0x1A, v2, 1);

    uint8_t out[128];
    int written = tlv_dump_raw(&wh, out, sizeof(out));
    ASSERT_GT(written, 0, "dump produces output");
    /* First byte should be tag 0x5A */
    ASSERT_EQ(out[0], 0x5A, "first tag in dump");
}

/* ---- Test: parse_raw loads into warehouse ---- */
TEST(test_parse_raw) {
    uint8_t pool[512];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    /* Raw TLV: tag=0x9F02 (2-byte), len=2, value={0x12, 0x34} */
    uint8_t raw[] = {0x9F, 0x02, 0x02, 0x12, 0x34};
    int parsed = tlv_parse_raw(raw, sizeof(raw), &wh);
    ASSERT_EQ(parsed, 1, "parsed 1 entry");
    ASSERT_EQ(wh.count, 1, "warehouse has 1 entry");

    uint8_t buf[4];
    uint16_t blen = 4;
    int rc = tlv_store_get(&wh, 0x9F02, buf, &blen);
    ASSERT_EQ(rc, 0, "get parsed tag");
    ASSERT_EQ(buf[0], 0x12, "value byte 0");
    ASSERT_EQ(buf[1], 0x34, "value byte 1");
}

/* ---- Test: dump_ordered outputs in specified order ---- */
TEST(test_dump_ordered) {
    uint8_t pool[512];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    tlv_store_set(&wh, 0x11, "\xAA", 1);
    tlv_store_set(&wh, 0x22, "\xBB", 1);
    tlv_store_set(&wh, 0x33, "\xCC", 1);

    uint32_t order[] = { 0x33, 0x11 };  /* Intentionally reorder */
    uint8_t out[64];
    int written = tlv_dump_ordered(&wh, order, 2, out, sizeof(out));
    ASSERT_GT(written, 0, "ordered dump produces output");
    /* First should be tag 0x33 */
    ASSERT_EQ(out[0], 0x33, "first ordered tag is 0x33");
}

/* ---- Test: tag_byte_length ---- */
TEST(test_tag_byte_length) {
    ASSERT_EQ(tlv_tag_byte_length(0x5A), 1, "1-byte tag len");
    ASSERT_EQ(tlv_tag_byte_length(0x9F02), 2, "2-byte tag len");
    ASSERT_EQ(tlv_tag_byte_length(0x9F2100), 3, "3-byte tag len");
    ASSERT_EQ(tlv_tag_byte_length(0xFFFFFFFF), 4, "4-byte tag len");
    ASSERT_EQ(tlv_tag_byte_length(0x00), 0, "zero tag rejected");
}

int main(void)
{
    printf("\n=== TLV Encode/Decode Tests ===\n\n");

    RUN(test_tag_1byte_encode);
    RUN(test_tag_2byte_encode);
    RUN(test_tag_roundtrip);
    RUN(test_dump_raw);
    RUN(test_parse_raw);
    RUN(test_dump_ordered);
    RUN(test_tag_byte_length);

    printf("\n%d passed, %d failed out of %d tests\n\n",
           g_tests_run - g_tests_fail, g_tests_fail, g_tests_run);
    return g_tests_fail > 0 ? 1 : 0;
}
