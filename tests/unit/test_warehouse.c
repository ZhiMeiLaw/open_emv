/**
 * @file tests/unit/test_warehouse.c
 * @brief Unit tests for TLV warehouse module.
 *
 * Standalone test — no external test framework dependency.
 * Compile with: gcc -I../include -c test_warehouse.c ../src/core/warehouse.c
 */

#include <stdio.h>
#include <string.h>
#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"

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

#define ASSERT_NEQ(a, b, msg) do { \
    if ((a) == (b)) { \
        printf("FAIL: %s (should not be equal)\n", msg); \
        g_tests_fail++; \
    } \
} while (0)

#define ASSERT_GT(a, b, msg) do { \
    if ((a) <= (b)) { \
        printf("FAIL: %s (expected %d > %d)\n", msg, (int)(a), (int)(b)); \
        g_tests_fail++; \
    } \
} while (0)

/* ---- Test: init resets state ---- */
TEST(test_init_resets) {
    uint8_t pool[1024];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    ASSERT_EQ(wh.count, 0, "count after init");
    ASSERT_EQ(wh.pool_used, 0, "pool_used after init");
}

/* ---- Test: store and get single value ---- */
TEST(test_store_get_single) {
    uint8_t pool[1024];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    const uint8_t val[] = {0x01, 0x02, 0x03};
    int rc = tlv_store_set(&wh, 0x9F02, val, 3);
    ASSERT_EQ(rc, 0, "store returns 0");
    ASSERT_EQ(wh.count, 1, "count after store");

    uint8_t buf[8];
    uint16_t blen = (uint16_t)sizeof(buf);
    rc = tlv_store_get(&wh, 0x9F02, buf, &blen);
    ASSERT_EQ(rc, 0, "get returns 0");
    ASSERT_EQ(blen, 3, "get length");
    ASSERT_EQ(memcmp(buf, val, 3), 0, "get content match");
}

/* ---- Test: get missing tag returns -1 ---- */
TEST(test_get_missing_tag) {
    uint8_t pool[1024];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    uint8_t buf[4] = {0};
    uint16_t blen = 4;
    int rc = tlv_store_get(&wh, 0xFFFF, buf, &blen);
    ASSERT_EQ(rc, -1, "get missing tag returns -1");
}

/* ---- Test: replace existing tag ---- */
TEST(test_replace_tag) {
    uint8_t pool[1024];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    const uint8_t v1[] = {0xAA, 0xBB};
    const uint8_t v2[] = {0xCC, 0xDD, 0xEE};

    tlv_store_set(&wh, 0x5A, v1, 2);
    ASSERT_EQ(wh.count, 1, "count=1 after first store");

    tlv_store_set(&wh, 0x5A, v2, 3);
    uint8_t buf[4];
    uint16_t blen = 4;
    tlv_store_get(&wh, 0x5A, buf, &blen);
    ASSERT_EQ(blen, 3, "replaced value has new length");
    ASSERT_EQ(memcmp(buf, v2, 3), 0, "replaced value matches new data");
}

/* ---- Test: delete entry ---- */
TEST(test_delete_entry) {
    uint8_t pool[1024];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    tlv_store_set(&wh, 0x11, "\x01", 1);
    ASSERT_EQ(tlv_contains(&wh, 0x11), 1, "tag exists before delete");

    tlv_store_delete(&wh, 0x11);
    ASSERT_EQ(tlv_contains(&wh, 0x11), 0, "tag absent after delete");
}

/* ---- Test: clear resets everything ---- */
TEST(test_clear) {
    uint8_t pool[1024];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    tlv_store_set(&wh, 0x11, "\x01", 1);
    tlv_store_set(&wh, 0x22, "\x02", 1);
    tlv_store_set(&wh, 0x33, "\x03", 1);
    ASSERT_EQ(wh.count, 3, "3 entries stored");

    tlv_warehouse_clear(&wh);
    ASSERT_EQ(wh.count, 0, "count=0 after clear");
    ASSERT_EQ(wh.pool_used, 0, "pool_used=0 after clear");
}

/* ---- Test: store multiple different tags ---- */
TEST(test_multi_store) {
    uint8_t pool[2048];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    tlv_store_set(&wh, 0x5A, "123456789012345", 15);
    tlv_store_set(&wh, 0x5F20, "My App", 7);
    tlv_store_set(&wh, 0x9F02, "\x00\x00\x00\x00\x01\x00", 6);

    ASSERT_EQ(wh.count, 3, "3 distinct entries");

    uint8_t buf[16];
    uint16_t blen = 16;
    tlv_store_get(&wh, 0x5A, buf, &blen);
    ASSERT_EQ(blen, 15, "PAN length correct");

    blen = 16;
    tlv_store_get(&wh, 0x5F20, buf, &blen);
    ASSERT_EQ(blen, 7, "label length correct");
}

/* ---- Test: OOM on store ---- */
TEST(test_oom) {
    uint8_t small_pool[8];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, small_pool, sizeof(small_pool));

    /* Try to store a 10-byte value into an 8-byte pool */
    uint8_t big_val[10] = {0};
    int rc = tlv_store_set(&wh, 0x99, big_val, 10);
    ASSERT_EQ(rc, -1, "store fails on OOM");
}

/* ---- Test: store zero-length rejected ---- */
TEST(test_zero_len_rejected) {
    uint8_t pool[1024];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    int rc = tlv_store_set(&wh, 0x11, NULL, 0);
    ASSERT_EQ(rc, -2, "zero-len set returns -2");
}

/* ---- Run all tests ---- */
int main(void)
{
    printf("\n=== TLV Warehouse Tests ===\n\n");

    RUN(test_init_resets);
    RUN(test_store_get_single);
    RUN(test_get_missing_tag);
    RUN(test_replace_tag);
    RUN(test_delete_entry);
    RUN(test_clear);
    RUN(test_multi_store);
    RUN(test_oom);
    RUN(test_zero_len_rejected);

    printf("\n%d passed, %d failed out of %d tests\n\n",
           g_tests_run - g_tests_fail, g_tests_fail, g_tests_run);
    return g_tests_fail > 0 ? 1 : 0;
}
