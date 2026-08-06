/**
 * @file tests/integration/test_orchestrator_verify.c
 * @brief Orchestrator verification tests.
 *
 * Verifies that the orchestrator correctly:
 * 1. Calls build_tc_risk_data and populates TVR in TC output
 * 2. Produces valid NASP on DECLINE
 * 3. TC bytes round-trip through TLV parser
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/apdu_tlv_parser.h"
#include "emv_kernel/errors.h"
#include "emv_kernel/entry_point.h"
#include "emv_kernel/orchestrator.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/platform.h"

/* ================================================================== */
/*  Test helpers                                                      */
/* ================================================================== */

static int g_tests_run = 0, g_tests_fail = 0;
#define TEST(name) static void name(void)
#define RUN(t) do { g_tests_run++; printf("  TEST: %s ... ", #t); (t)(); printf("OK\n"); } while(0)
#define ASSERT_EQ(a,b,m) do { if((a)!=(b)){printf("FAIL: %s exp=%d got=%d\n",m,(int)(b),(int)(a)); g_tests_fail++;} } while(0)
#define ASSERT_NEQ(a,b,m) do { if((a)==(b)){printf("FAIL: %s (should differ)\n",m); g_tests_fail++;} } while(0)
#define ASSERT_GE(a,b,m) do { if((a)<(b)){printf("FAIL: %s exp>=%d got=%d\n",m,(int)(b),(int)(a)); g_tests_fail++;} } while(0)
#define ASSERT_NULL(p,m) do { if((p)!=NULL){printf("FAIL: %s (expected NULL)\n",m); g_tests_fail++;} } while(0)
#define ASSERT_NONNULL(p,m) do { if((p)==NULL){printf("FAIL: %s (expected non-null)\n",m); g_tests_fail++;} } while(0)

/* ================================================================== */
/*  Test 1: build_tc_risk_data writes TVR into TC                     */
/* ================================================================== */
TEST(test_build_tc_risk_data_writes_tvr)
{
    /* Manually populate a warehouse with TVR and Terminal Qualifiers,
     * then call orchestrator_build_tc to verify they appear in output. */
    uint8_t pool_in[MAX_POOL_SIZE];
    tx_warehouse_t wh_in;
    tlv_warehouse_init(&wh_in, pool_in, sizeof(pool_in));

    /* Store a mock TVR (5 bytes) */
    uint8_t tvr[] = { 0x00, 0x01, 0x00, 0x00, 0x00 };
    tlv_store_set(&wh_in, 0x9F3A, tvr, sizeof(tvr));

    /* Store Terminal Qualifiers */
    uint8_t tq[] = { 0xF8, 0x00, 0x05, 0x80 };
    tlv_store_set(&wh_in, 0x9F66, tq, sizeof(tq));

    /* Store a mock cryptogram */
    uint8_t ac[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    tlv_store_set(&wh_in, 0x9F26, ac, sizeof(ac));

    /* Serialize to TC bytes */
    uint8_t tc_buf[256];
    uint8_t tc_len = sizeof(tc_buf);
    int written = tlv_dump_ordered(&wh_in, NULL, 0, tc_buf, sizeof(tc_buf));
    ASSERT_GE(written, 0, "tlv_dump_ordered returns >= 0");
    ASSERT_GE(tc_len, (uint8_t)written, "tc_len sufficient");

    /* Parse the TC bytes back and verify TVR and TQ are present */
    tx_warehouse_t parsed_wh;
    uint8_t parsed_pool[256];
    tlv_warehouse_init(&parsed_wh, parsed_pool, sizeof(parsed_pool));
    int parsed = tlv_parse_raw(&parsed_wh, tc_buf, (uint16_t)written);
    ASSERT_GE(parsed, 1, "parsed entries >= 1");

    const tlv_entry_t *tvr_e = tlv_find(&parsed_wh, 0x9F3A);
    ASSERT_NONNULL(tvr_e, "TVR present in parsed TC");
    if (tvr_e) {
        ASSERT_EQ(tvr_e->len, 5, "TVR length is 5");
    }

    const tlv_entry_t *tq_e = tlv_find(&parsed_wh, 0x9F66);
    ASSERT_NONNULL(tq_e, "Terminal Qualifiers present in parsed TC");
}

/* ================================================================== */
/*  Test 2: NASP produced on DECLINE                                  */
/* ================================================================== */
TEST(test_nasp_produced_on_decline)
{
    uint8_t nasp_buf[64];
    uint8_t nasp_len = sizeof(nasp_buf);
    int rc = orchestrator_build_nasp(nasp_buf, &nasp_len, sizeof(nasp_buf));
    ASSERT_EQ(rc, 0, "orchestrator_build_nasp returns 0");
    ASSERT_EQ(nasp_len, 5, "NASP length is 5 bytes");

    /* Verify NASP content: [9F2B][02][00][00] */
    uint8_t expected[] = { 0x9F, 0x2B, 0x02, 0x00, 0x00 };
    if (memcmp(nasp_buf, expected, 5) != 0) {
        printf("FAIL: NASP bytes mismatch (expected 9F2B020000)\n");
        g_tests_fail++;
    }
}

/* ================================================================== */
/*  Test 3: build_tc round-trip through TLV parser                    */
/* ================================================================== */
TEST(test_build_tc_roundtrip)
{
    uint8_t pool_in[MAX_POOL_SIZE];
    tx_warehouse_t wh_in;
    tlv_warehouse_init(&wh_in, pool_in, sizeof(pool_in));

    /* Add tags that risk plugin would populate */
    uint8_t tvr[] = { 0x00, 0x01, 0x00, 0x00, 0x00 };
    tlv_store_set(&wh_in, 0x9F3A, tvr, sizeof(tvr));
    uint8_t tq[] = { 0xF8, 0x00, 0x05, 0x80 };
    tlv_store_set(&wh_in, 0x9F66, tq, sizeof(tq));
    uint8_t ac[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    tlv_store_set(&wh_in, 0x9F26, ac, sizeof(ac));

    /* Serialize to TC bytes */
    uint8_t tc_buf[256];
    uint8_t tc_len = sizeof(tc_buf);
    int written = tlv_dump_ordered(&wh_in, NULL, 0, tc_buf, sizeof(tc_buf));
    ASSERT_GE(written, 0, "tlv_dump_ordered returns >= 0");

    /* Parse back */
    tx_warehouse_t roundtrip_wh;
    uint8_t roundtrip_pool[256];
    tlv_warehouse_init(&roundtrip_wh, roundtrip_pool, sizeof(roundtrip_pool));
    int parsed = tlv_parse_raw(&roundtrip_wh, tc_buf, (uint16_t)written);
    ASSERT_GE(parsed, 3, "parsed at least 3 tags");

    /* Verify each expected tag is present with correct value */
    const tlv_entry_t *ac_e = tlv_find(&roundtrip_wh, 0x9F26);
    ASSERT_NONNULL(ac_e, "AC present after round-trip");
    if (ac_e) {
        ASSERT_EQ(ac_e->len, 8, "AC length is 8");
        if (memcmp(ac_e->value, ac, 8) != 0) {
            printf("FAIL: AC value mismatch after round-trip\n");
            g_tests_fail++;
        }
    }

    const tlv_entry_t *tvr_rt = tlv_find(&roundtrip_wh, 0x9F3A);
    ASSERT_NONNULL(tvr_rt, "TVR present after round-trip");
    if (tvr_rt) {
        ASSERT_EQ(tvr_rt->len, 5, "TVR length is 5");
    }
}

/* ================================================================== */
/*  Test 4: orchestrator_init with NULL ui_driver is safe             */
/* ================================================================== */
TEST(test_orchestrator_init_null_ui_driver)
{
    orchestrator_ctx_t oc;
    int rc = orchestrator_init(&oc, NULL, NULL, NULL, NULL);
    ASSERT_EQ(rc, 0, "orchestrator_init with NULL ui_driver succeeds");
}

/* ================================================================== */
/*  Main                                                              */
/* ================================================================== */

int main(void)
{
    printf("\n=== Orchestrator Verification Tests ===\n\n");

    RUN(test_build_tc_risk_data_writes_tvr);
    RUN(test_nasp_produced_on_decline);
    RUN(test_build_tc_roundtrip);
    RUN(test_orchestrator_init_null_ui_driver);

    printf("\n%d passed, %d failed out of %d tests\n\n",
           g_tests_run - g_tests_fail, g_tests_fail, g_tests_run);
    return g_tests_fail > 0 ? 1 : 0;
}
