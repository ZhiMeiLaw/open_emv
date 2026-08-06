/**
 * @file tests/unit/test_kernel_boundary.c
 * @brief Boundary and robustness tests for the kernel framework.
 *
 * Tests null-safety, missing mandatory tags, and warehouse overflow.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/dict_validate.h"
#include "emv_kernel/errors.h"
#include "emv_kernel/orchestrator.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/kernel_registry.h"

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
/*  Test 1: null context → safe error                                 */
/* ================================================================== */
TEST(test_null_context_safe_error)
{
    /* kernel_execute with NULL ep_ctx should return error, not crash */
    int rc = kernel_execute(3, NULL);
    ASSERT_NEQ(rc, 0, "kernel_execute(NULL) returns non-zero");
    ASSERT_EQ(rc, ORCH_E_INVAL, "kernel_execute(NULL) returns ORCH_E_INVAL");

    /* orchestrator_init with NULL oc should return error */
    int rc2 = orchestrator_init(NULL, NULL, NULL, NULL, NULL);
    ASSERT_NEQ(rc2, 0, "orchestrator_init(NULL) returns non-zero");
    ASSERT_EQ(rc2, ORCH_E_INVAL, "orchestrator_init(NULL) returns ORCH_E_INVAL");
}

/* ================================================================== */
/*  Test 2: missing mandatory PAN → validation fail                   */
/* ================================================================== */
TEST(test_missing_mandatory_pan_validation_fail)
{
    /* Create a warehouse WITHOUT PAN (tag 0x5A) */
    uint8_t pool[256];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    /* Add some non-mandatory tags */
    uint8_t tq[] = { 0xF8, 0x00, 0x05, 0x80 };
    tlv_store_set(&wh, 0x9F66, tq, sizeof(tq));
    uint8_t amt[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    tlv_store_set(&wh, 0x9F02, amt, sizeof(amt));
    uint8_t cur[] = { 0x01, 0x56 };
    tlv_store_set(&wh, 0x5F2A, cur, sizeof(cur));
    /* Note: no PAN (0x5A) stored */

    /* Validate against K3 dictionary — PAN is mandatory */
    extern kernel_dict_t kernel3_dict;
    int rc = tlv_validate_dict(&kernel3_dict, &wh);
    ASSERT_NEQ(rc, 0, "tlv_validate_dict fails when PAN missing");
}

/* ================================================================== */
/*  Test 3: warehouse pool overflow → handled                         */
/* ================================================================== */
TEST(test_warehouse_pool_overflow_handled)
{
    /* Create a warehouse with a deliberately tiny pool */
    uint8_t tiny_pool[1];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, tiny_pool, sizeof(tiny_pool));

    /* Try to store any entry — should fail gracefully */
    uint8_t data[] = { 0x01, 0x02, 0x03 };
    int rc = tlv_store_set(&wh, 0x9F02, data, sizeof(data));
    ASSERT_NEQ(rc, 0, "tlv_store_set with tiny pool returns error");
    ASSERT_EQ(rc, WH_E_INVAL, "tlv_store_set returns WH_E_INVAL on overflow");
}

/* ================================================================== */
/*  Test 4: kernel_execute with unregistered kernel                   */
/* ================================================================== */
TEST(test_unregistered_kernel_returns_error)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));

    /* Kernel 99 is never registered */
    int rc = kernel_execute(99, &ep);
    ASSERT_NEQ(rc, 0, "kernel_execute(99) returns non-zero");
    ASSERT_EQ(rc, ORCH_E_NO_CONFIG, "kernel_execute(99) returns ORCH_E_NO_CONFIG");
}

/* ================================================================== */
/*  Test 5: tlv_validate_dict with NULL warehouse                     */
/* ================================================================== */
TEST(test_validate_dict_null_warehouse)
{
    extern kernel_dict_t kernel3_dict;
    int rc = tlv_validate_dict(&kernel3_dict, NULL);
    ASSERT_NEQ(rc, 0, "tlv_validate_dict(NULL) returns error");
}

/* ================================================================== */
/*  Test 6: tlv_dump_ordered with empty warehouse                     */
/* ================================================================== */
TEST(test_dump_ordered_empty_warehouse)
{
    uint8_t pool[256];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    uint8_t out[64];
    uint8_t out_len = 0;
    int rc = tlv_dump_ordered(&wh, NULL, 0, out, sizeof(out));
    ASSERT_EQ(rc, 0, "tlv_dump_ordered on empty wh returns 0");
}

/* ================================================================== */
/*  Main                                                              */
/* ================================================================== */

int main(void)
{
    printf("\n=== Kernel Boundary Tests ===\n\n");

    RUN(test_null_context_safe_error);
    RUN(test_missing_mandatory_pan_validation_fail);
    RUN(test_warehouse_pool_overflow_handled);
    RUN(test_unregistered_kernel_returns_error);
    RUN(test_validate_dict_null_warehouse);
    RUN(test_dump_ordered_empty_warehouse);

    printf("\n%d passed, %d failed out of %d tests\n\n",
           g_tests_run - g_tests_fail, g_tests_fail, g_tests_run);
    return g_tests_fail > 0 ? 1 : 0;
}
