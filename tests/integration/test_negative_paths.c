/**
 * @file tests/integration/test_negative_paths.c
 * @brief Negative-path integration tests for K3/K5/K7.
 *
 * Uses orchestrator_execute() for CVM/risk plugin tests and
 * kernel_execute() for kernel_ops path tests (e.g. expiry).
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

/* ================================================================== */
/*  Shared warehouse population helpers                               */
/* ================================================================== */

/* Populate a warehouse with minimal required tags for K3/K7 */
static void populate_k3_k7_wh(tx_warehouse_t *wh)
{
    uint8_t pan[] = { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xFF, 0xAA };
    tlv_store_set(wh, 0x5A, pan, sizeof(pan));
    uint8_t amt[] = { 0x00, 0x00, 0x00, 0x00, 0x01, 0xF4 };
    tlv_store_set(wh, 0x9F02, amt, sizeof(amt));
    uint8_t cur[] = { 0x01, 0x56 };
    tlv_store_set(wh, 0x5F2A, cur, sizeof(cur));
    uint8_t tq[] = { 0xF8, 0x00, 0x05, 0x80 };
    tlv_store_set(wh, 0x9F66, tq, sizeof(tq));
    uint8_t atc[] = { 0x00, 0x01 };
    tlv_store_set(wh, 0x9F36, atc, sizeof(atc));
    uint8_t aip[] = { 0x42 };
    tlv_store_set(wh, 0x87, aip, sizeof(aip));
}

/* ================================================================== */
/*  K3: CVM_FAIL → DECLINE (orchestrator path: CTQ requires PIN)      */
/* ================================================================== */
TEST(test_k3_cvm_fail_decline)
{
    orchestrator_ctx_t oc;
    orchestrator_init(&oc, NULL, NULL, NULL, NULL);  /* No UI driver */
    populate_k3_k7_wh(&oc.input_wh);

    /* Set CTQ with online_pin_required = 1 (byte1 bit 0) */
    uint8_t ctq[] = { 0x01, 0x00 };
    tlv_store_set(&oc.input_wh, 0x9F6C, ctq, sizeof(ctq));

    int rc = orchestrator_execute(3);
    (void)rc;
    const outcome_result_t *result = orchestrator_get_outcome();
    /* K3 CVM plugin: CTQ online_pin_required=1, no UI driver → CVM_FAIL */
    ASSERT_EQ(result->code, OUTCOME_DECLINE, "outcome is DECLINE");
}

/* ================================================================== */
/*  K7: SDS mismatch → DECLINE (orchestrator path: risk SDS check)    */
/* ================================================================== */
TEST(test_k7_sds_mismatch_decline)
{
    orchestrator_ctx_t oc;

    /* Set up K7 POS params with SDS code 0x01 */
    typedef struct { uint8_t sds_code; uint8_t tip_signature_supported:1; uint8_t tip_online_pin_supported:1; } pos_params_k7_t;
    pos_params_k7_t k7_pp = { .sds_code = 0x01, .tip_signature_supported = 0, .tip_online_pin_supported = 0 };
    orchestrator_init(&oc, NULL, NULL, &k7_pp, NULL);
    populate_k3_k7_wh(&oc.input_wh);

    /* Card returns SDS code 0x02 (mismatch!) */
    uint8_t sds[] = { 0x00, 0x02 };
    tlv_store_set(&oc.input_wh, 0x9F36, sds, sizeof(sds));

    int rc = orchestrator_execute(7);
    (void)rc;
    const outcome_result_t *result = orchestrator_get_outcome();
    /* K7 risk plugin: SDS mismatch → RISK_FAIL → DECLINE */
    ASSERT_EQ(result->code, OUTCOME_DECLINE, "outcome is DECLINE");
}

/* ================================================================== */
/*  K5: Amount exceeds unsigned_limit → online path                   */
/* ================================================================== */
TEST(test_k5_amount_exceeds_limit)
{
    orchestrator_ctx_t oc;

    /* K5 CVM: amount >= unsigned_amount_limit → CVM_PASS but sets
     * online signal. The orchestrator checks cvm_res==PASS and
     * risk_res==PASS → APPROVE_TERMINAL_CONDS. The online_required
     * flag is set by the kernel_ops in kernel_execute, not orchestrator.
     * So this test verifies the CVM path doesn't crash and returns PASS. */
    typedef struct {
        uint32_t unsigned_amount_limit;
        uint32_t cdcvm_limit;
        uint8_t  tip_signature_supported:1;
        uint8_t  tip_online_pin_supported:1;
    } pos_params_k5_t;
    pos_params_k5_t k5_pp = { .unsigned_amount_limit = 100, .cdcvm_limit = 0,
                               .tip_signature_supported = 0, .tip_online_pin_supported = 0 };
    orchestrator_init(&oc, NULL, NULL, &k5_pp, NULL);

    /* Amount = 500 (exceeds limit) */
    uint8_t amt[] = { 0x00, 0x00, 0x00, 0x00, 0x01, 0xF4 };
    tlv_store_set(&oc.input_wh, 0x9F02, amt, sizeof(amt));
    uint8_t cur[] = { 0x01, 0x56 };
    tlv_store_set(&oc.input_wh, 0x5F2A, cur, sizeof(cur));
    uint8_t pan[] = { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xFF, 0xAA };
    tlv_store_set(&oc.input_wh, 0x5A, pan, sizeof(pan));

    int rc = orchestrator_execute(5);
    /* CVM returns PASS (amount >= limit → online path, not decline) */
    ASSERT_EQ(rc, 0, "orchestrator_execute returns 0");
    const outcome_result_t *result = orchestrator_get_outcome();
    /* CVM PASS + Risk PASS + no crypto → APPROVE_TERMINAL_CONDS */
    ASSERT_EQ(result->code, OUTCOME_APPROVE_TERMINAL_CONDS, "outcome is APPROVE");
}

/* ================================================================== */
/*  K3: Expired card → DECLINE (kernel_execute path: processing restrictions) */
/* ================================================================== */
TEST(test_k3_expired_card_decline)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));

    /* Populate warehouse with expired card data */
    uint8_t exp_date[] = { 0x20, 0x01, 0x01 };  /* 2020-01-01 (past) */
    tlv_store_set(ep.wh, 0x5F24, exp_date, sizeof(exp_date));
    uint8_t txn_date[] = { 0x26, 0x01, 0x01 };  /* 2026-01-01 (future) */
    tlv_store_set(ep.wh, 0x9A, txn_date, sizeof(txn_date));
    uint8_t pan[] = { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xFF, 0xAA };
    tlv_store_set(ep.wh, 0x5A, pan, sizeof(pan));
    uint8_t tq[] = { 0xF8, 0x00, 0x05, 0x80 };
    tlv_store_set(ep.wh, 0x9F66, tq, sizeof(tq));
    uint8_t aip[] = { 0x42 };
    tlv_store_set(ep.wh, 0x87, aip, sizeof(aip));
    uint8_t ctq[] = { 0x00, 0x00 };
    tlv_store_set(ep.wh, 0x9F6C, ctq, sizeof(ctq));

    /* kernel_execute's Processing Restrictions hook (kernel_ops_kernel3.c
     * §5.5) checks expiry: txn_date > exp_date → decline_required = 1
     * kernel_determine_outcome → DECLINE */
    int rc = kernel_execute(3, &ep);
    ASSERT_EQ(rc, 0, "kernel_execute returns 0");
    /* Expired card → decline_required → DECLINE */
    ASSERT_EQ(ep.outcome, OUTCOME_DECLINE, "outcome is DECLINE");
}

/* ================================================================== */
/*  Main                                                              */
/* ================================================================== */

int main(void)
{
    printf("\n=== Negative Path Integration Tests ===\n\n");

    RUN(test_k3_cvm_fail_decline);
    RUN(test_k3_expired_card_decline);
    RUN(test_k5_amount_exceeds_limit);
    RUN(test_k7_sds_mismatch_decline);

    printf("\n%d passed, %d failed out of %d tests\n\n",
           g_tests_run - g_tests_fail, g_tests_fail, g_tests_run);
    return g_tests_fail > 0 ? 1 : 0;
}
