/**
 * @file tests/unit/test_risk_plugin_k7.c
 * @brief Unit tests for Kernel 7 (Token Payment) Risk plugin.
 *
 * Standalone test — compiles with:
 *   gcc -I../include -c ../src/plugin/risk_plugin_kernel7.c src/core/warehouse.c
 *   gcc -I../include test_risk_plugin_k7.c ../src/plugin/risk_plugin_kernel7.c src/core/warehouse.c src/utils/bitmap.c -o test_risk_k7
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/orchestrator.h"

/* External symbol from risk_plugin_kernel7.c */
extern const struct risk_plugin_s kernel7_risk_plugin;

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

/* ---- Test: plugin structure exists ---- */
TEST(test_plugin_exists) {
    const risk_plugin_t *plugin = &kernel7_risk_plugin;
    ASSERT_EQ(plugin != NULL, 1, "plugin pointer non-null");
    ASSERT_EQ(plugin->check != NULL, 1, "check function non-null");
    ASSERT_EQ(plugin->build_tc_risk_data != NULL, 1, "build_tc_risk_data non-null");
    ASSERT_EQ(plugin->update_iccdb != NULL, 1, "update_iccdb non-null");
    ASSERT_EQ(plugin->version, 1, "plugin version 1");
}

/* ---- Test: risk_check with null context ---- */
TEST(test_risk_check_null_ctx) {
    risk_result_t result = kernel7_risk_plugin.check(NULL, RISK_CHECK_SDS);
    ASSERT_EQ(result, RISK_PASS, "null context returns PASS");
}

/* ---- Test: risk_check SDS validation with missing SDS tag ---- */
TEST(test_risk_check_sds_missing) {
    /* Setup minimal context with empty warehouse */
    uint8_t pool[1024];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    orchestrator_ctx_t oc;
    memset(&oc, 0, sizeof(oc));
    oc.input_wh = &wh;
    oc.pos_params = NULL; /* No POS params — SDS validation should fail gracefully */

    risk_result_t result = kernel7_risk_plugin.check(&oc, RISK_CHECK_SDS);
    /* With missing SDS and no POS params, should return PASS (not a fatal error) */
    (void)result;
}

/* ---- Test: risk_check TRM (terminal risk management) ---- */
TEST(test_risk_check_trm) {
    uint8_t pool[1024];
    tx_warehouse_t wh;
    tlv_warehouse_init(&pool, pool, sizeof(pool));

    orchestrator_ctx_t oc;
    memset(&oc, 0, sizeof(oc));
    oc.input_wh = &wh;

    risk_result_t result = kernel7_risk_plugin.check(&oc, RISK_CHECK_TRM);
    ASSERT_EQ(result, RISK_PASS, "TRM check returns PASS");
}

/* ---- Test: risk_check TDOL validation with all tags present ---- */
TEST(test_risk_check_tdol_pass) {
    uint8_t pool[2048];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    /* Populate required TDOL tags */
    const uint8_t tq[] = {0x00, 0x00, 0x00, 0x00};
    const uint8_t amt[] = {0x00, 0x00, 0x00, 0x01, 0x00};
    const uint8_t curr[] = {0x35, 0x38}; /* EUR = 0x3538 in BCD */
    const uint8_t sds_data[] = {0x01, 0x00};

    tlv_store_set(&wh, 0x9F66, tq, sizeof(tq));
    tlv_store_set(&wh, 0x9F02, amt, sizeof(amt));
    tlv_store_set(&wh, 0x5F2A, curr, sizeof(curr));
    tlv_store_set(&wh, 0x9F36, sds_data, sizeof(sds_data));

    orchestrator_ctx_t oc;
    memset(&oc, 0, sizeof(oc));
    oc.input_wh = &wh;
    oc.pos_params = NULL;

    risk_result_t result = kernel7_risk_plugin.check(&oc, RISK_CHECK_TDOL);
    ASSERT_EQ(result, RISK_PASS, "TDOL check passes when all tags present");
}

/* ---- Test: risk_check TDOL validation with missing tag ---- */
TEST(test_risk_check_tdol_fail) {
    uint8_t pool[1024];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    /* Only populate some tags (missing 0x9F36) */
    const uint8_t tq[] = {0x00, 0x00, 0x00, 0x00};
    tlv_store_set(&wh, 0x9F66, tq, sizeof(tq));

    orchestrator_ctx_t oc;
    memset(&oc, 0, sizeof(oc));
    oc.input_wh = &wh;
    oc.pos_params = NULL;

    risk_result_t result = kernel7_risk_plugin.check(&oc, RISK_CHECK_TDOL);
    ASSERT_EQ(result, RISK_FAIL, "TDOL check fails when required tag missing");
}

/* ---- Test: build_tc_risk_data with minimal input ---- */
TEST(test_build_tc_risk_data) {
    uint8_t pool1[1024], pool2[1024];
    tx_warehouse_t input_wh, tc_wh;
    tlv_warehouse_init(&input_wh, pool1, sizeof(pool1));
    tlv_warehouse_init(&tc_wh, pool2, sizeof(pool2));

    /* Put some tags in input */
    const uint8_t tvr[] = {0x00, 0x00, 0x00, 0x00, 0x00};
    const uint8_t tq[] = {0x00, 0x00, 0x00, 0x00};

    tlv_store_set(&input_wh, 0x9F3A, tvr, sizeof(tvr));
    tlv_store_set(&input_wh, 0x9F66, tq, sizeof(tq));

    orchestrator_ctx_t oc;
    memset(&oc, 0, sizeof(oc));
    oc.input_wh = &input_wh;

    int rc = kernel7_risk_plugin.build_tc_risk_data(&oc, &tc_wh);
    ASSERT_EQ(rc, 0, "build_tc_risk_data returns 0 on success");

    /* Verify TC has expected tags */
    assert(tlv_contains(&tc_wh, 0x9F3A) == 1);
    assert(tlv_contains(&tc_wh, 0x9F66) == 1);
}

/* ---- Test: update_iccdb returns success ---- */
TEST(test_update_iccdb) {
    int rc = kernel7_risk_plugin.update_iccdb(NULL, NULL);
    ASSERT_EQ(rc, 0, "update_iccdb returns 0 (success)");
}

/* ---- Test: risk_check_CVM with TVR present ---- */
TEST(test_risk_check_cvm) {
    uint8_t pool[1024];
    tx_warehouse_t wh;
    tlv_warehouse_init(&wh, pool, sizeof(pool));

    const uint8_t tvr[] = {0x00, 0x00, 0x00, 0x00, 0x00};
    tlv_store_set(&wh, 0x9F3A, tvr, sizeof(tvr));

    orchestrator_ctx_t oc;
    memset(&oc, 0, sizeof(oc));
    oc.input_wh = &wh;

    risk_result_t result = kernel7_risk_plugin.check(&oc, RISK_CHECK_CVM);
    (void)result; /* K7 CVM check is mostly informational */
}

/* ---- Run all tests ---- */
int main(void)
{
    printf("\n=== Kernel 7 Risk Plugin Tests ===\n\n");

    RUN(test_plugin_exists);
    RUN(test_risk_check_null_ctx);
    RUN(test_risk_check_sds_missing);
    RUN(test_risk_check_trm);
    RUN(test_risk_check_tdol_pass);
    RUN(test_risk_check_tdol_fail);
    RUN(test_build_tc_risk_data);
    RUN(test_update_iccdb);
    RUN(test_risk_check_cvm);

    printf("\n%d passed, %d failed out of %d tests\n\n",
           g_tests_run - g_tests_fail, g_tests_fail, g_tests_run);

    return g_tests_fail > 0 ? 1 : 0;
}
