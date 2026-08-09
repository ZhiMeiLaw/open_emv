/**
 * @file tests/integration/test_k6_e2e.c
 * @brief End-to-end Kernel 6 (eMvCash) integration test.
 *
 * Simulates a full K6 transaction with mock card data:
 *   - SELECT AID → GPO → READ RECORD → No-CVM → GENERATE AC → Outcome
 *
 * K6 specific:
 *   - No offline data authentication
 *   - No CVM (always pass, Tag 9F34 = 0x1F 0x00 0x00)
 *   - IAC/TAC thresholds determine outcome (TC or AAC)
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

/* ================================================================== */
/*  Mock card data for K6 eMvCash                                     */
/* ================================================================== */

static void build_mock_select_response_k6(uint8_t *buf, uint16_t *len)
{
    uint16_t i = 0;
    /* [6F] FCI Template */
    buf[i++] = 0x6F; buf[i++] = 0x1A;
    /* [A5] FCI Proprietary Template */
    buf[i++] = 0xA5; buf[i++] = 0x18;
    /* [BF0C] FCI Issuer Discretionary */
    buf[i++] = 0xBF; buf[i++] = 0x0C; buf[i++] = 0x16;
    /* [9F38] PDOL */
    buf[i++] = 0x9F; buf[i++] = 0x38; buf[i++] = 0x0C;
    buf[i++] = 0x9F; buf[i++] = 0x66; buf[i++] = 0x04;
    buf[i++] = 0x9F; buf[i++] = 0x37; buf[i++] = 0x04;
    buf[i++] = 0x9F; buf[i++] = 0x02; buf[i++] = 0x06;
    buf[i++] = 0x5F; buf[i++] = 0x2A; buf[i++] = 0x02;
    /* [4F] AID for K6 */
    buf[i++] = 0x4F; buf[i++] = 0x07;
    buf[i++] = 0xA0; buf[i++] = 0x00; buf[i++] = 0x00;
    buf[i++] = 0x00; buf[i++] = 0x03; buf[i++] = 0x06;
    buf[i++] = 0x10;  /* K6 AID */
    /* [87] AIP = 0x40 (EMV compliant, no DDA/CDA) */
    buf[i++] = 0x87; buf[i++] = 0x01; buf[i++] = 0x40;
    /* [82] AUC */
    buf[i++] = 0x82; buf[i++] = 0x02; buf[i++] = 0xC0; buf[i++] = 0x00;
    *len = i;
}

static void build_mock_gpo_response_k6(uint8_t *buf, uint16_t *len)
{
    uint16_t i = 0;
    /* [9F27] CID = 0x08 → TC */
    buf[i++] = 0x9F; buf[i++] = 0x27; buf[i++] = 0x01;
    buf[i++] = 0x08;
    /* [9F36] ATC */
    buf[i++] = 0x9F; buf[i++] = 0x36; buf[i++] = 0x02;
    buf[i++] = 0x00; buf[i++] = 0x01;
    /* [87] AIP = 0x40 */
    buf[i++] = 0x87; buf[i++] = 0x01; buf[i++] = 0x40;
    /* [82] AUC */
    buf[i++] = 0x82; buf[i++] = 0x02; buf[i++] = 0xC0; buf[i++] = 0x00;
    /* [5F2D] Initial Balance = 500.00 */
    buf[i++] = 0x5F; buf[i++] = 0x2D; buf[i++] = 0x04;
    buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x01; buf[i++] = 0xF4;
    /* [9F7B] Cardholder Balance Limit */
    buf[i++] = 0x9F; buf[i++] = 0x7B; buf[i++] = 0x04;
    buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x03; buf[i++] = 0xE8;
    /* No AFL → offline approve */
    *len = i;
}

static void build_mock_read_record_response_k6(uint8_t *buf, uint16_t *len)
{
    uint16_t i = 0;
    /* [5A] PAN */
    buf[i++] = 0x5A; buf[i++] = 0x0A;
    buf[i++] = 0x12; buf[i++] = 0x34; buf[i++] = 0x56; buf[i++] = 0x78;
    buf[i++] = 0x90; buf[i++] = 0xAB; buf[i++] = 0xCD; buf[i++] = 0xEF;
    /* [4F] AID */
    buf[i++] = 0x4F; buf[i++] = 0x07;
    buf[i++] = 0xA0; buf[i++] = 0x00; buf[i++] = 0x00;
    buf[i++] = 0x00; buf[i++] = 0x03; buf[i++] = 0x06;
    buf[i++] = 0x10;
    /* [5F20] Application Label */
    buf[i++] = 0x5F; buf[i++] = 0x20; buf[i++] = 0x08;
    buf[i++] = 0x45; buf[i++] = 0x2D; buf[i++] = 0x6D; buf[i++] = 0x76;
    buf[i++] = 0x43; buf[i++] = 0x61; buf[i++] = 0x73; buf[i++] = 0x68;
    *len = i;
}

static void build_mock_genac_response_k6(uint8_t *buf, uint16_t *len)
{
    uint16_t i = 0;
    /* [9F26] Application Cryptogram = TC */
    buf[i++] = 0x9F; buf[i++] = 0x26; buf[i++] = 0x08;
    buf[i++] = 0x01; buf[i++] = 0x23; buf[i++] = 0x45; buf[i++] = 0x67;
    buf[i++] = 0x89; buf[i++] = 0xAB; buf[i++] = 0xCD; buf[i++] = 0xEF;
    /* [9F27] CID = 0x08 → TC */
    buf[i++] = 0x9F; buf[i++] = 0x27; buf[i++] = 0x01;
    buf[i++] = 0x08;
    /* [95] TVR = all zeros (no errors) */
    buf[i++] = 0x95; buf[i++] = 0x05;
    buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;
    buf[i++] = 0x00;
    /* [8A] ARC = 'Y1' (offline approved) */
    buf[i++] = 0x8A; buf[i++] = 0x02;
    buf[i++] = 'Y'; buf[i++] = '1';
    *len = i;
}

/* ================================================================== */
/*  Mock IC Reader Provider                                           */
/* ================================================================== */

typedef enum { MOCK_GPO, MOCK_READ_REC, MOCK_GAC } mock_state_k6_t;

static struct {
    mock_state_k6_t state;
} mock_ctx_k6;

static int mock_k6_init(void) { return 0; }
static int mock_k6_poll_card(uint32_t t) { (void)t; return 0; }
static void mock_k6_deactivate(void) {}

static int mock_k6_transceive(const uint8_t *send, uint16_t send_len,
                              uint8_t *recv, uint16_t recv_max,
                              uint16_t *recv_len)
{
    (void)send_len; (void)recv_max;
    uint8_t ins = send[1];

    if (ins == 0xA8) {
        /* GPO */
        build_mock_gpo_response_k6(recv, recv_len);
        mock_ctx_k6.state = MOCK_READ_REC;
    } else if (ins == 0xB2) {
        /* READ RECORD */
        build_mock_read_record_response_k6(recv, recv_len);
        mock_ctx_k6.state = MOCK_GAC;
    } else if (ins == 0xAE) {
        /* GENERATE AC */
        build_mock_genac_response_k6(recv, recv_len);
    } else {
        /* SELECT or other — return success with mock AID */
        uint16_t n = 0;
        uint8_t select_resp[] = {
            0x6F, 0x1A, 0xA5, 0x18, 0xBF, 0x0C, 0x16,
            0x9F, 0x38, 0x0C, 0x9F, 0x66, 0x04, 0x9F, 0x37, 0x04,
            0x9F, 0x02, 0x06, 0x5F, 0x2A, 0x02,
            0x4F, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x06, 0x10,
            0x87, 0x01, 0x40
        };
        n = sizeof(select_resp);
        if (n > recv_max) n = recv_max;
        memcpy(recv, select_resp, n);
        *recv_len = n;
    }

    /* Append SW 9000 */
    if (*recv_len + 2 <= recv_max) {
        recv[*recv_len++] = 0x90;
        recv[*recv_len++] = 0x00;
    }
    return 0;
}

const struct ic_reader_provider_s mock_icr_k6 = {
    .init = mock_k6_init,
    .poll_card = mock_k6_poll_card,
    .transceive = mock_k6_transceive,
    .deactivate = mock_k6_deactivate,
};

/* ================================================================== */
/*  Test helpers                                                      */
/* ================================================================== */

static int g_tests_run = 0, g_tests_fail = 0;

#define TEST(name) static void name(void)
#define RUN(t) do { g_tests_run++; printf("  TEST: %s ... ", #t); (t)(); printf("OK\n"); } while(0)
#define ASSERT_EQ(a,b,m) do { if((a)!=(b)){printf("FAIL: %s exp=%d got=%d\n",m,(int)(b),(int)(a)); g_tests_fail++;} } while(0)
#define ASSERT_GE(a,b,m) do { if((a)<(b)){printf("FAIL: %s exp>=%d got=%d\n",m,(int)(b),(int)(a)); g_tests_fail++;} } while(0)

/* ================================================================== */
/*  Test 1: Basic K6 kernel_execute flow → TC outcome                 */
/* ================================================================== */

TEST(test_k6_tc_outcome)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));
    ep.icr = &mock_icr_k6;

    int rc = kernel_execute(6, &ep);
    ASSERT_EQ(rc, 0, "kernel_execute returns 0");
    ASSERT_EQ(ep.outcome, OUTCOME_APPROVE_TERMINAL_CONDS, "outcome is APPROVE_TERMINAL");
}

/* ================================================================== */
/*  Test 2: Warehouse has mandatory K6 tags after GPO+READ RECORD    */
/* ================================================================== */

TEST(test_k6_warehouse_mandatory_tags)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));
    ep.icr = &mock_icr_k6;

    kernel_execute(6, &ep);

    /* CID should be present (from GPO) */
    const tlv_entry_t *cid = tlv_find(ep.wh, 0x9F27);
    ASSERT_GE(cid != NULL, 1, "CID present after GPO");
    if (cid) {
        uint8_t cid_type = (cid->value[0] >> 5) & 0x03;
        ASSERT_EQ(cid_type, 0x01, "CID indicates TC");
    }

    /* ATC should be present */
    const tlv_entry_t *atc = tlv_find(ep.wh, 0x9F36);
    ASSERT_GE(atc != NULL, 1, "ATC present");

    /* PAN should be present */
    const tlv_entry_t *pan = tlv_find(ep.wh, 0x5A);
    ASSERT_GE(pan != NULL, 1, "PAN present");
}

/* ================================================================== */
/*  Test 3: CVM Results = No CVM (0x1F 0x00 0x00)                    */
/* ================================================================== */

TEST(test_k6_no_cvm)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));
    ep.icr = &mock_icr_k6;

    kernel_execute(6, &ep);

    /* CVM Results should be 0x1F 0x00 0x00 (No CVM) */
    const tlv_entry_t *cvm = tlv_find(ep.wh, 0x9F34);
    ASSERT_GE(cvm != NULL, 1, "CVM Results present");
    if (cvm && cvm->len >= 3) {
        ASSERT_EQ(cvm->value[0], 0x1F, "CVM method = No CVM");
        ASSERT_EQ(cvm->value[1], 0x00, "CVM reserved = 0x00");
        ASSERT_EQ(cvm->value[2], 0x00, "CVM result = 0x00");
    }
}

/* ================================================================== */
/*  Test 4: Application Cryptogram present                            */
/* ================================================================== */

TEST(test_k6_application_cryptogram)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));
    ep.icr = &mock_icr_k6;

    kernel_execute(6, &ep);

    /* Application Cryptogram should be present */
    const tlv_entry_t *ac = tlv_find(ep.wh, 0x9F26);
    ASSERT_GE(ac != NULL, 1, "AC present");
    if (ac) {
        ASSERT_EQ(ac->len, 8, "AC length is 8 bytes");
    }
}

/* ================================================================== */
/*  Main                                                              */
/* ================================================================== */

int main(void)
{
    printf("\n=== K6 (eMvCash) End-to-End Integration Tests ===\n\n");

    RUN(test_k6_tc_outcome);
    RUN(test_k6_warehouse_mandatory_tags);
    RUN(test_k6_no_cvm);
    RUN(test_k6_application_cryptogram);

    printf("\n%d passed, %d failed out of %d tests\n\n",
           g_tests_run - g_tests_fail, g_tests_fail, g_tests_run);
    return g_tests_fail > 0 ? 1 : 0;
}
