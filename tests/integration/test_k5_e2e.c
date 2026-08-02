/**
 * @file tests/integration/test_k5_e2e.c
 * @brief End-to-end Kernel 5 integration test.
 *
 * Simulates a full K5 (qVISA) transaction with mock card data covering:
 *   - SELECT AID → GPO → READ RECORD (CDOL1) → GENERATE AC (CDA) → CVM via 9F50
 *
 * K5 differs from K3:
 *   - CDA (Composite Data Authentication) instead of fDDA
 *   - CVM based on 9F50 (Cardholder Verification Status) from GENERATE AC response
 *   - CDOL1/CDOL2 from READ RECORD instead of TDOL
 *   - Terminal Interchange Profile (9F53) for capability negotiation
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
/*  Mock card data for K5 CDA transaction                             */
/* ================================================================== */

static void build_mock_k5_select_response(uint8_t *buf, uint16_t *len)
{
    uint16_t i = 0;
    /* [6F] FCI Template */
    buf[i++] = 0x6F; buf[i++] = 0x18;
    buf[i++] = 0xA5; buf[i++] = 0x16;
    buf[i++] = 0xBF; buf[i++] = 0x0C; buf[i++] = 0x14;
    /* [9F38] PDOL */
    buf[i++] = 0x9F; buf[i++] = 0x38; buf[i++] = 0x0C;
    buf[i++] = 0x9F; buf[i++] = 0x66; buf[i++] = 0x04;
    buf[i++] = 0x9F; buf[i++] = 0x37; buf[i++] = 0x04;
    buf[i++] = 0x9F; buf[i++] = 0x02; buf[i++] = 0x06;
    buf[i++] = 0x5F; buf[i++] = 0x2A; buf[i++] = 0x02;
    /* [4F] AID */
    buf[i++] = 0x4F; buf[i++] = 0x07;
    buf[i++] = 0xA0; buf[i++] = 0x00; buf[i++] = 0x00;
    buf[i++] = 0x00; buf[i++] = 0x03; buf[i++] = 0x01;
    buf[i++] = 0x0C;
    /* [87] AIP — CDA supported (bit 2 = 1) */
    buf[i++] = 0x87; buf[i++] = 0x01; buf[i++] = 0x02;
    *len = i;
}

/* GPO response with CDOL1 (tag 8C), AFL, CID=TC */
static void build_mock_k5_gpo_response(uint8_t *buf, uint16_t *len)
{
    uint16_t i = 0;
    /* [9F27] CID = TC */
    buf[i++] = 0x9F; buf[i++] = 0x27; buf[i++] = 0x01;
    buf[i++] = 0x08;
    /* [9F36] ATC */
    buf[i++] = 0x9F; buf[i++] = 0x36; buf[i++] = 0x02;
    buf[i++] = 0x00; buf[i++] = 0x02;
    /* [87] AIP */
    buf[i++] = 0x87; buf[i++] = 0x01; buf[i++] = 0x02;
    /* [94] AFL — 9 bytes = 3 records × 3 bytes */
    buf[i++] = 0x94; buf[i++] = 0x09;
    buf[i++] = 0x11; buf[i++] = 0x01; buf[i++] = 0x03; /* SFI=1, rec 1-3 */
    buf[i++] = 0x12; buf[i++] = 0x01; buf[i++] = 0x01; /* SFI=2, rec 1   */
    *len = i;
}

/* READ RECORD response — SFI=1, record 1: CDOL1 + ICC cert data */
static void build_mock_k5_readrec1(uint8_t *buf, uint16_t *len)
{
    uint16_t i = 0;
    /* [8C] CDOL1 — card specifies what data to include in GENERATE AC */
    buf[i++] = 0x8C; buf[i++] = 0x0A;
    buf[i++] = 0x9F; buf[i++] = 0x37; buf[i++] = 0x04;  /* UN */
    buf[i++] = 0x9F; buf[i++] = 0x02; buf[i++] = 0x06;  /* Amount */
    buf[i++] = 0x5F; buf[i++] = 0x2A; buf[i++] = 0x02;  /* Currency */
    /* [9F46] ICC Public Key Certificate (partial, for mock) */
    buf[i++] = 0x9F; buf[i++] = 0x46; buf[i++] = 0x04;
    buf[i++] = 0x01; buf[i++] = 0x02; buf[i++] = 0x03; buf[i++] = 0x04;
    /* [9F47] ICC PK Exponent */
    buf[i++] = 0x9F; buf[i++] = 0x47; buf[i++] = 0x03;
    buf[i++] = 0x01; buf[i++] = 0x00; buf[i++] = 0x01;
    *len = i;
}

/* READ RECORD response — SFI=2, record 1: SDAD */
static void build_mock_k5_readrec2(uint8_t *buf, uint16_t *len)
{
    uint16_t i = 0;
    /* [9F4B] SDAD — CDA signature (simplified mock) */
    buf[i++] = 0x9F; buf[i++] = 0x4B; buf[i++] = 0x04;
    buf[i++] = 0xDE; buf[i++] = 0xAD; buf[i++] = 0xBE; buf[i++] = 0xEF;
    *len = i;
}

/* GENERATE AC response with CDA signature, CID=TC, 9F50=No CVM */
static void build_mock_k5_genac_response(uint8_t *buf, uint16_t *len)
{
    uint16_t i = 0;
    /* [9F26] AC */
    buf[i++] = 0x9F; buf[i++] = 0x26; buf[i++] = 0x08;
    buf[i++] = 0x11; buf[i++] = 0x22; buf[i++] = 0x33; buf[i++] = 0x44;
    buf[i++] = 0x55; buf[i++] = 0x66; buf[i++] = 0x77; buf[i++] = 0x88;
    /* [9F27] CID = TC */
    buf[i++] = 0x9F; buf[i++] = 0x27; buf[i++] = 0x01;
    buf[i++] = 0x08;
    /* [9F50] CVM Status = 0x00 (No CVM) */
    buf[i++] = 0x9F; buf[i++] = 0x50; buf[i++] = 0x01;
    buf[i++] = 0x00;
    /* [95] TVR */
    buf[i++] = 0x95; buf[i++] = 0x05;
    buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;
    buf[i++] = 0x00;
    /* [8A] ARC */
    buf[i++] = 0x8A; buf[i++] = 0x02;
    buf[i++] = 'Y'; buf[i++] = '1';
    *len = i;
}

/* ================================================================== */
/*  Mock IC Reader Provider                                           */
/* ================================================================== */

static struct {
    uint8_t sfi;
    uint8_t rec_num;
    uint8_t state;  /* 0=GPO, 1=READREC, 2=GAC */
} k5_mock;

static int k5_mock_init(void) { return 0; }
static int k5_mock_poll_card(uint32_t t) { (void)t; return 0; }
static void k5_mock_deactivate(void) {}

static int k5_mock_transceive(const uint8_t *send, uint16_t send_len,
                              uint8_t *recv, uint16_t recv_max,
                              uint16_t *recv_len)
{
    (void)send_len; (void)recv_max;
    uint8_t cla = send[0], ins = send[1];

    if (cla == 0x00 && ins == 0xA8) {
        /* GPO */
        build_mock_k5_gpo_response(recv, recv_len);
        k5_mock.state = 1;
    } else if (cla == 0x00 && ins == 0xB2) {
        /* READ RECORD */
        uint8_t p1 = send[2];
        uint8_t sfi = (p1 >> 3) & 0x1F;
        k5_mock.sfi = sfi;
        if (sfi == 1) {
            build_mock_k5_readrec1(recv, recv_len);
        } else if (sfi == 2) {
            build_mock_k5_readrec2(recv, recv_len);
        }
    } else if (cla == 0x00 && ins == 0xA6) {
        /* GENERATE AC */
        build_mock_k5_genac_response(recv, recv_len);
        k5_mock.state = 2;
    } else {
        /* SELECT */
        build_mock_k5_select_response(recv, recv_len);
    }

    if (*recv_len + 2 <= recv_max) {
        recv[*recv_len++] = 0x90;
        recv[*recv_len++] = 0x00;
    }
    return 0;
}

const struct ic_reader_provider_s k5_mock_icr = {
    .init = k5_mock_init,
    .poll_card = k5_mock_poll_card,
    .transceive = k5_mock_transceive,
    .deactivate = k5_mock_deactivate,
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
/*  Tests                                                             */
/* ================================================================== */

TEST(test_k5_tc_outcome)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));
    ep.icr = &k5_mock_icr;

    int rc = kernel_execute(5, &ep);
    ASSERT_EQ(rc, 0, "kernel_execute returns 0");
    ASSERT_EQ(ep.outcome, OUTCOME_APPROVE_TERMINAL_CONDS, "outcome is APPROVE_TERMINAL");
}

TEST(test_k5_cda_data_present)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));
    ep.icr = &k5_mock_icr;

    kernel_execute(5, &ep);

    /* CDOL1 should be present */
    const tlv_entry_t *cdol1 = tlv_find(ep.wh, 0x8C);
    ASSERT_GE(cdol1 != NULL, 1, "CDOL1 present");

    /* ICC cert should be present */
    const tlv_entry_t *icc_cert = tlv_find(ep.wh, 0x9F46);
    ASSERT_GE(icc_cert != NULL, 1, "ICC cert present");
}

TEST(test_k5_cvm_status_no_cvm)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));
    ep.icr = &k5_mock_icr;

    kernel_execute(5, &ep);

    /* 9F50 = No CVM should be in warehouse */
    const tlv_entry_t *cvm = tlv_find(ep.wh, 0x9F50);
    ASSERT_GE(cvm != NULL, 1, "CVM status present");
    if (cvm) {
        ASSERT_EQ(cvm->value[0], 0x00, "CVM status = No CVM");
    }
}

TEST(test_k5_crv_present)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));
    ep.icr = &k5_mock_icr;

    kernel_execute(5, &ep);

    /* CRV (9F6B) may be present if generated */
    const tlv_entry_t *crv = tlv_find(ep.wh, 0x9F6B);
    /* CRV is optional in this mock — just check it doesn't crash */
    (void)crv;
}

int main(void)
{
    printf("\n=== K5 End-to-End Integration Tests ===\n\n");

    RUN(test_k5_tc_outcome);
    RUN(test_k5_cda_data_present);
    RUN(test_k5_cvm_status_no_cvm);
    RUN(test_k5_crv_present);

    printf("\n%d passed, %d failed out of %d tests\n\n",
           g_tests_run - g_tests_fail, g_tests_fail, g_tests_run);
    return g_tests_fail > 0 ? 1 : 0;
}
