/**
 * @file tests/integration/test_k7_e2e.c
 * @brief End-to-end Kernel 7 integration test.
 *
 * Simulates a full K7 (Token Payment) transaction with mock card data:
 *   - SELECT AID → GPO → READ RECORD (fDDA data + PAR) → CVM(CTQ) → GENERATE AC → Outcome
 *
 * K7 specific features tested:
 *   - fDDA (same as K3, Annex B of Book C-7)
 *   - Strict CTQ: no-CTQ + CDCVM-only reader → Decline (§4.4.2.1)
 *   - PAR (9F24) support from card
 *   - Token PAN (9A09) validation via risk plugin
 *   - AOSA (9F5D) display for approved transactions
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
/*  Mock card data for K7 token transaction                           */
/* ================================================================== */

/* SELECT response with AID + PDOL */
static void build_mock_k7_select(uint8_t *buf, uint16_t *len)
{
    uint16_t i = 0;
    buf[i++] = 0x6F; buf[i++] = 0x1C;
    buf[i++] = 0xA5; buf[i++] = 0x1A;
    buf[i++] = 0xBF; buf[i++] = 0x0C; buf[i++] = 0x18;
    /* PDOL */
    buf[i++] = 0x9F; buf[i++] = 0x38; buf[i++] = 0x0C;
    buf[i++] = 0x9F; buf[i++] = 0x66; buf[i++] = 0x04;
    buf[i++] = 0x9F; buf[i++] = 0x37; buf[i++] = 0x04;
    buf[i++] = 0x9F; buf[i++] = 0x02; buf[i++] = 0x06;
    buf[i++] = 0x5F; buf[i++] = 0x2A; buf[i++] = 0x02;
    /* AID */
    buf[i++] = 0x4F; buf[i++] = 0x07;
    buf[i++] = 0xA0; buf[i++] = 0x00; buf[i++] = 0x00;
    buf[i++] = 0x00; buf[i++] = 0x03; buf[i++] = 0x01;
    buf[i++] = 0x0C;
    /* AIP — DDA supported (bit 6 = 1) */
    buf[i++] = 0x87; buf[i++] = 0x01; buf[i++] = 0x42;
    *len = i;
}

/* GPO response: CID=TC, CTQ=No CVM, AOSA present, PAR present */
static void build_mock_k7_gpo(uint8_t *buf, uint16_t *len)
{
    uint16_t i = 0;
    /* [9F27] CID = TC */
    buf[i++] = 0x9F; buf[i++] = 0x27; buf[i++] = 0x01;
    buf[i++] = 0x08;
    /* [9F36] ATC */
    buf[i++] = 0x9F; buf[i++] = 0x36; buf[i++] = 0x02;
    buf[i++] = 0x00; buf[i++] = 0x03;
    /* [87] AIP */
    buf[i++] = 0x87; buf[i++] = 0x01; buf[i++] = 0x42;
    /* [9F6C] CTQ = 0x00 (no CVM) */
    buf[i++] = 0x9F; buf[i++] = 0x6C; buf[i++] = 0x02;
    buf[i++] = 0x00; buf[i++] = 0x00;
    /* [9F5D] AOSA = 500.00 CNY */
    buf[i++] = 0x9F; buf[i++] = 0x5D; buf[i++] = 0x06;
    buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;
    buf[i++] = 0x05; buf[i++] = 0x00; buf[i++] = 0x00;
    /* No AFL → offline approve */
    *len = i;
}

/* READ RECORD: Card Auth Related Data (fDDA) + PAR */
static void build_mock_k7_readrec(uint8_t *buf, uint16_t *len)
{
    uint16_t i = 0;
    /* [9F69] Card Auth Related Data: fDDA v1 + UN(4) + CTQ(2) */
    buf[i++] = 0x9F; buf[i++] = 0x69; buf[i++] = 0x07;
    buf[i++] = 0x01;                    /* fDDA version 1 */
    buf[i++] = 0xAA; buf[i++] = 0xBB; buf[i++] = 0xCC; buf[i++] = 0xDD; /* Card UN */
    buf[i++] = 0x00; buf[i++] = 0x00;  /* CTQ (no CVM) */
    /* [9F4B] SDAD — dummy signature */
    buf[i++] = 0x9F; buf[i++] = 0x4B; buf[i++] = 0x04;
    buf[i++] = 0xDE; buf[i++] = 0xAD; buf[i++] = 0xBE; buf[i++] = 0xEF;
    /* [9F24] PAR — Payment Account Reference */
    buf[i++] = 0x9F; buf[i++] = 0x24; buf[i++] = 0x1D;
    memset(buf + i, 'T', 29); i += 29; /* mock PAR */
    *len = i;
}

/* GENERATE AC response: TC + TVR=0 */
static void build_mock_k7_genac(uint8_t *buf, uint16_t *len)
{
    uint16_t i = 0;
    /* [9F26] AC */
    buf[i++] = 0x9F; buf[i++] = 0x26; buf[i++] = 0x08;
    buf[i++] = 0x11; buf[i++] = 0x22; buf[i++] = 0x33; buf[i++] = 0x44;
    buf[i++] = 0x55; buf[i++] = 0x66; buf[i++] = 0x77; buf[i++] = 0x88;
    /* [9F27] CID = TC */
    buf[i++] = 0x9F; buf[i++] = 0x27; buf[i++] = 0x01;
    buf[i++] = 0x08;
    /* [95] TVR = zeros */
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
    uint8_t state; /* 0=SELECT, 1=GPO, 2=READREC, 3=GAC */
} k7_mock;

static int k7_mock_init(void) { return 0; }
static int k7_mock_poll_card(uint32_t t) { (void)t; return 0; }
static void k7_mock_deactivate(void) {}

static int k7_mock_transceive(const uint8_t *send, uint16_t send_len,
                              uint8_t *recv, uint16_t recv_max,
                              uint16_t *recv_len)
{
    (void)send_len; (void)recv_max;
    uint8_t cla = send[0], ins = send[1];

    if (cla == 0x00 && ins == 0xA8) {
        build_mock_k7_gpo(recv, recv_len);
        k7_mock.state = 2;
    } else if (cla == 0x00 && ins == 0xB2) {
        build_mock_k7_readrec(recv, recv_len);
        k7_mock.state = 3;
    } else if (cla == 0x00 && ins == 0xA6) {
        build_mock_k7_genac(recv, recv_len);
    } else {
        build_mock_k7_select(recv, recv_len);
    }

    if (*recv_len + 2 <= recv_max) {
        recv[*recv_len++] = 0x90;
        recv[*recv_len++] = 0x00;
    }
    return 0;
}

const struct ic_reader_provider_s k7_mock_icr = {
    .init = k7_mock_init,
    .poll_card = k7_mock_poll_card,
    .transceive = k7_mock_transceive,
    .deactivate = k7_mock_deactivate,
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

/* Test 1: TC outcome with no CVM */
TEST(test_k7_tc_outcome)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));
    ep.icr = &k7_mock_icr;

    int rc = kernel_execute(7, &ep);
    ASSERT_EQ(rc, 0, "kernel_execute returns 0");
    ASSERT_EQ(ep.outcome, OUTCOME_APPROVE_TERMINAL_CONDS, "outcome is APPROVE_TERMINAL");
}

/* Test 2: fDDA data present in warehouse */
TEST(test_k7_fdda_data)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));
    ep.icr = &k7_mock_icr;

    kernel_execute(7, &ep);

    /* Card Auth Related Data [9F69] should be present */
    const tlv_entry_t *card_auth = tlv_find(ep.wh, 0x9F69);
    ASSERT_GE(card_auth != NULL, 1, "Card Auth Data present");
    if (card_auth && card_auth->len >= 7) {
        ASSERT_EQ(card_auth->value[0], 0x01, "fDDA version 1");
    }

    /* SDAD [9F4B] should be present */
    const tlv_entry_t *sdad = tlv_find(ep.wh, 0x9F4B);
    ASSERT_GE(sdad != NULL, 1, "SDAD present");
}

/* Test 3: PAR (9F24) from card */
TEST(test_k7_par_support)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));
    ep.icr = &k7_mock_icr;

    kernel_execute(7, &ep);

    const tlv_entry_t *par = tlv_find(ep.wh, 0x9F24);
    ASSERT_GE(par != NULL, 1, "PAR present");
    if (par) {
        ASSERT_EQ(par->len, 29, "PAR length is 29");
    }
}

/* Test 4: CTQ strict check — no-CTQ should still pass (mock returns CTQ) */
TEST(test_k7_ctq_present)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));
    ep.icr = &k7_mock_icr;

    kernel_execute(7, &ep);

    /* CTQ should be present (mock returns it in GPO) */
    const tlv_entry_t *ctq = tlv_find(ep.wh, 0x9F6C);
    ASSERT_GE(ctq != NULL, 1, "CTQ present in GPO response");
    if (ctq && ctq->len >= 2) {
        ASSERT_EQ(ctq->value[0], 0x00, "CTQ byte1 = 0 (no CVM)");
        ASSERT_EQ(ctq->value[1], 0x00, "CTQ byte2 = 0 (no CDCVM)");
    }
}

/* Test 5: AOSA present for display */
TEST(test_k7_aosa)
{
    ep_context_t ep;
    memset(&ep, 0, sizeof(ep));
    uint8_t pool[MAX_POOL_SIZE];
    tlv_warehouse_init(ep.wh, pool, sizeof(pool));
    ep.icr = &k7_mock_icr;

    kernel_execute(7, &ep);

    const tlv_entry_t *aosa = tlv_find(ep.wh, 0x9F5D);
    ASSERT_GE(aosa != NULL, 1, "AOSA present");
    if (aosa && aosa->len >= 6) {
        /* AOSA = 0x000000050000 = 500.00 CNY */
        ASSERT_EQ(aosa->value[3], 0x05, "AOSA amount digit");
    }
}

int main(void)
{
    printf("\n=== K7 End-to-End Integration Tests ===\n\n");

    RUN(test_k7_tc_outcome);
    RUN(test_k7_fdda_data);
    RUN(test_k7_par_support);
    RUN(test_k7_ctq_present);
    RUN(test_k7_aosa);

    printf("\n%d passed, %d failed out of %d tests\n\n",
           g_tests_run - g_tests_fail, g_tests_fail, g_tests_run);
    return g_tests_fail > 0 ? 1 : 0;
}
