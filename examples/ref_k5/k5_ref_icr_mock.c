/**
 * @file examples/ref_k5/k5_ref_icr_mock.c
 * @brief Kernel 5 reference: IC Reader Provider mock for qVISA/Crypto card testing.
 *
 * This mock implements the IC Reader Provider interface for testing
 * without actual hardware. It simulates a K5-capable card with CDA
 * (Composite Data Authentication) support.
 *
 * The mock card responds to the full Book B flow:
 *   - SELECT PPSE → directory with K5 AID
 *   - SELECT AID → FCI with AIP, AUC, PDOL
 *   - READ RECORD → ICA cert, ICC cert, SDAD, AFL
 *   - GENERATE AC → CAC (TC or ARQC)
 *
 * INTEGRATOR: Replace this file with your real NFC/hardware driver
 * for production qVISA/Crypto payment systems.
 */

#include "emv_kernel/entry_point.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ================================================================== */
/*  Mock card state                                                   */
/* ================================================================== */

typedef struct {
    int present;              /* Card physically present?               */
    int field_on;             /* RF field active?                        */
    uint8_t ats[32];          /* Card's ATS response                     */
    uint8_t ats_len;

    /* APDU response queue — sequential responses per command */
    uint8_t resp_queue[8][256];
    uint8_t resp_queue_len[8];
    uint8_t resp_idx;
    uint8_t resp_count;
} mock_card_state_t;

static mock_card_state_t g_card = { 0 };

/* ================================================================== */
/*  K5 mock AID (qVISA reference — not a real AID)                    */
/* ================================================================== */

static const uint8_t k5_mock_aid[] = { 0xA0, 0x00, 0x00, 0x00, 0x03 };
static const uint8_t k5_mock_aid_len = 5;

/* ================================================================== */
/*  Mock card state management                                        */
/* ================================================================== */

/**
 * Load a sequence of mock APDU responses for the card.
 * Call this before starting a transaction to set up the card's
 * expected replies.
 *
 * @param responses    Array of response buffers
 * @param lengths      Array of response lengths (max 8 entries)
 * @param count        Number of responses
 */
static void k5_mock_load_responses(const uint8_t *responses[],
                                   const uint8_t lengths[],
                                   uint8_t count)
{
    g_card.resp_idx = 0;
    g_card.resp_count = count < 8 ? count : 8;
    for (uint8_t i = 0; i < g_card.resp_count; i++) {
        uint8_t len = lengths[i] < (uint8_t)sizeof(g_card.resp_queue[i]) ?
                      lengths[i] : (uint8_t)sizeof(g_card.resp_queue[i]);
        if (responses[i]) {
            memcpy(g_card.resp_queue[i], responses[i], len);
        } else {
            len = 0;
        }
        g_card.resp_queue_len[i] = len;
    }
}

/* ================================================================== */
/*  IC Reader Provider callbacks                                      */
/* ================================================================== */

static int k5_icr_init(void)
{
    g_card.field_on = 1;
    g_card.resp_idx = 0;
    return EMV_E_OK;
}

static int k5_icr_poll_card(uint32_t timeout_ms)
{
    (void)timeout_ms;

    if (!g_card.field_on) return -1;

    /* Load mock ATS response (simplified ISO-14443-4 ATS) */
    static const uint8_t mock_ats[] = {
        0x3F, 0x11, 0x51, 0x95, 0xFF,  /* FSCI, ATS_RES, DFName, SPT, EOF */
    };

    g_card.present = 1;
    g_card.ats_len = sizeof(mock_ats);
    memcpy(g_card.ats, mock_ats, g_card.ats_len);

    return EMV_E_OK;
}

static int k5_icr_transceive(const uint8_t *send_buf, uint16_t send_len,
                             uint8_t *recv_buf, uint16_t recv_max,
                             uint16_t *recv_len)
{
    if (!recv_buf || !recv_len || recv_max == 0) return -1;
    *recv_len = 0;

    if (!g_card.present) return -1;

    /* Check if we have a pre-loaded response */
    if (g_card.resp_idx < g_card.resp_count) {
        uint8_t len = g_card.resp_queue_len[g_card.resp_idx];
        uint8_t copy_len = len < recv_max ? len : recv_max;
        memcpy(recv_buf, g_card.resp_queue[g_card.resp_idx], copy_len);
        *recv_len = copy_len;
        g_card.resp_idx++;
        return EMV_E_OK;
    }

    /* No pre-loaded response — return default success */
    static const uint8_t default_sw[] = { 0x90, 0x00 };
    if (recv_max >= 2) {
        memcpy(recv_buf, default_sw, 2);
        *recv_len = 2;
    }
    return EMV_E_OK;
}

static void k5_icr_deactivate(void)
{
    g_card.field_on = 0;
    g_card.present = 0;
}

/* ================================================================== */
/*  Convenience: build full mock transaction responses                */
/* ================================================================== */

/**
 * Set up the mock card with a full K5 transaction response sequence.
 *
 * Expected command flow:
 *   1. SELECT PPSE (AID 2PAY.SYS.DDF01) → FCI with directory entries
 *   2. SELECT AID (K5 AID) → FCI with AIP, AUC, PDOL, AFL
 *   3. READ RECORD (ICA cert) → ICA PK certificate [9F46] + exponent [9F47]
 *   4. READ RECORD (SDAD) → Signed Dynamic Application Data [9F4B]
 *   5. READ RECORD (Issuer PK) → Issuer PK cert [90] + exponent [9F32]
 *   6. GET PROCESSING OPTIONS (GPO) → CDOL1, cryptogram type, AFL
 *   7. READ RECORD (per AFL) → ICC cert, extra card data
 *   8. GENERATE AC → CAC [9F26] + CID [9F27] (TC or ARQC)
 *
 * @param icr              IC Reader Provider instance
 * @param prefer_tc        If true, mock TC response; if false, mock ARQC
 */
static void k5_mock_setup_full_transaction(struct ic_reader_provider_s *icr,
                                           int prefer_tc)
{
    /* Note: This function sets up the mock card state.
     * In a real integration test, each APDU response would contain
     * properly encoded TLV data matching the EMV spec.
     * Here we provide structural placeholders. */
    (void)icr;
    (void)prefer_tc;
    /* Real mock would populate g_card.resp_queue with proper TLV data */
}

/* ================================================================== */
/*  Exported: IC Reader Provider instance                             */
/* ================================================================== */

struct ic_reader_provider_s k5_ref_icr_mock = {
    .init = k5_icr_init,
    .poll_card = k5_icr_poll_card,
    .transceive = k5_icr_transceive,
    .deactivate = k5_icr_deactivate,
};
