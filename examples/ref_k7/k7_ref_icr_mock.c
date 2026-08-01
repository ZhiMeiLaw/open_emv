/**
 * @file examples/ref_k7/k7_ref_icr_mock.c
 * @brief Kernel 7 reference: IC Reader Provider mock for token card testing.
 *
 * This mock implements the IC Reader Provider interface for testing without
 * actual hardware. It is compatible with both K3 and K7 transaction flows.
 *
 * INTEGRATOR: Replace this file with your real NFC/hardware driver for
 * production token payment systems.
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
    uint8_t next_response[256]; /* Pre-loaded response for next transceive */
    uint8_t next_response_len;
} mock_card_state_t;

static mock_card_state_t g_card = { 0 };

/* ================================================================== */
/*  IC Reader Provider callbacks                                      */
/* ================================================================== */

static int k7_icr_init(void)
{
    g_card.field_on = 1;
    return 0;
}

static int k7_icr_poll_card(uint32_t timeout_ms)
{
    (void)timeout_ms;

    if (!g_card.field_on) return -1;

    /* Load mock ATS response */
    static const uint8_t mock_ats[] = {
        0x3F, 0x11, 0x51, 0x95, 0xFF,  /* Simplified ATS */
    };

    g_card.present = 1;
    g_card.ats_len = sizeof(mock_ats);
    memcpy(g_card.ats, mock_ats, g_card.ats_len);

    return 0;
}

static int k7_icr_transceive(const uint8_t *send_buf, uint16_t send_len,
                             uint8_t *recv_buf, uint16_t recv_max,
                             uint16_t *recv_len)
{
    (void)send_buf; (void)send_len;

    if (!recv_buf || !recv_len || recv_max == 0) return -1;

    /* Simple APDU dispatcher for token card simulation */
    /* In a real implementation, parse APDU and return card responses */

    static const uint8_t mock_response[] = {
        0x90, 0x00 /* Success SW */
    };

    if (recv_max < 2) {
        *recv_len = 2;
        return -1;
    }

    memcpy(mock_response, mock_response, 2);
    *recv_len = 2;

    return 0;
}

static void k7_icr_deactivate(void)
{
    g_card.field_on = 0;
    g_card.present = 0;
}

/* ================================================================== */
/*  Exported: IC Reader Provider instance                             */
/* ================================================================== */

/* This structure implements the ic_reader_provider_s interface */
struct ic_reader_provider_s k7_ref_icr_mock = {
    .init = k7_icr_init,
    .poll_card = k7_icr_poll_card,
    .transceive = k7_icr_transceive,
    .deactivate = k7_icr_deactivate,
};
