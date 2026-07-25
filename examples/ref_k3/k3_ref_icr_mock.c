/**
 * @file examples/ref_k3/k3_ref_icr_mock.c
 * @brief Mock IC Reader Provider for testing without real hardware.
 *
 * Simulates a card insertion and EMV contactless exchange.
 * Use this to verify the full kernel flow in a simulator environment.
 *
 * The mock implements all 4 required callbacks of struct ic_reader_provider_s:
 *   - init()
 *   - poll_card(timeout_ms)
 *   - transceive(send_buf, send_len, recv_buf, recv_max, recv_len)
 *   - deactivate()
 *
 * INTEGRATOR: Replace this file with your real NFC/hardware driver.
 */

#include "emv_kernel/entry_point.h"
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
/*  init — power on RF field                                         */
/* ================================================================== */
static int mock_init(void)
{
    g_card.field_on = 1;
    return 0;
}

/* ================================================================== */
/*  poll_card — simulate card presence                               */
/* ================================================================== */
static int mock_poll_card(uint32_t timeout_ms)
{
    (void)timeout_ms;

    if (!g_card.field_on) return -1;

    /* Load mock ATS response */
    /* Real implementation: read ATQ response from ISO 14443-3 ATRQ */
    static const uint8_t mock_ats[] = {
        0x3F, 0x11, 0x51, 0x95, 0xFF,  /* Simplified ATS */
    };

    g_card.present = 1;
    g_card.ats_len = sizeof(mock_ats);
    memcpy(g_card.ats, mock_ats, g_card.ats_len);

    return 0;
}

/* ================================================================== */
/*  transceive — simulate APDU responses                              */
/* ================================================================== */

/**
 * Build a mock ERP response (LLCP exchange).
 * Returns card capabilities in a TLV-like format.
 */
static void build_mock_erp_response(uint8_t *out, uint16_t *out_len)
{
    /* Mock: say the card supports contactless and tag profiling */
    out[0] = 0x05;  /* LLCP Version */
    out[1] = 0x10;  /* MIUX */
    *out_len = 2;
}

/**
 * Build a mock GPO (GET PROCESSING OPTIONS) response.
 * This is the most important mock — it contains all tags
 * the kernel needs to proceed.
 */
static void build_mock_gpo_response(uint8_t *out, uint16_t *out_len)
{
    uint16_t idx = 0;

    /* [87] AIP = 0x02 (supports contactless, no offline decryption, no CVM) */
    out[idx++] = 0x87; out[idx++] = 0x01; out[idx++] = 0x02;

    /* [82] AUC = 0x00 0xFF (allow all transaction types) */
    out[idx++] = 0x82; out[idx++] = 0x02;
    out[idx++] = 0x00; out[idx++] = 0xFF;

    /* [DF9F66] CDOL1 length = 0x10 (16 bytes) */
    out[idx++] = 0xDF; out[idx++] = 0x9F; out[idx++] = 0x66;
    out[idx++] = 0x01; out[idx++] = 0x10;

    /* [9F37] Unpredictable Number (4 bytes — usually from card RNG) */
    out[idx++] = 0x9F; out[idx++] = 0x37;
    out[idx++] = 0x04;
    out[idx++] = 0xA1; out[idx++] = 0xB2; out[idx++] = 0xC3; out[idx++] = 0xD4;

    *out_len = idx;
}

/**
 * Build a mock SET ATTRIBUTE response (for ODA DNL step).
 */
static void build_mock_set_attr_response(uint8_t *out, uint16_t *out_len)
{
    /* Mock: 8 bytes of ICData (real: encrypted dynamic number + data) */
    memset(out, 0xAA, 8);
    *out_len = 8;
}

/**
 * Build a mock TOA (Terminal Action Analysis) response.
 */
static void build_mock_toa_response(uint8_t *out, uint16_t *out_len)
{
    uint16_t idx = 0;

    /* [9F7E] ICC CRT (TDES-MAC response) — 8 bytes */
    out[idx++] = 0x9F; out[idx++] = 0x7E;
    out[idx++] = 0x08;
    out[idx++] = 0xDE; out[idx++] = 0xAD; out[idx++] = 0xBE;
    out[idx++] = 0xEF; out[idx++] = 0xCA; out[idx++] = 0xFE;

    *out_len = idx;
}

/**
 * Build a mock SELECT response (application selection).
 */
static void build_mock_select_response(uint8_t *out, uint16_t *out_len)
{
    uint16_t idx = 0;

    /* [4F] AID = A0 00 00 00 03 (default Visa/Mastercard prefix) */
    out[idx++] = 0x4F; out[idx++] = 0x05;
    out[idx++] = 0xA0; out[idx++] = 0x00; out[idx++] = 0x00;
    out[idx++] = 0x00; out[idx++] = 0x03;

    /* [50] App Label = "DEFAULT" */
    out[idx++] = 0x50; out[idx++] = 0x07;
    memcpy(out + idx, "DEFAULT", 7);
    idx += 7;

    /* [87] AIP */
    out[idx++] = 0x87; out[idx++] = 0x01; out[idx++] = 0x02;

    *out_len = idx;
}

/* ---- Main transceive handler ---- */
static int mock_transceive(const uint8_t *send_buf, uint16_t send_len,
                           uint8_t *recv_buf, uint16_t recv_max,
                           uint16_t *recv_len)
{
    if (!send_buf || send_len == 0) return -1;

    uint8_t cla = send_buf[0];
    uint8_t ins = send_buf[1];

    /* Check if this is an APDU command or raw NFCDEP PDU */
    if (cla == 0x00 && ins != 0x00) {
        /* It's an APDU command */
        switch (ins) {
        case 0xA4:  /* SELECT AID */
            build_mock_select_response(recv_buf, recv_len);
            break;

        case 0xA8:  /* GET PROCESSING OPTIONS (GPO) */
            build_mock_gpo_response(recv_buf, recv_len);
            break;

        case 0xCB:  /* GET DATA (ICA certificate) */
            /* Return mock 256-byte RSA certificate */
            if (recv_max >= 258) {
                uint16_t idx = 0;
                recv_buf[idx++] = 0x9F; recv_buf[idx++] = 0x21;
                recv_buf[idx++] = 0x02; recv_buf[idx++] = 0xFF;
                memset(recv_buf + idx, 0xCC, 256);  /* Mock cert body */
                idx += 256;
                *recv_len = idx;
            } else {
                *recv_len = 0;
            }
            break;

        case 0x84:  /* SET ATTRIBUTE (ODA DNL) */
            build_mock_set_attr_response(recv_buf, recv_len);
            break;

        case 0x88:  /* TOA (Terminal Action Analysis) */
            build_mock_toa_response(recv_buf, recv_len);
            break;

        default:
            /* Generic: SW=0x6A80 (incorrect parameters) */
            if (recv_max >= 2) {
                recv_buf[0] = 0x6A;
                recv_buf[1] = 0x80;
                *recv_len = 2;
            }
            return 0x6A80;
        }
    } else {
        /* Raw NFCDEP / LLCP PDU — return mock ERP response */
        build_mock_erp_response(recv_buf, recv_len);
    }

    /* Ensure zero-terminated length */
    if (*recv_len > recv_max) *recv_len = recv_max;

    return 0;
}

/* ================================================================== */
/*  deactivate                                                        */
/* ================================================================== */
static void mock_deactivate(void)
{
    g_card.present = 0;
    g_card.field_on = 0;
}

/* ================================================================== */
/*  Public API: get the mock IC reader provider instance              */
/* ================================================================== */

/**
 * Get a ready-to-use IC Reader Provider interface pointing to mock cards.
 * Call this in your test code:
 *
 *   ep_context_t ctx = { .icr = k3_get_mock_icr() };
 *   entry_point_run(&ctx, pos_params);
 */
const struct ic_reader_provider_s *k3_get_mock_icr(void)
{
    /* Static to ensure lifetime — NOT thread-safe */
    static const struct ic_reader_provider_s mock_provider = {
        .init         = mock_init,
        .poll_card    = mock_poll_card,
        .transceive   = mock_transceive,
        .deactivate   = mock_deactivate,
    };
    return &mock_provider;
}
