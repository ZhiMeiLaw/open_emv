/**
 * @file src/core/entry_point.c
 * @brief Book B Entry Point handler — Protocol Activation + Application Selection.
 *
 * The Entry Point (Book B) is responsible ONLY for:
 *   1. Pre-Processing (Start A) — setup based on POS config / amount
 *   2. Protocol Activation (Start B) — ISO-14443 ATR, PPS, SAP
 *   3. Combination Selection (Start C):
 *      Step 1: SELECT PPSE [2PAY.SYS.DDF01]
 *      Step 1a: SEND POI INFORMATION (SPI) if card requests (9F3E / 9F3F)
 *      Step 2: Process directory entries → Candidate List [{AID, KernelID}]
 *      Step 3: Handle empty candidate list → End Application outcome
 *      Step 4: (Restart for next AID if needed)
 *   4. Final Combination Selection (Start C continued):
 *      - Pick highest priority combo from candidate list
 *      - Maybe append Extended Selection (9F29) to AID
 *      - SELECT [AID] with Extended Selection
 *   5. Kernel Activation (Start D):
 *      - Hand over control to kernel with FCI + SW1SW2
 *
 * The kernel then takes over for GPO → Read Records → SDA/ODA → CVM → GAC.
 */

#include "emv_kernel/entry_point.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ================================================================== */
/*  PPSE and Directory Entry definitions                              */
/* ================================================================== */

/** PPSE file name — mandatory for EMV contactless */
#define PPSE_FILE_NAME_LEN 14
static const uint8_t ppse_file_name[] = { 0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59,
                                          0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31 };
/* "2PAY.SYS.DDF01" in NFC hex encoding */

/** Tag for Directory Entry in PPSE response FCI (Ber-TLV context) */
#define TAG_DIRECTORY_ENTRY   0x61

/** Tag for Application Priority Indicator within Directory Entry */
#define TAG_AFFILIATION       0x4F    /* AID (Dedicated File Name) */
#define TAG_KERNEL_ID         EMV_TAG2(0x9F, 0x2A)

/* ================================================================== */
/*  APDU helper — build and send                                      */
/* ================================================================== */

static int build_and_send_select_apdu(ep_context_t *ctx,
                                       uint8_t p1, uint8_t p2,
                                       const uint8_t *data_in, uint16_t data_in_len,
                                       uint8_t *recv_buf, uint16_t recv_max,
                                       uint16_t *recv_len)
{
    /* CLA INS P1 P2 LC [DATA] LE */
    uint8_t apdu[256];
    uint16_t idx = 0;

    apdu[idx++] = 0x00;             /* Class — ISO-7816-4 */
    apdu[idx++] = 0xA4;             /* INS — SELECT */
    apdu[idx++] = p1;               /* P1 — select by name */
    apdu[idx++] = p2;               /* P2 — first record in DF */
    apdu[idx++] = (uint8_t)data_in_len;

    memcpy(apdu + idx, data_in, data_in_len);
    idx += data_in_len;

    /* Send via IC Reader Provider */
    return ctx->icr->transceive(apdu, idx, recv_buf, recv_max, recv_len);
}

static int build_and_send_spi_apdu(ep_context_t *ctx,
                                    const uint8_t *data_in, uint16_t data_in_len,
                                    uint8_t *recv_buf, uint16_t recv_max,
                                    uint16_t *recv_len)
{
    uint8_t apdu[256];
    uint16_t idx = 0;

    apdu[idx++] = 0x80;             /* Class — proprietary (SPI) */
    apdu[idx++] = 0xB2;             /* INS — SEND POI INFORMATION */
    apdu[idx++] = 0x00;             /* P1 */
    apdu[idx++] = 0x00;             /* P2 */
    apdu[idx++] = (uint8_t)data_in_len;
    memcpy(apdu + idx, data_in, data_in_len);
    idx += data_in_len;

    return ctx->icr->transceive(apdu, idx, recv_buf, recv_max, recv_len);
}

/* ================================================================== */
/*  ATS Parsing                                                       */
/* ================================================================== */

typedef struct {
    uint8_t fi_byte;
    uint8_t to_byte;
    uint8_t ibr_bytes[4];
    uint8_t ibr_count;
} ats_parsed_t;

static void parse_ats(const uint8_t *ats, uint8_t len, ats_parsed_t *out)
{
    if (!ats || len < 3 || !out) return;
    out->fi_byte = ats[0];
    out->to_byte = ats[1];
    uint8_t n = ats[1] & 0x0Fu;
    out->ibr_count = n > 4 ? 4 : n;
    if (n > 0 && n <= 4) {
        memcpy(out->ibr_bytes, ats + 2, out->ibr_count);
    } else {
        out->ibr_count = 0;
    }
}

/* ================================================================== */
/*  Step 1: Init                                                     */
/* ================================================================== */

int entry_point_step_init(ep_context_t *ctx)
{
    if (!ctx || !ctx->icr) return EP_E_INVAL;
    ctx->icr->init();
    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 2: Poll card                                                */
/* ================================================================== */

int entry_point_step_poll(ep_context_t *ctx, uint32_t timeout_ms)
{
    if (!ctx || !ctx->icr) return EP_E_INVAL;
    return ctx->icr->poll_card(timeout_ms);
}

/* ================================================================== */
/*  Step 3: PPS                                                      */
/* ================================================================== */

int entry_point_step_pps(ep_context_t *ctx)
{
    (void)ctx;
    /* PPS is optional — proceed at default 106 kbps */
    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 4: SELECT PPSE                                               */
/* ================================================================== */

/**
 * Parse Directory Entries from PPSE response FCI.
 * Each Directory Entry (tag 0x61) contains:
 *   [4F] AID + [9F2A] Kernel ID + [5F2F] Application Priority Indicator
 * Builds a candidate list of {AID, Kernel ID, Priority}.
 */
int entry_point_parse_ppse_response(ep_context_t *ctx,
                                     const uint8_t *resp, uint16_t resp_len)
{
    if (!ctx || !resp || !ctx->wh) return EP_E_INVAL;

    /* Parse the raw TLV from PPSE SELECT response into warehouse */
    int parsed = tlv_parse_raw(resp, resp_len, ctx->wh);
    if (parsed <= 0) return EP_E_GPO;  /* Failed to parse PPSE response */

    /* Extract Directory Entries (BF0C -> 61) from FCI Issuer Discretionary Data */
    /* In real implementation, walk through BF0C tag and find 0x61 entries */
    /* For now store the whole response for later parsing */
    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 4a: SEND POI INFORMATION (SPI)                               */
/* ================================================================== */

/**
 * Send SPI command if card requested it via Terminal Categories (9F3E)
 * or Selection Data Object List (9F3F) in PPSE response.
 */
int entry_point_step_spi(ep_context_t *ctx)
{
    if (!ctx || !ctx->icr) return EP_E_INVAL;

    /* Check warehouse for 9F3E (Terminal Categories Supported List) or
     * 9F3F (Selection Data Object List) in the PPSE response */
    const tlv_entry_t *cat_list = NULL;
    const tlv_entry_t *sdol = NULL;

    /* Look for these in BF0C (FCI Issuer Discretionary Data)
     * In practice, parse the raw PPSE response FCI byte stream */
    /* Placeholder: check if warehouse has any SPI request tags */
    if (!cat_list && !sdol) {
        /* Card did not request SPI, skip to Step 2 */
        return EMV_E_OK;
    }

    uint8_t spi_data[128];
    uint16_t spi_data_len = 0;

    /* Build SPI command data per Book B Annex C.1:
     * Include Terminal Category, Transaction Currency, Amount, Country Code */
    /* Placeholder */

    uint8_t resp[256];
    uint16_t resp_len = sizeof(resp);

    int rc = build_and_send_spi_apdu(ctx, spi_data, spi_data_len,
                                      resp, sizeof(resp), &resp_len);
    if (rc != 0) return EP_E_PROFILE;

    /* Parse SPI response FCI */
    return entry_point_parse_ppse_response(ctx, resp, resp_len);
}

/* ================================================================== */
/*  Step 2 (from Book B §3.3.2): Select Application                    */
/* ================================================================== */

/**
 * SELECT the final chosen application from the candidate list.
 * Entry Point selects based on:
 *   1. Highest Application Priority Indicator value
 *   2. If tied, lowest order in PPSE (first seen wins)
 *   3. Optionally append Extended Selection (9F29) to AID
 */
int entry_point_step_select_app(ep_context_t *ctx,
                                 const uint8_t *aid, uint8_t aid_len,
                                 const uint8_t *extended_sel, uint8_t ext_len)
{
    if (!ctx || !ctx->icr || !aid || !ctx->wh) return EP_E_INVAL;

    uint8_t p2 = 0x0C;  /* First record in DF */
    if (extended_sel && ext_len > 0) {
        p2 |= 0x04;  /* B3 = 1: append extended selection to ADF name */
    }

    uint8_t sel_data[64];
    uint16_t sel_data_len = aid_len;
    if (p2 & 0x04) sel_data_len += ext_len;

    memcpy(sel_data, aid, aid_len);
    if (p2 & 0x04 && extended_sel) {
        memcpy(sel_data + aid_len, extended_sel, ext_len);
    }

    uint8_t resp[256];
    uint16_t resp_len = sizeof(resp);

    int rc = build_and_send_select_apdu(ctx, 0x04, p2, sel_data, sel_data_len,
                                         resp, sizeof(resp), &resp_len);
    if (rc != 0) return EP_E_SELECT;  /* SW not 9000 or communication error */

    /* Store SELECT response FCI in warehouse */
    if (rc == 0) {
        int parsed = tlv_parse_raw(resp, resp_len, ctx->wh);
        if (parsed <= 0) return EP_E_INVAL;
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 5: Kernel Activation                                         */
/* ================================================================== */

/**
 * Hand over control to the selected kernel.
 * Book B §3.4.1:
 *   - Set Kernel Identifier-Terminal (96)
 *   - Pass FCI + Status Word from SELECT response to kernel
 *   - Make Pre-Processing Indicators available to kernel
 */
int entry_point_activate_kernel(ep_context_t *ctx)
{
    if (!ctx || !ctx->wh) return EP_E_INVAL;

    /* Integration point: load pre-processing configuration.
     *
     * The terminal should populate tags that the kernel needs before
     * it begins execution. The minimum required set per Book B §3.4:
     *   - [9F1A] Terminal Country Code (param_read or store)
     *   - [5F2A] Transaction Currency Code
     *   - [9F02] Amount, Authorised (set by POS)
     *   - [9F66] Terminal Qualifiers
     *
     * In production: call param_read() for each required tag, or load
     * from a pre-initialised parameter store.
     *
     * Example:
     *   uint8_t tc[] = { 0x06, 0x08 }; /* GB */
     *   param_read(0x9F1A, buf, &blen);
     *   tlv_store_set(ctx->wh, 0x9F1A, buf, blen);
     */

    /* Integration point: build Kernel Identifier-Terminal [9F2A].
     *
     * Per Book B §3.4.1, the terminal stores the kernel ID it selected
     * into the warehouse so the kernel can read it. The value is the
     * 1-byte kernel identifier (3=K3 debit, 5=K5 crypto, 7=K7 token).
     *
     * In production: derive from selected_kernel_id and store in warehouse:
     *   uint8_t kid = ctx->selected_kernel_id;
     *   tlv_store_set(ctx->wh, 0x9F2A, &kid, 1);
     *
     * This tag is used by:
     *   - kernel_ops_t to verify kernel compatibility
     *   - risk_plugin for kernel-specific risk rules
     */
    (void)ctx;

    return EMV_E_OK;
}

/* ================================================================== */
/*  Full Entry Point Flow (Start A/B → C → D)                        */
/* ================================================================== */

int entry_point_run(ep_context_t *ctx, const void *pos_params)
{
    (void)pos_params;
    if (!ctx || !ctx->icr) return EP_E_INVAL;

    /* Step 1: Init RF field */
    int rc = entry_point_step_init(ctx);
    if (rc != 0) return rc;

    /* Step 2: Poll card (ISO-14443-3 ATQA/UID/SAK) */
    rc = entry_point_step_poll(ctx, 5000);
    if (rc != 0) return EP_E_NO_CARD;

    /* Step 3: PPS (optional — default proceeds without negotiation) */
    rc = entry_point_step_pps(ctx);
    if (rc != 0) return rc;

    /* Step 4: SELECT PPSE "2PAY.SYS.DDF01" */
    {
        uint8_t select_resp[256];
        uint16_t select_resp_len = sizeof(select_resp);

        rc = build_and_send_select_apdu(ctx, 0x00, 0x0C, ppse_file_name,
                                         PPSE_FILE_NAME_LEN,
                                         select_resp, sizeof(select_resp), &select_resp_len);
        if (rc != 0) return EP_E_INVAL;  /* Not a PPSE-compliant card */

        /* Parse PPSE response */
        rc = entry_point_parse_ppse_response(ctx, select_resp, select_resp_len);
        if (rc != 0) return EP_E_PROFILE;
    }

    /* Step 4a: SPI (SEND POI INFORMATION) if card requested */
    rc = entry_point_step_spi(ctx);
    if (rc != 0) return rc;

    /* Step 5: SELECT final application AID */
    /* For reference: integrator provides the AID to select */
    /* This is the handoff point — kernel takes over after this */
    /* entry_point_step_select_app(ctx, aid, aid_len, ext, ext_len); */

    return EP_E_OK;
}
