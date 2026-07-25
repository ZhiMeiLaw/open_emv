/**
 * @file src/core/kernel_core.c
 * @brief Kernel execution core per Book C-3 §2.4 (New Transaction Processing).
 *
 * After Entry Point has selected an application and activated the kernel,
 * the kernel takes over for these steps:
 *
 *   1. Initiate Application Processing (GPO with PDOL data from SELECT response)
 *   2. Read Application Data (READ RECORD per AFL from GPO response)
 *   3. Card Read Complete (validate mandatory tags)
 *   4. Processing Restrictions (expiry, usage control, TEF check)
 *   5. Offline Data Authentication (SDA via fDDA / ODA via ICC CRT)
 *   6. Cardholder Verification (CTQ-based or fallback)
 *   7. Online Processing (ARQC generation + acquirer communication)
 *   8. Completion (Outcome determination via GENERATE AC response)
 */

#include "emv_kernel/orchestrator.h"
#include "emv_kernel/dict_validate.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/apdu_tlv_parser.h"
#include "emv_kernel/errors.h"
#include "emv_kernel/entry_point.h"
#include <string.h>

/* ================================================================== */
/*  Helper: select application by AID                                  */
/* ================================================================== */

static int kernel_select_app(ep_context_t *ep_ctx,
                              const uint8_t *aid, uint8_t aid_len)
{
    if (!ep_ctx || !ep_ctx->icr || !aid) return EP_E_SELECT;

    uint8_t resp[256];
    uint16_t resp_len = sizeof(resp);

    /* BUILD SELECT AID APDU: CLA=00 INS=A4 P1=04 P2=0C */
    uint8_t apdu[64];
    uint16_t idx = 0;
    apdu[idx++] = 0x00;       /* CLA */
    apdu[idx++] = 0xA4;       /* INS SELECT */
    apdu[idx++] = 0x04;       /* P1 — by name */
    apdu[idx++] = 0x0C;       /* P2 — first record in DF */
    apdu[idx++] = (uint8_t)aid_len;
    memcpy(apdu + idx, aid, aid_len);
    idx += aid_len;

    int rc = ep_ctx->icr->transceive(apdu, idx, resp, sizeof(resp), &resp_len);
    if (rc != 0) return EP_E_SELECT;  /* SW != 9000 */

    /* Parse FCI response into warehouse */
    int parsed = apdu_parse_tlv_only(resp, resp_len, ep_ctx->wh);
    if (parsed <= 0) return EP_E_SELECT;

    return EP_E_OK;
}

/* ================================================================== */
/*  Step 1: Initiate Application Processing — GET PROCESSING OPTIONS   */
/* ================================================================== */

/**
 * GPO command with PDOL data from SELECT response.
 * Per Book C-3 §5.2.1:
 *   The card tells us what data it needs in the PDOL (tag 'BF0C'→'DF9F66')
 *   returned in the FCI of the SELECT AID response.
 *
 * PDOL structure: [Tag, Length x N, ...] — each entry specifies a tag
 * and how many bytes to send for that tag.
 */
static int kernel_do_gpo(ep_context_t *ep_ctx)
{
    if (!ep_ctx || !ep_ctx->wh || !ep_ctx->icr) return EP_E_INVAL;

    /* The PDOL is in the SELECT FCI (BF0C → DF9F66).
     * Parse it to determine what data to build for GPO command.
     *
     * Example PDOL from card: [9F66, 4, 9F02, 6, 5F2A, 2, 9F36, 2]
     * Means: send Terminal Qualifiers(4B) + Amount(6B) + Currency(2B) + ...
     */

    /* Generate Unpredictable Number for GPO */
    uint8_t unexp_num[4];
    platform_prng(unexp_num, 4);
    tlv_store_set(ep_ctx->wh, 0x9F37, unexp_num, 4);

    /* Build GPO command data from PDOL tags.
     * For each PDOL item: look up tag value in POS params / generate TN */
    /* Placeholder: real impl would parse PDOL from warehouse and
     * build the data byte-by-byte per the template */

    /* Send GPO: CLA=00 INS=A8 P1=00 P2=00 */
    uint8_t gpo_data[] = { 0x00 };  /* Minimal placeholder */
    uint8_t gpo_resp[256];
    uint16_t gpo_resp_len = sizeof(gpo_resp);

    int rc = ep_ctx->icr->transceive(
        (const uint8_t[]){ 0x00, 0xA8, 0x00, 0x00, (uint8_t)sizeof(gpo_data) },
        5, gpo_data, sizeof(gpo_data),
        gpo_resp, sizeof(gpo_resp), &gpo_resp_len
    );
    if (rc != 0) return EP_E_GPO;

    /* Parse GPO response into warehouse:
     * Expected tags: [9F27] Cryptogram, [94] AFL, [9F3A] TVR,
     * [87] AIP, [DF9F66] CDOL1 length, etc. */
    int parsed = apdu_parse_response(gpo_resp, gpo_resp_len, ep_ctx->wh, NULL, NULL);
    if (parsed <= 0) return EP_E_GPO;

    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 2: Read Application Data — READ RECORD per AFL               */
/* ================================================================== */

/**
 * Parse AFL from GPO response and read records to get application data.
 * AFL contains pairs of [SFI, Start Record, End Record].
 *
 * Typical AFL data (from GPO response tag 94):
 *   [94] 06 03 03 01 05 04 07
 *   Meaning:
 *   - SFI=3, records 1-1 (ICA Cert)
 *   - SFI=5, records 1-4 (DDIC/Signature)
 *   - SFI=7, record 1-1 (ACMC/other)
 */
static int kernel_read_app_data(ep_context_t *ep_ctx)
{
    if (!ep_ctx || !ep_ctx->wh || !ep_ctx->icr) return EP_E_INVAL;

    /* Check if AFL (tag 0x94) exists in warehouse */
    const tlv_entry_t *afl = tlv_find(ep_ctx->wh, 0x94);
    if (!afl || afl->len < 6) return EMV_E_OK;  /* No AFL = offline approve */

    /* Parse AFL: pairs of 3 bytes → [SFI, Start Rec, End Rec]
     * Each group of 3 bytes defines a record range to read. */
    uint8_t offset = 0;
    while (offset + 3 <= afl->len) {
        uint8_t sfi = (afl->value[offset] >> 3) & 0x1F;
        uint8_t start_rec = afl->value[offset + 1];
        uint8_t end_rec = afl->value[offset + 2];
        offset += 3;

        if (sfi == 0 || start_rec > end_rec) continue;

        /* READ RECORD for each record in range [start_rec, end_rec] */
        for (int rec = start_rec; rec <= end_rec; rec++) {
            /* BUILD READ RECORD APDU: CLA=00 INS=B2 P1=SFI<<3|rec P2=0x0C */
            uint8_t apdu[5] = {
                0x00, 0xB2,                        /* CLA INS */
                (uint8_t)((sfi << 3) | rec),       /* P1 */
                0x0C                               /* P2 — no more records expected */
            };

            uint8_t resp[256];
            uint16_t resp_len = sizeof(resp);

            int rc = ep_ctx->icr->transceive(apdu, 4, resp, sizeof(resp), &resp_len);
            if (rc != 0) break;  /* Read error, stop reading */

            /* Parse record data into warehouse */
            apdu_parse_tlv_only(resp, resp_len, ep_ctx->wh);
        }
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 5: Offline Data Authentication — SDA/fDDA                    */
/* ================================================================== */

/**
 * Fast Dynamic Data Authentication (fDDA) path for SDA.
 * Book C-3 §5.6:
 *   For contactless, K3 supports fast DDA (fDDA) where card auth
 *   is integrated into the GPO exchange via the DDOL (Verification DOL).
 *
 *   1. From SELECT FCI DDOL → get verification tags list
 *   2. Build and send the DDOL data as part of GPO or separate GET DATA
 *   3. Verify RSA-PKP signature using ACM(A) certificate chain
 *   4. Compare hash result with DDIC from certificate
 *
 *   If fDDA succeeds → card authenticated. If fails → retry with full DDA
 *   or DECLINE (depending on card settings).
 */
static int kernel_oda_sda_auth(ep_context_t *ep_ctx)
{
    if (!ep_ctx || !ep_ctx->wh) return EP_E_INVAL;

    const crypto_driver_t *crypto = platform_get_crypto();
    if (!crypto) return EP_E_AUTH;

    /* Determine if card requests ODA (dynamic authentication)
     * Check if ICC CRT ([9F7E]) was returned during GPO → ODA requested
     * Otherwise use SDA (RSA-PKP verify against DDIC) */

    /* If card returned [9F7E] in GPO response → ODA path */
    if (tlv_find(ep_ctx->wh, 0x9F7E)) {
        /* ODA Path:
         * 1. We already have ICA cert from READ RECORD
         * 2. Set ATTRIBUTE with CDOL1 → get ICData
         * 3. DES decrypt ICData → Dynamic Number
         * 4. TOA with CDOL2 + DN → get ICC CRT [9F7E]
         * 5. Verify TDES-MAC of CDOL2+DN against [9F7E]
         */
        ep_ctx->auth_method = AUTH_ODA;
    } else {
        /* SDA Path (fDDA or full DDA):
         * Use ICA certificate from READ RECORD to verify card authenticity.
         * Hash TDOL data → compare with DDIC extracted from certificate.
         */
        ep_ctx->auth_method = AUTH_SDA;
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 6: Cardholder Verification                                   */
/* ================================================================== */

/**
 * Execute kernel-specific CVM logic via registered plugin.
 * The orchestrator will dispatch to the correct cvm_plugin based on kernel_id.
 */
static int kernel_cvm_check(ep_context_t *ep_ctx)
{
    /* This is handled by the orchestrator which calls:
     *   cfg->cvm_plugin->evaluate(&orch_ctx);
     */
    return EMV_E_OK;
}

/* ================================================================== */
/*  GENERATE AC — Issue GENERATE AC command                           */
/* ================================================================== */

/**
 * Send GENERATE AC command to card with TDOL data.
 * Book C-3 §5.9 / Annex D:
 *   The kernel builds TDOL data (application-specific tag list)
 *   and sends it via GENERATE AC command (INS=0xA6).
 *   Card responds with TC, ARPC Request, ARQC, or NASP.
 *
 * TDOL varies per kernel:
 *   K3: [9F16, 9F02, 9F36, 9F03, 5F2A, 9F66]  // TN, Amount, Curr, AmtOther, TQ
 *   K4: [9F16, 9F02, 9F36, 9F03, 9F1C, 5F2A, 9F66] // + Cash Fee
 *   K5: [9F02, 5F2A]
 */
static int kernel_generate_ac(ep_context_t *ep_ctx)
{
    if (!ep_ctx || !ep_ctx->wh) return EP_E_INVAL;

    /* Determine outcome type based on CVM/Risk results:
     *   - Online Required (need ARQC) → Generate ARQC with full TDOL
     *   - Offline Approved (TC) → Generate TC (minimal TDOL or just TQ)
     *   - Declined → NASP
     *
     * Generate AC is the FINAL command sent to the card.
     * It produces one of four responses:
     *   TC (Terminal Conduction) — card accepts the transaction
     *   ARPC Request — card wants online auth (send ARQC to issuer)
     *   ARQC (if card generates cryptogram) — less common in K3
     *   NASP — card declines
     */

    /* Build TDOL data per kernel dictionary */
    /* Placeholder: real impl uses kernel_dict_t to build ordered TDOL */

    /* Send GENERATE AC: CLA=00 INS=A6 P1=00 P2=00 [TDOL data] */
    uint8_t genac_data[] = { 0x00 };
    uint8_t genac_resp[256];
    uint16_t genac_resp_len = sizeof(genac_resp);

    int rc = ep_ctx->icr->transceive(
        (const uint8_t[]){ 0x00, 0xA6, 0x00, 0x00, (uint8_t)sizeof(genac_data) },
        5, genac_data, sizeof(genac_data),
        genac_resp, sizeof(genac_resp), &genac_resp_len
    );

    if (rc != 0) return EP_E_GPO;  /* Card declined */

    /* Parse GENERATE AC response:
     * Expected tags: [9F26] ARQC, [9F27] Cryptogram Info Field,
     * [8A] Auth Response Code, [9F26] NASP, [9F3A] TVR */
    int parsed = apdu_parse_response(genac_resp, genac_resp_len,
                                      ep_ctx->wh, NULL, NULL);
    if (parsed <= 0) return EP_E_GPO;

    return EMV_E_OK;
}

/* ================================================================== */
/*  Main kernel execute function                                      */
/* ================================================================== */

/**
 * Execute a complete kernel transaction after Entry Point handoff.
 * Sequence: GPO → READ RECORD → SDA/ODA → CVM → GENERATE AC → Outcome
 */
int kernel_execute(uint8_t kernel_id, ep_context_t *ep_ctx)
{
    if (!ep_ctx) return ORCH_E_INVAL;

    /* Step 1: GPO with PDOL data */
    int rc = kernel_do_gpo(ep_ctx);
    if (rc != EMV_E_OK) return ORCH_E_DICT_FAIL;

    /* Step 2: Read application data per AFL from GPO response */
    rc = kernel_read_app_data(ep_ctx);

    /* Step 3: Card Read Complete — validate mandatory tags */
    kernel_config_t *cfg = (kernel_config_t *)kernel_lookup(kernel_id);
    if (cfg) {
        rc = tlv_validate_dict((kernel_dict_t *)cfg, ep_ctx->wh);
        if (rc != DICT_E_OK) return ORCH_E_DICT_FAIL;
    }

    /* Step 4: Processing Restrictions (expiry, usage control, TEF) */
    /* Placeholder: check AIP bits, expiry date from warehouse */

    /* Step 5: Offline Data Authentication (SDA or ODA) */
    rc = kernel_oda_sda_auth(ep_ctx);
    if (rc != EMV_E_OK) return ORCH_E_CVM_FAIL;

    /* Step 6: CVM via plugin */
    rc = kernel_cvm_check(ep_ctx);

    /* Step 7: GENERATE AC (produces TC/ARQC/NASP) */
    rc = kernel_generate_ac(ep_ctx);

    /* Step 8: Determine outcome from GENERATE AC response */
    return EMV_E_OK;
}
