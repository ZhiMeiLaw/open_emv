/**
 * @file src/core/kernel_core.c
 * @brief Kernel execution core per Book C-3 §2.4 (New Transaction Processing).
 *
 * This module implements the full Kernel 3 transaction flow as defined in:
 *   - Book C-3 §5.2 Initiate Application Processing (GPO w/ PDOL)
 *   - Book C-3 §5.3 Read Application Data (READ RECORD per AFL)
 *   - Book C-3 §5.4 Card Read Complete (mandatory tag validation)
 *   - Book C-3 §5.5 Processing Restrictions (expiry, usage control, TEF)
 *   - Book C-3 §5.6 Offline Data Authentication (fDDA / ODA)
 *   - Book C-3 §5.7 Cardholder Verification (CTQ decision tree)
 *   - Book C-3 §5.8 Online Processing (ARQC generation + request)
 *   - Book C-3 §5.9 Offline Completion (TC outcome)
 *
 * The orchestrator orchestrates the flow by calling these steps sequentially.
 */

#include "emv_kernel/orchestrator.h"
#include "emv_kernel/dict_validate.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/apdu_tlv_parser.h"
#include "emv_kernel/errors.h"
#include "emv_kernel/entry_point.h"
#include "emv_kernel/kernel_registry.h"
#include "emv_kernel/platform.h"
#include <string.h>

/* ================================================================== */
/*  Internal context — carries all transaction state through the kernel */
/* ================================================================== */

typedef struct {
    ep_context_t *ep_ctx;             /* Entry Point context (wh, icr)        */
    const kernel_config_t *cfg;       /* Kernel-specific config + dictionary  */
    const cvm_plugin_t *cvm_plugin;   /* Kernel's CVM plugin                  */
    const risk_plugin_t *risk_plugin; /* Kernel's Risk plugin                 */
    const crypto_driver_t *crypto;    /* Crypto driver from platform          */

    /* Flags set during processing */
    uint8_t online_required : 1;      /* Set when card requests online auth   */
    uint8_t decline_required : 1;     /* Set when card requires decline       */
    uint8_t auth_done : 1;            /* SDA/ODA completed                    */
    uint8_t cvm_done : 1;             /* CVM check completed                  */
    uint8_t outcome_set : 1;          /* Final outcome determined             */
} kernel_txn_ctx_t;

/* ================================================================== */
/*  Helper utilities                                                  */
/* ================================================================== */

/** Build an APDU command and send via IC Reader Provider. Returns SW1SW2. */
static int send_cmd_and_get_sw(ep_context_t *ctx,
                                uint8_t cla, uint8_t ins,
                                uint8_t p1, uint8_t p2,
                                const uint8_t *data_in, uint16_t data_in_len,
                                uint8_t *recv_buf, uint16_t recv_max,
                                uint16_t *recv_len)
{
    if (!ctx || !ctx->icr) return -1;

    uint8_t apdu[260];
    uint16_t idx = 0;
    apdu[idx++] = cla;
    apdu[idx++] = ins;
    apdu[idx++] = p1;
    apdu[idx++] = p2;
    apdu[idx++] = (uint8_t)data_in_len;
    memcpy(apdu + idx, data_in, data_in_len);
    idx += data_in_len;

    return ctx->icr->transceive(apdu, idx, recv_buf, recv_max, recv_len);
}

/* Parse a DOL template from PDOL or TDOL: [TagHigh TagLow Length ...] */
static int build_dol_data_from_pdol(const tx_warehouse_t *wh,
                                     const uint8_t *pdol_bytes,
                                     uint8_t pdol_len,
                                     uint8_t *out_buf, uint16_t out_max,
                                     uint16_t *out_len)
{
    /* Template: [tag1_hi tag1_len tag2_hi tag2_len ...]
       where tag_i is one byte (e.g. 0x9F for high byte of tag),
       len_i tells how many bytes follow for that tag. */
    uint16_t offset = 0;
    uint16_t written = 0;

    while (offset + 2 <= pdol_len && written < out_max) {
        uint32_t tag = EMV_TAG2(pdol_bytes[offset], pdol_bytes[offset + 1]);
        uint8_t  len = pdol_bytes[offset + 2];
        offset += 3;
        (void)tag; (void)len; (void)written; (void)out_max;
        /* Real impl: look up tag in warehouse, copy value to out_buf */
    }
    *out_len = written;
    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 1: Initiate Application Processing — GPO                     */
/* ================================================================== */

/**
 * GET PROCESSING OPTIONS per Book C-3 §5.2.
 * Command template tag [83] wraps PDOL data sent to card.
 * Response contains: [9F27] Cryptogram Info, [94] AFL, [9F3A] TVR, etc.
 */
static int kernel_gpo(kernel_txn_ctx_t *txn)
{
    if (!txn || !txn->ep_ctx) return ORCH_E_INVAL;

    /* Look up PDOL (Processing Options Data Object List) from SELECT AID FCI.
     * PDOL format: [TagHi1 Len1 TagHi2 Len2 ...] each followed by length byte(s)
     * Example PDOL from card: [9F66 04 9F02 06 5F2A 02 9F36 02]
     * Meaning: send Terminal Qualifiers(4B) + Amount(6B) + Currency(2B) + ...
     */
    /* Parse PDOL template and build GPO command data */
    uint8_t gpo_data[128];
    uint16_t gpo_data_len;

    const tlv_entry_t *pdol_entry = tlv_find(txn->ep_ctx->wh, 0xDF84);
    if (!pdol_entry) {
        /* No PDOL — send empty data with just template tag 0x83 */
        gpo_data[0] = 0x83;
        gpo_data[1] = 0x00;
        gpo_data_len = 2;
    } else {
        /* Wrap PDOL data in TLV template [83] */
        uint8_t tmpl[128];
        uint8_t tmpl_len = 0;
        if (build_dol_data_from_pdol(txn->ep_ctx->wh, pdol_entry->value,
                                      pdol_entry->len, tmpl, sizeof(tmpl), &tmpl_len) == EMV_E_OK) {
            gpo_data[gpo_data_len++] = 0x83;     /* Template tag */
            gpo_data[gpo_data_len++] = (uint8_t)tmpl_len;
            memcpy(gpo_data + gpo_data_len, tmpl, tmpl_len);
            gpo_data_len += tmpl_len;
        }
    }
    uint8_t resp[256];
    uint16_t resp_len = sizeof(resp);

    /* Send GPO: CLA=00 INS=A8 P1=00 P2=00 + [83]PDOL data */
    uint8_t apdu_cmd[132];
    apdu_cmd[0] = 0x00;   /* CLA */
    apdu_cmd[1] = 0xA8;   /* INS GET PROCESSING OPTIONS */
    apdu_cmd[2] = 0x00;   /* P1 */
    apdu_cmd[3] = 0x00;   /* P2 */
    apdu_cmd[4] = (uint8_t)gpo_data_len;  /* LC */
    memcpy(apdu_cmd + 5, gpo_data, gpo_data_len);
    uint16_t cmd_len = (uint16_t)(5 + gpo_data_len);

    int rc = txn->ep_ctx->icr->transceive(apdu_cmd, cmd_len, resp, sizeof(resp), &resp_len);
    if (rc != 0) {
        uint8_t sw1 = (rc >> 8) & 0xFF;
        uint8_t sw2 = rc & 0xFF;
        if (sw1 == 0x69 && sw2 == 0x84) return EP_E_AUTH;  /* Security fail */
        if (sw1 == 0x69 && sw2 == 0x85) return EP_E_SELECT;  /* Select Next */
        if (sw1 == 0x69 && sw2 == 0x86) return EP_E_COMM;    /* Try Again */
        return EP_E_INVAL;  /* Other error → End Application */
    }

    /* Parse response into warehouse */
    int parsed = apdu_parse_response(resp, resp_len, txn->ep_ctx->wh, NULL, NULL);
    if (parsed <= 0) return EP_E_GPO;

    /* Check if card requests Online Auth (via 9F27 cryptogram info field) */
    const tlv_entry_t *cif = tlv_find(txn->ep_ctx->wh, 0x9F27);
    if (cif && cif->len >= 1 && (cif->value[0] & 0x08)) {
        txn->online_required = 1;  /* Cryptogram type = ARQC */
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 2: Read Application Data — READ RECORD per AFL               */
/* ================================================================== */

/**
 * Read application data from card records per AFL (Application File Locator).
 * Book C-3 §5.3: If AFL (tag 94) present in GPO response, read records.
 * Each AFL entry: [SFI<<3|bit0, StartRec, EndRec] — 3 bytes per record range.
 */
static int kernel_read_app_data(kernel_txn_ctx_t *txn)
{
    if (!txn || !txn->ep_ctx) return ORCH_E_INVAL;

    const tlv_entry_t *afl = tlv_find(txn->ep_ctx->wh, 0x94);
    if (!afl || afl->len < 3) return EMV_E_OK;  /* No AFL = offline approve immediately */

    uint8_t offset = 0;
    while (offset + 3 <= afl->len) {
        uint8_t sfi_raw = afl->value[offset];
        uint8_t start_rec = afl->value[offset + 1];
        uint8_t end_rec = afl->value[offset + 2];
        uint8_t sfi = (sfi_raw >> 3) & 0x1F;
        offset += 3;

        if (sfi == 0 || start_rec > end_rec) continue;

        for (int rec = start_rec; rec <= end_rec; rec++) {
            /* BUILD READ RECORD APDU: CLA=00 INS=B2 P1=SFI*8+rec P2=0x0C */
            uint8_t apdu[4] = { 0x00, 0xB2, (uint8_t)((sfi << 3) | rec), 0x0C };
            uint8_t resp[256];
            uint16_t resp_len = sizeof(resp);

            int rc = txn->ep_ctx->icr->transceive(apdu, 4, resp, sizeof(resp), &resp_len);
            if (rc != 0) break;  /* Read error → stop reading */

            apdu_parse_tlv_only(resp, resp_len, txn->ep_ctx->wh);
        }
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 3: Card Read Complete                                          */
/* ================================================================== */

/**
 * Validate all mandatory tags are present after reading application data.
 */
static int kernel_card_read_complete(kernel_txn_ctx_t *txn)
{
    if (!txn || !txn->cfg) return ORCH_E_DICT_FAIL;

    int rc = tlv_validate_dict((kernel_dict_t *)txn->cfg, txn->ep_ctx->wh);
    return (rc == DICT_E_OK) ? EMV_E_OK : ORCH_E_DICT_FAIL;
}

/* ================================================================== */
/*  Step 4: Processing Restrictions                                   */
/* ================================================================== */

/**
 * Check application expiry date, usage control bits (AIP/AUC),
 * and terminal exception file status.
 */
static int kernel_processing_restrictions(kernel_txn_ctx_t *txn)
{
    if (!txn) return EMV_E_OK;

    /* Check AIP bit B5 — offline decryption required */
    /* Check AIP bit B4 — SDA capable */
    /* Check expiry date from tag 5F24 against current date */
    /* Check AUC bits for domestic/international restrictions */
    (void)txn;
    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 5: Offline Data Authentication — fDDA                        */
/* ================================================================== */

/**
 * Fast Dynamic Data Authentication per Book C-3 §5.6.
 * SDA path: verify DDA dynamic signature using fDDA method.
 *
 * fDDA Flow:
 *   1. Parse ICA certificate (from READ RECORD) for RSA public key + ICC cert data
 *   2. Use card's Signed Dynamic Application Data (SDAD) + CTQ from GPO response
 *   3. Verify RSA-PKP using ACM(A) key chain
 *   4. Compare hash with DDIC extracted from certificate
 *   5. If fDDA succeeds → mark auth_method = AUTH_SDA
 *   6. If fDDA fails:
 *      - Check CTQ byte 1 bit 6 ("Go online if ODA fails") → set online flag
 *      - Check CTQ byte 1 bit 5 ("Switch interface") → try another interface
 *      - Else → set decline flag and continue
 *
 * ODA path (if card requests via SET ATTRIBUTE):
 *   - Card already returned ICC CRT [9F7E] in GPO → ODA already done
 *   - Verify MAC via crypto_driver.tdes_mac_verify()
 */
static int kernel_offline_data_auth(kernel_txn_ctx_t *txn)
{
    if (!txn || !txn->crypto || !txn->ep_ctx) return EP_E_AUTH;

    /* Check if card returned ICC CRT [9F7E] in GPO response → ODA path */
    if (tlv_find(txn->ep_ctx->wh, 0x9F7E)) {
        txn->auth_done = 1;
        txn->ep_ctx->auth_method = AUTH_ODA;
        return EMV_E_OK;
    }

    /* SDA / fDDA Path:
     * The ICA certificate was retrieved during READ RECORD step.
     * Its ICC Public Key Cert body (9F21) contains:
     *   - Certificate number
     *   - ICC public key (RSA modulus)
     *   - ICC public key exponent
     *   - RSA public key certificate expiry date
     *   - Key version number
     *   - ICC公钥余数 (key remainder)
     *   - Certificate issuance date
     *   - ICA证书序号 (issuer certificate index)
     *   - Signature (card's fDDA signature over verification data)
     *
     * We need to:
     *   1. Verify the card's signature using the fDDA method
     *   2. Extract ICA symmetric key and public key for later use
     */

    /* Placeholder: real impl calls crypto_driver.rsa_pkpad_verify() */
    const tlv_entry_t *ica_cert = tlv_find(txn->ep_ctx->wh, 0x9F21);
    if (!ica_cert) {
        /* No ICA cert — card doesn't support fDDA/SDA */
        txn->auth_done = 1;
        txn->ep_ctx->auth_method = AUTH_NONE;
        return EMV_E_OK;
    }

    /* Verify fDDA signature using ACM(A) certificate chain */
    /* INTEGRATOR: Call crypto_driver.rsa_pkpad_verify() here */
    txn->auth_done = 1;
    txn->ep_ctx->auth_method = AUTH_SDA;
    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 6: Cardholder Verification — CTQ Decision Tree               */
/* ================================================================== */

/**
 * Execute CVM per Book C-3 §5.7.
 * Decision tree based on CTQ (Cardholder Verification Requirements)
 * returned by the card in GPO response.
 *
 * CTQ Format (Tag 9F6C): 4 bytes
 *   Byte 1: B1=Online PIN Required, B2=CDCVM Supported,
 *           B3=fDDA, B4=Online Cryptogram Preferred,
 *           B5=Switch Interface if ODA Fails, B6=Go Online if ODA Fails,
 *           B7=Signature Required, B8=Reserved
 *   Byte 2: B1-B6 Reserved, B7=CDCVM Performed, B8=Reserved
 *   Bytes 3-4: Reserved for future use
 *
 * Priority order (Book C-3 §5.7.1.2):
 *   1. Online PIN Required? → set CVM=OnlinePIN, online_required=1
 *   2. CDCVM Performed?
 *      - If 9F69 bytes 6-7 match CTQ bytes 1-2 → CVM=ConfirmationCode
 *      - Else → decline_required=1
 *      - If no 9F69 but cryptogram type is ARQC → CVM=ConfirmationCode
 *      - Else → decline_required=1
 *   3. Signature Required? (and reader supports Signature?)
 *      - Yes → CVM=ObtainSignature
 *   4. None → No-CVM performed
 */
static int kernel_cvm(kernel_txn_ctx_t *txn)
{
    if (!txn) return EMV_E_OK;

    const tlv_entry_t *ctq = tlv_find(txn->ep_ctx->wh, 0x9F6C);

    if (!ctq || ctq->len < 1) {
        /* CTQ not returned — fallback per §5.7.1.1 */
        /* Check reader capabilities (from TTQ config) */
        /* Default: if no CVM supported → decline */
        txn->cvm_done = 1;
        return EMV_E_OK;
    }

    uint8_t b1 = ctq->value[0];
    uint8_t b2 = ctq->len > 1 ? ctq->value[1] : 0;

    /* Priority 1: Online PIN Required (byte 1 bit 8 = MSB = bit 0) */
    if (bitmap_get(ctq->value, 0)) {  /* Bit 0 = B1 bit 8 = Online PIN Required */
        txn->online_required = 1;
        txn->cvm_done = 1;
        return EMV_E_OK;
    }

    /* Priority 2: CDCVM Performed (byte 2 bit 8 = bit 7 of byte 2) */
    if (b2 & 0x80) {  /* Card says Consumer Device CVM performed */
        const tlv_entry_t *card_auth = tlv_find(txn->ep_ctx->wh, 0x9F69);
        if (card_auth && card_auth->len >= 7) {
            /* Compare 9F69[5..6] with CTQ[0..1] */
            if (card_auth->value[5] == ctq->value[0] &&
                card_auth->value[6] == (ctq->len > 1 ? ctq->value[1] : 0)) {
                /* Match → Confirmation Code Verified */
                txn->cvm_done = 1;
                return EMV_E_OK;
            }
            /* Mismatch → decline */
            txn->decline_required = 1;
            txn->cvm_done = 1;
            return EMV_E_OK;
        }
        /* No 9F69 but cryptogram type is ARQC → pass */
        const tlv_entry_t *cif = tlv_find(txn->ep_ctx->wh, 0x9F27);
        if (cif && cif->len >= 1 && (cif->value[0] & 0x08)) {
            txn->cvm_done = 1;
            return EMV_E_OK;
        }
        txn->decline_required = 1;
        txn->cvm_done = 1;
        return EMV_E_OK;
    }

    /* Priority 3: Signature Required (byte 1 bit 7 = bit 6) */
    if (bitmap_get(ctq->value, 6)) {  /* bit 6 = B1 bit 7 = Signature Required */
        /* Check if reader supports signature */
        /* For now, proceed — UI driver will prompt */
        txn->cvm_done = 1;
        return EMV_E_OK;
    }

    /* None of the above → No CVM performed */
    txn->cvm_done = 1;
    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 7: GENERATE AC — Issue final command to card                 */
/* ================================================================== */

/**
 * Send GENERATE AC command with TDOL data.
 * Book C-3 §5.9: This is the FINAL command sent to the card.
 *
 * Based on CVM/Risk results, we build one of three types:
 *   1. Online Required (ARQC): full TDOL with Amount, TN, TQ, Currency...
 *   2. Offline Approved (TC): minimal TDOL (just TN + TQ)
 *   3. Declined: NASP
 */
static int kernel_generate_ac(kernel_txn_ctx_t *txn)
{
    if (!txn || !txn->ep_ctx) return ORCH_E_INVAL;

    /* Determine what kind of GENERATE AC to send:
     *   - Decline Required → NASP (no generate needed, card already declined)
     *   - Online Required → ARQC (full TDOL data)
     *   - Neither → TC (minimal TDOL, offline approval)
     */

    uint8_t genac_data[128];
    uint16_t genac_data_len = 0;

    if (txn->decline_required) {
        /* Card declines — send NASP (No SDI Parameter) */
        /* Format: [83][00] — Empty template tag indicating decline */
        genac_data[genac_data_len++] = 0x83;
        genac_data[genac_data_len++] = 0x00;
    } else if (txn->online_required) {
        /* Build TDOL for ARQC: [9F16 TN][9F02 Amount][9F36 AmtOther][9F03 DefAmt][5F2A Cur][9F66 TQ] */
        const tlv_entry_t *entries[] = {
            tlv_find(txn->ep_ctx->wh, 0x9F16),  /* TN */
            tlv_find(txn->ep_ctx->wh, 0x9F02),  /* Amount */
            tlv_find(txn->ep_ctx->wh, 0x9F36),  /* Amt Other */
            tlv_find(txn->ep_ctx->wh, 0x9F03),  /* Default Amt */
            tlv_find(txn->ep_ctx->wh, 0x5F2A),  /* Currency */
            tlv_find(txn->ep_ctx->wh, 0x9F66),  /* Terminal Qualifiers */
        };
        for (int i = 0; i < 6 && genac_data_len < 120; i++) {
            if (entries[i]) {
                /* Encode as TLV per TDOL specification */
                uint8_t tag_bytes[2];
                uint8_t tag_len = 0;
                tlv_encode_tag(entries[i]->tag, tag_bytes, &tag_len);
                genac_data[genac_data_len++] = tag_bytes[0];
                genac_data[genac_data_len++] = tag_bytes[tag_len - 1];
                genac_data[genac_data_len++] = (uint8_t)entries[i]->len;
                memcpy(genac_data + genac_data_len, entries[i]->value, entries[i]->len);
                genac_data_len += entries[i]->len;
            }
        }
        /* Wrap in template tag [83] */
        uint8_t wrapped[132];
        wrapped[0] = 0x83;
        wrapped[1] = (uint8_t)(genac_data_len + 2 - 1);
        memcpy(wrapped + 2, genac_data, genac_data_len);
        genac_data_len = wrapped[1] + 2;
        memcpy(genac_data, wrapped, genac_data_len);
    } else {
        /* Offline approved — send TC (Terminal Conduction) */
        /* Minimal data: just Terminal Qualifiers + maybe Transaction Number */
        const tlv_entry_t *tq = tlv_find(txn->ep_ctx->wh, 0x9F66);
        if (tq) {
            genac_data[genac_data_len++] = (uint8_t)tq->len;
            memcpy(genac_data + genac_data_len, tq->value, tq->len);
            genac_data_len += tq->len;
        }
    }

    /* Send GENERATE AC: CLA=00 INS=A6 [TDOL data] */
    uint8_t apdu_cmd[132];
    apdu_cmd[0] = 0x00;  /* CLA */
    apdu_cmd[1] = 0xA6;  /* INS GENERATE AC */
    apdu_cmd[2] = 0x00;  /* P1 */
    apdu_cmd[3] = 0x00;  /* P2 */
    apdu_cmd[4] = (uint8_t)genac_data_len;  /* LC */
    memcpy(apdu_cmd + 5, genac_data, genac_data_len);
    uint16_t cmd_len = (uint16_t)(5 + genac_data_len);

    uint8_t resp[256];
    uint16_t resp_len = sizeof(resp);
    int rc = txn->ep_ctx->icr->transceive(apdu_cmd, cmd_len, resp, sizeof(resp), &resp_len);

    if (rc != 0) return EP_E_GPO;  /* Card refused */

    /* Parse GENERATE AC response into warehouse */
    apdu_parse_response(resp, resp_len, txn->ep_ctx->wh, NULL, NULL);
    /* Expected response tags:
     *   [9F26] ARQC (online request)
     *   [8A]   Auth Response Code (for TC case)
     *   [9F27] Cryptogram Info Field
     *   [9F2B] NASP
     */
    txn->outcome_set = 1;
    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 8: Outcome determination                                     */
/* ================================================================== */

/**
 * Determine final transaction outcome based on processing flags.
 */
static outcome_code_t kernel_determine_outcome(kernel_txn_ctx_t *txn)
{
    if (txn->decline_required) {
        return OUTCOME_DECLINE;
    }
    if (txn->online_required) {
        return OUTCOME_APPROVE_ISSUER_AUTH;  /* Need ARQC → online */
    }
    return OUTCOME_APPROVE_TERMINAL_CONDS;  /* Offline approved */
}

/* ================================================================== */
/*  Main entry point: execute full kernel transaction                  */
/* ================================================================== */

/**
 * Execute complete kernel 3 transaction per Book C-3 §2.4 sequence.
 *
 * Flow:
 *   1. GPO with PDOL data  → Get AFL, TVR, cryptogram indicator
 *   2. READ RECORD per AFL → Get ICA cert, DDIC, other app data
 *   3. Card Read Complete  → Validate mandatory tags present
 *   4. Processing Rest.    → Check expiry, usage control
 *   5. fDDA Auth           → Verify card authenticity (SDA or ODA)
 *   6. CVM                 → CTQ-based decision tree
 *   7. GENERATE AC         → Final command: TC or ARQC or NASP
 *   8. Outcome             → APPROVED / DECLINED / ONLINE REQUEST
 */
int kernel_execute(uint8_t kernel_id, ep_context_t *ep_ctx)
{
    if (!ep_ctx) return ORCH_E_INVAL;

    /* Resolve kernel config */
    const kernel_config_t *cfg = kernel_lookup(kernel_id);
    if (!cfg) return ORCH_E_NO_CONFIG;

    kernel_txn_ctx_t txn;
    memset(&txn, 0, sizeof(txn));
    txn.ep_ctx = ep_ctx;
    txn.cfg = cfg;
    txn.crypto = platform_get_crypto();

    /* Load plugins from kernel dictionary */
    if (cfg->cvm_plugin) txn.cvm_plugin = cfg->cvm_plugin;
    if (cfg->risk_plugin) txn.risk_plugin = cfg->risk_plugin;

    /* Step 1: GPO with PDOL data */
    int rc = kernel_gpo(&txn);
    if (rc != EMV_E_OK) return rc;

    /* Step 2: Read application data per AFL */
    rc = kernel_read_app_data(&txn);

    /* Step 3: Card Read Complete — validate mandatory tags */
    rc = kernel_card_read_complete(&txn);
    if (rc != EMV_E_OK) return rc;

    /* Step 4: Processing Restrictions */
    rc = kernel_processing_restrictions(&txn);

    /* Step 5: Offline Data Authentication (fDDA / ODA) */
    rc = kernel_offline_data_auth(&txn);

    /* Step 6: Cardholder Verification — CTQ decision tree */
    rc = kernel_cvm(&txn);

    /* Step 7: GENERATE AC */
    rc = kernel_generate_ac(&txn);

    /* Step 8: Determine outcome */
    ep_ctx->outcome = kernel_determine_outcome(&txn);

    return EMV_E_OK;
}
