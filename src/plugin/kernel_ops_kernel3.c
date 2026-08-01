/**
 * @file src/plugin/kernel_ops_kernel3.c
 * @brief Kernel 3 per-kernel processing hooks per EMV Book C-3 v2.12.
 *
 * The kernel framework (kernel_core.c) provides a generic transaction skeleton.
 * Each kernel implements its own kernel_ops_t to handle kernel-specific logic:
 *   - Processing Restrictions (Section 5.5)
 *   - Offline Data Authentication — fDDA (Section 5.6)
 *   - Cardholder Verification — CTQ decision tree (Section 5.7)
 *   - GENERATE AC + Outcome determination (Sections 5.8 / 5.9)
 *
 * The generic skeleton calls these hooks at the right time.
 */

#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/errors.h"
#include "emv_kernel/orchestrator.h"
#include <string.h>

/* ================================================================== */
/*  Internal context — wraps what each hook needs                      */
/* ================================================================== */
/* Note: kernel_hook_ctx_t is defined in kernel_interface.h */

/* ================================================================== */
/*  Helper: parse CTQ bits (Book C-3 §5.7.1.2)                       */
/* ================================================================== */

typedef struct {
    uint8_t online_pin_required  : 1;  /* CTQ byte1 bit8 (MSB of byte0) */
    uint8_t signature_required   : 1;  /* CTQ byte1 bit7               */
    uint8_t go_online_oda_fail   : 1;  /* CTQ byte1 bit6               */
    uint8_t switch_if_oda_fail   : 1;  /* CTQ byte1 bit5               */
    uint8_t go_online_expired    : 1;  /* CTQ byte1 bit4               */
    uint8_t switch_cash          : 1;  /* CTQ byte1 bit3               */
    uint8_t switch_cashback      : 1;  /* CTQ byte1 bit2               */
    uint8_t cdcvm_performed      : 1;  /* CTQ byte2 bit8               */
    uint8_t issuer_update_pos    : 1;  /* CTQ byte2 bit7               */
} k3_ctq_fields_t;

static void k3_ctq_parse(const uint8_t *ctq_bytes, uint8_t len, k3_ctq_fields_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!ctq_bytes || len < 1) return;

    /* EMV bitmaps are MSB-first: bit 0 = MSB of byte 0 */
    out->online_pin_required  = bitmap_get(ctq_bytes, 0);  /* B1 bit 8 */
    out->signature_required   = bitmap_get(ctq_bytes, 1);  /* B1 bit 7 */
    out->go_online_oda_fail   = bitmap_get(ctq_bytes, 2);  /* B1 bit 6 */
    out->switch_if_oda_fail   = bitmap_get(ctq_bytes, 3);  /* B1 bit 5 */
    out->go_online_expired    = bitmap_get(ctq_bytes, 4);  /* B1 bit 4 */
    out->switch_cash          = bitmap_get(ctq_bytes, 5);  /* B1 bit 3 */
    out->switch_cashback      = bitmap_get(ctq_bytes, 6);  /* B1 bit 2 */

    if (len > 1) {
        out->cdcvm_performed    = bitmap_get(ctq_bytes + 1, 0); /* B2 bit 8 */
        out->issuer_update_pos  = bitmap_get(ctq_bytes + 1, 1); /* B2 bit 7 */
    }
}

/* ================================================================== */
/*  Helper: determine transaction type (Purchase / Cash / Cashback)    */
/* ================================================================== */
/* Per §3.4.1: Transaction Type = 9C byte 0 (numeric)                  */
/*   '00' = Purchase          '01' = Manual Cash                       */
/*   '20' = Refund/Credit     other = implementation-specific          */
/* Cashback: Amount, Other (9F03) > 0 indicates cashback present.     */
static int k3_is_cash_transaction(const tx_warehouse_t *wh)
{
    const tlv_entry_t *tt = tlv_find(wh, 0x9C);  /* Transaction Type */
    if (!tt || tt->len < 1) return 0;
    return (tt->value[0] == 0x01);  /* '01' = manual cash */
}

static int k3_is_cashback_transaction(const tx_warehouse_t *wh)
{
    const tlv_entry_t *amt_other = tlv_find(wh, 0x9F03);  /* Amount, Other */
    if (!amt_other || amt_other->len < 6) return 0;
    /* BCD 6-byte: non-zero means cashback present */
    for (int i = 0; i < 6; i++) {
        if (amt_other->value[i] != 0) return 1;
    }
    return 0;
}

/* ================================================================== */
/*  Hook 1: Processing Restrictions  (§5.5)                          */
/* ================================================================== */

static int k3_check_processing_restrictions(kernel_hook_ctx_t *ctx)
{
    if (!ctx || !ctx->wh) return EMV_E_OK;

    const tx_warehouse_t *wh = ctx->wh;

    /* ---- §5.5.1.1: Application Expiry Check ---- */
    /* Implementation-Conditional: required for offline-capable readers.
     * Spec: if TC returned AND txn_date > expiry_date → check CTQ.
     * Since CID (TC/AAC/ARQC) is not yet available at this point,
     * we conservatively check the date and let CTQ decide the outcome. */
    const tlv_entry_t *exp_date = tlv_find(wh, 0x5F24);  /* YYMMDD */
    const tlv_entry_t *txn_date = tlv_find(wh, 0x9A);    /* YYMMDD */

    if (txn_date && txn_date->len >= 3) {
        if (!exp_date || exp_date->len < 3) {
            /* No expiry date returned — treat as expired */
            const tlv_entry_t *ctq = tlv_find(wh, 0x9F6C);
            k3_ctq_fields_t ctq_f;
            k3_ctq_parse(ctq ? ctq->value : NULL,
                         ctq ? (uint8_t)ctq->len : 0, &ctq_f);
            if (ctq_f.go_online_expired) {
                ctx->online_required = 1;
                return EMV_E_OK;
            }
            ctx->decline_required = 1;
            return -1;
        }

        int cmp = memcmp(txn_date->value, exp_date->value, 3);
        if (cmp > 0) {
            /* Application expired */
            const tlv_entry_t *ctq = tlv_find(wh, 0x9F6C);
            k3_ctq_fields_t ctq_f;
            k3_ctq_parse(ctq ? ctq->value : NULL,
                         ctq ? (uint8_t)ctq->len : 0, &ctq_f);

            if (ctq_f.go_online_expired) {
                ctx->online_required = 1;
                return EMV_E_OK;
            }
            ctx->decline_required = 1;
            return -1;
        }
    }

    /* ---- §5.5.1.2: Terminal Exception File (TEF) Check ---- */
    /* Implementation-Optional — acquirer-merchant configurable.
     * Stub: real impl would check PAN against TEF list via ICCDB. */
    (void)ctx;

    /* ---- §5.5.1.3: AUC Check — Manual Cash Transactions ---- */
    const tlv_entry_t *auc = tlv_find(wh, 0x82);   /* Application Usage Control */
    const tlv_entry_t *iccc = tlv_find(wh, 0x5F28); /* Issuer Country Code */
    const tlv_entry_t *tc = tlv_find(wh, 0x9F1A);   /* Terminal Country Code */

    if (k3_is_cash_transaction(wh) && auc && auc->len >= 1
        && iccc && iccc->len >= 2 && tc && tc->len >= 2) {
        uint8_t auc_b1 = auc->value[0];
        int domestic = (memcmp(iccc->value, tc->value, 2) == 0);

        /* Byte 1: bit 8 = domestic cash, bit 7 = international cash */
        uint8_t cash_ok = 0;
        if (domestic && (auc_b1 & 0x80)) cash_ok = 1;
        if (!domestic && (auc_b1 & 0x40)) cash_ok = 1;

        if (!cash_ok) {
            const tlv_entry_t *ctq = tlv_find(wh, 0x9F6C);
            k3_ctq_fields_t ctq_f;
            k3_ctq_parse(ctq ? ctq->value : NULL,
                         ctq ? (uint8_t)ctq->len : 0, &ctq_f);

            if (ctq_f.switch_cash) {
                return -2;  /* Try Another Interface — cash */
            }
            ctx->decline_required = 1;
            return -1;
        }
    }

    /* ---- §5.5.1.4: AUC Check — Cashback Transactions ---- */
    if (k3_is_cashback_transaction(wh) && auc && auc->len >= 2
        && iccc && iccc->len >= 2 && tc && tc->len >= 2) {
        uint8_t auc_b2 = auc->value[1];
        int domestic = (memcmp(iccc->value, tc->value, 2) == 0);

        /* Byte 2: bit 8 = domestic cashback, bit 7 = international cashback */
        uint8_t cashback_ok = 0;
        if (domestic && (auc_b2 & 0x80)) cashback_ok = 1;
        if (!domestic && (auc_b2 & 0x40)) cashback_ok = 1;

        if (!cashback_ok) {
            const tlv_entry_t *ctq = tlv_find(wh, 0x9F6C);
            k3_ctq_fields_t ctq_f;
            k3_ctq_parse(ctq ? ctq->value : NULL,
                         ctq ? (uint8_t)ctq->len : 0, &ctq_f);

            if (ctq_f.switch_cashback) {
                return -2;  /* Try Another Interface — cashback */
            }
            ctx->decline_required = 1;
            return -1;
        }
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Hook 2: Offline Data Authentication — fDDA  (§5.6, Annex C)       */
/* ================================================================== */

static int k3_check_offline_auth(kernel_hook_ctx_t *ctx, auth_method_t *auth_result)
{
    if (!ctx || !ctx->wh || !auth_result) return EMV_E_INVAL;

    const tx_warehouse_t *wh = ctx->wh;

    /* Check if card returned ICC CRT [9F7E] in GPO → ODA path */
    if (tlv_find(wh, 0x9F7E)) {
        *auth_result = AUTH_ODA;
        ctx->auth_done = 1;
        return EMV_E_OK;
    }

    /* Check AIP byte 1 bit 6 — DDA supported? */
    const tlv_entry_t *aip = tlv_find(wh, 0x87);
    if (!aip || aip->len < 1 || !bitmap_get(aip->value, 2)) {
        /* AIP bit 6 (B3) = 0 → DDA not supported */
        *auth_result = AUTH_NONE;
        ctx->auth_done = 1;
        return EMV_E_OK;
    }

    /* fDDA path: verify dynamic signature per Annex C */
    const tlv_entry_t *sdad = tlv_find(wh, 0x9F4B);  /* Signed Dynamic Application Data */
    if (!sdad) {
        /* No SDAD — card does not support fDDA for this transaction */
        *auth_result = AUTH_NONE;
        ctx->auth_done = 1;
        return EMV_E_OK;
    }

    /* Validate fDDA version from Card Auth Related Data [9F69] */
    const tlv_entry_t *card_auth = tlv_find(wh, 0x9F69);
    if (!card_auth || card_auth->len < 1) {
        /* Missing card auth data — fDDA cannot proceed */
        goto fdda_fail;
    }
    uint8_t fdda_version = card_auth->value[0];
    if (fdda_version != 0x01) {
        /* Only fDDA version 1 supported */
        goto fdda_fail;
    }

    /* ---- Build Terminal Dynamic Data for DDA hash (Table C-1) ----
     * Hash input = concatenation of:
     *   [9F37] Unpredictable Number (Reader) — 4 bytes
     *   [9F02] Amount, Authorised            — 6 bytes
     *   [5F2A] Transaction Currency Code     — 2 bytes
     *   [9F69] Card Authentication Related Data — variable (5-16 bytes)
     */
    const tlv_entry_t *un = tlv_find(wh, 0x9F37);
    const tlv_entry_t *amt = tlv_find(wh, 0x9F02);
    const tlv_entry_t *cur = tlv_find(wh, 0x5F2A);

    if (!un || !amt || !cur) {
        /* Missing required data for fDDA */
        goto fdda_fail;
    }

    /* Assemble hash input */
    uint8_t hash_input[32];
    uint16_t hash_len = 0;

    /* [9F37] UN (4 bytes) */
    memcpy(hash_input + hash_len, un->value, un->len);
    hash_len += un->len;

    /* [9F02] Amount (6 bytes) */
    memcpy(hash_input + hash_len, amt->value, amt->len);
    hash_len += amt->len;

    /* [5F2A] Currency (2 bytes) */
    memcpy(hash_input + hash_len, cur->value, cur->len);
    hash_len += cur->len;

    /* [9F69] Card Auth Related Data (full length) */
    memcpy(hash_input + hash_len, card_auth->value, card_auth->len);
    hash_len += card_auth->len;

    /* ---- Verify ICC Public Key Certificate [9F46] ---- */
    /* The certificate is passed to rsa_pkpad_verify which:
     *  1. Verifies the CA signature using the ACM(A) key chain
     *  2. Extracts the DDIC from the certificate
     *  3. Hashes the terminal dynamic data (hash_input)
     *  4. Compares hash with DDIC
     *
     * INTEGRATOR: Replace the placeholder call with the real
     * crypto_driver.rsa_pkpad_verify() implementation.
     */
    const tlv_entry_t *icc_cert = tlv_find(wh, 0x9F46);
    if (!icc_cert) {
        goto fdda_fail;
    }

    if (!ctx->crypto || !ctx->crypto->rsa_pkpad_verify) {
        /* No crypto driver available — cannot verify */
        goto fdda_fail;
    }

    int verify_rc = ctx->crypto->rsa_pkpad_verify(
        icc_cert->value, (size_t)icc_cert->len,
        NULL, 0,            /* DDIC — extracted internally by driver */
        hash_input, (size_t)hash_len
    );

    if (verify_rc == 0) {
        /* fDDA verification succeeded */
        *auth_result = AUTH_SDA;
        ctx->auth_done = 1;
        return EMV_E_OK;
    }

fdda_fail:
    /* fDDA failed — consult CTQ for issuer preference */
    {
    const tlv_entry_t *ctq = tlv_find(wh, 0x9F6C);
    k3_ctq_fields_t ctq_f;
    k3_ctq_parse(ctq ? ctq->value : NULL,
                 ctq ? (uint8_t)ctq->len : 0, &ctq_f);

    if (ctq_f.go_online_oda_fail) {
        /* Go online if ODA fails */
        ctx->online_required = 1;
        *auth_result = AUTH_NONE;
        ctx->auth_done = 1;
        return EMV_E_OK;
    } else if (ctq_f.switch_if_oda_fail) {
        /* Switch interface if ODA fails */
        ctx->decline_required = 1;
        *auth_result = AUTH_NONE;
        ctx->auth_done = 1;
        return -1;
    } else {
        /* Default: decline */
        ctx->decline_required = 1;
        *auth_result = AUTH_NONE;
        ctx->auth_done = 1;
        return -1;
    }
    }
}

/* ================================================================== */
/*  Hook 3: CVM Results — CTQ Decision Tree (§5.7)                    */
/* ================================================================== */

static int k3_build_cvm_results(kernel_hook_ctx_t *ctx)
{
    if (!ctx || !ctx->wh) return EMV_E_OK;

    const tx_warehouse_t *wh = ctx->wh;
    const tlv_entry_t *ctq = tlv_find(wh, 0x9F6C);

    if (!ctq || ctq->len < 1) {
        /* CTQ not returned — §5.7.1.1 fallback */
        /* Check reader capabilities from TTQ */
        const tlv_entry_t *ttq = tlv_find(wh, 0x9F66);
        if (ttq && ttq->len >= 1) {
            /* Byte 1 bit 2 = Signature supported by reader */
            if (bitmap_get(ttq->value, 6)) {  /* bit 6 = B1 bit 7 */
                /* Reader supports signature — but card didn't request it */
                /* No CVM performed */
            }
        }
        /* No CVM required */
        return EMV_E_OK;
    }

    k3_ctq_fields_t ctq_f;
    k3_ctq_parse(ctq->value, (uint8_t)ctq->len, &ctq_f);

    /* Priority 1: Online PIN Required */
    if (ctq_f.online_pin_required) {
        ctx->online_required = 1;
        return EMV_E_OK;
    }

    /* Priority 2: CDCVM Performed */
    if (ctq_f.cdcvm_performed) {
        const tlv_entry_t *card_auth = tlv_find(wh, 0x9F69);
        if (card_auth && card_auth->len >= 7) {
            /* Compare 9F69[5..6] with CTQ[0..1] */
            if (card_auth->value[5] == ctq->value[0] &&
                card_auth->value[6] == (ctq->len > 1 ? ctq->value[1] : 0)) {
                /* Match → Confirmation Code Verified */
                return EMV_E_OK;
            }
            /* Mismatch → decline */
            ctx->decline_required = 1;
            return -1;
        }
        /* No 9F69 — check if cryptogram type is ARQC */
        const tlv_entry_t *cif = tlv_find(wh, 0x9F27);
        if (cif && cif->len >= 1 && (cif->value[0] & 0x08)) {
            /* ARQC → pass */
            return EMV_E_OK;
        }
        ctx->decline_required = 1;
        return -1;
    }

    /* Priority 3: Signature Required */
    if (ctq_f.signature_required) {
        /* Request signature from reader */
        return EMV_E_OK;
    }

    /* None of the above → No CVM performed */
    return EMV_E_OK;
}

/* ================================================================== */
/*  Hook 4: Build GENERATE AC data (§5.8 / §5.9)                      */
/* ================================================================== */

static int k3_build_generate_ac(const kernel_hook_ctx_t *ctx, tx_warehouse_t *out_wh)
{
    if (!ctx || !ctx->wh || !out_wh) return EMV_E_INVAL;

    const tx_warehouse_t *wh = ctx->wh;

    /* Build TDOL data: [9F16 TN][9F02 Amount][9F36 ATC][9F03 DefAmt][5F2A Cur][9F66 TQ] */
    uint8_t genac_data[128];
    uint16_t data_len = 0;

    const tlv_entry_t *entries[] = {
        tlv_find(wh, 0x9F16),  /* TN */
        tlv_find(wh, 0x9F02),  /* Amount Auth */
        tlv_find(wh, 0x9F36),  /* ATC */
        tlv_find(wh, 0x9F03),  /* Default Amt */
        tlv_find(wh, 0x5F2A),  /* Currency */
        tlv_find(wh, 0x9F66),  /* Terminal Qualifiers */
    };
    static const uint16_t tags[] = {
        0x9F16, 0x9F02, 0x9F36, 0x9F03, 0x5F2A, 0x9F66
    };

    for (int i = 0; i < 6 && data_len < 120; i++) {
        if (entries[i]) {
            /* Encode as TLV */
            uint8_t tag_bytes[3];
            uint8_t tag_len = 0;
            tlv_encode_tag(tags[i], tag_bytes, &tag_len);
            genac_data[data_len++] = tag_bytes[0];
            if (tag_len > 1) genac_data[data_len++] = tag_bytes[1];
            genac_data[data_len++] = (uint8_t)entries[i]->len;
            memcpy(genac_data + data_len, entries[i]->value, entries[i]->len);
            data_len += entries[i]->len;
        }
    }

    /* Wrap in Command Template [83] */
    uint8_t wrapped[132];
    wrapped[0] = 0x83;
    wrapped[1] = (uint8_t)data_len;
    memcpy(wrapped + 2, genac_data, data_len);
    uint16_t wrapped_len = data_len + 2;

    /* Store in output warehouse as raw bytes for later APDU assembly */
    return tlv_store_set(out_wh, 0x83, wrapped, wrapped_len);
}

/* ================================================================== */
/*  Hook 5: Parse GENERATE AC response → determine outcome            */
/* ================================================================== */

static int k3_parse_generate_ac_response(kernel_hook_ctx_t *ctx)
{
    if (!ctx || !ctx->wh) return EMV_E_INVAL;

    const tx_warehouse_t *wh = ctx->wh;

    /* Parse response tags into warehouse */
    /* Expected: [9F26] ARQC, [8A] ARC, [9F27] CID, [9F2B] NASP */

    /* Check CID for cryptogram type */
    const tlv_entry_t *cid = tlv_find(wh, 0x9F27);
    if (cid && cid->len >= 1) {
        uint8_t cid_byte = cid->value[0];
        uint8_t cid_type = (cid_byte >> 6) & 0x03;

        switch (cid_type) {
        case 0x00:  /* AAC */
            ctx->decline_required = 1;
            break;
        case 0x01:  /* TC */
            ctx->online_required = 0;
            break;
        case 0x02:  /* ARQC */
            ctx->online_required = 1;
            break;
        case 0x03:  /* RFU — treat as AAC */
            ctx->decline_required = 1;
            break;
        }
    }

    /* If TTQ byte2 bit8 = 1 → force online */
    const tlv_entry_t *ttq = tlv_find(wh, 0x9F66);
    if (ttq && ttq->len >= 2 && bitmap_get(ttq->value + 1, 0)) {  /* Byte 2 bit 8 */
        ctx->online_required = 1;
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Public: Kernel 3 operations table                                  */
/* ================================================================== */

static kernel_ops_t k3_ops = {
    .check_processing_restrictions = k3_check_processing_restrictions,
    .check_offline_auth            = k3_check_offline_auth,
    .build_cvm_results             = k3_build_cvm_results,
    .build_generate_ac             = k3_build_generate_ac,
    .parse_generate_ac_response    = k3_parse_generate_ac_response,
};

const kernel_ops_t *k3_get_kernel_ops(void)
{
    return &k3_ops;
}
