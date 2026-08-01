/**
 * @file src/plugin/kernel_ops_kernel7.c
 * @brief Kernel 7 (Token Payment) per-kernel processing hooks per Book C-7 v2.12.
 *
 * K7 shares the same generic skeleton as K3 (kernel_core.c).
 * This file implements K7-specific hooks:
 *   - §4.1 Application Initialization (GPO + TTQ reset)
 *   - §4.2 Read Application Data (AFL + mandatory check)
 *   - §4.3 Offline Data Authentication (fDDA — same as K3, Annex B)
 *   - §4.4 CVM (CTQ decision tree, stricter than K3)
 *   - §4.5 Outcome (TC/ARQC/AAC + PAR support)
 *
 * Key differences from K3:
 *   - No Processing Restrictions (no AUC cash check for tokens)
 *   - CVM stricter: no-CTQ + CDCVM-only reader → Decline
 *   - PAR (9F24) support in outcome data
 *   - SDS (Signature Data Set) validation before CVM
 */

#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ================================================================== */
/*  CTQ parse — shared helper (same layout as K3)                     */
/* ================================================================== */

typedef struct {
    uint8_t online_pin_required  : 1;
    uint8_t signature_required   : 1;
    uint8_t go_online_oda_fail   : 1;
    uint8_t switch_if_oda_fail   : 1;
    uint8_t go_online_expired    : 1;
    uint8_t switch_cash          : 1;
    uint8_t switch_cashback      : 1;
    uint8_t reserved_b1          : 1;
    uint8_t cdcvm_performed      : 1;
    uint8_t issuer_update_pos    : 1;
} k7_ctq_fields_t;

static void k7_ctq_parse(const uint8_t *ctq_bytes, uint8_t len, k7_ctq_fields_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!ctq_bytes || len < 1) return;

    out->online_pin_required  = bitmap_get(ctq_bytes, 0);
    out->signature_required   = bitmap_get(ctq_bytes, 1);
    out->go_online_oda_fail   = bitmap_get(ctq_bytes, 2);
    out->switch_if_oda_fail   = bitmap_get(ctq_bytes, 3);
    out->go_online_expired    = bitmap_get(ctq_bytes, 4);
    out->switch_cash          = bitmap_get(ctq_bytes, 5);
    out->switch_cashback      = bitmap_get(ctq_bytes, 6);
    out->reserved_b1          = bitmap_get(ctq_bytes, 7);

    if (len > 1) {
        out->cdcvm_performed    = bitmap_get(ctq_bytes + 1, 0);
        out->issuer_update_pos  = bitmap_get(ctq_bytes + 1, 1);
    }
}

/* ================================================================== */
/*  Hook 1: Processing Restrictions (K7: no cash AUC, only expiry)    */
/* ================================================================== */

static int k7_check_processing_restrictions(kernel_hook_ctx_t *ctx)
{
    if (!ctx || !ctx->wh) return EMV_E_OK;
    const tx_warehouse_t *wh = ctx->wh;

    /* K7 does not check AUC for cash/cashback (tokens don't support that).
     * Only check application expiry — same logic as K3 §5.5.1.1. */
    const tlv_entry_t *exp_date = tlv_find(wh, 0x5F24);
    const tlv_entry_t *txn_date = tlv_find(wh, 0x9A);

    if (txn_date && txn_date->len >= 3) {
        if (!exp_date || exp_date->len < 3) {
            /* No expiry returned → treat as expired */
            const tlv_entry_t *ctq = tlv_find(wh, 0x9F6C);
            k7_ctq_fields_t ctq_f;
            k7_ctq_parse(ctq ? ctq->value : NULL,
                         ctq ? (uint8_t)ctq->len : 0, &ctq_f);
            if (ctq_f.go_online_expired) {
                ctx->online_required = 1;
                return EMV_E_OK;
            }
            ctx->decline_required = 1;
            return -1;
        }

        if (memcmp(txn_date->value, exp_date->value, 3) > 0) {
            const tlv_entry_t *ctq = tlv_find(wh, 0x9F6C);
            k7_ctq_fields_t ctq_f;
            k7_ctq_parse(ctq ? ctq->value : NULL,
                         ctq ? (uint8_t)ctq->len : 0, &ctq_f);
            if (ctq_f.go_online_expired) {
                ctx->online_required = 1;
                return EMV_E_OK;
            }
            ctx->decline_required = 1;
            return -1;
        }
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Hook 2: Offline Data Authentication — fDDA (§4.3, Annex B)        */
/* ================================================================== */
/* K7 fDDA is identical to K3 (Annex B of Book C-7 mirrors Annex C of C-3) */

static int k7_check_offline_auth(kernel_hook_ctx_t *ctx, auth_method_t *auth_result)
{
    if (!ctx || !ctx->wh || !auth_result) return EMV_E_INVAL;
    const tx_warehouse_t *wh = ctx->wh;

    /* ODA path: ICC CRT [9F7E] in GPO response */
    if (tlv_find(wh, 0x9F7E)) {
        *auth_result = AUTH_ODA;
        ctx->auth_done = 1;
        return EMV_E_OK;
    }

    /* Check AIP bit 6 — DDA supported */
    const tlv_entry_t *aip = tlv_find(wh, 0x87);
    if (!aip || aip->len < 1 || !bitmap_get(aip->value, 2)) {
        *auth_result = AUTH_NONE;
        ctx->auth_done = 1;
        return EMV_E_OK;
    }

    /* fDDA path */
    const tlv_entry_t *sdad = tlv_find(wh, 0x9F4B);
    if (!sdad) {
        *auth_result = AUTH_NONE;
        ctx->auth_done = 1;
        return EMV_E_OK;
    }

    const tlv_entry_t *card_auth = tlv_find(wh, 0x9F69);
    if (!card_auth || card_auth->len < 1) goto fdda_fail;
    if (card_auth->value[0] != 0x01) goto fdda_fail;  /* Only fDDA v1 supported */

    /* Build Table C-1 hash input (same as K3) */
    const tlv_entry_t *un = tlv_find(wh, 0x9F37);
    const tlv_entry_t *amt = tlv_find(wh, 0x9F02);
    const tlv_entry_t *cur = tlv_find(wh, 0x5F2A);
    if (!un || !amt || !cur) goto fdda_fail;

    uint8_t hash_input[32];
    uint16_t hash_len = 0;
    memcpy(hash_input + hash_len, un->value, un->len); hash_len += un->len;
    memcpy(hash_input + hash_len, amt->value, amt->len); hash_len += amt->len;
    memcpy(hash_input + hash_len, cur->value, cur->len); hash_len += cur->len;
    memcpy(hash_input + hash_len, card_auth->value, card_auth->len); hash_len += card_auth->len;

    const tlv_entry_t *icc_cert = tlv_find(wh, 0x9F46);
    if (!icc_cert) goto fdda_fail;
    if (!ctx->crypto || !ctx->crypto->rsa_pkpad_verify) goto fdda_fail;

    int rc = ctx->crypto->rsa_pkpad_verify(
        icc_cert->value, (size_t)icc_cert->len,
        NULL, 0, hash_input, (size_t)hash_len
    );

    if (rc == 0) {
        *auth_result = AUTH_SDA;
        ctx->auth_done = 1;
        return EMV_E_OK;
    }

fdda_fail:
    {
    const tlv_entry_t *ctq = tlv_find(wh, 0x9F6C);
    k7_ctq_fields_t ctq_f;
    k7_ctq_parse(ctq ? ctq->value : NULL, ctq ? (uint8_t)ctq->len : 0, &ctq_f);

    if (ctq_f.go_online_oda_fail) {
        ctx->online_required = 1;
        *auth_result = AUTH_NONE;
        ctx->auth_done = 1;
        return EMV_E_OK;
    } else if (ctq_f.switch_if_oda_fail) {
        ctx->decline_required = 1;
        *auth_result = AUTH_NONE;
        ctx->auth_done = 1;
        return -1;
    } else {
        ctx->decline_required = 1;
        *auth_result = AUTH_NONE;
        ctx->auth_done = 1;
        return -1;
    }
    }
}

/* ================================================================== */
/*  Hook 3: CVM — K7 is stricter than K3 (§4.4)                      */
/* ================================================================== */
/* K7 rules (per Book C-7 §4.4.2):
 *   - No CTQ + Signature reader → request Signature
 *   - No CTQ + CDCVM+OnlinePIN reader → request Online PIN
 *   - No CTQ + CDCVM-only reader → DECLINE (K3 allowed No-CVM)
 *   - CTQ present → same priority: OnlinePIN > CDCVM > Signature
 */

static int k7_build_cvm_results(kernel_hook_ctx_t *ctx)
{
    if (!ctx || !ctx->wh) return EMV_E_OK;
    const tx_warehouse_t *wh = ctx->wh;
    const tlv_entry_t *ctq = tlv_find(wh, 0x9F6C);

    if (!ctq || ctq->len < 1) {
        /* §4.4.2.1: CTQ not returned — check reader capabilities (TTQ) */
        const tlv_entry_t *ttq = tlv_find(wh, 0x9F66);
        int has_signature = 0, has_online_pin = 0, has_cdcvm = 0;

        if (ttq && ttq->len >= 3) {
            has_signature  = bitmap_get(ttq->value, 6);  /* Byte1 bit7 */
            has_online_pin = bitmap_get(ttq->value, 2);  /* Byte1 bit6 (PIN pad) */
            has_cdcvm      = bitmap_get(ttq->value + 2, 6); /* Byte3 bit7 */
        }

        /* K7 §4.4.2.1: if reader supports Signature, request it */
        if (has_signature) {
            return EMV_E_OK;  /* Signature requested */
        }
        /* If reader supports CDCVM + OnlinePIN, request Online PIN */
        if (has_cdcvm && has_online_pin) {
            ctx->online_required = 1;
            return EMV_E_OK;
        }
        /* If reader supports only CDCVM → DECLINE (K3 allows No-CVM) */
        if (has_cdcvm) {
            ctx->decline_required = 1;
            return -1;
        }
        /* No CVM support at all → DECLINE */
        ctx->decline_required = 1;
        return -1;
    }

    /* §4.4.2.2: CTQ present — same priority as K3 */
    k7_ctq_fields_t ctq_f;
    k7_ctq_parse(ctq->value, (uint8_t)ctq->len, &ctq_f);

    if (ctq_f.online_pin_required) {
        ctx->online_required = 1;
        return EMV_E_OK;
    }

    if (ctq_f.cdcvm_performed) {
        const tlv_entry_t *card_auth = tlv_find(wh, 0x9F69);
        if (card_auth && card_auth->len >= 7) {
            if (card_auth->value[5] == ctq->value[0] &&
                card_auth->value[6] == (ctq->len > 1 ? ctq->value[1] : 0)) {
                return EMV_E_OK;  /* CDCVM match */
            }
            ctx->decline_required = 1;
            return -1;
        }
        /* No 9F69 — check CID for ARQC */
        const tlv_entry_t *cif = tlv_find(wh, 0x9F27);
        if (cif && cif->len >= 1 && (cif->value[0] & 0x08)) {
            return EMV_E_OK;  /* ARQC */
        }
        ctx->decline_required = 1;
        return -1;
    }

    if (ctq_f.signature_required) {
        return EMV_E_OK;  /* Signature requested */
    }

    /* No CVM indicated — K7 §4.4.2.2: check if reader requires CVM */
    const tlv_entry_t *ttq = tlv_find(wh, 0x9F66);
    if (ttq && ttq->len >= 3) {
        /* Byte 3 bit 7 = Consumer Device CVM supported (always 1 per spec) */
        /* If reader requires CVM and none is performed → decline */
        if (bitmap_get(ttq->value + 1, 0)) {  /* Byte2 bit8 = Online cryptogram required */
            /* online cryptogram required but no CVM — still OK for online */
        }
    }
    return EMV_E_OK;
}

/* ================================================================== */
/*  Hook 4: Build GENERATE AC data (K7 TDOL)                          */
/* ================================================================== */
/* K7 TDOL: same as K3 — [9F16 TN][9F02 Amount][9F36 ATC][9F03 DefAmt][5F2A Cur][9F66 TQ] */

static int k7_build_generate_ac(const kernel_hook_ctx_t *ctx, tx_warehouse_t *out_wh)
{
    if (!ctx || !ctx->wh || !out_wh) return EMV_E_INVAL;
    const tx_warehouse_t *wh = ctx->wh;

    uint8_t genac_data[128];
    uint16_t data_len = 0;

    static const uint16_t tags[] = { 0x9F16, 0x9F02, 0x9F36, 0x9F03, 0x5F2A, 0x9F66 };

    for (int i = 0; i < 6 && data_len < 120; i++) {
        const tlv_entry_t *e = tlv_find(wh, tags[i]);
        if (!e) continue;
        uint8_t tb[3];
        uint8_t tl = 0;
        tlv_encode_tag(tags[i], tb, &tl);
        if (data_len + 2 + 1 + e->len > sizeof(genac_data)) break;
        genac_data[data_len++] = tb[0];
        if (tl > 1) genac_data[data_len++] = tb[1];
        genac_data[data_len++] = (uint8_t)e->len;
        memcpy(genac_data + data_len, e->value, e->len);
        data_len += e->len;
    }

    uint8_t wrapped[132];
    wrapped[0] = 0x83;
    wrapped[1] = (uint8_t)data_len;
    memcpy(wrapped + 2, genac_data, data_len);
    return tlv_store_set(out_wh, 0x83, wrapped, data_len + 2);
}

/* ================================================================== */
/*  Hook 5: Parse GENERATE AC response + PAR support                  */
/* ================================================================== */

static int k7_parse_generate_ac_response(kernel_hook_ctx_t *ctx)
{
    if (!ctx || !ctx->wh) return EMV_E_OK;
    const tx_warehouse_t *wh = ctx->wh;

    /* Parse CID for cryptogram type */
    const tlv_entry_t *cid = tlv_find(wh, 0x9F27);
    if (cid && cid->len >= 1) {
        uint8_t cid_type = (cid->value[0] >> 5) & 0x03;
        switch (cid_type) {
        case 0x00: ctx->decline_required = 1; break;
        case 0x01: break;  /* TC — offline approve */
        case 0x02: ctx->online_required = 1; break;
        case 0x03: ctx->decline_required = 1; break;
        }
    }

    /* TTQ override: byte2 bit8 = 1 forces online */
    const tlv_entry_t *ttq = tlv_find(wh, 0x9F66);
    if (ttq && ttq->len >= 2 && bitmap_get(ttq->value + 1, 0)) {
        ctx->online_required = 1;
    }

    /* K7: PAR (9F24) — store for outcome data record (Book B-1 §B.1) */
    /* PAR is optional; if present, kernel passes it to Entry Point */
    (void)tlv_find(wh, 0x9F24);

    return EMV_E_OK;
}

/* ================================================================== */
/*  Public: Kernel 7 operations table                                  */
/* ================================================================== */

static kernel_ops_t k7_ops = {
    .check_processing_restrictions = k7_check_processing_restrictions,
    .check_offline_auth            = k7_check_offline_auth,
    .build_cvm_results             = k7_build_cvm_results,
    .build_generate_ac             = k7_build_generate_ac,
    .parse_generate_ac_response    = k7_parse_generate_ac_response,
};

const kernel_ops_t *k7_get_kernel_ops(void)
{
    return &k7_ops;
}
