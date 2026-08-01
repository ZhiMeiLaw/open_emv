/**
 * @file src/plugin/kernel_ops_kernel5.c
 * @brief Kernel 5 (qVISA / Crypto) per-kernel processing hooks per Book C-5 v2.12.
 *
 * K5 key differences from K3:
 *   - CDA (Composite Data Authentication) instead of fDDA
 *   - TVR-based Terminal Action Analysis (TAC/IAC) determines cryptogram type
 *   - Card returns CVM status in Tag 9F50 (not CTQ-based decision tree)
 *   - Dynamic Terminal Interchange Profile (Tag 9F53)
 *   - CDOL1/CDOL2 instead of TDOL
 *
 * This file implements the 5 hooks that the generic kernel_core.c skeleton calls.
 */

#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ================================================================== */
/*  K5-specific CTQ / TVR helpers                                      */
/* ================================================================== */

/* ---- AIP parse (K5 uses different bit positions than K3) ---- */
/* AIP Byte 1: bit 1 = CDA supported (K3 uses bit 6 for DDA) */

static int aip_cda_supported(const uint8_t *aip, uint8_t len)
{
    if (!aip || len < 1) return 0;
    return bitmap_get(aip, 1);  /* B2 = CDA supported */
}

/* ---- TVR bit constants (Book C-5 Table A-10) ---- */
/* Byte 1 */
#define TVR_B1_OFFLINE_AUTH_NOT_PERFORMED  7  /* bit 8  = index 7 */
#define TVR_B1_CDA_FAILED                  2  /* bit 3  = index 2 */
#define TVR_B1_ICC_DATA_MISSING            5  /* bit 6  = index 5 */
/* Byte 5 */
#define TVR_B5_CA_PK_MISSING               2  /* bit 3  = index 2 */

/* ---- Terminal Interchange Profile (Tag 9F53) bits ---- */
#define TIP_B1_CVM_REQUIRED                7  /* bit 8  = index 7 */
#define TIP_B1_TRANSIT_READER              2  /* bit 3  = index 2 */
#define TIP_B1_CONTACT_CHIP_SUPPORTED      1  /* bit 2  = index 1 */

/* ================================================================== */
/*  Helper: check mandatory data for K5 READ RECORD                   */
/* ================================================================== */
/* K5 §3.4.1.2 — mandatory card data (Select Next if absent)           */

static int k5_check_mandatory_data(const tx_warehouse_t *wh)
{
    const tlv_entry_t *tags[] = {
        tlv_find(wh, 0x8C),   /* CDOL1 */
        tlv_find(wh, 0x57),   /* Track 2 Equivalent Data */
        tlv_find(wh, 0x5F24), /* Application Expiry Date */
        tlv_find(wh, 0x5A),   /* PAN */
    };
    static const uint32_t tag_names[] = { 0x8C, 0x57, 0x5F24, 0x5A };

    for (int i = 0; i < 4; i++) {
        if (!tags[i]) {
            /* Missing mandatory data → Select Next */
            return -3;  /* signal: select next application */
        }
    }
    return 0;
}

/* K5 CDA mandatory data check (§3.4.1.3) */
static int k5_check_cda_data(const tx_warehouse_t *wh, uint8_t *tvr_b1, uint8_t *tvr_b5)
{
    const tlv_entry_t *tags[] = {
        tlv_find(wh, 0x8F),   /* CAPK Index */
        tlv_find(wh, 0x90),   /* Issuer PK Certificate */
        tlv_find(wh, 0x9F32), /* Issuer PK Exponent */
        tlv_find(wh, 0x92),   /* Issuer PK Remainder (conditional) */
        tlv_find(wh, 0x9F46), /* ICC PK Certificate */
        tlv_find(wh, 0x9F47), /* ICC PK Exponent */
        tlv_find(wh, 0x9F48), /* ICC PK Remainder (conditional) */
    };
    static const uint32_t tag_ids[] = { 0x8F, 0x90, 0x9F32, 0x92, 0x9F46, 0x9F47, 0x9F48 };

    int missing = 0;
    for (int i = 0; i < 7; i++) {
        /* Tag 92 and 9F48 are conditional (only if required by key sizes) */
        if (tag_ids[i] == 0x92 || tag_ids[i] == 0x9F48) {
            /* Skip conditional tags for now — real impl would check sizes */
            continue;
        }
        if (!tags[i]) missing = 1;
    }

    if (missing) {
        if (tvr_b1) { *tvr_b1 |= (1 << TVR_B1_CDA_FAILED); *tvr_b1 |= (1 << TVR_B1_ICC_DATA_MISSING); }
        if (tvr_b5)  { /* CA key missing handled separately */ }
        return -1;
    }
    return 0;
}

/* ================================================================== */
/*  Hook 1: Processing Restrictions (K5 §3.6)                         */
/* ================================================================== */
/* K5 checks: AUC (3.6.1), Expiry (3.6.2), Effective Date (3.6.3)     */

static int k5_check_processing_restrictions(kernel_hook_ctx_t *ctx)
{
    if (!ctx || !ctx->wh) return EMV_E_OK;
    const tx_warehouse_t *wh = ctx->wh;

    /* §3.6.1: Application Usage Control — simplified (no cash checks for qVISA) */
    /* AUC check is acquirer-merchant configurable; skip for reference impl */

    /* §3.6.2: Application Expiry Date Check */
    const tlv_entry_t *exp_date = tlv_find(wh, 0x5F24);
    const tlv_entry_t *txn_date = tlv_find(wh, 0x9A);

    if (txn_date && txn_date->len >= 3) {
        if (!exp_date || exp_date->len < 3) {
            /* No expiry date — decline */
            ctx->decline_required = 1;
            return -1;
        }
        if (memcmp(txn_date->value, exp_date->value, 3) > 0) {
            /* Expired — check TIP for go-online-if-expired */
            /* For reference: default to decline */
            ctx->decline_required = 1;
            return -1;
        }
    }

    /* §3.6.3: Application Effective Date Check (optional) */
    const tlv_entry_t *eff_date = tlv_find(wh, 0x5F25);  /* if present */
    if (eff_date && eff_date->len >= 3 && txn_date && txn_date->len >= 3) {
        if (memcmp(txn_date->value, eff_date->value, 3) < 0) {
            /* Application not yet effective — decline */
            ctx->decline_required = 1;
            return -1;
        }
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Hook 2: CDA (Composite Data Authentication) — K5 §3.8.2           */
/* ================================================================== */
/* K5 uses CDA (not fDDA): RSA signature over CDOL1 data              */
/* Same verify flow as K3's fDDA but with different data context      */

static int k5_check_offline_auth(kernel_hook_ctx_t *ctx, auth_method_t *auth_result)
{
    if (!ctx || !ctx->wh || !auth_result) return EMV_E_INVAL;
    const tx_warehouse_t *wh = ctx->wh;

    /* Check AIP for CDA support */
    const tlv_entry_t *aip = tlv_find(wh, 0x82);
    if (!aip || aip->len < 1 || !aip_cda_supported(aip->value, aip->len)) {
        /* CDA not supported — mark as none */
        *auth_result = AUTH_NONE;
        ctx->auth_done = 1;
        return EMV_E_OK;
    }

    /* Check for CDA signature (SDAD in K5 = 9F4B) */
    const tlv_entry_t *sdad = tlv_find(wh, 0x9F4B);
    if (!sdad) {
        *auth_result = AUTH_NONE;
        ctx->auth_done = 1;
        return EMV_E_OK;
    }

    /* Verify CDA signature using crypto driver */
    /* INTEGRATOR: Implement real CDA verification here */
    /* CDA flow:
     * 1. Reconstruct CDOL1 data from GPO/READ RECORD
     * 2. Parse ICC PK Certificate (9F46) + Exponent (9F47) + Remainder (9F48)
     * 3. Parse Issuer PK Certificate (90) + Exponent (9F32) + Remainder (92)
     * 4. Get CAPK from terminal config (index from 8F)
     * 5. Verify ICC PK cert against CAPK (RSA-PKP)
     * 6. Verify SDAD against ICC PK
     */
    if (!ctx->crypto || !ctx->crypto->rsa_pkpad_verify) {
        /* No crypto driver — mark CDA as failed */
        ctx->decline_required = 1;
        *auth_result = AUTH_NONE;
        ctx->auth_done = 1;
        return -1;
    }

    const tlv_entry_t *icc_cert = tlv_find(wh, 0x9F46);
    if (!icc_cert) {
        ctx->decline_required = 1;
        *auth_result = AUTH_NONE;
        ctx->auth_done = 1;
        return -1;
    }

    /* Placeholder: real impl calls rsa_pkpad_verify with CDOL1 data */
    int rc = ctx->crypto->rsa_pkpad_verify(
        icc_cert->value, (size_t)icc_cert->len,
        NULL, 0, sdad->value, (size_t)sdad->len
    );

    if (rc == 0) {
        *auth_result = AUTH_SDA;
        ctx->auth_done = 1;
        return EMV_E_OK;
    }

    /* CDA failed — check TIP for fallback */
    const tlv_entry_t *tip = tlv_find(wh, 0x9F53);
    if (tip && tip->len >= 1 && bitmap_get(tip->value, 1)) {  /* bit 2 = contact chip supported */
        ctx->decline_required = 1;
    } else {
        ctx->decline_required = 1;
    }
    *auth_result = AUTH_NONE;
    ctx->auth_done = 1;
    return -1;
}

/* ================================================================== */
/*  Hook 3: CVM Processing — K5 §3.8.3                                */
/* ================================================================== */
/* K5 CVM is based on Tag 9F50 (Cardholder Verification Status) from  */
/* GENERATE AC response, NOT on CTQ decision tree.                    */

static int k5_build_cvm_results(kernel_hook_ctx_t *ctx)
{
    if (!ctx || !ctx->wh) return EMV_E_OK;
    const tx_warehouse_t *wh = ctx->wh;

    /* K5: CVM status comes from 9F50 in GENERATE AC response */
    /* For now (pre-GAC), check if 9F50 is already present (from a prior GAC) */
    const tlv_entry_t *cvm_status = tlv_find(wh, 0x9F50);
    if (!cvm_status || cvm_status->len < 1) {
        /* 9F50 not yet available — CVM will be evaluated after GENERATE AC */
        return EMV_E_OK;
    }

    uint8_t status = cvm_status->value[0];

    /* Per §3.8.3.1: evaluate 9F50 value */
    switch (status) {
    case 0x00:  /* No CVM */
        /* §3.8.3.3: if TIP says CVM required and transit reader → decline */
        {
            const tlv_entry_t *tip = tlv_find(wh, 0x9F53);
            if (tip && tip->len >= 1) {
                if (bitmap_get(tip->value, TIP_B1_CVM_REQUIRED) &&
                    !bitmap_get(tip->value, TIP_B1_TRANSIT_READER)) {
                    ctx->decline_required = 1;
                    return -1;
                }
            }
        }
        break;

    case 0x10:  /* Obtain Signature */
        {
            const tlv_entry_t *tip = tlv_find(wh, 0x9F53);
            if (tip && tip->len >= 1) {
                if (!bitmap_get(tip->value, 6)) {  /* bit 7 = signature supported */
                    ctx->decline_required = 1;
                    return -1;
                }
            }
        }
        break;

    case 0x20:  /* Online PIN */
        {
            const tlv_entry_t *tip = tlv_find(wh, 0x9F53);
            if (tip && tip->len >= 1) {
                if (!bitmap_get(tip->value, 5)) {  /* bit 6 = online PIN supported */
                    ctx->decline_required = 1;
                    return -1;
                }
            }
            ctx->online_required = 1;
        }
        break;

    case 0x30 ... 0x3F:  /* CDCVM Selected */
        /* CDCVM limit check handled in kernel_generate_ac */
        break;

    default:
        /* Invalid 9F50 value → decline */
        ctx->decline_required = 1;
        return -1;
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Hook 4: Build GENERATE AC data (K5 §3.8.1 — CDOL1)                */
/* ================================================================== */
/* K5 uses CDOL1 (from READ RECORD) instead of TDOL                   */
/* Reference Control Parameter (P1): bit 5 = CDA requested            */

static int k5_build_generate_ac(const kernel_hook_ctx_t *ctx, tx_warehouse_t *out_wh)
{
    if (!ctx || !ctx->wh || !out_wh) return EMV_E_INVAL;
    const tx_warehouse_t *wh = ctx->wh;

    /* Get CDOL1 from warehouse (tag 0x8C) */
    const tlv_entry_t *cdol1 = tlv_find(wh, 0x8C);
    if (!cdol1) {
        /* No CDOL1 — use empty template */
        uint8_t empty[] = { 0x83, 0x00 };
        return tlv_store_set(out_wh, 0x83, empty, 2);
    }

    /* Parse CDOL1 template and build GENERATE AC data */
    /* CDOL1 format: [TagHigh Len TagHigh Len ...] */
    uint8_t genac_data[128];
    uint16_t data_len = 0;

    uint16_t offset = 0;
    while (offset + 2 <= cdol1->len && data_len + 10 <= sizeof(genac_data)) {
        uint32_t tag = EMV_TAG2(cdol1->value[offset], cdol1->value[offset + 1]);
        uint8_t  len = cdol1->value[offset + 2];
        offset += 3;

        const tlv_entry_t *entry = tlv_find(wh, tag);
        if (!entry) {
            /* Unknown tag → fill with zeros per §3.8.1.2 */
            if (data_len + 1 + 1 + len > sizeof(genac_data)) break;
            genac_data[data_len++] = (uint8_t)(tag >> 8);
            genac_data[data_len++] = (uint8_t)(tag & 0xFF);
            genac_data[data_len++] = len;
            memset(genac_data + data_len, 0, len);
            data_len += len;
            continue;
        }

        uint8_t copy_len = entry->len < len ? entry->len : len;
        if (data_len + 2 + 1 + copy_len > sizeof(genac_data)) break;
        genac_data[data_len++] = (uint8_t)(tag >> 8);
        genac_data[data_len++] = (uint8_t)(tag & 0xFF);
        genac_data[data_len++] = (uint8_t)copy_len;
        memcpy(genac_data + data_len, entry->value, copy_len);
        data_len += copy_len;
    }

    /* Wrap in Command Template [83] */
    uint8_t wrapped[132];
    wrapped[0] = 0x83;
    wrapped[1] = (uint8_t)data_len;
    memcpy(wrapped + 2, genac_data, data_len);
    return tlv_store_set(out_wh, 0x83, wrapped, data_len + 2);
}

/* ================================================================== */
/*  Hook 5: Parse GENERATE AC response + CVM outcome (K5 §3.8.1-4)    */
/* ================================================================== */

static int k5_parse_generate_ac_response(kernel_hook_ctx_t *ctx)
{
    if (!ctx || !ctx->wh) return EMV_E_OK;
    const tx_warehouse_t *wh = ctx->wh;

    /* Parse CID [9F27] for cryptogram type */
    const tlv_entry_t *cid = tlv_find(wh, 0x9F27);
    if (!cid || cid->len < 1) {
        /* No CID — decline */
        ctx->decline_required = 1;
        return EMV_E_OK;
    }

    uint8_t cid_byte = cid->value[0];
    uint8_t cid_type = (cid_byte >> 6) & 0x03;

    switch (cid_type) {
    case 0x00:  /* AAC */
        ctx->decline_required = 1;
        break;
    case 0x01:  /* TC */
        /* §3.8.1.10: TC + no SDAD → decline */
        if (!tlv_find(wh, 0x9F4B)) {
            ctx->decline_required = 1;
        }
        break;
    case 0x02:  /* ARQC */
        /* §3.8.1.11: if requested TC but got ARQC → decline */
        break;
    case 0x03:  /* RFU */
        ctx->decline_required = 1;
        break;
    }

    /* §3.8.4: Outcome determination based on CID */
    if (!ctx->decline_required) {
        if (cid_type == 0x02) {  /* ARQC */
            /* Check Issuer Update Parameter [9F60] for "Present and Hold" */
            const tlv_entry_t *iou = tlv_find(wh, 0x9F60);
            if (iou && iou->len >= 1) {
                if (iou->value[0] == 0x01) {
                    /* "Present and Hold" — keep online_required */
                    ctx->online_required = 1;
                } else if (iou->value[0] == 0x02) {
                    /* "Two Presentments" — keep online_required */
                    ctx->online_required = 1;
                }
                /* 0x00 or absent → online as normal */
            }
            if (!ctx->online_required) ctx->online_required = 1;
        }
        /* TC → offline approve (online_required stays 0) */
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Public: Kernel 5 operations table                                  */
/* ================================================================== */

static kernel_ops_t k5_ops = {
    .check_processing_restrictions = k5_check_processing_restrictions,
    .check_offline_auth            = k5_check_offline_auth,
    .build_cvm_results             = k5_build_cvm_results,
    .build_generate_ac             = k5_build_generate_ac,
    .parse_generate_ac_response    = k5_parse_generate_ac_response,
};

const kernel_ops_t *k5_get_kernel_ops(void)
{
    return &k5_ops;
}
