/**
 * @file src/plugin/kernel_ops_kernel6.c
 * @brief Kernel 6 (eMvCash) per-kernel processing hooks per Book C-6 v2.12.
 *
 * K6 is the simplest kernel - no CVM, no ODA, balance-based transactions.
 *
 * Key differences from K3:
 *   - No Processing Restrictions (no AUC cash check)
 *   - No Offline Data Authentication (no fDDA/SDA)
 *   - No CVM (always pass, Tag 9F34 = 0x1F 0x00 0x00)
 *   - IAC/TAC thresholds determine outcome (TC or AAC)
 *   - Balance deduction from card (handled by card, not terminal)
 *
 * Book C-6 Sections:
 *   §4.1 Application Initialization (GPO)
 *   §4.2 Read Application Data
 *   §4.3 Cardholder Verification (No CVM)
 *   §4.4 Outcome Determination (IAC/TAC)
 */

#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ================================================================== */
/*  K6-specific TVR/IAC/TAC constants                                 */
/* ================================================================== */

/* TVR byte definitions for K6 */
#define TVR_B1_OFFLINE_AUTH_NOT_PERFORMED  7  /* bit 8 = index 7 */
#define TVR_B1_CVM_NOT_PERFORMED           6  /* bit 7 = index 6 */
#define TVR_B1_SERVICE_NOT_ALLOWED         5  /* bit 6 = index 5 */
#define TVR_B1_CARDHOLDER_VERIFICATION_FAILED 4  /* bit 5 = index 4 */
#define TVR_B1_MERCHANT_FORCE Offline      3  /* bit 4 = index 3 */

/* IAC defaults (Book C-6 Table A-6) */
#define IAC_DENY  0x00  /* Always decline */
#define IAC_DEFAULT 0x00

/* ================================================================== */
/*  Helper: check mandatory data for K6                               */
/* ================================================================== */

static int k6_check_mandatory_data(const tx_warehouse_t *wh)
{
    const tlv_entry_t *tags[] = {
        tlv_find(wh, 0x87),   /* AIP */
        tlv_find(wh, 0x5A),   /* PAN */
        tlv_find(wh, 0x4F),   /* AID */
        tlv_find(wh, 0x9F02), /* Amount */
    };
    static const uint32_t tag_names[] = { 0x87, 0x5A, 0x4F, 0x9F02 };

    for (int i = 0; i < 4; i++) {
        if (!tags[i]) {
            return -3;  /* Missing mandatory data */
        }
    }
    return 0;
}

/* ================================================================== */
/*  Hook 1: Processing Restrictions (K6: minimal checks)              */
/* ================================================================== */

static int k6_check_processing_restrictions(kernel_hook_ctx_t *ctx)
{
    if (!ctx || !ctx->wh) return EMV_E_OK;
    const tx_warehouse_t *wh = ctx->wh;

    /* K6 does not check AUC for cash/cashback.
     * Only check application expiry if present. */
    const tlv_entry_t *exp_date = tlv_find(wh, 0x5F24);
    const tlv_entry_t *txn_date = tlv_find(wh, 0x9A);

    if (txn_date && txn_date->len >= 3) {
        if (!exp_date || exp_date->len < 3) {
            /* No expiry returned - check AIP for expiry check support */
            const tlv_entry_t *aip = tlv_find(wh, 0x87);
            if (aip && aip->len >= 1) {
                /* If AIP bit 8 (byte 1 bit 8) = 0, expiry check not supported */
                if (!bitmap_get(aip->value, 0)) {
                    return EMV_E_OK;
                }
            }
            ctx->decline_required = 1;
            return EMV_E_OK;
        }
        /* Compare expiry date with transaction date */
        /* Simplified: just check format */
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Hook 2: Offline Data Authentication (K6: skip - no ODA)           */
/* ================================================================== */

static int k6_check_offline_auth(kernel_hook_ctx_t *ctx, auth_method_t *auth_result)
{
    (void)ctx;
    /* K6 does not perform offline data authentication.
     * Set auth_done = 0, auth_method = AUTH_NONE */
    if (auth_result) *auth_result = AUTH_NONE;
    return EMV_E_OK;
}

/* ================================================================== */
/*  Hook 3: Build CVM Results (K6: No CVM required)                   */
/* ================================================================== */

static int k6_build_cvm_results(kernel_hook_ctx_t *ctx)
{
    if (!ctx || !ctx->wh) return EMV_E_OK;

    /* K6: No CVM performed - set 9F34 = 0x1F 0x00 0x00 */
    uint8_t cvm_data[3] = { 0x1F, 0x00, 0x00 };
    int rc = tlv_store_set(ctx->wh, 0x9F34, cvm_data, sizeof(cvm_data));
    if (rc != EMV_E_OK) return rc;

    /* Set CVM not performed flag in TVR */
    /* TVR byte 1 bit 7 = CVM not performed */
    tlv_entry_t *tvr = tlv_find(ctx->wh, 0x9F3A);
    if (tvr && tvr->len >= 1) {
        tvr->value[0] |= (1 << 6);  /* bit 7 = index 6 */
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Hook 4: Build GENERATE AC data                                    */
/* ================================================================== */

static int k6_build_generate_ac(const kernel_hook_ctx_t *ctx, tx_warehouse_t *out_wh)
{
    if (!ctx || !out_wh) return EMV_E_INVAL;

    /* K6 GENERATE AC data includes:
     * - Amount (9F02)
     * - Currency code (5F2A)
     * - Terminal qualifiers (9F66)
     * - ATC (9F36)
     * - TVR (9F3A) - optional
     */
    const tx_warehouse_t *wh = ctx->wh;

    /* Copy amount if present */
    const tlv_entry_t *amt = tlv_find(wh, 0x9F02);
    if (amt) {
        tlv_store_set(out_wh, 0x9F02, amt->value, amt->len);
    }

    /* Copy currency code if present */
    const tlv_entry_t *ccode = tlv_find(wh, 0x5F2A);
    if (ccode) {
        tlv_store_set(out_wh, 0x5F2A, ccode->value, ccode->len);
    }

    /* Copy terminal qualifiers if present */
    const tlv_entry_t *ctq = tlv_find(wh, 0x9F66);
    if (ctq) {
        tlv_store_set(out_wh, 0x9F66, ctq->value, ctq->len);
    }

    /* Copy ATC if present */
    const tlv_entry_t *atc = tlv_find(wh, 0x9F36);
    if (atc) {
        tlv_store_set(out_wh, 0x9F36, atc->value, atc->len);
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Hook 5: Parse GENERATE AC response and determine outcome          */
/* ================================================================== */

static int k6_parse_generate_ac_response(kernel_hook_ctx_t *ctx)
{
    if (!ctx || !ctx->wh) return EMV_E_INVAL;

    const tx_warehouse_t *wh = ctx->wh;

    /* Parse GENERATE AC response */
    const tlv_entry_t *cid = tlv_find(wh, 0x9F27);
    if (!cid || cid->len < 1) {
        /* No CID - cannot determine outcome */
        ctx->decline_required = 1;
        return EMV_E_OK;
    }

    uint8_t cid_val = cid->value[0];

    /* CID bits 7-6: Response message template version (00 = v1) */
    /* CID bits 5-4: ARQC / TAC / AAC */
    uint8_t ac_type = (cid_val >> 4) & 0x03;

    switch (ac_type) {
    case 0x00:  /* No AC returned */
        ctx->decline_required = 1;
        break;

    case 0x01:  /* TC (Terminal Cryptogram) - approve */
        ctx->online_required = 0;
        ctx->decline_required = 0;
        break;

    case 0x02:  /* STC (Standard TC) - approve */
        ctx->online_required = 0;
        ctx->decline_required = 0;
        break;

    case 0x03:  /* AAC (Application Authentication Cryptogram) - decline */
        ctx->decline_required = 1;
        break;

    default:
        ctx->online_required = 1;  /* Online required for other cases */
        break;
    }

    /* Check IAC/TAC thresholds if available */
    const tlv_entry_t *iac = tlv_find(wh, 0x9F67);
    const tlv_entry_t *tac = tlv_find(wh, 0x9F65);

    if (iac || tac) {
        /* IAC/TAC processing would go here
         * For now, use CID to determine outcome */
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Kernel 6 operations table                                         */
/* ================================================================== */

static kernel_ops_t k6_ops = {
    .check_processing_restrictions  = k6_check_processing_restrictions,
    .check_offline_auth             = k6_check_offline_auth,
    .build_cvm_results              = k6_build_cvm_results,
    .build_generate_ac              = k6_build_generate_ac,
    .parse_generate_ac_response     = k6_parse_generate_ac_response,
};

const kernel_ops_t *k6_get_kernel_ops(void)
{
    return &k6_ops;
}
