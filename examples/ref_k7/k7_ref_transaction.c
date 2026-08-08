/**
 * @file examples/ref_k7/k7_ref_transaction.c
 * @brief Kernel 7 reference: end-to-end token payment transaction per Book B + Book C-7.
 *
 * Simplified reference implementation following K3 pattern with K7-specific
 * token features: SDS validation, token PAN checks, and token CVM strategies.
 *
 * This file shows the K7 transaction flow structure. Integrators should
 * adapt platform-specific details (ICR, ICCDB, crypto) for their target.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/apdu_tlv_parser.h"
#include "emv_kernel/errors.h"
#include "emv_kernel/entry_point.h"
#include "emv_kernel/kernel_registry.h"
#include "emv_kernel/orchestrator.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/platform.h"

#include <string.h>

/* Forward declarations from sibling files */
extern const crypto_driver_t ref_crypto_driver;
extern struct cvm_plugin_s kernel7_cvm_plugin;
extern struct risk_plugin_s kernel7_risk_plugin;
extern kernel_dict_t kernel7_dict;

/* POS parameters structure for K7 (Token Payment) */
typedef struct {
    uint8_t sds_code;              /* Single Digit SDS from issuer */
    uint8_t tip_signature_supported : 1;
    uint8_t tip_online_pin_supported : 1;
    uint32_t unsigned_limit;       /* Amount ≤ this → No-CVM */
    uint32_t signed_limit;         /* Amount > unsigned, ≤ this → PIN */
    uint8_t pin_key_index;         /* Key index for PIN encryption */
} pos_params_k7_t;

extern void pos_params_init_defaults_k7(void);

/* ================================================================== */
/*  STEP 1: Application startup                                       */
/* ================================================================== */

static void k7_init(void)
{
    kernel7_dict.cvm_plugin = &kernel7_cvm_plugin;
    kernel7_dict.risk_plugin = &kernel7_risk_plugin;
    kernel_register((const kernel_config_t *)&kernel7_dict);
    platform_register_crypto(&ref_crypto_driver);
    pos_params_init_defaults_k7();
    /* Load default ICCDB from NV storage (token card data) here */
}

/* ================================================================== */
/*  Main Transaction Execution                                        */
/* ================================================================== */

/**
 * Execute a complete K7 token transaction.
 */
int k7_execute_transaction(const struct ic_reader_provider_s *icr,
                           const pos_params_k7_t *pos_params,
                           uint8_t *tc_out, uint8_t *tc_len, uint8_t tc_max_len,
                           outcome_code_t *outcome)
{
    if (!icr || !icr->init || !icr->poll_card || !icr->transceive) {
        if (outcome) *outcome = OUTCOME_ERROR;
        return EMV_E_INVAL;
    }

    /* ---- Phase A: Transaction workspace ---- */
    tx_warehouse_t wh;
    uint8_t pool_in[MAX_POOL_SIZE];
    tlv_warehouse_init(&wh, pool_in, sizeof(pool_in));

    /* ---- Phase B: Entry Point (Book B flow) ---- */

    ep_context_t ep_ctx;
    memset(&ep_ctx, 0, sizeof(ep_ctx));
    ep_ctx.wh = &wh;
    ep_ctx.icr = icr;

    /* Call entry_point_run which handles:
     *   - Protocol activation
     *   - Application selection (PPSE, AID select)
     *   - Card authentication (SDA/ODA)
     *   - GPO processing
     */
    int ret = entry_point_run(&ep_ctx, pos_params);
    if (ret < 0) {
        if (outcome) *outcome = OUTCOME_RESTART;
        return ret;
    }

    /* ---- Phase C: Kernel Orchestrator (Book C-7) ---- */

    /* Initialize orchestrator context */
    orchestrator_ctx_t oc;
    ret = orchestrator_init(&oc, &ref_crypto_driver, NULL, pos_params, NULL);
    if (ret < 0) {
        if (outcome) *outcome = OUTCOME_ERROR;
        return ret;
    }

    /* Execute Kernel 7 - this runs:
     *   - Dictionary validation
     *   - CVM plugin evaluation
     *   - Risk plugin checks (including SDS validation for K7)
     *   - Cryptogram generation
     *   - Outcome determination
     */
    ret = kernel_execute(7, &ep_ctx);
    if (ret < 0) {
        if (outcome) *outcome = OUTCOME_ERROR;
        return ret;
    }

    /* ---- Phase D: Outcome Handling ---- */

    /* Get final outcome */
    const outcome_result_t *result = orchestrator_get_outcome();
    if (!result) {
        if (outcome) *outcome = OUTCOME_ERROR;
        return EMV_E_INVAL;
    }

    if (outcome) *outcome = result->code;

    /* Build TC or NASP output based on outcome */
    if (result->code == OUTCOME_APPROVE_ISSUER_AUTH ||
        result->code == OUTCOME_APPROVE_TERMINAL_CONDS) {
        /* Build Terminal Conduction (TC) data */
        uint8_t tc_buf[256];
        uint8_t tc_bl = sizeof(tc_buf);
        int rc = orchestrator_build_tc(tc_buf, &tc_bl, sizeof(tc_buf));
        if (rc >= 0 && tc_out && tc_len) {
            if (*tc_len > tc_bl) *tc_len = tc_bl;
            memcpy(tc_out, tc_buf, tc_bl);
        }
        *tc_len = tc_bl;
    } else if (result->code == OUTCOME_DECLINE) {
        /* Build No Application SDI Parameter (NASP) */
        uint8_t nasp_buf[64];
        uint8_t nasp_bl = sizeof(nasp_buf);
        int rc = orchestrator_build_nasp(nasp_buf, &nasp_bl, sizeof(nasp_buf));
        if (rc >= 0 && tc_out && tc_len) {
            if (*tc_len > nasp_bl) *tc_len = nasp_bl;
            memcpy(tc_out, nasp_buf, nasp_bl);
        }
        *tc_len = nasp_bl;
    }

    /* K7-specific: After successful transaction, update ICCDB with token state */
    /* This would increment token usage counters, refresh SDS validation state, etc. */

    return EMV_E_OK;
}

/* ================================================================== */
/*  Token-specific helper: Validate token PAN matches stored data     */
/* ================================================================== */

static int k7_validate_token_pan(const tx_warehouse_t *wh)
{
    const tlv_entry_t *pan_e = tlv_find(wh, 0x5A);
    if (!pan_e || pan_e->len < 10 || pan_e->len > 19) {
        return -1; /* Invalid token PAN length */
    }

    /* In a real implementation, compare against stored token data
     * (from ICCDB or secure element). This is a placeholder. */
    (void)pan_e;
    return 0;
}

/* ================================================================== */
/*  Token SDS checker (called from risk plugin or transaction flow)   */
/* ================================================================== */

int k7_validate_sds_token(uint8_t sds_from_card, uint8_t sds_stored)
{
    /* Verify token SDS matches terminal-stored value */
    return (sds_from_card == sds_stored) ? 0 : -1;
}
