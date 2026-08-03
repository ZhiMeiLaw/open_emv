/**
 * @file examples/ref_k5/k5_ref_transaction.c
 * @brief Kernel 5 (qVISA / Crypto) reference: end-to-end transaction per Book B + Book C-5.
 *
 * K5 flow differs from K3 in these key ways:
 *   - Card auth: CDA (Composite Data Authentication) instead of SDA/fDDA
 *   - CVM: amount-only check (No-CVM when amount ≤ unsigned_limit)
 *   - Cryptogram: CAC (Cryptogram Authentication Code), called CAC in Book C-5
 *   - No PIN support — unsigned_limit is the sole CVM gate
 *
 * This reference shows the full transaction flow structure.
 * Integrators should adapt platform-specific details (ICR, ICCDB, crypto)
 * for their target platform.
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
#include "emv_kernel/dict_validate.h"

#include <string.h>

/* Forward declarations from sibling files */
extern const crypto_driver_t k5_ref_crypto_driver;
extern struct cvm_plugin_s kernel5_cvm_plugin;
extern struct risk_plugin_s kernel5_risk_plugin;
extern kernel_dict_t kernel5_dict;

/* POS parameters for K5 (qVISA / Crypto) */
typedef struct {
    uint32_t unsigned_limit;      /* Amount ≤ this → No-CVM approved */
} pos_params_k5_t;

extern void pos_params_init_defaults_k5(void);

/* ================================================================== */
/*  STEP 1: Application startup                                       */
/* ================================================================== */

static void k5_init(void)
{
    kernel5_dict.cvm_plugin = &kernel5_cvm_plugin;
    kernel5_dict.risk_plugin = &kernel5_risk_plugin;
    kernel_register((const kernel_config_t *)&kernel5_dict);
    platform_register_crypto(&k5_ref_crypto_driver);
    pos_params_init_defaults_k5();
    /* Load default ICCDB from NV storage here */
}

/* ================================================================== */
/*  Main Transaction Execution                                        */
/* ================================================================== */

/**
 * Execute a complete K5 transaction.
 *
 * K5 (Book C-5) flow:
 *   1. Entry Point (Book B): protocol activation, select, CDA auth, GPO
 *   2. Kernel: CVM amount check → build GENERATE AC → parse response
 *   3. Outcome: TC (offline approve) or ARQC (online) or decline
 *
 * @param icr              IC Reader Provider (user-implemented)
 * @param pos_params       Terminal configuration for K5
 * @param tc_out           On output: TC or NASP bytes
 * @param tc_len           In/out: max output size → actual output size
 * @param outcome          On output: transaction result code
 * @return 0 on success, negative error code on failure
 */
int k5_execute_transaction(const struct ic_reader_provider_s *icr,
                           const pos_params_k5_t *pos_params,
                           uint8_t *tc_out, uint8_t *tc_len, uint8_t tc_max_len,
                           outcome_code_t *outcome)
{
    if (!icr || !icr->init || !icr->poll_card || !icr->transceive) {
        if (outcome) *outcome = OUTCOME_ERROR;
        return EMV_E_INVAL;
    }
    if (!pos_params) {
        if (outcome) *outcome = OUTCOME_ERROR;
        return PLAT_E_INVAL;
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

    int ret = entry_point_run(&ep_ctx, pos_params);
    if (ret < 0) {
        if (outcome) *outcome = OUTCOME_RESTART;
        return ret;
    }

    /* ---- Phase C: Kernel 5 execution (Book C-5) ---- */

    /* Step C1: CVM — amount-only check.
     * K5 has no PIN path. If amount > unsigned_limit, the transaction
     * goes online (ARQC). If amount <= limit, No-CVM path is approved.
     * This check is performed inside kernel5_cvm_plugin.evaluate(). */

    /* Step C2: Risk checks (TRM, CRM, VEL).
     * K5 risk plugin runs checks with the amount-only CVM result. */

    /* Step C3: Run kernel execution via orchestrator. */
    orchestrator_ctx_t oc;
    ret = orchestrator_init(&oc, &k5_ref_crypto_driver, NULL, pos_params);
    if (ret < 0) {
        if (outcome) *outcome = OUTCOME_ERROR;
        return ret;
    }

    ret = kernel_execute(5, &ep_ctx);
    if (ret < 0) {
        if (outcome) *outcome = OUTCOME_ERROR;
        return ret;
    }

    /* ---- Phase D: Outcome determination ---- */

    const outcome_result_t *result = orchestrator_get_outcome();
    if (!result) {
        if (outcome) *outcome = OUTCOME_ERROR;
        return EMV_E_INVAL;
    }
    if (outcome) *outcome = result->code;

    switch (result->code) {
    case OUTCOME_APPROVE_ISSUER_AUTH:
        /* Online approved — ARPC received from acquirer.
         * For K5, issuer auth override may grant TC-equivalent outcome. */
        break;

    case OUTCOME_APPROVE_TERMINAL_CONDS:
        /* Offline approved — TC generated.
         * Build TC TLV with [9F26] CAC and [8A] auth response code. */
        {
            uint8_t tc_buf[256];
            uint8_t tc_bl = sizeof(tc_buf);
            int rc = orchestrator_build_tc(tc_buf, &tc_bl, sizeof(tc_buf));
            if (rc >= 0 && tc_out && tc_len) {
                uint8_t out_len = tc_bl < *tc_len ? tc_bl : *tc_len;
                memcpy(tc_out, tc_buf, out_len);
                *tc_len = out_len;
            }
        }
        break;

    case OUTCOME_DECLINE:
        /* Declined — build NASP (No Application SDI Parameter) */
        {
            uint8_t nasp_buf[64];
            uint8_t nasp_bl = sizeof(nasp_buf);
            int rc = orchestrator_build_nasp(nasp_buf, &nasp_bl, sizeof(nasp_buf));
            if (rc >= 0 && tc_out && tc_len) {
                uint8_t out_len = nasp_bl < *tc_len ? nasp_bl : *tc_len;
                memcpy(tc_out, nasp_buf, out_len);
                *tc_len = out_len;
            }
        }
        break;

    case OUTCOME_RESTART:
    default:
        /* Online required or error — caller decides next step */
        break;
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  K5-specific helpers                                               */
/* ================================================================== */

/**
 * Build CDOL1 data for K5 GENERATE AC command.
 * CDOL1 tags come from the GPO response (READ RECORD data).
 *
 * @param wh    Transaction warehouse (populated by entry point)
 * @param buf   Output buffer for CDOL1 bytes
 * @param len   In: max size, Out: actual CDOL1 length
 * @return 0 on success
 */
static int k5_build_cdol1(const tx_warehouse_t *wh, uint8_t *buf, uint8_t *len)
{
    if (!wh || !buf || !len) return EMV_E_INVAL;

    /* CDOL1 is a Command DOL — its structure is defined by the card's
     * PDOL (Profile DOL) in the SELECT response. The actual tag list
     * and order come from parsing the PDOL.
     *
     * For K5 reference, we build the most common CDOL1 structure:
     * [8C] CDOL1 data length indicator
     *
     * In practice: parse PDOL from SELECT FCI, resolve each tag's
     * value from the warehouse, and serialize.
     */

    /* Minimal: store CDOL1 placeholder — real impl builds from PDOL */
    (void)wh;
    *len = 0;
    return EMV_E_OK;
}

/**
 * Parse K5 GENERATE AC response to determine outcome.
 *
 * K5 uses [9F27] Cryptogram Information Data (CID) to indicate
 * the cryptogram type:
 *   0x08 = TC  (Terminal Conduction — offline approved)
 *   0x0A = ARQC (Authorise Request Cryptogram — online required)
 *   0x0C = ARPC (Authorise Request Process Code — online approved)
 *   0x04 = NASP (No Application SDI Parameter — declined)
 *
 * @param resp     GENERATE AC response APDU data (without SW)
 * @param resp_len Response length
 * @return outcome code
 */
outcome_code_t k5_parse_generate_ac_response(const uint8_t *resp, uint8_t resp_len)
{
    if (!resp || resp_len < 2) return OUTCOME_ERROR;

    /* Parse TLV manually to find CID [9F27] in the GENERATE AC response.
     * tlv_parse_raw() into a temp warehouse, then tlv_find(). */
    tx_warehouse_t resp_wh;
    uint8_t resp_pool[256];
    tlv_warehouse_init(&resp_wh, resp_pool, sizeof(resp_pool));
    tlv_parse_raw(&resp_wh, resp, resp_len);

    const tlv_entry_t *cid = tlv_find(&resp_wh, 0x9F27);
    if (cid && cid->len >= 1) {
        uint8_t cid_val = cid->value[0];
        switch (cid_val) {
        case 0x08:  /* TC */
            return OUTCOME_APPROVE_TERMINAL_CONDS;
        case 0x0A:  /* ARQC */
            return OUTCOME_APPROVE_ISSUER_AUTH;
        case 0x0C:  /* ARPC */
            return OUTCOME_APPROVE_ISSUER_AUTH;
        case 0x04:  /* NASP */
            return OUTCOME_DECLINE;
        default:
            return OUTCOME_ERROR;
        }
    }

    /* Fallback: check ARQC [9F26] presence */
    const tlv_entry_t *arqc = tlv_find(&resp_wh, 0x9F26);
    if (arqc) {
        return OUTCOME_APPROVE_ISSUER_AUTH;
    }

    return OUTCOME_ERROR;
}
