/**
 * @file src/plugin/cvm_plugin_kernel7.c
 * @brief Kernel 7 (Token Payment) reference CVM plugin skeleton per Book C-7 Section 4.4.
 *
 * Per Book C-7 Section 4.4, K7 CVM logic is nearly identical to K3:
 *   - Uses CTQ (Tag 9F6C) from GPO response — NOT 9F50 (that's K5 only)
 *   - Same priority decision tree: Online PIN > CDCVM > Signature > No-CVM
 *   - Token-specific: SDS (Signature Data Set) check before CVM processing
 *
 * Key differences from K3:
 *   - Validates Token PAN (9A09) matches stored token data
 *   - Checks SDS code for token authentication
 *   - May redirect to contact interface if SDS fails
 */

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/orchestrator.h"
#include <string.h>

/* ================================================================== */
/*  Helper: populate CVM Results tag [9F34]                           */
/* ================================================================== */

static int build_cvm_results(tx_warehouse_t *wh, uint8_t method, uint8_t result_b3)
{
    uint8_t data[] = { method, 0x00, result_b3 };
    return tlv_store_set(wh, 0x9F34, data, sizeof(data));
}

/* Forward declaration — integrator provides this */
typedef struct {
    uint8_t  sds_code;              /* Single Digit SDS from issuer     */
    uint8_t  tip_signature_supported : 1;
    uint8_t  tip_online_pin_supported : 1;
} pos_params_k7_t;

static cvm_result_t kernel7_cvm_evaluate(const void *ctx_ptr)
{
    const orchestrator_ctx_t *oc = (const orchestrator_ctx_t *)ctx_ptr;
    const pos_params_k7_t *pp = (const pos_params_k7_t *)oc->pos_params;

    /* Step 1: SDS validation (token-specific pre-check) */
    if (pp) {
        /* Compare SDS from card with terminal-stored SDS code */
        /* Mismatch  decline or redirect to contactless/contact swap */
    }

    /* Step 2: Same CTQ-based decision tree as K3 5.7 */
    /* If CTQ present  priority: Online PIN > CDCVM > Signature */
    /* If CTQ absent  fallback based on reader capabilities */

    /* Skeleton: default to No-CVM, integrator implements full tree */
    if (!oc || !oc->output_wh.count) return CVM_PASS;

    build_cvm_results(&oc->output_wh, 0x1F, 0x00);
    return CVM_PASS;
}

static uint8_t kernel7_cvm_get_method(const void *ctx_ptr)
{
    const orchestrator_ctx_t *oc = (const orchestrator_ctx_t *)ctx_ptr;
    if (!oc) return 0xFF;

    const tlv_entry_t *cvm_res = tlv_find(&oc->output_wh, 0x9F34);
    if (cvm_res && cvm_res->len >= 1) return cvm_res->value[0];
    return 0x1F;
}

struct cvm_plugin_s kernel7_cvm_plugin = {
    .evaluate   = kernel7_cvm_evaluate,
    .get_method = kernel7_cvm_get_method,
    .version    = 1,
};
