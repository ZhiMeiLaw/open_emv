/**
 * @file examples/ref_k5/kernel5_cvm.c
 * @brief Kernel 5 (qVISA) reference CVM plugin.
 *
 * K5 CVM strategy (Book C §4.7):
 *   - Amount-only check: if amount ≤ unsigned_amount_limit → Crypto CVM
 *   - No PIN support — transactions above limit must be declined or retried
 *   - Generates Card Authentication Code (CAC) instead of full ARQC
 */

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/kernel_interface.h"

typedef struct {
    uint32_t unsigned_amount_limit;  /* Max amount for Crypto CVM        */
    uint8_t  key_index;              /* Key index for CAC generation      */
} pos_params_k5_t;

static uint32_t get_amount(const tx_warehouse_t *wh)
{
    const tlv_entry_t *e = tlv_find(wh, 0x9F02);
    if (!e || e->len != 6) return 0;
    return bcd_6byte_to_uint(e->value);
}

static cvm_result_t kernel5_cvm_evaluate(const void *ctx_ptr)
{
    const orchestrator_ctx_t *oc = (const orchestrator_ctx_t *)ctx_ptr;
    const pos_params_k5_t *pp = (const pos_params_k5_t *)oc->pos_params;
    if (!pp) return CVM_NOT_SUPPORTED;

    uint32_t amount = get_amount(&oc->input_wh);

    /* K5: Simple amount check against unsigned limit */
    if (amount <= pp->unsigned_amount_limit) {
        return CVM_PASS;  /* Crypto CVM — generate CAC */
    }

    /* Above limit — no PIN fallback in K5, must decline */
    return CVM_FAIL;
}

static uint8_t kernel5_cvm_get_method(const void *ctx_ptr)
{
    (void)ctx_ptr;
    /* K5 always uses Crypto CVM (EMV CVM method code not defined in
       standard table — returned as implementation-defined) */
    return 0xFF;  /* Implementation-specific CVM for qVISA crypto */
}

struct cvm_plugin_s kernel5_cvm_plugin = {
    .evaluate  = kernel5_cvm_evaluate,
    .get_method = kernel5_cvm_get_method,
    .version   = 1,
};
