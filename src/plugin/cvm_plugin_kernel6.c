/**
 * @file src/plugin/cvm_plugin_kernel6.c
 * @brief Kernel 6 (eMvCash) reference CVM plugin per Book C-6.
 *
 * K6 has no cardholder verification:
 *   - No PIN required
 *   - No signature required
 *   - Always passes CVM check
 *   - CVM Results tag [9F34] is always 0x1F 0x00 0x00 (No CVM)
 *
 * Book C-6 Section 4.4: "The terminal shall not perform any CVM."
 */

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/orchestrator.h"

static int build_cvm_results(tx_warehouse_t *wh)
{
    if (!wh) return WH_E_INVAL;
    /* No CVM: method=0x1F, reserved=0x00, result=0x00 */
    uint8_t data[3] = { 0x1F, 0x00, 0x00 };
    return tlv_store_set(wh, 0x9F34, data, sizeof(data));
}

static cvm_result_t kernel6_cvm_evaluate(const void *ctx_ptr)
{
    (void)ctx_ptr;
    /* K6: No CVM required - always pass */
    return CVM_PASS;
}

static uint8_t kernel6_cvm_get_method(const void *ctx_ptr)
{
    (void)ctx_ptr;
    return 0x1F;  /* No CVM */
}

struct cvm_plugin_s kernel6_cvm_plugin = {
    .evaluate   = kernel6_cvm_evaluate,
    .get_method = kernel6_cvm_get_method,
    .version    = 1,
};
