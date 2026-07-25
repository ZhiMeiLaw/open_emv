/**
 * @file examples/ref_k3/kernel3_cvm.c
 * @brief Kernel 3 reference CVM plugin implementation.
 *
 * K3 CVM strategy (Book C §4.6):
 *   1. If amount <= unsigned_limit → No-CVM (skip verification)
 *   2. If unsigned_limit < amount <= signed_limit → Offline PIN required
 *   3. If amount > signed_limit → Requires online auth (ARQC, skip CVM)
 */

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/platform.h"

/* Forward declaration of integrator-provided POS params structure */
typedef struct {
    uint32_t unsigned_limit;      /* Amount below which no CVM is needed     */
    uint32_t signed_limit;        /* Amount above which online auth required */
    uint8_t  pin_key_index;       /* Key index for offline PIN encryption     */
} pos_params_k3_t;

/* Helper: extract 6-byte BCD amount from warehouse */
static uint32_t get_amount(const tx_warehouse_t *wh)
{
    const tlv_entry_t *e = tlv_find(wh, 0x9F02);
    if (!e || e->len != 6) return 0;
    return bcd_6byte_to_uint(e->value);
}

/* ---- evaluate: determine CVM method and execute ---- */
static cvm_result_t kernel3_cvm_evaluate(const void *ctx_ptr)
{
    const orchestrator_ctx_t *oc = (const orchestrator_ctx_t *)ctx_ptr;
    const pos_params_k3_t *pp = (const pos_params_k3_t *)oc->pos_params;
    if (!pp) return CVM_NOT_SUPPORTED;

    uint32_t amount = get_amount(&oc->input_wh);

    /* Case 1: Small amount — No CVM required */
    if (amount <= pp->unsigned_limit) {
        return CVM_PASS;
    }

    /* Case 2: Above unsigned but within signed limit — Offline PIN */
    if (amount <= pp->signed_limit) {
        /* Prompt cardholder for PIN */
        extern ui_driver_t *g_ui_driver;
        if (g_ui_driver && g_ui_driver->prompt_pin) {
            const tlv_entry_t *pan_entry = tlv_find(&oc->input_wh, 0x5A);
            if (pan_entry) {
                uint8_t pin_block[16];
                uint16_t pin_len = sizeof(pin_block);

                int rc = g_ui_driver->prompt_pin(
                    pan_entry->value, (uint16_t)pan_entry->len,
                    pin_block, &pin_len, pp->pin_key_index
                );
                if (rc == 0) {
                    /* PIN entered successfully — store in warehouse for card verification */
                    tlv_store_set((tx_warehouse_t *)&oc->input_wh,  /* cast: input_wh field is mutable */
                                  0x9F3A, pin_block, pin_len);
                    return CVM_PASS;
                } else if (rc == -2) {
                    return CVM_FAIL;  /* Wrong PIN */
                }
            }
        }
        return CVM_FAIL;  /* PIN prompt failed or not available */
    }

    /* Case 3: Large amount — requires online auth (skip CVM) */
    return CVM_PASS;
}

/* ---- get_method: return CVM method code per EMV table ---- */
static uint8_t kernel3_cvm_get_method(const void *ctx_ptr)
{
    (void)ctx_ptr;
    const orchestrator_ctx_t *oc = (const orchestrator_ctx_t *)ctx_ptr;
    uint32_t amount = get_amount(&oc->input_wh);
    const pos_params_k3_t *pp = (const pos_params_k3_t *)oc->pos_params;
    if (!pp) return 0xFF;

    if (amount <= pp->unsigned_limit) {
        return 0x00;  /* No CVM */
    }
    if (amount <= pp->signed_limit) {
        return 0x02;  /* Encrypted PIN */
    }
    return 0x00;  /* Online auth — no CVM needed */
}

struct cvm_plugin_s kernel3_cvm_plugin = {
    .evaluate  = kernel3_cvm_evaluate,
    .get_method = kernel3_cvm_get_method,
    .version   = 1,
};
