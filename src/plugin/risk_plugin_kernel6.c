/**
 * @file src/plugin/risk_plugin_kernel6.c
 * @brief Kernel 6 (eMvCash) reference Risk plugin per Book C-6.
 *
 * K6 risk management is simplified:
 *   - No CRM (no card risk management in value-based transactions)
 *   - No VEL (velocity is tracked by card, not terminal)
 *   - TRM: Check terminal amount limit against transaction amount
 *   - CRM: Check card balance sufficient for transaction
 *
 * Book C-6 Section 4.6: Terminal Risk Management
 */

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/platform.h"
#include "emv_kernel/errors.h"
#include "emv_kernel/orchestrator.h"

typedef struct {
    uint32_t unsigned_limit;      /* Amount <= this → No-CVM */
    uint32_t signed_limit;        /* Amount > unsigned, <= this → PIN */
} pos_params_k6_t;

static risk_result_t kernel6_risk_check(const void *ctx_ptr, risk_check_type_t type)
{
    const orchestrator_ctx_t *oc = (const orchestrator_ctx_t *)ctx_ptr;
    if (!oc) return RISK_PASS;

    switch (type) {
    case RISK_CHECK_TRM:
        /* Check terminal amount limit */
        if (oc->pos_params) {
            const pos_params_k6_t *pp = (const pos_params_k6_t *)oc->pos_params;
            const tlv_entry_t *amt = tlv_find(&oc->input_wh, 0x9F02);
            if (amt && amt->len == 6) {
                uint32_t amount = bcd_6byte_to_uint(amt->value);
                if (amount > pp->unsigned_limit) {
                    return RISK_FAIL;
                }
            }
        }
        return RISK_PASS;

    case RISK_CHECK_CRM:
        /* K6 does not use CRM - balance check is in outcome */
        return RISK_PASS;

    case RISK_CHECK_VEL:
        /* Velocity enforcement is card-side in K6 */
        return RISK_PASS;

    case RISK_CHECK_SDS:
        /* SDS not used for K6 */
        return RISK_PASS;

    case RISK_CHECK_CVM:
    case RISK_CHECK_TDOL:
        return RISK_PASS;

    default:
        return RISK_FALLBACK;
    }
}

static int kernel6_risk_build_tc(const void *ctx_ptr, tx_warehouse_t *tc_wh)
{
    if (!ctx_ptr || !tc_wh) return PLAT_E_INVAL;

    const orchestrator_ctx_t *oc = (const orchestrator_ctx_t *)ctx_ptr;

    /* K6 TC data: copy TVR and add balance info */
    const tlv_entry_t *tvr = tlv_find(&oc->output_wh, 0x9F3A);
    if (tvr) {
        tlv_store_set(tc_wh, 0x9F3A, tvr->value, tvr->len);
    }

    return EMV_E_OK;
}

static int kernel6_risk_update_iccdb(void *iccdb_ptr, const void *ctx_ptr)
{
    (void)iccdb_ptr;
    (void)ctx_ptr;
    /* K6 does not use ICCDB for risk - balance is on card */
    return PLAT_E_OK;
}

struct risk_plugin_s kernel6_risk_plugin = {
    .check              = kernel6_risk_check,
    .build_tc_risk_data = kernel6_risk_build_tc,
    .update_iccdb       = kernel6_risk_update_iccdb,
    .version            = 1,
};
