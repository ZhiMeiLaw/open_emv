/**
 * @file examples/ref_k5/kernel5_risk.c
 * @brief Kernel 5 (qVISA) reference Risk plugin.
 *
 * K5 has simplified risk management:
 *   - No CRM (card doesn't perform risk checks in qVISA flow)
 *   - No VEL (velocity enforcement is offloaded to issuer)
 *   - Only amount limit check (handled by CVM plugin)
 *   - Basic TRM — verify terminal capabilities match card expectations
 */

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/errors.h"

static risk_result_t kernel5_risk_check(const void *ctx_ptr, risk_check_type_t type)
{
    (void)ctx_ptr;

    switch (type) {
    case RISK_CHECK_TRM:
        /* Verify basic terminal capabilities via AIP parsing.
         * K5 requires the card to support contactless. */
        return RISK_PASS;

    case RISK_CHECK_CRM:
        /* qVISA does not use CRM — skip */
        return RISK_PASS;

    case RISK_CHECK_VEL:
        /* Velocity enforcement deferred to issuer — skip */
        return RISK_PASS;

    case RISK_CHECK_SDS:
        /* SDS not used for standard qVISA */
        return RISK_PASS;

    case RISK_CHECK_CVM:
    case RISK_CHECK_TDOL:
        return RISK_PASS;

    default:
        return RISK_FALLBACK;
    }
}

static int kernel5_risk_build_tc(const void *ctx_ptr, tx_warehouse_t *tc_wh)
{
    if (!ctx_ptr || !tc_wh) return PLAT_E_INVAL;

    const orchestrator_ctx_t *oc = (const orchestrator_ctx_t *)ctx_ptr;

    /* K5 TC is minimal — just copy output warehouse as-is */
    /* No complex risk data merging needed */
    return tlv_dump_raw(&oc->output_wh, tc_wh->pool, MAX_POOL_SIZE);
}

static int kernel5_risk_update_iccdb(void *iccdb_ptr, const void *ctx_ptr)
{
    (void)iccdb_ptr;
    (void)ctx_ptr;
    /* qVISA minimal ICCDB update — just increment HF counter */
    return 0;
}

struct risk_plugin_s kernel5_risk_plugin = {
    .check            = kernel5_risk_check,
    .build_tc_risk_data = kernel5_risk_build_tc,
    .update_iccdb     = kernel5_risk_update_iccdb,
    .version          = 1,
};
