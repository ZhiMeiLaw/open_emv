/**
 * @file src/plugin/risk_plugin_kernel5.c
 * @brief Kernel 5 (qVISA) reference Risk plugin.
 *
 * K5 has simplified risk management:
 *   - No CRM (card does not perform risk checks in qVISA flow)
 *   - No VEL (velocity enforcement is offloaded to issuer)
 *   - Only amount limit check (handled by CVM plugin)
 *   - Basic TRM — verify terminal capabilities match card expectations
 */

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/errors.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/platform.h"
#include "emv_kernel/orchestrator.h"

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
    if (!iccdb_ptr || !ctx_ptr) return PLAT_E_INVAL;

    const orchestrator_ctx_t *oc = (const orchestrator_ctx_t *)ctx_ptr;
    if (!oc || oc->input_wh.count == 0) return PLAT_E_INVAL;

    uint8_t card_hash[8];
    orchestrator_compute_card_hash(&oc->input_wh, card_hash);

    /* Increment HF counter (K5 minimal update — no CRM/VEL) */
    uint8_t hf[2] = {0};
    uint8_t hf_len = (uint8_t)sizeof(hf);
    iccdb_read(card_hash, ICCDB_FIELD_HF_COUNTER, hf, &hf_len);
    uint16_t new_val = ((uint16_t)hf[0] << 8) | hf[1];
    new_val++;
    hf[0] = (uint8_t)(new_val >> 8);
    hf[1] = (uint8_t)(new_val & 0xFF);
    iccdb_write(card_hash, ICCDB_FIELD_HF_COUNTER, hf, sizeof(hf));

    return PLAT_E_OK;
}

struct risk_plugin_s kernel5_risk_plugin = {
    .check            = kernel5_risk_check,
    .build_tc_risk_data = kernel5_risk_build_tc,
    .update_iccdb     = kernel5_risk_update_iccdb,
    .version          = 1,
};
