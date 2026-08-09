/**
 * @file examples/ref_k6/k6_ref_transaction.c
 * @brief Kernel 6 reference: end-to-end transaction per Book C-6.
 *
 * Complete K6 flow:
 *   1. Application initialization (GPO)
 *   2. Read application data (AFL)
 *   3. Card Read Complete (mandatory tag check)
 *   4. Processing Restrictions (expiry check)
 *   5. Offline Data Auth (skipped for K6)
 *   6. CVM (No CVM for K6)
 *   7. GENERATE AC (with IAC/TAC thresholds)
 *   8. Outcome determination
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
#include "emv_kernel/dict_validate.h"
#include "emv_kernel/platform.h"

#include <string.h>

/* Forward declarations from sibling files */
extern const crypto_driver_t ref_crypto_driver_k6;
extern struct cvm_plugin_s kernel6_cvm_plugin;
extern struct risk_plugin_s kernel6_risk_plugin;
extern kernel_dict_t kernel6_dict;

/* POS parameters for K6 */
typedef struct {
    uint32_t unsigned_limit;
    uint32_t signed_limit;
} pos_params_k6_t;

extern void pos_params_init_defaults_k6(void);
extern const pos_params_k6_t *pos_params_get_k6(void);

/* ================================================================== */
/*  STEP 1: Application startup                                       */
/* ================================================================== */

static void k6_init(void)
{
    kernel6_dict.cvm_plugin = &kernel6_cvm_plugin;
    kernel6_dict.risk_plugin = &kernel6_risk_plugin;
    kernel_register((const kernel_config_t *)&kernel6_dict);
    platform_register_crypto(&ref_crypto_driver_k6);
    pos_params_init_defaults_k6();
}

/* ================================================================== */
/*  Main Transaction Execution                                        */
/* ================================================================== */

int k6_execute_transaction(const struct ic_reader_provider_s *icr,
                           const pos_params_k6_t *pos_params,
                           uint8_t *tc_out, uint16_t *tc_len,
                           outcome_code_t *outcome)
{
    if (!icr || !tc_len || !outcome) return EP_E_INVAL;

    k6_init();

    ep_context_t ep_ctx;
    memset(&ep_ctx, 0, sizeof(ep_ctx));
    ep_ctx.ic_reader = icr;
    ep_ctx.pos_params = pos_params;

    /* Run full entry point + kernel flow */
    int rc = entry_point_execute(&ep_ctx);
    if (rc != EP_E_OK) {
        *outcome = OUTCOME_ERROR;
        return rc;
    }

    /* Copy outcome data */
    if (tc_out && tc_len && ep_ctx.wh.count > 0) {
        int written = tlv_dump_raw(&ep_ctx.wh, tc_out, *tc_len);
        if (written > 0) *tc_len = (uint16_t)written;
    }

    *outcome = ep_ctx.outcome;
    return EMV_E_OK;
}
