/**
 * @file examples/ref_k3/kernel3_process.c
 * @brief Kernel 3 reference implementation — wires together config, CVM, and risk.
 *
 * This is the "glue" file that integrators would adapt. It:
 *   1. Initializes the K3 kernel config with its dictionary, CVM plugin, and risk plugin
 *   2. Registers it with the kernel registry
 *   3. Provides a single entry point to execute a K3 transaction
 */

#include "emv_kernel/types.h"
#include "emv_kernel/kernel_registry.h"
#include "emv_kernel/orchestrator.h"
#include "emv_kernel/kernel_interface.h"

/* Forward declarations from sibling files */
extern struct cvm_plugin_s kernel3_cvm_plugin;
extern struct risk_plugin_s kernel3_risk_plugin;
extern kernel_dict_t kernel3_dict;
extern const kernel_config_t *kernel3_get_config(void);

/* ================================================================== */
/*  Initialize and register K3                                        */
/* ================================================================== */

/**
 * Register Kernel 3 with the dispatch table.
 * Call once at application startup before any transactions.
 */
void kernel3_init(void)
{
    /* Wire plugins into the dictionary */
    kernel3_dict.cvm_plugin = &kernel3_cvm_plugin;
    kernel3_dict.risk_plugin = &kernel3_risk_plugin;

    /* Register with global kernel dispatch table */
    const kernel_config_t *cfg = kernel3_get_config();
    kernel_register(cfg);
}

/* ================================================================== */
/*  Execute a complete K3 transaction                                 */
/* ================================================================== */

/**
 * Run a Kernel 3 transaction end-to-end.
 * The integrator must:
 *   1. Call kernel3_init() at startup
 *   2. Call platform_register_crypto() with their crypto driver
 *   3. Configure POS params via param_write() or a dedicated function
 *   4. Provide an IC Reader Provider (set on ep_context.icr)
 */
int kernel3_execute_transaction(ep_context_t *ep_ctx,
                                pos_params_k3_t *pos_params,
                                outcome_result_t *outcome_out)
{
    /* Step 1: Run entry point flow (select, auth, GPO) */
    int rc = entry_point_run(ep_ctx, pos_params);
    if (rc != 0) return rc;

    /* Step 2: Initialize orchestrator */
    const crypto_driver_t *crypto = platform_get_crypto();
    orchestrator_ctx_t oc;
    rc = orchestrator_init(&oc, crypto, NULL, pos_params);
    if (rc != 0) return -1;

    /* Step 3: Execute K3 */
    rc = orchestrator_execute(3);  /* kernel_id = 3 */
    if (rc != 0) return rc;

    /* Step 4: Get outcome */
    const outcome_result_t *result = orchestrator_get_outcome();
    if (outcome_out && result) {
        memcpy(outcome_out, result, sizeof(outcome_result_t));
    }

    return 0;
}
