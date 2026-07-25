/**
 * @file emv_kernel/orchestrator.h
 * @brief Kernel execution orchestrator — generic flow skeleton.
 *
 * Ties together the entry point result, kernel dictionary, plugins,
 * and crypto to produce a transaction outcome.
 */

#ifndef EMV_KERNEL_ORCHESTRATOR_H
#define EMV_KERNEL_ORCHESTRATOR_H

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/kernel_interface.h"

/* ---- Outcome details per Book A §6.2 ---- */
typedef struct {
    outcome_code_t code;          /* APPROVE_ISSUER / APPROVE_TERMINAL / DECLINE / RESTART / ERROR */

    /* Terminal Verification Results (TVR) — 5 bytes */
    uint8_t tvr[5];

    /* Terminal Action Codes — TAR1 / TAR2 */
    uint8_t tar1;
    uint8_t tar2;

    /* Transaction parameters */
    uint8_t amount_authorised[6];      /* 9F02 */
    uint8_t currency_code[2];          /* 5F2A */
    uint16_t acquirer_country_code;     /* 0x9F67 */
    uint8_t terminal_qualifiers[4];    /* 9F66 */

    /* Additional data */
    uint8_t app_label[32];
    uint8_t app_label_len;
} outcome_result_t;

/* ================================================================== */
/*  Orchestrator Context                                              */
/* ================================================================== */

typedef struct {
    /* Transaction-level warehouse (input data from card + terminal) */
    tx_warehouse_t input_wh;

    /* Output warehouse for TC/NASP construction */
    tx_warehouse_t output_wh;

    /* POS parameters (integrator-provided, pre-loaded before run) */
    const void *pos_params;

    /* ICCDB state (caller-owned, passed by pointer) */
    void *iccdb;

    /* Kernel config (resolved by kernel_id lookup) */
    const kernel_config_t *kernel_cfg;

    /* Auth state (set by entry point handler) */
    auth_method_t auth_method;
    uint8_t has_verified_sda : 1;
    uint8_t has_verified_oda : 1;
    uint8_t ica_sym_key[16];
    uint8_t ica_sym_key_len;

    /* Plugin handles (registered via platform_init) */
    const crypto_driver_t *crypto;
    const term_acq_interface_t *acq_iface;

    /* Final outcome */
    outcome_result_t result;

    /* CVM result (for TVR building) */
    uint8_t cvm_method_used;

    /* Error tracking */
    int last_error;
} orchestrator_ctx_t;

/* ================================================================== */
/*  Public API                                                        */
/* ================================================================== */

/**
 * Initialize the orchestrator with platform drivers and POS params.
 * @return 0 on success.
 */
int orchestrator_init(orchestrator_ctx_t *oc,
                      const crypto_driver_t *crypto,
                      const term_acq_interface_t *acq_iface,
                      const void *pos_params);

/**
 * Execute a kernel transaction from start to outcome determination.
 * This is the main entry point after the entry_point_run() has completed.
 * @param kernel_id   The kernel to execute (3, 5, 7, ...)
 * @return 0 on success, negative error code on failure.
 */
int orchestrator_execute(uint8_t kernel_id);

/**
 * Get the final outcome result after orchestrator_execute().
 */
const outcome_result_t *orchestrator_get_outcome(void);

/**
 * Build Terminal Conduction Data (TC) for an approved transaction.
 * Writes BER-TLV bytes ready to send to card.
 */
int orchestrator_build_tc(uint8_t *tc_bytes, uint8_t *tc_len, uint8_t max_len);

/**
 * Build No Application SDI Parameter (NASP) for a declined transaction.
 */
int orchestrator_build_nasp(uint8_t *nasp_bytes, uint8_t *nasp_len, uint8_t max_len);

#endif /* EMV_KERNEL_ORCHESTRATOR_H */
