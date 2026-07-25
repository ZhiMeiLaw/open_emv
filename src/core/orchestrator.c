/**
 * @file src/core/orchestrator.c
 * @brief Kernel execution orchestrator — generic transaction flow.
 *
 * After the entry point handler has selected an application and completed
 * card authentication, the orchestrator runs the kernel-specific logic:
 * dictionary validation → CVM → Risk → Cryptogram → Outcome → TC/NASP.
 */

#include "emv_kernel/orchestrator.h"
#include "emv_kernel/dict_validate.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/kernel_registry.h"
#include <string.h>

/* Global orchestrator state (single transaction at a time) */
static orchestrator_ctx_t g_oc;
static outcome_result_t g_last_outcome;

/* ================================================================== */
/*  5.1  Generic orchestration loop                                    */
/* ================================================================== */

int orchestrator_init(orchestrator_ctx_t *oc,
                      const crypto_driver_t *crypto,
                      const term_acq_interface_t *acq_iface,
                      const void *pos_params)
{
    if (!oc) return -1;

    memset(oc, 0, sizeof(*oc));
    oc->crypto = crypto;
    oc->acq_iface = acq_iface;
    oc->pos_params = pos_params;
    oc->auth_method = AUTH_NONE;

    /* Initialize both warehouses with caller-managed memory */
    /* Caller should provide pool pointers; use static fallback for now */
    static uint8_t pool_in[MAX_POOL_SIZE];
    static uint8_t pool_out[MAX_POOL_SIZE];

    tlv_warehouse_init(&oc->input_wh, pool_in, sizeof(pool_in));
    tlv_warehouse_init(&oc->output_wh, pool_out, sizeof(pool_out));

    /* Copy last known outcome if available */
    memcpy(&g_last_outcome, &oc->result, sizeof(outcome_result_t));

    return 0;
}

int orchestrator_execute(uint8_t kernel_id)
{
    /* Resolve kernel config */
    const kernel_config_t *cfg = kernel_lookup(kernel_id);
    if (!cfg) {
        g_oc.last_error = -1;
        g_last_outcome.code = OUTCOME_ERROR;
        return -1;
    }
    g_oc.kernel_cfg = cfg;

    /* Validate mandatory tags via dictionary */
    const kernel_dict_t *dict = (const kernel_dict_t *)cfg;
    int rc = tlv_validate_dict(dict, &g_oc.input_wh);
    if (rc != 0) {
        g_oc.last_error = -2;
        g_last_outcome.code = OUTCOME_DECLINE;
        return -2;
    }

    /* Run CVM plugin */
    cvm_result_t cvm_res = CVM_PASS;
    if (cfg->cvm_plugin && cfg->cvm_plugin->evaluate) {
        cvm_res = cfg->cvm_plugin->evaluate(&g_oc);
    }
    g_oc.cvm_method_used = cfg->cvm_plugin ? cfg->cvm_plugin->get_method(&g_oc) : 0xFF;

    if (cvm_res == CVM_FAIL) {
        g_last_outcome.code = OUTCOME_DECLINE;
        return -3;
    }

    /* Run Risk plugin */
    risk_result_t risk_res = RISK_PASS;
    if (cfg->risk_plugin && cfg->risk_plugin->check) {
        risk_res = cfg->risk_plugin->check(&g_oc, RISK_CHECK_TRM);
        if (risk_res == RISK_FAIL) {
            g_last_outcome.code = OUTCOME_DECLINE;
            return -4;
        }
    }

    /* Generate cryptogram (ARQC / CAC) */
    if (g_oc.crypto && g_oc.crypto->generate_cryptogram) {
        uint8_t cryptogram[16];
        size_t crypt_len = sizeof(cryptogram);
        rc = g_oc.crypto->generate_cryptogram(
            CRYPTO_DES, NULL, 0, 0,   /* key info from context */
            NULL, 0,                   /* DOL data from warehouse */
            cryptogram, &crypt_len
        );
        if (rc == 0) {
            tlv_store_set(&g_oc.output_wh, 0x9F26, cryptogram, (uint16_t)crypt_len);
        }
    }

    /* Determine outcome */
    if (risk_res == RISK_PASS && cvm_res == CVM_PASS) {
        g_last_outcome.code = OUTCOME_APPROVE_TERMINAL_CONDS;
    } else {
        g_last_outcome.code = OUTCOME_DECLINE;
    }

    /* Save final result */
    memcpy(&g_oc.result, &g_last_outcome, sizeof(outcome_result_t));

    return 0;
}

/* ================================================================== */
/*  5.2  Outcome determination                                         */
/* ================================================================== */

/* Outcome codes mapping per Book A §6.2 table 6.1 */
static outcome_code_t determine_outcome(risk_result_t risk, cvm_result_t cvm)
{
    if (risk == RISK_FAIL || cvm == CVM_FAIL) {
        return OUTCOME_DECLINE;
    }
    if (risk == RISK_FALLBACK) {
        return cvm == CVM_PASS ? OUTCOME_APPROVE_TERMINAL_CONDS : OUTCOME_RESTART;
    }
    return OUTCOME_APPROVE_TERMINAL_CONDS;
}

/* ================================================================== */
/*  5.3  Terminal Conduction (TC) building                             */
/* ================================================================== */

int orchestrator_build_tc(uint8_t *tc_bytes, uint8_t *tc_len, uint8_t max_len)
{
    if (!tc_bytes || !tc_len) return -1;

    /* Build TC TLV using validated risk data + outcome parameters */
    /* Tags typically included in TC:
     *   9F27 — Cryptogram (ARQC)
     *   8A    — Authorization Response Code
     *   9F10  — Issuer Application Data (IAD)
     *   5F2A  — Transaction Currency Code
     *   9F02  — Amount, Authorised
     *   9F1A  — Terminal Country Code
     *   9F36  — Amount, Other
     *   9F03  — Other Amount
     *   9F66  — Terminal Qualifiers (reflected)
     */

    int written = tlv_dump_ordered(&g_oc.output_wh, NULL, 0, tc_bytes, max_len);
    if (written <= 0) return -1;

    *tc_len = (uint8_t)written;
    return 0;
}

/* ================================================================== */
/*  NASP (No Application SDI Parameter)                                */
/* ================================================================== */

int orchestrator_build_nasp(uint8_t *nasp_bytes, uint8_t *nasp_len, uint8_t max_len)
{
    if (!nasp_bytes || !nasp_len) return -1;

    /* NASP is minimal: [9F2B] No Application SDI Parameter + [9F66] */
    /* For decline, just send the decline indicator back to card */
    uint8_t nasp[] = {
        0x9F, 0x2B,             /* Tag: NASP */
        0x02,                   /* Length */
        0x00, 0x00              /* NASP value (decline code) */
    };

    if (sizeof(nasp) > max_len) return -1;
    memcpy(nasp_bytes, nasp, sizeof(nasp));
    *nasp_len = (uint8_t)sizeof(nasp);
    return 0;
}

/* ================================================================== */
/*  5.4  ARPC path (placeholder)                                       */
/* ================================================================== */

/*
 * When outcome is APPROVE_ISSUER_AUTH:
 * 1. Format NASP with ARQC + transaction data
 * 2. Send to acquirer (external to kernel)
 * 3. Parse ARPC response:
 *    - Decrypt response with ACQ key
 *    - Extract terminal verification results
 *    - Determine final accept/reject decision
 */

/* ================================================================== */
/*  Getter                                                           */
/* ================================================================== */

const outcome_result_t *orchestrator_get_outcome(void)
{
    return &g_last_outcome;
}
