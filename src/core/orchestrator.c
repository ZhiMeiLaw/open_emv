/**
 * @file src/core/orchestrator.c
 * @brief Kernel execution orchestrator — generic transaction flow.
 */

#include "emv_kernel/orchestrator.h"
#include "emv_kernel/dict_validate.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/kernel_registry.h"
#include "emv_kernel/errors.h"
#include "emv_kernel/platform.h"
#include <string.h>

/* ---- Card hash helper ------------------------------------------------ */
/**
 * Derive an 8-byte card identifier from the transaction warehouse.
 * Uses PAN (tag 0x5A) as primary source; falls back to AID (tag 0x4F).
 * Result is an XOR-fold of the source bytes into 8 bytes.
 */
void orchestrator_compute_card_hash(const tx_warehouse_t *wh, uint8_t *out_hash)
{
    if (!wh || !out_hash) return;

    const tlv_entry_t *pan = tlv_find(wh, 0x5A);
    const tlv_entry_t *src = (pan && pan->len >= 8) ? pan :
                             ((pan && pan->len > 0) ? pan :
                              tlv_find(wh, 0x4F));  /* fall back to AID */

    if (!src || src->len == 0) {
        memset(out_hash, 0, 8);
        return;
    }

    memset(out_hash, 0, 8);
    for (uint16_t i = 0; i < src->len; i++) {
        out_hash[i % 8] ^= src->value[i];
    }
}

static orchestrator_ctx_t g_oc;
static outcome_result_t g_last_outcome;

/* ---- 5.1  Generic orchestration loop --------------------------------- */

int orchestrator_init(orchestrator_ctx_t *oc,
                      const crypto_driver_t *crypto,
                      const term_acq_interface_t *acq_iface,
                      const void *pos_params)
{
    if (!oc) return ORCH_E_INVAL;

    memset(oc, 0, sizeof(*oc));
    oc->crypto = crypto;
    oc->acq_iface = acq_iface;
    oc->pos_params = pos_params;
    oc->auth_method = AUTH_NONE;

    static uint8_t pool_in[MAX_POOL_SIZE];
    static uint8_t pool_out[MAX_POOL_SIZE];

    tlv_warehouse_init(&oc->input_wh, pool_in, sizeof(pool_in));
    tlv_warehouse_init(&oc->output_wh, pool_out, sizeof(pool_out));

    memcpy(&g_last_outcome, &oc->result, sizeof(outcome_result_t));

    return EMV_E_OK;
}

int orchestrator_execute(uint8_t kernel_id)
{
    const kernel_config_t *cfg = kernel_lookup(kernel_id);
    if (!cfg) {
        g_oc.last_error = (int)ORCH_E_NO_CONFIG;
        g_last_outcome.code = OUTCOME_ERROR;
        return ORCH_E_NO_CONFIG;
    }
    g_oc.kernel_cfg = cfg;

    const kernel_dict_t *dict = (const kernel_dict_t *)cfg;
    int rc = tlv_validate_dict(dict, &g_oc.input_wh);
    if (rc != DICT_E_OK) {
        g_oc.last_error = -2;
        g_last_outcome.code = OUTCOME_DECLINE;
        return ORCH_E_DICT_FAIL;
    }

    cvm_result_t cvm_res = CVM_PASS;
    if (cfg->cvm_plugin && cfg->cvm_plugin->evaluate) {
        cvm_res = cfg->cvm_plugin->evaluate(&g_oc);
    }
    g_oc.cvm_method_used = cfg->cvm_plugin ? cfg->cvm_plugin->get_method(&g_oc) : 0xFF;

    if (cvm_res == CVM_FAIL) {
        g_last_outcome.code = OUTCOME_DECLINE;
        return ORCH_E_CVM_FAIL;
    }

    risk_result_t risk_res = RISK_PASS;
    if (cfg->risk_plugin && cfg->risk_plugin->check) {
        risk_res = cfg->risk_plugin->check(&g_oc, RISK_CHECK_TRM);
        if (risk_res == RISK_FAIL) {
            g_last_outcome.code = OUTCOME_DECLINE;
            return ORCH_E_RISK_FAIL;
        }
    }

    if (g_oc.crypto && g_oc.crypto->generate_cryptogram) {
        uint8_t cryptogram[16];
        size_t crypt_len = sizeof(cryptogram);
        rc = g_oc.crypto->generate_cryptogram(
            CRYPTO_DES, NULL, 0, 0, NULL, 0, cryptogram, &crypt_len
        );
        if (rc == 0) {
            tlv_store_set(&g_oc.output_wh, 0x9F26, cryptogram, (uint16_t)crypt_len);
        }
    }

    if (risk_res == RISK_PASS && cvm_res == CVM_PASS) {
        g_last_outcome.code = OUTCOME_APPROVE_TERMINAL_CONDS;
    } else {
        g_last_outcome.code = OUTCOME_DECLINE;
    }

    /* Update ICCDB counters on approval */
    if (g_last_outcome.code == OUTCOME_APPROVE_TERMINAL_CONDS ||
        g_last_outcome.code == OUTCOME_APPROVE_ISSUER_AUTH) {
        /* Populate TC risk data (TVR, Terminal Qualifiers, etc.) */
        if (cfg->risk_plugin && cfg->risk_plugin->build_tc_risk_data) {
            cfg->risk_plugin->build_tc_risk_data(&g_oc, &g_oc.output_wh);
        }
        /* Increment card state counters */
        if (cfg->risk_plugin && cfg->risk_plugin->update_iccdb && g_oc.iccdb) {
            cfg->risk_plugin->update_iccdb(g_oc.iccdb, &g_oc);
        }
    }

    memcpy(&g_oc.result, &g_last_outcome, sizeof(outcome_result_t));

    return EMV_E_OK;
}

/* ---- 5.3  Terminal Conduction (TC) building --------------------------- */

int orchestrator_build_tc(uint8_t *tc_bytes, uint8_t *tc_len, uint8_t max_len)
{
    if (!tc_bytes || !tc_len) return ORCH_E_INVAL;

    int written = tlv_dump_ordered(&g_oc.output_wh, NULL, 0, tc_bytes, max_len);
    if (written <= 0) return ORCH_E_INVAL;

    *tc_len = (uint8_t)written;
    return EMV_E_OK;
}

/* ---- NASP ------------------------------------------------------------- */

int orchestrator_build_nasp(uint8_t *nasp_bytes, uint8_t *nasp_len, uint8_t max_len)
{
    if (!nasp_bytes || !nasp_len) return ORCH_E_INVAL;

    uint8_t nasp[] = {
        0x9F, 0x2B,
        0x02,
        0x00, 0x00
    };

    if (sizeof(nasp) > max_len) return ORCH_E_INVAL;
    memcpy(nasp_bytes, nasp, sizeof(nasp));
    *nasp_len = (uint8_t)sizeof(nasp);
    return EMV_E_OK;
}

/* ---- Getter ----------------------------------------------------------- */

const outcome_result_t *orchestrator_get_outcome(void)
{
    return &g_last_outcome;
}
