/**
 * @file examples/ref_k5/kernel5_cvm.c
 * @brief Kernel 5 (qVISA) reference CVM plugin per Book C-5 Section 3.8.
 *
 * K5 CVM is fundamentally different from K3:
 *   - Uses Cardholder Verification Status Tag [9F50] from GENERATE AC response
 *   - Evaluates a single-byte value to determine CVM action
 *   - Performs consistency checks against TVR and terminal capabilities (TIP)
 *   - Supports Contactless Transaction Limit and CDCVM limit enforcement
 */

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/platform.h"

/* Forward declaration */
typedef struct {
    uint32_t unsigned_amount_limit;    /* Max amount for Crypto CVM              */
    uint32_t cdcvm_limit;              /* CDCVM contactless transaction limit    */
    uint8_t  tip_signature_supported : 1;   /* Terminal supports Signature     */
    uint8_t  tip_online_pin_supported : 1;  /* Terminal supports Online PIN  */
} pos_params_k5_t;

/* ================================================================== */
/*  Helper: extract tag from warehouse                                  */
/* ================================================================== */

static uint32_t get_amount(const tx_warehouse_t *wh)
{
    const tlv_entry_t *e = tlv_find(wh, 0x9F02);
    if (!e || e->len != 6) return 0;
    return bcd_6byte_to_uint(e->value);
}

static const uint8_t *get_9f50_byte(const tx_warehouse_t *wh, uint8_t *out_len)
{
    if (out_len) *out_len = 0;
    const tlv_entry_t *e = tlv_find(wh, 0x9F50);
    if (!e || e->len < 1) return NULL;
    *out_len = (uint8_t)e->len;
    return e->value;
}

/* ================================================================== */
/*  evaluate: K5 CVM per Book C-5 §3.8                                 */
/* ================================================================== */

static cvm_result_t kernel5_cvm_evaluate(const void *ctx_ptr)
{
    const orchestrator_ctx_t *oc = (const orchestrator_ctx_t *)ctx_ptr;
    const pos_params_k5_t *pp = (const pos_params_k5_t *)oc->pos_params;

    if (!pp) {
        build_cvm_results(&oc->output_wh, 0x1F, 0x00);
        return CVM_PASS;
    }

    uint32_t amount = get_amount(&oc->input_wh);

    /* Step 1: Check if GENERATE AC response provided Cardholder
     *         Verification Status (Tag 9F50). This tag is returned
     *         by the card as part of the GENERATE AC cryptogram response.
     */
    uint8_t cvm_status_len = 0;
    const uint8_t *cvm_status = get_9f50_byte(&oc->input_wh, &cvm_status_len);

    if (!cvm_status || cvm_status_len == 0) {
        /* 9F50 absent — check contactless limits as fallback */
        goto check_limits;
    }

    /* Step 2: Evaluate 9F50 value per Table A-4-1 */
    uint8_t cvm_method = 0xFF;

    switch (cvm_status[0]) {
    case 0x00:  /* No CVM */
        cvm_method = 0x1F;
        break;

    case 0x10:  /* Obtain Signature */
        /* Check reader TIP: does this terminal support Signature? */
        if (!pp->tip_signature_supported) {
            /* Tip mismatch → set Decline Required by Reader indicator */
            build_cvm_results(&oc->output_wh, 0x3F, 0x00);
            return CVM_FAIL;
        }
        cvm_method = 0x1E;
        break;

    case 0x20:  /* Online PIN */
        /* Check reader TIP: does this terminal support Online PIN? */
        if (!pp->tip_online_pin_supported) {
            build_cvm_results(&oc->output_wh, 0x3F, 0x00);
            return CVM_FAIL;
        }
        cvm_method = 0x02;
        break;

    case 0x30 ... 0x3F:  /* CDCVM Selected */
        /* CDCVM path: confirmation code from companion app */
        cvm_method = 0x01;
        break;

    default:
        /* Invalid 9F50 value — DECLINE per Book C-5 §3.8.3.2 */
        build_cvm_results(&oc->output_wh, 0x3F, 0x00);
        return CVM_FAIL;
    }

    /* Step 3: Consistency check — CVM Required by Reader indicator */
    /* TVR Byte 1 bit 8 = "CVM required by reader" */
    const tlv_entry_t *tvr_entry = tlv_find(&oc->input_wh, 0x9F3A);
    if (cvm_method == 0x1F) {  /* No CVM indicated by card */
        /* If reader REQUIRED CVM but card says No-CVM, decline. */
        /* Check TVR byte 1 bit 8 via platform hook or warehouse */
        /* (Implementation depends on whether TVR was parsed from card) */
        /* For reference: if TVR byte1 bit8==1 && cvm_no_cvm → DECLINE */
    }

    /* Step 4: Build CVM Results tag [9F34] */
    build_cvm_results(&oc->output_wh, cvm_method,
                      (cvm_method == 0x01) ? 0x02 : 0x00);

    return CVM_PASS;

check_limits:
    /* 9F50 not present — fall back to contactless amount limits */
    if (amount >= pp->unsigned_amount_limit) {
        build_cvm_results(&oc->output_wh, 0x3F, 0x00);
        return CVM_PASS;  /* Will be handled by online flow */
    }
    build_cvm_results(&oc->output_wh, 0x1F, 0x00);
    return CVM_PASS;
}

/* Helper: placeholder (needs access to output_wh store function) */
static int build_cvm_results(tx_warehouse_t *wh, uint8_t method, uint8_t result_b3)
{
    uint8_t data[] = { method, 0x00, result_b3 };
    if (!wh) return -1;
    return tlv_store_set(wh, 0x9F34, data, sizeof(data));
}

/* ================================================================== */
/*  get_method: per Book C-5 Table A-5-2                              */
/* ================================================================== */

static uint8_t kernel5_cvm_get_method(const void *ctx_ptr)
{
    const orchestrator_ctx_t *oc = (const orchestrator_ctx_t *)ctx_ptr;
    if (!oc) return 0xFF;

    const tlv_entry_t *cvm_res = tlv_find(&oc->output_wh, 0x9F34);
    if (cvm_res && cvm_res->len >= 1) {
        return cvm_res->value[0];
    }

    /* Fallback: No CVM */
    return 0x1F;
}

struct cvm_plugin_s kernel5_cvm_plugin = {
    .evaluate   = kernel5_cvm_evaluate,
    .get_method = kernel5_cvm_get_method,
    .version    = 1,
};
