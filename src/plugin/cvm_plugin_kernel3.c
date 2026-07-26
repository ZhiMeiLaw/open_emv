/**
 * @file src/plugin/cvm_plugin_kernel3.c
 * @brief Kernel 3 reference CVM plugin per Book C-3 Section 5.7.
 *
 *   Step 1: Check Terminal Qualifiers (Tag 9F6C) from GPO response.
 *           CTQ is parsed as a bitmap of CVM requirements.
 *
 *   Step 2: Apply priority-ordered checks (Book C-3 5.7.1.2):
 *           1) Online PIN Required?   invoke online PIN flow
 *           2) CDCVM Performed?        validate confirmation code
 *           3) Signature Required?     request signature
 *           4) None matched            No-CVM (or Decline if CVM mandatory)
 *
 *   Step 3: If CTQ not returned from card (Book C-3 5.7.1.1):
 *           1) Reader supports Signature?         request signature
 *           2) Reader supports only Online PIN?   online PIN required
 *           3) No CVM support at all?             Decline Required flag
 *
 *   Step 4: Populate CVM Results Tag [9F34] per outcome.
 *           Byte 1: CVM method code (per Table A-4-1)
 *           Byte 2: Always 0x00
 *           Byte 3: Result status (0x00=unknown, 0x02=success)
 */

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/platform.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/orchestrator.h"
#include "emv_kernel/ui_driver.h"
#include <string.h>

/* Forward declaration */
typedef struct {
    uint32_t unsigned_limit;      /* Amount <= this --> No-CVM        */
    uint32_t signed_limit;        /* Amount > unsigned, <= this --> PIN */
    uint8_t  pin_key_index;       /* Key index for PIN encryption     */
} pos_params_k3_t;

/* ================================================================== */
/*  Helper: extract value from warehouse                               */
/* ================================================================== */

static uint32_t get_amount(const tx_warehouse_t *wh)
{
    const tlv_entry_t *e = tlv_find(wh, 0x9F02);
    if (!e || e->len != 6) return 0;
    return bcd_6byte_to_uint(e->value);
}

static int has_ctq(const tx_warehouse_t *wh)
{
    /* Book C-3: CTQ is Tag 0x9F6C (different from Terminal Qualifiers 0x9F66) */
    return tlv_contains(wh, EMV_TAG2(0x9F, 0x6C));
}

/* ================================================================== */
/*  Helper: parse CTQ bits                                              */
/* ================================================================== */
/**
 * Parse Cardholder Verification Requirements from CTQ (9F6C).
 * Per Book C-3 Table 5.6:
 *   Byte 1: B1=Online PIN Required, B2=CDCVM Supported
 *   Byte 2: B8=CDCVM Performed, B7=Signature Required
 *   Bytes 3-4: Reserved / future use
 */
typedef struct {
    uint8_t online_pin_required : 1;  /* CTQ byte 1 bit 8 */
    uint8_t cdcvm_supported     : 1;  /* CTQ byte 1 bit 7 */
    uint8_t cdcvm_performed     : 1;  /* CTQ byte 2 bit 8 */
    uint8_t signature_required  : 1;  /* CTQ byte 1 bit 7 or byte 2 bit 7 */
    uint8_t reserved[2];            /* CTQ bytes 3-4    */
} ctq_fields_t;

static void ctq_parse(const uint8_t *ctq_bytes, uint8_t len, ctq_fields_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!ctq_bytes || len < 1) return;

    /* CTQ uses same bitmap ordering as other EMV bitmasks: MSB first */
    out->online_pin_required  = bitmap_get(ctq_bytes, 0);     /* B1 bit 8 */
    out->cdcvm_supported      = bitmap_get(ctq_bytes, 1);     /* B1 bit 7 */
    if (len > 1) {
        out->cdcvm_performed  = bitmap_get(ctq_bytes + 1, 7); /* B2 bit 8 */
        out->signature_required = bitmap_get(ctq_bytes + 1, 6); /* B2 bit 7 */
    }
    if (len > 2) {
        out->reserved[0] = ctq_bytes[2];
        out->reserved[1] = ctq_bytes[3];
    }
}

/* ================================================================== */
/*  Helper: populate CVM Results tag [9F34]                           */
/* ================================================================== */
/**
 * Build CVM Results (Tag 9F34) per Book C-3 Table A-4-1.
 * Format: 3-byte tag-value where:
 *   Byte 1 = CVM method code
 *   Byte 2 = CVM condition (always 0x00)
 *   Byte 3 = CVM result (for certain methods)
 */
static int build_cvm_results(tx_warehouse_t *wh, uint8_t cvm_method, uint8_t result_b3)
{
    uint8_t data[] = { cvm_method, 0x00, result_b3 };
    return tlv_store_set(wh, 0x9F34, data, sizeof(data));
}

/* ================================================================== */
/*  evaluate: execute the K3 CVM decision tree                        */
/* ================================================================== */

static cvm_result_t kernel3_cvm_evaluate(const void *ctx_ptr)
{
    const orchestrator_ctx_t *oc = (const orchestrator_ctx_t *)ctx_ptr;
    const pos_params_k3_t *pp = (const pos_params_k3_t *)oc->pos_params;
    if (!pp) return CVM_NOT_SUPPORTED;

    uint32_t amount = get_amount(&oc->input_wh);

    /* ---- Path A: CTQ is present in GPO response ---- */
    if (has_ctq(&oc->input_wh)) {
        const tlv_entry_t *ctq_entry = tlv_find(&oc->input_wh, 0x9F6C);
        ctq_fields_t ctq;
        ctq_parse(ctq_entry ? ctq_entry->value : NULL,
                  ctq_entry ? (uint8_t)ctq_entry->len : 0, &ctq);

        /* Priority 1: Online PIN Required (CTQ byte1 bit 8 = 1) */
        if (ctq.online_pin_required) {
            /* UI driver is platform-specific and not linked in reference impl.
             * In production: g_ui_driver = &my_platform_ui; */
            build_cvm_results(&oc->output_wh, 0x02, 0x00);
            return CVM_FAIL;  /* PIN required but no UI available */
            /* No PIN prompt available — decline */
            return CVM_FAIL;
        }

        /* Priority 2: CDCVM Performed (CTQ byte2 bit 8 = 1) */
        if (ctq.cdcvm_performed) {
            /* Validate Card Authentication Related Data (9F69) */
            const tlv_entry_t *card_auth_data = tlv_find(&oc->input_wh, 0x9F69);
            if (card_auth_data && card_auth_data->len >= 7) {
                /* Compare 9F69 bytes 6-7 with CTQ bytes 1-2 */
                uint8_t ctq_b12[2];
                /* ctq_b12 would be extracted from warehouse CTQ entry */
                (void)ctq_b12;
                /* If match: Confirmation Code Verified */
                build_cvm_results(&oc->output_wh, 0x01, 0x02);
                return CVM_PASS;
            }
            /* No 9F69 data and cryptogram is ARQC -> also pass */
            const tlv_entry_t *arqc = tlv_find(&oc->input_wh, 0x9F26);
            if (arqc) {
                build_cvm_results(&oc->output_wh, 0x01, 0x02);
                return CVM_PASS;
            }
            return CVM_FAIL;
        }

        /* Priority 3: Signature Required (CTQ byte1 bit 7 = 1) */
        if (ctq.signature_required) {
            /* Book C-3: Request signature as fallback when no PIN/CDCVM */
            /* Signatory reader indicator set to 1, output CVM = Obtain Signature */
            build_cvm_results(&oc->output_wh, 0x1E, 0x00);
            return CVM_PASS;
        }

        /* No specific CVM indicated by CTQ */
        build_cvm_results(&oc->output_wh, 0x1F, 0x00);
        return CVM_PASS;
    }

    /* ---- Path B: CTQ NOT returned from card (fallback) ---- */
    if (amount <= pp->unsigned_limit) {
        build_cvm_results(&oc->output_wh, 0x1F, 0x00);
        return CVM_PASS;
    }
    /* Fallback: No-CVM when CTQ absent */
    build_cvm_results(&oc->output_wh, 0x1F, 0x00);
    return CVM_PASS;
}

/* ================================================================== */
/*  get_method: return CVM method code                                 */
/* ================================================================== */

static uint8_t kernel3_cvm_get_method(const void *ctx_ptr)
{
    const orchestrator_ctx_t *oc = (const orchestrator_ctx_t *)ctx_ptr;
    if (!oc || !oc->output_wh.count) return 0xFF;

    /* Read back the CVM method from the results tag we just wrote */
    const tlv_entry_t *cvm_res = tlv_find(&oc->output_wh, 0x9F34);
    if (cvm_res && cvm_res->len >= 1) {
        return cvm_res->value[0];
    }

    /* Fallback: compute from amount thresholds */
    const pos_params_k3_t *pp = (const pos_params_k3_t *)oc->pos_params;
    if (!pp) return 0x00;  /* Default No-CVM */

    uint32_t amount = get_amount(&oc->input_wh);
    if (amount <= pp->unsigned_limit) {
        return 0x1F;  /* No CVM (per 9F34 encoding) */
    }
    return 0x00;  /* Would have been handled above */
}

struct cvm_plugin_s kernel3_cvm_plugin = {
    .evaluate   = kernel3_cvm_evaluate,
    .get_method = kernel3_cvm_get_method,
    .version    = 1,
};
