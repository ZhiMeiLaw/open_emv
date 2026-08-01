/**
 * @file src/core/kernel_core.c
 * @brief Kernel execution core — generic skeleton with per-kernel hooks.
 *
 * Architecture:
 *   - Generic skeleton handles: GPO, READ RECORD, Card Read Complete,
 *     GENERATE AC, outcome determination.
 *   - Per-kernel hooks (kernel_ops_t) handle:
 *       Processing Restrictions (§5.5)
 *       Offline Data Auth / fDDA (§5.6)
 *       CVM decision tree (§5.7)
 *       GENERATE AC data build + response parsing (§5.8/§5.9)
 *
 * Each kernel (K3, K5, K7) implements its own kernel_ops_t and registers
 * it via kernel_register(). The framework calls the ops at the right time.
 */

#include "emv_kernel/orchestrator.h"
#include "emv_kernel/dict_validate.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/apdu_tlv_parser.h"
#include "emv_kernel/errors.h"
#include "emv_kernel/entry_point.h"
#include "emv_kernel/kernel_registry.h"
#include "emv_kernel/platform.h"
#include <string.h>

/* ================================================================== */
/*  Internal context                                                   */
/* ================================================================== */

typedef struct {
    ep_context_t *ep_ctx;             /* Entry Point context              */
    const kernel_config_t *cfg;       /* Kernel config + dictionary       */
    const kernel_ops_t *ops;          /* Per-kernel processing hooks      */
    const crypto_driver_t *crypto;    /* Crypto driver from platform      */
    const void *pos_params;           /* Terminal POS params              */

    /* Transaction flags */
    uint8_t online_required : 1;
    uint8_t decline_required : 1;
    uint8_t auth_done       : 1;
    auth_method_t auth_method;
} kernel_txn_ctx_t;

/* ================================================================== */
/*  Helper: send APDU command                                          */
/* ================================================================== */

static int send_apdu(ep_context_t *ctx,
                     uint8_t cla, uint8_t ins,
                     uint8_t p1, uint8_t p2,
                     const uint8_t *data_in, uint16_t data_in_len,
                     uint8_t *recv_buf, uint16_t recv_max,
                     uint16_t *recv_len)
{
    if (!ctx || !ctx->icr) return EP_E_INVAL;

    uint8_t apdu[260];
    uint16_t idx = 0;
    apdu[idx++] = cla;
    apdu[idx++] = ins;
    apdu[idx++] = p1;
    apdu[idx++] = p2;
    apdu[idx++] = (uint8_t)data_in_len;
    memcpy(apdu + idx, data_in, data_in_len);
    idx += data_in_len;

    return ctx->icr->transceive(apdu, idx, recv_buf, recv_max, recv_len);
}

/* ================================================================== */
/*  Build DOL data from PDOL template                                  */
/* ================================================================== */

/**
 * Parse PDOL template [TagHigh Len TagHigh Len ...] and populate output.
 * Each tag is looked up from the warehouse.
 */
static int build_pdol_data(const tx_warehouse_t *wh,
                           const uint8_t *pdol_template, uint8_t pdol_len,
                           uint8_t *out_buf, uint16_t out_max,
                           uint16_t *out_len)
{
    uint16_t offset = 0;
    uint16_t written = 0;

    while (offset + 2 <= pdol_len && written + 10 <= out_max) {
        uint32_t tag = EMV_TAG2(pdol_template[offset],
                                pdol_template[offset + 1]);
        uint8_t  len = pdol_template[offset + 2];
        offset += 3;

        /* Look up tag in warehouse */
        const tlv_entry_t *entry = tlv_find(wh, tag);
        if (!entry) continue;  /* Skip if tag not found */

        /* Encode as TLV */
        uint8_t tag_bytes[3];
        uint8_t tag_bytes_len = 0;
        tlv_encode_tag(tag, tag_bytes, &tag_bytes_len);

        if (written + 2 + 1 + entry->len > out_max) break;

        out_buf[written++] = tag_bytes[0];
        if (tag_bytes_len > 1) out_buf[written++] = tag_bytes[1];
        out_buf[written++] = (uint8_t)entry->len;
        memcpy(out_buf + written, entry->value, entry->len);
        written += entry->len;
    }

    *out_len = written;
    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 1: Initiate Application Processing — GPO                      */
/* ================================================================== */

static int kernel_gpo(kernel_txn_ctx_t *txn)
{
    if (!txn || !txn->ep_ctx) return ORCH_E_INVAL;

    /* Look up PDOL (Tag 0x9F38) from SELECT AID FCI */
    const tlv_entry_t *pdol_entry = tlv_find(txn->ep_ctx->wh, 0x9F38);

    uint8_t gpo_data[128];
    uint16_t gpo_data_len = 0;

    if (!pdol_entry || pdol_entry->len == 0) {
        /* No PDOL — send empty template */
        gpo_data[0] = 0x83;
        gpo_data[1] = 0x00;
        gpo_data_len = 2;
    } else {
        /* Parse PDOL template and build GPO command data */
        uint8_t tmpl[128];
        uint16_t tmpl_len = 0;
        if (build_pdol_data(txn->ep_ctx->wh, pdol_entry->value,
                            pdol_entry->len, tmpl, sizeof(tmpl),
                            &tmpl_len) == EMV_E_OK) {
            gpo_data[gpo_data_len++] = 0x83;
            gpo_data[gpo_data_len++] = (uint8_t)tmpl_len;
            memcpy(gpo_data + gpo_data_len, tmpl, tmpl_len);
            gpo_data_len += tmpl_len;
        }
    }

    /* Send GPO: CLA=00 INS=A8 P1=00 P2=00 */
    uint8_t apdu_cmd[132];
    apdu_cmd[0] = 0x00;  /* CLA */
    apdu_cmd[1] = 0xA8;  /* INS GET PROCESSING OPTIONS */
    apdu_cmd[2] = 0x00;  /* P1 */
    apdu_cmd[3] = 0x00;  /* P2 */
    apdu_cmd[4] = (uint8_t)gpo_data_len;
    memcpy(apdu_cmd + 5, gpo_data, gpo_data_len);
    uint16_t cmd_len = (uint16_t)(5 + gpo_data_len);

    uint8_t resp[256];
    uint16_t resp_len = sizeof(resp);
    int rc = send_apdu(txn->ep_ctx, 0x00, 0xA8, 0x00, 0x00,
                       gpo_data, gpo_data_len,
                       resp, sizeof(resp), &resp_len);

    if (rc != 0) {
        uint8_t sw1 = (uint8_t)((rc >> 8) & 0xFF);
        uint8_t sw2 = (uint8_t)(rc & 0xFF);
        if (sw1 == 0x69 && sw2 == 0x84) return EP_E_AUTH;
        if (sw1 == 0x69 && sw2 == 0x85) return EP_E_SELECT;
        if (sw1 == 0x69 && sw2 == 0x86) return EP_E_COMM;
        return EP_E_GPO;
    }

    /* Parse GPO response into warehouse */
    int parsed = apdu_parse_response(resp, resp_len, txn->ep_ctx->wh, NULL, NULL);
    if (parsed <= 0) return EP_E_GPO;

    /* Parse CID from GPO response — §5.4.3.1 / §5.4.3.2
     * CID [9F27] byte 1: bits 6-5 = 00=AAC, 01=TC, 10=ARQC, 11=RFU */
    const tlv_entry_t *gpo_cid = tlv_find(txn->ep_ctx->wh, 0x9F27);
    if (gpo_cid && gpo_cid->len >= 1) {
        uint8_t cid_byte = gpo_cid->value[0];
        uint8_t cid_type = (cid_byte >> 5) & 0x03;
        switch (cid_type) {
        case 0x00:  /* AAC in GPO → card declines */
            txn->decline_required = 1;
            break;
        case 0x01:  /* TC in GPO → offline approve */
            break;
        case 0x02:  /* ARQC in GPO → online required */
            txn->online_required = 1;
            break;
        case 0x03:  /* RFU → treat as AAC */
            txn->decline_required = 1;
            break;
        }
    }

    /* Store AOSA (9F5D) for §4.3 UI display if present */
    const tlv_entry_t *aosa = tlv_find(txn->ep_ctx->wh, 0x9F5D);
    if (aosa && aosa->len >= 6) {
        tlv_store_set(txn->ep_ctx->wh, 0x9F5D, aosa->value, aosa->len);
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 2: Read Application Data — READ RECORD per AFL               */
/* ================================================================== */

static int kernel_read_app_data(kernel_txn_ctx_t *txn)
{
    if (!txn || !txn->ep_ctx) return ORCH_E_INVAL;

    const tlv_entry_t *afl = tlv_find(txn->ep_ctx->wh, 0x94);
    if (!afl || afl->len < 3) return EMV_E_OK;

    uint8_t offset = 0;
    while (offset + 3 <= afl->len) {
        uint8_t sfi_raw = afl->value[offset];
        uint8_t start_rec = afl->value[offset + 1];
        uint8_t end_rec = afl->value[offset + 2];
        uint8_t sfi = (sfi_raw >> 3) & 0x1F;
        offset += 3;

        if (sfi == 0 || start_rec > end_rec) continue;

        for (int rec = start_rec; rec <= end_rec; rec++) {
            uint8_t apdu[4] = { 0x00, 0xB2, (uint8_t)((sfi << 3) | rec), 0x0C };
            uint8_t resp[256];
            uint16_t resp_len = sizeof(resp);

            int rc = send_apdu(txn->ep_ctx, 0x00, 0xB2,
                               (uint8_t)((sfi << 3) | rec), 0x0C,
                               NULL, 0, resp, sizeof(resp), &resp_len);
            if (rc != 0) break;

            apdu_parse_tlv_only(resp, resp_len, txn->ep_ctx->wh);
        }
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 3: Card Read Complete                                          */
/* ================================================================== */

static int kernel_card_read_complete(kernel_txn_ctx_t *txn)
{
    if (!txn || !txn->cfg) return ORCH_E_DICT_FAIL;

    int rc = tlv_validate_dict((kernel_dict_t *)txn->cfg, txn->ep_ctx->wh);
    return (rc == DICT_E_OK) ? EMV_E_OK : ORCH_E_DICT_FAIL;
}

/* ================================================================== */
/*  Step 4-7: Per-kernel hooks (Processing Restrictions, Auth, CVM, GAC) */
/* ================================================================== */

static int kernel_process_hooks(kernel_txn_ctx_t *txn)
{
    if (!txn || !txn->ops) return EMV_E_OK;

    /* Build hook context */
    kernel_hook_ctx_t hook_ctx;
    memset(&hook_ctx, 0, sizeof(hook_ctx));
    hook_ctx.wh = txn->ep_ctx->wh;
    hook_ctx.crypto = txn->crypto;
    hook_ctx.online_required = txn->online_required;
    hook_ctx.decline_required = txn->decline_required;

    /* ---- §5.5: Processing Restrictions ---- */
    if (txn->ops->check_processing_restrictions) {
        int rc = txn->ops->check_processing_restrictions(&hook_ctx);
        if (rc < 0) {
            if (rc == -2) txn->online_required = 1;
            else txn->decline_required = 1;
        }
    }

    /* ---- §5.6: Offline Data Authentication ---- */
    if (txn->ops->check_offline_auth) {
        int rc = txn->ops->check_offline_auth(&hook_ctx, &txn->auth_method);
        if (rc < 0) {
            /* Auth failed — decline_required or online_required already set */
        }
    }

    /* ---- §5.7: CVM ---- */
    if (txn->ops->build_cvm_results) {
        int rc = txn->ops->build_cvm_results(&hook_ctx);
        if (rc < 0) {
            txn->decline_required = 1;
        }
    }

    /* ---- §5.8: Build GENERATE AC data ---- */
    if (txn->ops->build_generate_ac) {
        int rc = txn->ops->build_generate_ac(&hook_ctx, txn->ep_ctx->wh);
        if (rc != EMV_E_OK) return ORCH_E_INVAL;
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 8: Send GENERATE AC and parse response                        */
/* ================================================================== */

static int kernel_generate_ac(kernel_txn_ctx_t *txn)
{
    if (!txn || !txn->ep_ctx) return ORCH_E_INVAL;

    /* Read TDOL data built by build_generate_ac hook.
     * The hook stores the [83] command template data directly in the
     * warehouse. Look for it there. */
    const tlv_entry_t *entry = tlv_find(txn->ep_ctx->wh, 0x83);
    uint8_t genac_buf[128];
    uint16_t genac_len = 0;

    if (entry) {
        genac_len = entry->len < sizeof(genac_buf) ? entry->len : sizeof(genac_buf);
        memcpy(genac_buf, entry->value, genac_len);
    } else {
        /* No TDOL data — send empty template */
        genac_buf[0] = 0x83;
        genac_buf[1] = 0x00;
        genac_len = 2;
    }

    /* Send GENERATE AC: CLA=00 INS=A6 P1=00 P2=00 [TDOL data] */
    uint8_t apdu_cmd[132];
    apdu_cmd[0] = 0x00;
    apdu_cmd[1] = 0xA6;
    apdu_cmd[2] = 0x00;
    apdu_cmd[3] = 0x00;
    apdu_cmd[4] = (uint8_t)genac_len;
    memcpy(apdu_cmd + 5, genac_buf, genac_len);

    uint8_t resp[256];
    uint16_t resp_len = sizeof(resp);
    int rc = send_apdu(txn->ep_ctx, 0x00, 0xA6, 0x00, 0x00,
                       genac_buf, genac_len,
                       resp, sizeof(resp), &resp_len);
    if (rc != 0) return EP_E_GPO;

    /* Parse GENERATE AC response — tags: [9F26] ARQC, [8A] ARC, [9F27] CID, [9F2B] NASP */
    apdu_parse_response(resp, resp_len, txn->ep_ctx->wh, NULL, NULL);

    /* Call per-kernel response parser */
    if (txn->ops && txn->ops->parse_generate_ac_response) {
        kernel_hook_ctx_t hook_ctx;
        memset(&hook_ctx, 0, sizeof(hook_ctx));
        hook_ctx.wh = txn->ep_ctx->wh;
        hook_ctx.crypto = txn->crypto;
        hook_ctx.online_required = txn->online_required;
        hook_ctx.decline_required = txn->decline_required;
        txn->ops->parse_generate_ac_response(&hook_ctx);
        txn->online_required = hook_ctx.online_required;
        txn->decline_required = hook_ctx.decline_required;
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Step 9: Outcome determination                                      */
/* ================================================================== */

static outcome_code_t kernel_determine_outcome(kernel_txn_ctx_t *txn)
{
    if (txn->decline_required) {
        return OUTCOME_DECLINE;
    }
    if (txn->online_required) {
        return OUTCOME_APPROVE_ISSUER_AUTH;
    }
    return OUTCOME_APPROVE_TERMINAL_CONDS;
}

/* ================================================================== */
/*  Helper: build Terminal Conduction (TC) output data                 */
/* ================================================================== */

/**
 * Build TC TLV for approved offline transaction.
 * Includes: [9F26] AC, [8A] ARC (if available), [9F27] CID, [95] TVR
 */
int kernel_build_tc(uint8_t *tc_out, uint16_t tc_max, uint16_t *tc_len,
                    const ep_context_t *ep_ctx)
{
    if (!tc_out || !tc_len || !ep_ctx) return ORCH_E_INVAL;
    if (tc_max < 15) return ORCH_E_INVAL;

    uint16_t off = 0;
    const tx_warehouse_t *wh = ep_ctx->wh;

    /* [9F26] Application Cryptogram — 8 bytes */
    const tlv_entry_t *arqc = tlv_find(wh, 0x9F26);
    if (arqc && arqc->len == 8 && off + 2 + 8 <= tc_max) {
        tc_out[off++] = 0x9F; tc_out[off++] = 0x26;
        tc_out[off++] = 0x08;
        memcpy(tc_out + off, arqc->value, 8);
        off += 8;
    }

    /* [8A] Authorisation Response Code — 2 bytes (optional) */
    const tlv_entry_t *arc = tlv_find(wh, 0x8A);
    if (arc && arc->len >= 2 && off + 2 + 2 <= tc_max) {
        tc_out[off++] = 0x8A; tc_out[off++] = 0x02;
        memcpy(tc_out + off, arc->value, 2);
        off += 2;
    }

    /* [95] TVR — 5 bytes */
    const tlv_entry_t *tvr = tlv_find(wh, 0x95);
    if (tvr && tvr->len >= 5 && off + 2 + 5 <= tc_max) {
        tc_out[off++] = 0x95; tc_out[off++] = 0x05;
        memcpy(tc_out + off, tvr->value, 5);
        off += 5;
    }

    *tc_len = off;
    return EMV_E_OK;
}

/* ================================================================== */
/*  Helper: build NASP output data                                     */
/* ================================================================== */

/**
 * Build No Application SDI Parameter (NASP) for declined transaction.
 * [9F2B] 02 0000
 */
int kernel_build_nasp(uint8_t *nasp_out, uint16_t nasp_max, uint16_t *nasp_len)
{
    if (!nasp_out || !nasp_len) return ORCH_E_INVAL;
    if (nasp_max < 4) return ORCH_E_INVAL;

    nasp_out[0] = 0x9F;
    nasp_out[1] = 0x2B;
    nasp_out[2] = 0x02;
    nasp_out[3] = 0x00;
    nasp_out[4] = 0x00;
    *nasp_len = 5;
    return EMV_E_OK;
}

/* ================================================================== */
/*  Main entry point                                                   */
/* ================================================================== */

int kernel_execute(uint8_t kernel_id, ep_context_t *ep_ctx)
{
    if (!ep_ctx) return ORCH_E_INVAL;

    /* Resolve kernel config */
    const kernel_config_t *cfg = kernel_lookup(kernel_id);
    if (!cfg) return ORCH_E_NO_CONFIG;

    kernel_txn_ctx_t txn;
    memset(&txn, 0, sizeof(txn));
    txn.ep_ctx = ep_ctx;
    txn.cfg = cfg;
    txn.ops = cfg->ops;
    txn.crypto = platform_get_crypto();
    txn.pos_params = NULL;  /* Set by caller if needed */

    /* Step 1: GPO with PDOL data */
    int rc = kernel_gpo(&txn);
    if (rc != EMV_E_OK) return rc;

    /* Step 2: Read application data per AFL */
    rc = kernel_read_app_data(&txn);

    /* Step 3: Card Read Complete — validate mandatory tags */
    rc = kernel_card_read_complete(&txn);
    if (rc != EMV_E_OK) return rc;

    /* Step 4-7: Per-kernel hooks */
    rc = kernel_process_hooks(&txn);

    /* Step 8: GENERATE AC */
    rc = kernel_generate_ac(&txn);

    /* Step 9: Determine outcome */
    ep_ctx->outcome = kernel_determine_outcome(&txn);

    return EMV_E_OK;
}
