/**
 * @file src/core/entry_point.c
 * @brief Book B non-contact card initiator flow implementation.
 */

#include "emv_kernel/entry_point.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ---- APDU helper ----------------------------------------------------- */

static int send_apdu(ep_context_t *ctx,
                     uint8_t ins, uint8_t p1, uint8_t p2,
                     const uint8_t *data_in, uint16_t data_in_len,
                     uint8_t *recv_buf, uint16_t recv_max,
                     uint16_t *recv_len)
{
    (void)recv_buf;
    (void)recv_max;
    (void)recv_len;
    (void)data_in;
    (void)data_in_len;
    return EP_E_INVAL;  /* Placeholder — full impl in reference code */
}

/* ---- ATS Parsing ------------------------------------------------------ */

typedef struct {
    uint8_t fi_byte;
    uint8_t to_byte;
    uint8_t ibr_bytes[4];
    uint8_t ibr_count;
} ats_parsed_t;

static void parse_ats(const uint8_t *ats, uint8_t len, ats_parsed_t *out)
{
    if (!ats || len < 3 || !out) return;

    out->fi_byte = ats[0];
    out->to_byte = ats[1];

    uint8_t n = ats[1] & 0x0Fu;
    out->ibr_count = n > 4 ? 4 : n;
    if (n > 0 && n <= 4) {
        memcpy(out->ibr_bytes, ats + 2, out->ibr_count);
    } else {
        out->ibr_count = 0;
    }
}

/* ---- Step: Init ------------------------------------------------------- */

int entry_point_step_init(ep_context_t *ctx)
{
    if (!ctx || !ctx->icr) return EP_E_INVAL;
    ctx->icr->init();
    return EMV_E_OK;
}

/* ---- Step: Poll card -------------------------------------------------- */

int entry_point_step_poll(ep_context_t *ctx, uint32_t timeout_ms)
{
    if (!ctx || !ctx->icr) return EP_E_INVAL;
    return ctx->icr->poll_card(timeout_ms);
}

/* ---- Step: PPS -------------------------------------------------------- */

int entry_point_step_pps(ep_context_t *ctx)
{
    (void)ctx;
    return EMV_E_OK;
}

/* ---- Step: ERP Exchange ---------------------------------------------- */

int entry_point_step_erp(ep_context_t *ctx)
{
    if (!ctx || !ctx->wh) return EP_E_INVAL;

    uint8_t resp[128];
    uint16_t resp_len = sizeof(resp);

    uint8_t req[] = { 0x04 };
    int rc = ctx->icr->transceive(req, sizeof(req), resp, sizeof(resp), &resp_len);
    if (rc != 0) return EP_E_PROFILE_FAILED;

    tlv_parse_raw(resp, resp_len, ctx->wh);
    return EMV_E_OK;
}

/* ---- Step: Application Select ----------------------------------------- */

int entry_point_step_select(ep_context_t *ctx)
{
    if (!ctx) return EP_E_INVAL;
    return EMV_E_OK;
}

/* ---- Step: SDA Authentication ------------------------------------------ */

int entry_point_step_auth_sda(ep_context_t *ctx)
{
    if (!ctx || !ctx->wh) return EP_E_INVAL;

    const crypto_driver_t *crypto = platform_get_crypto();
    if (!crypto) return EP_E_AUTH;

    ctx->auth_method = AUTH_SDA;
    return EMV_E_OK;
}

/* ---- Step: ODA Authentication ------------------------------------------ */

int entry_point_step_auth_oda(ep_context_t *ctx)
{
    if (!ctx || !ctx->wh) return EP_E_INVAL;

    const crypto_driver_t *crypto = platform_get_crypto();
    if (!crypto) return EP_E_AUTH;

    ctx->auth_method = AUTH_ODA;
    return EMV_E_OK;
}

/* ---- Step: GPO -------------------------------------------------------- */

int entry_point_step_gpo(ep_context_t *ctx)
{
    if (!ctx || !ctx->wh || !ctx->icr) return EP_E_INVAL;

    uint8_t unexp_num[4];
    int prng_rc = platform_prng(unexp_num, 4);
    if (prng_rc != 0) return EP_E_COMM;

    tlv_store_set(ctx->wh, 0x9F37, unexp_num, 4);

    uint8_t gpo_resp[256];
    uint16_t gpo_resp_len = sizeof(gpo_resp);

    const tlv_entry_t *e_unexp = tlv_find(ctx->wh, 0x9F37);
    if (!e_unexp) return EP_E_GPO;

    int rc = ctx->icr->transceive(
        (const uint8_t[]){ 0x00, 0xA8, 0x00, 0x00, (uint8_t)e_unexp->len },
        5,
        e_unexp->value, e_unexp->len,
        gpo_resp, sizeof(gpo_resp), &gpo_resp_len
    );
    if (rc != 0) return EP_E_GPO;

    int parsed = tlv_parse_raw(gpo_resp, gpo_resp_len, ctx->wh);
    if (parsed < 0) return EP_E_GPO;

    return EMV_E_OK;
}

/* ---- Full Transaction Flow -------------------------------------------- */

int entry_point_run(ep_context_t *ctx, const void *pos_params)
{
    (void)pos_params;
    if (!ctx || !ctx->icr) return EP_E_INVAL;

    int rc = entry_point_step_init(ctx);
    if (rc != 0) return rc;

    rc = entry_point_step_poll(ctx, 5000);
    if (rc != 0) return EP_E_NO_CARD;

    rc = entry_point_step_pps(ctx);
    if (rc != 0) return rc;

    rc = entry_point_step_erp(ctx);
    if (rc != 0) return rc;

    rc = entry_point_step_select(ctx);
    if (rc != 0) return rc;

    rc = entry_point_step_auth_sda(ctx);
    if (rc != 0) {
        rc = entry_point_step_auth_oda(ctx);
        if (rc != 0) return EP_E_AUTH;
    }

    rc = entry_point_step_gpo(ctx);
    if (rc != 0) return rc;

    return EP_E_OK;
}
