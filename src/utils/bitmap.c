/**
 * @file src/utils/bitmap.c
 * @brief Bitmap utilities and EMV field parsers (AIP, AUC, TVR, TAR).
 */

#include "emv_kernel/bitmap.h"
#include "emv_kernel/errors.h"

void aip_parse(const uint8_t *aip_bytes, uint8_t aip_len, aip_fields_t *out)
{
    if (!aip_bytes || !out || aip_len == 0) return;

    out->b1_mandatory_iod_1 = bitmap_get(aip_bytes, 0);
    out->b1_sda_capable = bitmap_get(aip_bytes, 2);
    out->b1_oda_capable = bitmap_get(aip_bytes, 3);
    out->b1_offline_decryption = bitmap_get(aip_bytes, 4);
    out->b1_cardholder_verification = bitmap_get(aip_bytes, 5);
    out->b1_terminal_verification = bitmap_get(aip_bytes, 6);
    out->b1_ic_data_interaction = bitmap_get(aip_bytes, 7);
    out->b1_mandatory_iod_2 = 0;
    out->reserved_b2 = aip_len > 1 ? aip_bytes[1] : 0;
}

void auc_parse(const uint8_t *auc_bytes, uint8_t auc_len, auc_fields_t *out)
{
    if (!auc_bytes || !out || auc_len == 0) return;

    out->international_allow = bitmap_get(auc_bytes, 0);
    out->domestic_purchase = auc_len > 1 ? (uint8_t)bitmap_get(auc_bytes + 1, 0) : 0;
    out->reserved_b2 = auc_len > 1 ? auc_bytes[1] : 0;
    out->reserved_b3 = auc_len > 2 ? auc_bytes[2] : 0;
}

void terminal_qualifiers_parse(const uint8_t *tq_bytes, uint8_t tq_len, terminal_qualifiers_t *out)
{
    if (!tq_bytes || !out) return;

    out->byte1_has_online_credentials = bitmap_get(tq_bytes, 0);
    out->byte1_cvm_supported = bitmap_get(tq_bytes, 1);
    out->byte1_online_pkp = bitmap_get(tq_bytes, 2);
    out->byte1_issued_by_processor = bitmap_get(tq_bytes, 3);
    out->byte1_reissue_document = bitmap_get(tq_bytes, 4);
    out->byte1_request_pin = bitmap_get(tq_bytes, 5);
    out->byte1_language_preference = bitmap_get(tq_bytes, 6);
    out->byte1_merchant_priority = bitmap_get(tq_bytes, 7);

    if (tq_len > 1) {
        const uint8_t *b2 = tq_bytes + 1;
        out->byte2_default_term = bitmap_get(b2, 0);
        out->byte2_contactless_warm_reset = bitmap_get(b2, 1);
        out->byte2_cvv_enabled = bitmap_get(b2, 2);
        out->byte2_cvv_result_available = bitmap_get(b2, 3);
        out->byte2_sas_supported = bitmap_get(b2, 4);
        out->byte2_cvm_result_available = bitmap_get(b2, 5);
        out->byte2_trm_indicator = bitmap_get(b2, 6);
        out->byte2_undefined = bitmap_get(b2, 7);
    }

    if (tq_len > 2) {
        out->byte3_pos_entry_mode = tq_bytes[2];
    }
    if (tq_len > 3) {
        out->byte4_cryptogram_type = tq_bytes[3];
    }
}

int tvr_to_hex(const uint8_t *tvr, uint8_t len, char *hex_out, uint8_t hex_max)
{
    if (!tvr || !hex_out || hex_max < len * 2 + 1) return TLVE_E_INVAL;

    for (uint8_t i = 0; i < len && i < 5; i++) {
        const char hx[] = "0123456789ABCDEF";
        hex_out[i * 2]     = hx[(tvr[i] >> 4) & 0x0F];
        hex_out[i * 2 + 1] = hx[tvr[i] & 0x0F];
    }
    hex_out[len * 2] = '\0';
    return (int)(len * 2);
}
