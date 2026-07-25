/**
 * @file src/utils/apdu_tlv_parser.c
 * @brief Parse APDU card responses into the TLV warehouse.
 *
 * Every command sent to the EMV card returns a cAPDU response:
 *   [BER-TLV data...] + [SW1 SW2]
 *
 * This module parses the BER-TLV portion and stores everything in the
 * transaction-scoped warehouse, so all downstream modules (CVM, Risk,
 * Orchestrator) can access any tag by its uint32_t key.
 *
 * Example parsed responses:
 *   GPO response → 87(AIP), 82(AUC), DF9F66(CDOL), 9F37(UnexpNum)
 *   SELECT → 4F(AID), 50(Label), 87(AIP), 5A(PAN indicator)
 *   SET ATTRIBUTE → 9F8C(ICData for ODA DNL)
 *   TOA → 9F7E(ICC-CRT), 9F27(Cryptogram Info)
 *   GET DATA [9F21] → 9F21(ICA Certificate DER)
 */

#include "emv_kernel/apdu_tlv_parser.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ================================================================== */
/*  apdu_parse_response                                               */
/* ================================================================== */

/**
 * Parse an APDU response into the warehouse.
 * SW1SW2 is extracted as the last 2 bytes. Everything before is BER-TLV.
 */
int apdu_parse_response(const uint8_t *resp_data, uint16_t resp_len,
                        tx_warehouse_t *wh, uint8_t *sw1_out, uint8_t *sw2_out)
{
    if (!resp_data || resp_len < 2 || !wh) {
        return TLVE_E_INVAL;
    }

    /* Extract SW1 SW2 from last 2 bytes */
    uint8_t sw1 = resp_data[resp_len - 2];
    uint8_t sw2 = resp_data[resp_len - 1];
    if (sw1_out) *sw1_out = sw1;
    if (sw2_out) *sw2_out = sw2;

    /* TLV payload is everything before SW */
    uint16_t tlv_len = resp_len - 2;
    int parsed = tlv_parse_raw(resp_data, tlv_len, wh);

    /* Store SW status in warehouse under TAG_SW_STATUS */
    if (parsed >= 0) {
        uint16_t sw_val = apdu_sw_status(sw1, sw2);
        /* Raw two-byte representation */
        uint8_t sw_bytes[2];
        host_to_be16(sw_val, sw_bytes);
        tlv_store_set(wh, TAG_SW_STATUS, sw_bytes, 2);
    }

    return parsed;
}

/* ================================================================== */
/*  apdu_parse_tlv_only                                               */
/* ================================================================== */

/**
 * Parse only the TLV data, no SW handling.
 * Used when APDU errors are handled separately (e.g., 6986 Try Again).
 */
int apdu_parse_tlv_only(const uint8_t *tlv_data, uint16_t tlv_len,
                        tx_warehouse_t *wh)
{
    if (!tlv_data || !wh) return TLVE_E_INVAL;

    return tlv_parse_raw(tlv_data, tlv_len, wh);
}
