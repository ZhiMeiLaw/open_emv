/**
 * @file emv_kernel/apdu_tlv_parser.h
 * @brief Parse APDU SW1:SW2 + TLV response bytes into the TLV warehouse.
 *
 * Every non-contact card command returns an APDU response consisting of:
 *   [TLV payload... ] + [SW1 SW2] (last 2 bytes)
 *
 * This module extracts and parses the TLV payload, storing everything
 * in a transaction-scoped warehouse. The two SW bytes are also stored
 * as tag 0xFFFF for reference.
 */

#ifndef EMV_KERNEL_APDU_TLV_PARSER_H
#define EMV_KERNEL_APDU_TLV_PARSER_H

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"

/* Special tag to store SW status code */
#define TAG_SW_STATUS          0xFFFF

/* ================================================================== */
/*  cAPDU Response Parser                                               */
/* ================================================================== */

/**
 * Parse a raw APDU response (data + SW1SW2) into the warehouse.
 *
 * Expected input format:
 *   [BER-TLV bytes...] [SW1] [SW2]
 * SW1:SW2 is the LAST 2 bytes of recv_buf.
 * Everything before that is treated as TLV data.
 *
 * TLV tags parsed from the card include (but not limited to):
 *   - GPO: 87 (AIP), 82 (AUC), DF9F66 (CDOL), 9F37 (unpredictable num)
 *   - SELECT: 4F (AID), 50 (Label), 87 (AIP)
 *   - SET ATTRIBUTE: 9F8C (ICData)
 *   - TOA: 9F7E (ICC CRT), 9F27 (Cryptogram)
 *   - GET DATA: 9F21 (ICA Certificate)
 *
 * @param resp_data   Full response buffer (including trailing SW1SW2)
 * @param resp_len    Total length including SW1SW2
 * @param wh          Warehouse to store parsed tags
 * @param sw1_out     Output: SW1 byte (e.g., 0x90 = success)
 * @param sw2_out     Output: SW2 byte
 * @return Number of TLV entries parsed, or negative error code.
 */
int apdu_parse_response(const uint8_t *resp_data, uint16_t resp_len,
                        tx_warehouse_t *wh, uint8_t *sw1_out, uint8_t *sw2_out);

/**
 * Convenience: parse just the TLV portion (no SW appended).
 * For responses where SW handling differs from standard APDU.
 */
int apdu_parse_tlv_only(const uint8_t *tlv_data, uint16_t tlv_len,
                        tx_warehouse_t *wh);

/**
 * Check if the APDU response indicates success.
 * Returns 1 if SW == 0x90 0x00 (NORMAL), 0 otherwise.
 */
static inline int apdu_is_success(uint8_t sw1, uint8_t sw2)
{
    return sw1 == 0x90 && sw2 == 0x00;
}

/**
 * Build a SW status code for use in the warehouse.
 */
static inline uint16_t apdu_sw_status(uint8_t sw1, uint8_t sw2)
{
    return ((uint16_t)sw1 << 8) | (uint16_t)sw2;
}

#endif /* EMV_KERNEL_APDU_TLV_PARSER_H */
