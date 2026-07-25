/**
 * @file emv_kernel/tlv_encode.h
 * @brief BER-TLV encoding/decoding and warehouse serialization.
 */

#ifndef EMV_KERNEL_TLV_ENCODE_H
#define EMV_KERNEL_TLV_ENCODE_H

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"

/* ------------------------------------------------------------------ */
/*  BER-TLV tag encoding / decoding                                   */
/* ------------------------------------------------------------------ */

/**
 * Encode an EMV tag into raw bytes.
 * @param tag    32-bit tag number (e.g. 0x9F02)
 * @param out    Output buffer (max 4 bytes needed)
 * @param out_len In: max output; Out: actual bytes written (1–4)
 * @return 0 on success, -1 if buffer too small or tag is 0.
 */
int tlv_encode_tag(uint32_t tag, uint8_t *out, uint8_t *out_len);

/**
 * Decode raw bytes into a 32-bit tag.
 * @param in     Input buffer with encoded tag bytes
 * @param len    Number of tag bytes available
 * @param tag    Output: decoded tag number
 * @return Bytes consumed from in (1–4), or -1 on error.
 */
int tlv_decode_tag(const uint8_t *in, uint8_t len, uint32_t *tag);

/**
 * Determine the byte length needed to encode a tag.
 */
uint8_t tlv_tag_byte_length(uint32_t tag);

/* ------------------------------------------------------------------ */
/*  TLV length encoding (short form ≤ 127 bytes, long form > 127)    */
/* ------------------------------------------------------------------ */

/** Encode length field into bytes. Returns bytes written. */
uint8_t tlv_encode_length(uint16_t len, uint8_t *out, uint8_t out_max);

/** Decode length field. Returns bytes consumed, or -1 on error. */
int tlv_decode_length(const uint8_t *in, uint8_t in_len, uint16_t *len_out);

/* ------------------------------------------------------------------ */
/*  Warehouse → raw byte stream                                       */
/* ------------------------------------------------------------------ */

/** Serialize all warehouse entries to raw TLV bytes (insertion order). */
int tlv_dump_raw(const tx_warehouse_t *wh, uint8_t *out, uint8_t out_len);

/** Serialize entries in a specified tag order. */
int tlv_dump_ordered(const tx_warehouse_t *wh,
                     const uint32_t *tag_order, uint8_t tag_count,
                     uint8_t *out, uint8_t out_len);

/* ------------------------------------------------------------------ */
/*  Raw byte stream → warehouse (parser)                              */
/* ------------------------------------------------------------------ */

/** Parse incoming BER-TLV bytes into the warehouse. */
int tlv_parse_raw(const uint8_t *in_buf, uint16_t in_len, tx_warehouse_t *wh);

/* ------------------------------------------------------------------ */
/*  BCD helpers                                                       */
/* ------------------------------------------------------------------ */

/** Convert NAD/PAD hex string to binary bytes for AID storage. */
int aid_nad_pad_to_bytes(const char *hex_str, uint8_t *out, uint8_t *out_len, uint8_t max_len);

#endif /* EMV_KERNEL_TLV_ENCODE_H */
