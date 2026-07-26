/**
 * @file src/utils/tlv_encode.c
 * @brief BER-TLV encoding, decoding, and warehouse serialization.
 */

#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ---- Tag encoding ---------------------------------------------------- */

uint8_t tlv_tag_byte_length(uint32_t tag)
{
    if (tag == 0 || tag > 0xFFFFFF00) return 0;
    if (tag <= 0xFF) return 1;
    if (tag <= 0xFFFF) return 2;
    if (tag <= 0xFFFFFF) return 3;
    return 4;
}

int tlv_encode_tag(uint32_t tag, uint8_t *out, uint8_t *out_len)
{
    if (!out || !out_len || tag == 0) return TLVE_E_INVAL;

    uint8_t n = tlv_tag_byte_length(tag);
    if (n == 0 || n > *out_len) return TLVE_E_INVAL;

    for (uint8_t i = 0; i < n; i++) {
        out[n - 1 - i] = (uint8_t)(tag & 0xFF);
        tag >>= 8;
    }
    *out_len = n;
    return TLVE_E_OK;
}

int tlv_decode_tag(const uint8_t *in, uint8_t in_len, uint32_t *tag)
{
    if (!in || !tag || in_len == 0) return TLVE_E_INVAL;

    uint8_t tag_bytes;
    if ((in[0] & 0x1F) != 0x1F) {
        tag_bytes = 1;
    } else {
        tag_bytes = 1;
        while (tag_bytes < in_len && (in[tag_bytes] & 0x80)) {
            tag_bytes++;
        }
        if (tag_bytes > 4) return TLVE_E_BAD_FORMAT;
    }

    uint32_t result = 0;
    for (uint8_t i = 0; i < tag_bytes; i++) {
        result = (result << 8) | in[i];
    }
    *tag = result;
    return (int)tag_bytes;
}

/* ---- Length encoding ------------------------------------------------- */

uint8_t tlv_encode_length(uint16_t len, uint8_t *out, uint8_t out_max)
{
    if (len <= 127) {
        if (out_max < 1) return 0;
        out[0] = (uint8_t)len;
        return 1;
    }

    uint8_t len_bytes = 0;
    uint16_t tmp = len;
    while (tmp > 0) { tmp >>= 8; len_bytes++; }

    uint8_t total = 1 + len_bytes;
    if (total > out_max || total > 5) return 0;

    out[0] = (uint8_t)(0x80 | len_bytes);
    for (uint8_t i = 0; i < len_bytes; i++) {
        out[1 + len_bytes - 1 - i] = (uint8_t)(len & 0xFF);
        len >>= 8;
    }
    return total;
}

int tlv_decode_length(const uint8_t *in, uint8_t in_len, uint16_t *len_out)
{
    if (!in || !len_out || in_len == 0) return TLVE_E_INVAL;

    if (!(in[0] & 0x80)) {
        *len_out = (uint16_t)in[0];
        return 1;
    }

    uint8_t num_len_bytes = in[0] & 0x7F;
    if (num_len_bytes == 0 || num_len_bytes > 2 || num_len_bytes + 1 > in_len) {
        return TLVE_E_BAD_FORMAT;
    }

    uint16_t val = 0;
    for (uint8_t i = 0; i < num_len_bytes; i++) {
        val = (val << 8) | in[1 + i];
    }
    *len_out = val;
    return 1 + (int)num_len_bytes;
}

/* ---- Dump ------------------------------------------------------------- */

static int dump_entry_raw(const tlv_entry_t *entry, uint8_t *out, uint8_t out_len)
{
    uint8_t buf[6];
    uint8_t tl = 0;
    if (tlv_encode_tag(entry->tag, buf, &tl) != TLVE_E_OK) return TLVE_E_INVAL;

    uint8_t ll = tlv_encode_length(entry->len, buf + tl, 6 - tl);
    uint8_t total = tl + ll + entry->len;
    if (total > out_len) return TLVE_E_TRUNCATED;

    memcpy(out, buf, tl + ll);
    memcpy(out + tl + ll, entry->value, entry->len);
    return (int)total;
}

int tlv_dump_raw(const tx_warehouse_t *wh, uint8_t *out, uint8_t out_len)
{
    if (!wh || !out) return TLVE_E_INVAL;

    uint8_t offset = 0;
    for (uint8_t i = 0; i < wh->count; i++) {
        const tlv_entry_t *e = &wh->entries[i];
        if (!e->value) continue;

        int written = dump_entry_raw(e, out + offset, out_len - offset);
        if (written < 0) return TLVE_E_TRUNCATED;
        offset += (uint8_t)written;
    }
    return (int)offset;
}

int tlv_dump_ordered(const tx_warehouse_t *wh,
                     const uint32_t *tag_order, uint8_t tag_count,
                     uint8_t *out, uint8_t out_len)
{
    if (!wh || !out || !tag_order) return TLVE_E_INVAL;

    uint8_t offset = 0;
    for (uint8_t i = 0; i < tag_count; i++) {
        const tlv_entry_t *e = tlv_find(wh, tag_order[i]);
        if (!e) continue;

        int written = dump_entry_raw(e, out + offset, out_len - offset);
        if (written < 0) return TLVE_E_TRUNCATED;
        offset += (uint8_t)written;
    }
    return (int)offset;
}

/* ---- Parse ------------------------------------------------------------ */

int tlv_parse_raw(const uint8_t *in_buf, uint16_t in_len, tx_warehouse_t *wh)
{
    if (!in_buf || !wh || in_len == 0) return TLVE_E_INVAL;

    uint16_t offset = 0;
    int parsed = 0;

    while (offset < in_len) {
        uint32_t tag;
        uint16_t value_len;

        int tag_bytes = tlv_decode_tag(in_buf + offset, in_len - offset, &tag);
        if (tag_bytes < 0) break;
        offset += (uint8_t)tag_bytes;

        int len_bytes = tlv_decode_length(in_buf + offset, in_len - offset, &value_len);
        if (len_bytes < 0) break;
        offset += (uint8_t)len_bytes;

        if (offset + value_len > in_len) break;

        int rc = tlv_store_set(wh, tag, in_buf + offset, (uint16_t)value_len);
        if (rc < 0) break;

        offset += value_len;
        parsed++;
    }

    return parsed;
}

/* ---- AID hex string helper ------------------------------------------- */

int aid_nad_pad_to_bytes(const char *hex_str, uint8_t *out, uint8_t *out_len, uint8_t max_len)
{
    if (!hex_str || !out || !out_len) return TLVE_E_INVAL;

    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0) return TLVE_E_BAD_FORMAT;
    if (hex_len / 2 > max_len) return TLVE_E_INVAL;

    uint8_t bytes_needed = (uint8_t)(hex_len / 2);
    *out_len = bytes_needed;

    for (uint8_t i = 0; i < bytes_needed; i++) {
        const char *pair = hex_str + i * 2;
        uint8_t hi = pair[0] >= 'A' ? (pair[0] - 'A' + 10) :
                     pair[0] >= 'a' ? (pair[0] - 'a' + 10) : pair[0] - '0';
        uint8_t lo = pair[1] >= 'A' ? (pair[1] - 'A' + 10) :
                     pair[1] >= 'a' ? (pair[1] - 'a' + 10) : pair[1] - '0';
        out[i] = (hi << 4) | lo;
    }
    return TLVE_E_OK;
}
