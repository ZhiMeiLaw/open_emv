/**
 * @file emv_kernel/bitmap.h
 * @brief Bitmap manipulation and EMV field parsing helpers.
 *
 * Used for AIP (87), AUC (82), TVR, TAR, and other bit-map tags per
 * EMV Contactless Book A §6.2.
 */

#ifndef EMV_KERNEL_BITMAP_H
#define EMV_KERNEL_BITMAP_H

#include "emv_kernel/types.h"

/* ------------------------------------------------------------------ */
/*  Generic bitmap operations                                         */
/* ------------------------------------------------------------------ */

/** Set a bit in a buffer (0-indexed from MSB of byte 0). */
static inline void bitmap_set(uint8_t *buf, uint16_t bit_idx)
{
    buf[bit_idx >> 3] |= (uint8_t)(1u << (7 - (bit_idx & 7)));
}

/** Clear a bit in a buffer. */
static inline void bitmap_clear(uint8_t *buf, uint16_t bit_idx)
{
    buf[bit_idx >> 3] &= (uint8_t)~(1u << (7 - (bit_idx & 7)));
}

/** Check if a bit is set (returns 1 or 0). */
static inline int bitmap_get(const uint8_t *buf, uint16_t bit_idx)
{
    return (buf[bit_idx >> 3] >> (7 - (bit_idx & 7))) & 1;
}

/** Count number of set bits in a buffer. */
static inline uint8_t bitmap_count_bits(const uint8_t *buf, uint8_t byte_count)
{
    uint8_t count = 0;
    for (uint8_t i = 0; i < byte_count; i++) {
        uint8_t b = buf[i];
        for (int bit = 7; bit >= 0; bit--) {
            if (b & (1 << bit)) count++;
        }
    }
    return count;
}

/* ------------------------------------------------------------------ */
/*  EMV-specific bitmap parsers                                       */
/* ------------------------------------------------------------------ */

/* AIP (tag 0x87) — typically 2 bytes. Book A defines bit meanings. */
typedef struct {
    uint8_t b1_mandatory_iod_1 : 1;    /* Bit B1 — IOD indicator 1    */
    uint8_t b1_mandatory_iod_2 : 1;    /* Bit B2 — IOD indicator 2    */
    uint8_t b1_sda_capable : 1;        /* Bit B3 — SDA capable        */
    uint8_t b1_oda_capable : 1;        /* Bit B4 — ODA capable        */
    uint8_t b1_offline_decryption : 1; /* Bit B5 — Offline decryption */
    uint8_t b1_cardholder_verification : 1; /* Bit B6 — Cardholder verification */
    uint8_t b1_terminal_verification : 1;   /* Bit B7 — Terminal verification */
    uint8_t b1_ic_data_interaction : 1;     /* Bit B8 — ICC data interaction */
    /* Byte 2 varies by kernel */
    uint8_t reserved_b2;
} aip_fields_t;

/** Parse AIP byte(s) into structured fields. */
void aip_parse(const uint8_t *aip_bytes, uint8_t aip_len, aip_fields_t *out);

/* AUC (tag 0x82) — Application Usage Control. Typically 2 bytes. */
typedef struct {
    /* Byte 1 — International */
    uint8_t international_allow : 1;
    uint8_t international_restrict : 1;
    uint8_t domestic_purchase : 1;
    uint8_t domestic_cashback : 1;
    uint8_t goods_and_services : 1;
    uint8_t bill_payment : 1;
    uint8_t atm_withdrawal : 1;
    uint8_t foreign_purchase : 1;
    /* Byte 2 — Domestic */
    uint8_t dom_purchase : 1;
    uint8_t dom_cashback : 1;
    uint8_t dom_goods_svc : 1;
    uint8_t dom_bill_pmt : 1;
    uint8_t dom_atm : 1;
    uint8_t dom_foreign : 1;
    uint8_t dom_other : 1;
    uint8_t dom_undefined : 1;
    /* Byte 3+ — can be extended */
    uint8_t reserved_b2;
    uint8_t reserved_b3;
} auc_fields_t;

/** Parse AUC byte(s) into structured fields. */
void auc_parse(const uint8_t *auc_bytes, uint8_t auc_len, auc_fields_t *out);

/* TVR (tag 0x9F3A) — 5 bytes. Book C defines bit positions per kernel. */
/* Simplified field accessor — caller indexes bytes [0..4] */
static inline uint8_t tvr_byte(const uint8_t *tvr, uint8_t idx)
{
    if (idx >= 5 || !tvr) return 0;
    return tvr[idx];
}

/* TVR bit accessors (byte 1 common to most kernels) */
static inline int tvr_icc_malfunction(const uint8_t *tvr) { return bitmap_get(tvr, 0); }
static inline int tvr_lost_card(const uint8_t *tvr)      { return bitmap_get(tvr, 1); }
static inline int tvr_stale_card(const uint8_t *tvr)      { return bitmap_get(tvr, 2); }
static inline int tvr_pin_try_limit_exceeded(const uint8_t *tvr) { return bitmap_get(tvr, 3); }
static inline int tvr_deny_cardholder(const uint8_t *tvr) { return bitmap_get(tvr, 4); }
static inline int tvr_expired_card(const uint8_t *tvr)    { return bitmap_get(tvr, 5); }
static inline int tvr_above_fpr_limit(const uint8_t *tvr) { return bitmap_get(tvr, 6); }
static inline int tvr_below_ere_limit(const uint8_t *tvr) { return bitmap_get(tvr, 7); }

/* Terminal Qualifiers (tag 0x9F66) — 4 bytes */
typedef struct {
    uint8_t byte1_has_online_credentials;    /* B1 */
    uint8_t byte1_cvm_supported;             /* B2 */
    uint8_t byte1_online_pkp;                /* B3 */
    uint8_t byte1_issued_by_processor;       /* B4 */
    uint8_t byte1_reissue_document;          /* B5 */
    uint8_t byte1_request_pin;               /* B6 */
    uint8_t byte1_language_preference;       /* B7 */
    uint8_t byte1_ Merchant_priority;         /* B8 */
    uint8_t byte2_default_term;              /* B9 */
    uint8_t byte2_contactless_warm_reset;    /* B10 */
    uint8_t byte2_cvv_enabled;               /* B11 */
    uint8_t byte2_cvv_result_available;      /* B12 */
    uint8_t byte2_sas_supported;             /* B13 */
    uint8_t byte2_cvm_result_available;      /* B14 */
    uint8_t byte2_trm_indicator;             /* B15 */
    uint8_t byte2_undefined;                 /* B16 */
    uint8_t byte3_pos_entry_mode;            /* Bits 17-24, encoded */
    uint8_t byte4_cryptogram_type;           /* Various bits */
} terminal_qualifiers_t;

/** Parse 4-byte terminal qualifiers tag (0x9F66). */
void terminal_qualifiers_parse(const uint8_t *tq_bytes, uint8_t tq_len, terminal_qualifiers_t *out);

/* Serialize TVR byte array to hex string for debugging */
int tvr_to_hex(const uint8_t *tvr, uint8_t len, char *hex_out, uint8_t hex_max);

#endif /* EMV_KERNEL_BITMAP_H */
