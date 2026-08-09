/**
 * @file src/dict/kernel6_dict.c
 * @brief Kernel 6 (eMvCash / Value-Based) data dictionary.
 *
 * Based on EMV Contactless Book C-6 v2.12.
 * E-MvCash is a value-based application where balance is stored on the card.
 * Key characteristics:
 *   - No cardholder verification (no PIN, no signature)
 *   - No offline data authentication
 *   - Transaction amount deducted from stored balance
 *   - Uses IAC/TAC thresholds for outcome determination
 */

#include "emv_kernel/types.h"
#include "emv_kernel/dict_validate.h"

/* Forward declarations */
extern const struct cvm_plugin_s kernel6_cvm_plugin;
extern const struct risk_plugin_s kernel6_risk_plugin;
extern const struct kernel_ops_s *k6_get_kernel_ops(void);

/* Dictionary items for Kernel 6 (E-MvCash) */
static dict_item_t kernel6_items[] = {
    /* === Terminal-provided data for GENERATE AC === */
    { 0x9F02, TAG_SRC_TERMINAL,  TAG_TYPE_NUMERIC,  6,  6,  1, "Amount, Authorised" },
    { 0x5F2A, TAG_SRC_TERMINAL,  TAG_TYPE_NUMERIC,  2,  2,  1, "Transaction Currency Code" },
    { 0x9F66, TAG_SRC_TERMINAL,  TAG_TYPE_BITMASK,  4,  4,  1, "Terminal Qualifiers" },
    { 0x9F36, TAG_SRC_TERMINAL,  TAG_TYPE_BINARY,   2,  2,  1, "Application Transaction Counter" },
    { 0x9F1F, TAG_SRC_TERMINAL,  TAG_TYPE_BINARY,   8,  8,  0, " ICC SDAD (optional)" },

    /* === GPO response tags === */
    { 0x87,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 1, 2, 1, "Application Interchange Profile (AIP)" },
    { 0x82,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 1, 2, 1, "Application Usage Control (AUC)" },
    { 0x94,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  3, 252, 0, "Application File Locator (AFL)" },
    { 0xDF9F, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  4, 64, 0, "Proprietary data (CDOL)" },
    { 0x9F27, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  1, 1, 0, "Cryptogram Information Data (CID)" },
    { 0x5F2D, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_NUMERIC, 4, 6, 1, "Initial Balance" },
    { 0x9F7F, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_NUMERIC, 4, 6, 0, "Last Balance (optional)" },
    { 0x9F7B, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_NUMERIC, 4, 6, 0, "Cardholder Balance Limit" },
    { 0x9F36, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  2, 2, 1, "Application Transaction Counter (ATC)" },
    { 0x9F3A, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 5, 5, 0, "Terminal Verification Results (TVR)" },

    /* === Required card data === */
    { 0x5A,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_STRING,  10, 19, 1, "Application PAN" },
    { 0x5F20, TAG_SRC_CARD_OTHER,    TAG_TYPE_STRING,  2,  32, 0, "Application Label" },
    { 0x4F,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_AID,     5,  16, 1, "AID (DF Name)" },
    { 0x5F24, TAG_SRC_CARD_OTHER,    TAG_TYPE_DATE,    3,  3, 0, "Application Expiry Date" },

    /* === IAC/TAC thresholds (Book C-6 §4.2) === */
    { 0x9F67, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  2,  2,  0, "Issuer Authentication Requirements (IAC defaults)" },
    { 0x9F65, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  2,  2,  0, "Issuer Authentication Requirements (TAC defaults)" },
    { 0x9F64, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  2,  2,  0, "Issuer Authentication Requirements (IAC defaults)" },

    /* === Output tags === */
    { 0x9F26, TAG_SRC_GENERATED,     TAG_TYPE_BINARY,  8,  8,  1, "Application Cryptogram (TC/STC)" },
    { 0x83,   TAG_SRC_GENERATED,     TAG_TYPE_BINARY,  2,  132, 0, "Terminal Risk Management data" },
    { 0x9F34, TAG_SRC_GENERATED,     TAG_TYPE_BINARY,  3,  3,  0, "CVM Results (always No-CVM for K6)" },
    { 0x9F7C, TAG_SRC_GENERATED,     TAG_TYPE_NUMERIC, 4,  6,  0, "New Balance after transaction" },
    { 0x8A,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_STRING,  2,  2,  0, "Authorisation Response Code (ARC)" },
};

kernel_dict_t kernel6_dict = {
    .kernel_id       = 6,
    .items           = kernel6_items,
    .item_count      = sizeof(kernel6_items) / sizeof(kernel6_items[0]),
    .cvm_plugin      = NULL,  /* Set by integrator */
    .risk_plugin     = NULL,
    .ops             = NULL,  /* Set by integrator */
};

const kernel_config_t *kernel6_get_config(void)
{
    return (const kernel_config_t *)&kernel6_dict;
}
