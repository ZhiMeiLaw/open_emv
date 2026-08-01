/**
 * @file src/dict/kernel5_dict.c
 * @brief Kernel 5 (qVISA / Crypto) data dictionary.
 *
 * Based on EMV Contactless Book C-5 v2.12.
 * Minimal CVM — amount-only check, no PIN support.
 * Supports CDA (Composite Data Authentication) card authentication.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/dict_validate.h"

/* Forward declarations */
extern struct cvm_plugin_s kernel5_cvm_plugin;
extern struct risk_plugin_s kernel5_risk_plugin;
extern const struct kernel_ops_s *k5_get_kernel_ops(void);

/* Dictionary items for Kernel 5 */
static dict_item_t kernel5_items[] = {
    /* === CDOL1 (from READ RECORD, used for GENERATE AC) === */
    { 0x8C,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  2, 64, 1, "CDOL1 (Command DOL 1)" },

    /* === TDOL-like tags (terminal-provided for GENERATE AC) === */
    { 0x9F02, TAG_SRC_TERMINAL,  TAG_TYPE_NUMERIC,  6, 6, 1, "Amount, Authorised" },
    { 0x5F2A, TAG_SRC_TERMINAL,  TAG_TYPE_NUMERIC,  2, 2, 1, "Transaction Currency Code" },
    { 0x9F66, TAG_SRC_TERMINAL,  TAG_TYPE_BITMASK,  4, 4, 1, "Terminal Qualifiers" },

    /* === Card response from GPO === */
    { 0x82,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 1, 2, 1, "Application Interchange Profile (AIP)" },
    { 0x87,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 1, 2, 0, "Application Priority Indicator" },
    { 0x94,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  3, 252, 0, "Application File Locator (AFL)" },
    { 0x9F37, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  4, 4, 0, "Unpredictable Number" },
    { 0x9F27, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 1, 1, 0, "Cryptogram Information Data (CID)" },

    /* === Required card data === */
    { 0x5A,   TAG_SRC_CARD_OTHER,    TAG_TYPE_STRING,  5, 19, 1, "Application PAN" },
    { 0x4F,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_AID,     5, 16, 1, "AID (DF Name)" },
    { 0x5F24, TAG_SRC_CARD_OTHER,    TAG_TYPE_DATE,    3, 3, 1, "Application Expiry Date" },
    { 0x57,   TAG_SRC_CARD_OTHER,    TAG_TYPE_BINARY,  2, 19, 1, "Track 2 Equivalent Data" },

    /* === CDA data (from READ RECORD) === */
    { 0x9F4B, TAG_SRC_CARD_OTHER,    TAG_TYPE_BINARY,  4, 256, 0, "Signed Dynamic Application Data (SDAD)" },
    { 0x9F46, TAG_SRC_CARD_OTHER,    TAG_TYPE_BINARY,  64, 256, 0, "ICC Public Key Certificate" },
    { 0x9F47, TAG_SRC_CARD_OTHER,    TAG_TYPE_BINARY,  1, 3, 0, "ICC Public Key Exponent" },
    { 0x9F48, TAG_SRC_CARD_OTHER,    TAG_TYPE_BINARY,  0, 248, 0, "ICC Public Key Remainder" },
    { 0x90,   TAG_SRC_CARD_OTHER,    TAG_TYPE_BINARY,  64, 256, 0, "Issuer Public Key Certificate" },
    { 0x9F32, TAG_SRC_CARD_OTHER,    TAG_TYPE_BINARY,  1, 3, 0, "Issuer Public Key Exponent" },
    { 0x92,   TAG_SRC_CARD_OTHER,    TAG_TYPE_BINARY,  0, 248, 0, "Issuer Public Key Remainder" },
    { 0x8F,   TAG_SRC_CARD_OTHER,    TAG_TYPE_BINARY,  1, 1, 0, "CAPK Index" },

    /* === CVM status (from GENERATE AC response) === */
    { 0x9F50, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  1, 1, 0, "Cardholder Verification Status" },
    { 0x9F53, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  2, 2, 0, "Terminal Interchange Profile (dynamic)" },

    /* === Outcome tags === */
    { 0x9F26, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  8, 8, 1, "Application Cryptogram (AC)" },
    { 0x9F34, TAG_SRC_GENERATED,     TAG_TYPE_BINARY,  3, 3, 0, "CVM Results" },
    { 0x95,   TAG_SRC_GENERATED,     TAG_TYPE_BITMASK, 5, 5, 0, "Terminal Verification Results (TVR)" },
    { 0x8A,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_STRING,  2, 2, 0, "Authorisation Response Code (ARC)" },
    { 0x9F60, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  1, 1, 0, "Issuer Update Parameter" },
};

kernel_dict_t kernel5_dict = {
    .kernel_id       = 5,
    .items           = kernel5_items,
    .item_count      = sizeof(kernel5_items) / sizeof(kernel5_items[0]),
    .cvm_plugin      = NULL,  /* Set by integrator */
    .risk_plugin     = NULL,
    .ops             = NULL,  /* Set by integrator */
};

const kernel_config_t *kernel5_get_config(void)
{
    return (const kernel_config_t *)&kernel5_dict;
}
