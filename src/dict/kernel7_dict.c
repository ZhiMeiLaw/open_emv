/**
 * @file src/dict/kernel7_dict.c
 * @brief Kernel 7 (Token Payment) data dictionary.
 *
 * EMV Contactless Book C v2.12, Kernel 7 — Token-Based Transaction
 * Processing. Defines all tags used in token payment workflows
 * including CVM, risk, SDS, fDDA authentication, and outcome tags.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/dict_validate.h"

/* Forward declarations */
extern const struct cvm_plugin_s kernel7_cvm_plugin;
extern const struct risk_plugin_s kernel7_risk_plugin;
extern const struct kernel_ops_s *k7_get_kernel_ops(void);

static dict_item_t kernel7_items[] = {
    /* === TDOL tags (terminal-provided for GENERATE AC) === */
    { 0x9F66, TAG_SRC_TERMINAL,  TAG_TYPE_BITMASK, 4, 4, 1, "Terminal Qualifiers" },
    { 0x9F02, TAG_SRC_TERMINAL,  TAG_TYPE_NUMERIC, 6, 6, 1, "Amount, Authorised" },
    { 0x5F2A, TAG_SRC_TERMINAL,  TAG_TYPE_NUMERIC, 2, 2, 1, "Transaction Currency Code" },
    { 0x9F36, TAG_SRC_TERMINAL,  TAG_TYPE_BINARY,  2, 2, 1, "Token Request Date (SDS code)" },

    /* === GPO response tags === */
    { 0x87,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 1, 2, 1, "Application Interchange Profile (AIP)" },
    { 0xDF9F, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  4, 64, 0, "CDOL data from card" },
    { 0x9F27, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  1, 1, 0, "Cryptogram Information Data (CID)" },

    /* === Required card data (from READ RECORD) === */
    { 0x5A,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_STRING,  10, 19, 1, "Token PAN (replacement PAN)" },
    { 0x5F24, TAG_SRC_CARD_OTHER,    TAG_TYPE_DATE,    3,  3,  0, "Application Expiry Date" },
    { 0x9A,   TAG_SRC_GENERATED,     TAG_TYPE_DATE,    3,  3,  0, "Transaction Date" },
    { 0xA9,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  0,  48, 0, "Token Request Reference Data" },
    { 0x5F28, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_STRING,  2,  32, 0, "Token Hold Name" },
    { 0x4F,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_AID,     5,  16, 1, "AID (DF Name)" },

    /* === fDDA authentication data (from READ RECORD) === */
    { 0x9F4B, TAG_SRC_CARD_OTHER,    TAG_TYPE_BINARY,  4,  256, 0, "Signed Dynamic Application Data (SDAD)" },
    { 0x9F46, TAG_SRC_CARD_OTHER,    TAG_TYPE_BINARY,  64, 256, 0, "ICC Public Key Certificate" },
    { 0x9F69, TAG_SRC_CARD_OTHER,    TAG_TYPE_BINARY,  5,  16,  0, "Card Authentication Related Data" },
    { 0x9F37, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  4,  4,  0, "Unpredictable Number" },
    { 0x9F7E, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  8,  8,  0, "ICC CRT (Tag 9F7E — ODA path)" },

    /* === CTQ / TVR (from GPO / READ RECORD) === */
    { 0x9F6C, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 2,  2,  0, "Card Transaction Qualifiers (CTQ)" },
    { 0x9F3A, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 5,  5,  0, "Terminal Verification Results (TVR)" },

    /* === Output tags === */
    { 0x9F26, TAG_SRC_GENERATED,     TAG_TYPE_BINARY,  8,  8,  1, "Application Cryptogram (ARQC/TAC/AAC)" },
    { 0x9F34, TAG_SRC_GENERATED,     TAG_TYPE_BINARY,  3,  3,  0, "CVM Results" },
    { 0x83,   TAG_SRC_GENERATED,     TAG_TYPE_BINARY,  2,  132, 0, "Token Request Data (wrapper for GENERATE AC input)" },

    /* === Token-specific optional === */
    { 0x9F7D, TAG_SRC_GENERATED,     TAG_TYPE_BINARY,  8,  8,  0, "Additional Terminal Capabilities (token)" },
    { 0x8A,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_STRING,  2,  2,  0, "Authorisation Response Code (ARC)" },
    { 0x5F20, TAG_SRC_CARD_OTHER,    TAG_TYPE_STRING,  2,  32, 0, "Application Label" },
};

kernel_dict_t kernel7_dict = {
    .kernel_id       = 7,
    .items           = kernel7_items,
    .item_count      = sizeof(kernel7_items) / sizeof(kernel7_items[0]),
    .cvm_plugin      = &kernel7_cvm_plugin,
    .risk_plugin     = &kernel7_risk_plugin,
    .ops             = NULL,  /* Set at registration time */
};

const kernel_config_t *kernel7_get_config(void)
{
    return (const kernel_config_t *)&kernel7_dict;
}
