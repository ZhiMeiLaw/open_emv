/**
 * @file src/dict/kernel7_dict.c
 * @brief Kernel 7 (Token Payment) data dictionary.
 *
 * EMV Contactless Book C v2.12, Kernel 7 — Token-Based Transaction Processing.
 * Defines all tags used in token payment workflows including CVM, risk,
 * and authentication-related tags.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/dict_validate.h"

/* Forward declarations */
extern const struct cvm_plugin_s kernel7_cvm_plugin;
extern const struct risk_plugin_s kernel7_risk_plugin;
extern const struct kernel_ops_s *k7_get_kernel_ops(void);

static dict_item_t kernel7_items[] = {
    /* === Token-specific TDOL tags === */
    { 0x9F66, TAG_SRC_TERMINAL,  TAG_TYPE_BITMASK, 4, 4, 1, "Terminal Qualifiers (required for token)" },
    { 0x9F02, TAG_SRC_TERMINAL,  TAG_TYPE_NUMERIC, 6, 6, 1, "Amount, Authorised" },
    { 0x5F2A, TAG_SRC_TERMINAL,  TAG_TYPE_NUMERIC, 2, 2, 1, "Transaction Currency Code" },

    /* === Token identifiers === */
    { 0x5A,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_STRING, 10,19, 1, "Token PAN (replacement for real PAN)" },
    { 0xA9,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY, 0,48, 0, "Token Request Reference Data" },
    { 0x5F28, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_STRING, 2,32, 0, "Token Hold Name" },
    { 0x9F7D, TAG_SRC_GENERATED,     TAG_TYPE_BINARY, 8, 8, 0, "Additional Terminal Capabilities (token)" },

    /* === SDS (Signature Data Set) === */
    { 0x9F36, TAG_SRC_TERMINAL,      TAG_TYPE_BINARY, 2, 2, 1, "Token Request Date / SDS code" },

    /* === GPO response tags === */
    { 0x87,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 1, 2, 1, "Application Interchange Profile (AIP)" },
    { 0xDF9F, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  4,64, 0, "CDOL data from card" },

    /* === Cryptogram & outcome === */
    { 0x9F27, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY, 8, 8, 1, "Cryptogram output tag" },
    { 0x9F26, TAG_SRC_GENERATED,       TAG_TYPE_BINARY, 8, 8, 1, "ARQC for token auth" },
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
