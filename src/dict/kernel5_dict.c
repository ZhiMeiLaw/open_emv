/**
 * @file src/dict/kernel5_dict.c
 * @brief Kernel 5 (qVISA / Crypto) data dictionary.
 *
 * Based on EMV Contactless Book C v2.12, Kernel 5 specification.
 * Minimal CVM — amount-only check, no PIN support.
 * Supports both ODA and SDA card authentication.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/dict_validate.h"

/* Forward declarations */
extern struct cvm_plugin_s kernel5_cvm_plugin;
extern struct risk_plugin_s kernel5_risk_plugin;

/* Dictionary items for Kernel 5 */
static dict_item_t kernel5_items[] = {
    /* === TDOL (Book C K5 §4.7.2 — simplified) === */
    { 0x9F02, TAG_SRC_TERMINAL,  TAG_TYPE_NUMERIC, 6, 6, 1, "Amount, Authorised" },
    { 0x5F2A, TAG_SRC_TERMINAL,  TAG_TYPE_NUMERIC, 2, 2, 1, "Transaction Currency Code" },

    /* === Card response from GPO === */
    { 0x87,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 1, 2, 1, "Application Interchange Profile (AIP)" },
    { 0x82,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 1, 2, 1, "Application Usage Control (AUC)" },
    { 0xDF9F, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  4,64, 0, "CDOL1 / CDOL2 data" },
    { 0x9F37, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  4, 4, 0, "Unpredictable Number" },

    /* === Required card data === */
    { 0x5A,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_STRING, 5,19, 1, "PAN" },
    { 0x4F,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_AID,    5,16, 1, "AID" },
    { 0x87,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK,1, 2, 1, "AIP" },

    /* === CVM-specific tags === */
    { 0x9F6B, TAG_SRC_GENERATED, TAG_TYPE_BINARY, 4, 4, 1, "Cryptogram Reference Value (CRV)" },
    { 0x9F7D, TAG_SRC_GENERATED, TAG_TYPE_BINARY, 8, 8, 0, "Additional Terminal Capabilities" },

    /* === Outcome output tags === */
    { 0x9F27, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY, 8, 8, 1, "Card Authentication Code (CAC)" },
    { 0x9F26, TAG_SRC_GENERATED,       TAG_TYPE_BINARY, 8, 8, 1, "ARQC (if online needed)" },
};

kernel_dict_t kernel5_dict = {
    .kernel_id       = 5,
    .items           = kernel5_items,
    .item_count      = sizeof(kernel5_items) / sizeof(kernel5_items[0]),
    .cvm_plugin      = NULL,  /* Set by integrator */
    .risk_plugin     = NULL,
};

const kernel_config_t *kernel5_get_config(void)
{
    return (const kernel_config_t *)&kernel5_dict;
}
