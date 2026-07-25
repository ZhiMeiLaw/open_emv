/**
 * @file src/dict/kernel3_dict.c
 * @brief Kernel 3 (Debit/Credit) data dictionary.
 *
 * Based on EMV Contactless Book C v2.12, Kernel 3 specification.
 * Supports offline PIN and No-CVM for debit/credit transactions.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/dict_validate.h"

/* Forward declarations — defined by integrator in examples/ref_k3/ */
extern struct cvm_plugin_s kernel3_cvm_plugin;
extern struct risk_plugin_s kernel3_risk_plugin;

/* ---- TDOL tags (Book C K3 §4.6) ---- */
static const uint32_t kernel3_tdol[] = {
    0x9F16,  /* Transaction Number (TN)          */
    0x9F02,  /* Amount, Authorised (Terminal)     */
    0x9F36,  /* Amount, Other (Terminal)          */
    0x9F03,  /* Other Amount (Const/default)      */
    0x5F2A,  /* Transaction Currency Code         */
    0x9F66,  /* Terminal Qualifiers               */
};

/* ---- Dictionary items — all tags used by Kernel 3 ---- */
static dict_item_t kernel3_items[] = {
    /* === TDOL (send to card) === */
    { 0x9F16, TAG_SRC_GENERATED, TAG_TYPE_NUMERIC,  4, 4, 1, "Transaction Number (TN)" },
    { 0x9F02, TAG_SRC_TERMINAL,  TAG_TYPE_NUMERIC,  6, 6, 1, "Amount, Authorised" },
    { 0x9F36, TAG_SRC_TERMINAL,  TAG_TYPE_NUMERIC,  2, 2, 1, "Amount, Other" },
    { 0x9F03, TAG_SRC_CONST,     TAG_TYPE_NUMERIC,  6, 6, 1, "Other Amount (default 0)" },
    { 0x5F2A, TAG_SRC_TERMINAL,  TAG_TYPE_NUMERIC,  2, 2, 1, "Transaction Currency Code" },
    { 0x9F66, TAG_SRC_TERMINAL,  TAG_TYPE_BITMASK,  4, 4, 1, "Terminal Qualifiers" },

    /* === Card response tags (from GPO / Get Processing Options) === */
    { 0x87,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 1, 2, 1, "Application Interchange Profile (AIP)" },
    { 0x82,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 1, 2, 1, "Application Usage Control (AUC)" },
    { 0x94,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  5,32, 1, "Select Data (ADF Name + SFI)" },
    { 0xDF9F, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  4,64, 0, "Proprietary tag (CDOL1, etc.)" },

    /* === Required card data === */
    { 0x5A,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_STRING,  5,19, 1, "Application Primary Account Number (PAN)" },
    { 0x5F20, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_STRING,  2,32, 0, "Application Label" },
    { 0x5F24, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_DATE,    3, 3, 0, "Application Expiry Date" },
    { 0x4F,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_AID,     5,16, 1, "Dedicated File (DF) Name — AID" },

    /* === Cryptogram & verification output tags === */
    { 0x9F27, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  8, 8, 1, "Cryptogram (Card Authentication Code)" },
    { 0x9F3A, TAG_SRC_TERMINAL,      TAG_TYPE_BINARY,  2, 2, 0, "APPROVAL CODE / AUTHORISATION RESPONSE CODE" },
    { 0x9F34, TAG_SRC_TERMINAL,      TAG_TYPE_BINARY,  4, 4, 1, "Terminal Result Tags" },

    /* === Terminal verification result (TVR) — 5 bytes === */
    { 0x9F3A, TAG_SRC_GENERATED, TAG_TYPE_BINARY, 5, 5, 0, "Terminal Verification Results (TVR)" },

    /* === Outcome parameters === */
    { 0x9F26, TAG_SRC_GENERATED, TAG_TYPE_BINARY, 8, 8, 1, "Application Cryptogram (ARQC)" },
    { 0x5F34, TAG_SRC_TERMINAL,  TAG_TYPE_STRING, 1,32, 0, "Merchant Name and Location" },
    { 0x9F4E, TAG_SRC_TERMINAL,  TAG_TYPE_STRING, 1,16, 0, "Merchant Category Code" },
};

kernel_dict_t kernel3_dict = {
    .kernel_id       = 3,
    .items           = kernel3_items,
    .item_count      = sizeof(kernel3_items) / sizeof(kernel3_items[0]),
    .cvm_plugin      = NULL,  /* Set by integrator at registration time */
    .risk_plugin     = NULL,
};

const kernel_config_t *kernel3_get_config(void)
{
    return (const kernel_config_t *)&kernel3_dict;
}
