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
extern const struct kernel_ops_s *k3_get_kernel_ops(void);

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

    /* === GPO response tags (from GET PROCESSING OPTIONS) === */
    { 0x87,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 1, 2, 0, "Application Interchange Profile (AIP)" },
    { 0x82,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 1, 2, 0, "Application Usage Control (AUC)" },
    { 0x94,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  3, 252, 0, "Application File Locator (AFL)" },
    { 0xDF9F, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  4, 64, 0, "Proprietary tag (CDOL1, etc.)" },
    { 0x9F27, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  1, 1, 0, "Cryptogram Information Data (CID)" },

    /* === Required card data (from READ RECORD) === */
    { 0x5A,   TAG_SRC_CARD_OTHER,    TAG_TYPE_STRING,  5, 19, 1, "Application PAN" },
    { 0x5F20, TAG_SRC_CARD_OTHER,    TAG_TYPE_STRING,  2, 32, 0, "Application Label" },
    { 0x5F24, TAG_SRC_CARD_OTHER,    TAG_TYPE_DATE,    3, 3, 0, "Application Expiry Date" },
    { 0x4F,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_AID,     5, 16, 1, "AID (DF Name)" },
    { 0x9F36, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BINARY,  2, 2, 1, "Application Transaction Counter (ATC)" },
    { 0x95,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 5, 5, 1, "Terminal Verification Results (TVR)" },

    /* === fDDA data (from last READ RECORD) === */
    { 0x9F69, TAG_SRC_CARD_OTHER,    TAG_TYPE_BINARY,  5, 16, 0, "Card Authentication Related Data" },
    { 0x9F6C, TAG_SRC_CARD_GPO_RESP, TAG_TYPE_BITMASK, 2, 2, 0, "Card Transaction Qualifiers (CTQ)" },
    { 0x9F4B, TAG_SRC_CARD_OTHER,    TAG_TYPE_BINARY,  4, 256, 0, "Signed Dynamic Application Data (SDAD)" },

    /* === Output tags === */
    { 0x9F26, TAG_SRC_GENERATED,     TAG_TYPE_BINARY,  8, 8, 1, "Application Cryptogram (ARQC/TAC/AAC)" },
    { 0x8A,   TAG_SRC_CARD_GPO_RESP, TAG_TYPE_STRING,  2, 2, 0, "Authorisation Response Code (ARC)" },
    { 0x9F34, TAG_SRC_GENERATED,     TAG_TYPE_BINARY,  3, 3, 0, "Terminal Result Tags (CVM results)" },
};

kernel_dict_t kernel3_dict = {
    .kernel_id       = 3,
    .items           = kernel3_items,
    .item_count      = sizeof(kernel3_items) / sizeof(kernel3_items[0]),
    .cvm_plugin      = NULL,  /* Set by integrator at registration time */
    .risk_plugin     = NULL,
    .ops             = NULL,  /* Set by integrator at registration time */
};

const kernel_config_t *kernel3_get_config(void)
{
    return (const kernel_config_t *)&kernel3_dict;
}
