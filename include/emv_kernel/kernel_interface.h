/**
 * @file emv_kernel/kernel_interface.h
 * @brief Plugin interfaces for CVM, Risk Management, Crypto Driver,
 *        and Kernel configuration/dispatch.
 *
 * These structs are the contract between kernel framework core and
 * user-provided implementations. Each kernel gets its own set of
 * plugins registered at startup.
 */

#ifndef EMV_KERNEL_KERNEL_INTERFACE_H
#define EMV_KERNEL_KERNEL_INTERFACE_H

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"

/* Forward declarations */
struct crypto_driver_s;
struct outcome_result_s;  /* defined in orchestrator.h */

/* Forward declarations to avoid circular deps */
struct crypto_driver_s;

/* ================================================================== */
/*  CVM Plugin Interface                                              */
/* ================================================================== */

/* cvm_result_t, cvm_plugin_t — enum already defined in types.h */

typedef struct cvm_plugin_s {
    /**
     * Evaluate cardholder verification conditions.
     * @param ctx Transaction context with warehouse, POS params, ICCDB.
     * @return CVM_PASS, CVM_FAIL, or CVM_NOT_SUPPORTED.
     */
    cvm_result_t (*evaluate)(const void *ctx);

    /**
     * Return the CVM method used (per EMV table).
     * 0x00 = No CVM, 0x01 = Plain PIN, 0x02 = Encrypted PIN, etc.
     * @param ctx Transaction context.
     * @return CVM method code, or 0xFF if unknown.
     */
    uint8_t (*get_method)(const void *ctx);

    uint8_t version;   /**< Plugin interface version */
} cvm_plugin_t;


/* ================================================================== */
/*  Risk Plugin Interface                                             */
/* ================================================================== */

/* risk_result_t, risk_check_type_t already defined in types.h */

typedef struct risk_plugin_s {
    /**
     * Check a specific risk category.
     */
    risk_result_t (*check)(const void *ctx, risk_check_type_t type);

    /**
     * Build Terminal Conduction Data with risk parameters.
     * Called when outcome is APPROVE.
     * @param tc_wh Output TLV warehouse for TC tags.
     * @return 0 on success, -1 on error.
     */
    int (*build_tc_risk_data)(const void *ctx, tx_warehouse_t *tc_wh);

    /**
     * Update ICCDB after a successful transaction.
     * Increments counters, updates velocity data, etc.
     * @param iccdb Pointer to caller's ICCDB state.
     * @return 0 on success.
     */
    int (*update_iccdb)(void *iccdb, const void *ctx);

    uint8_t version;
} risk_plugin_t;


/* ================================================================== */
/*  Crypto Driver Interface                                           */
/* ================================================================== */

typedef struct crypto_driver_s {
    /**
     * RSA-PKP signature verification (for SDA).
     * Verifies ICA certificate against ACM(A) and checks DDIC against DOL hash.
     */
    int (*rsa_pkpad_verify)(
        const uint8_t *cert_der, size_t cert_len,
        const uint8_t *ddic, size_t ddic_len,
        const uint8_t *data, size_t data_len);

    /**
     * DES decrypt for ODA Dynamic Number Layer.
     * Decrypts ICData using the ICA symmetric key.
     */
    int (*des_decrypt)(
        const uint8_t *key, size_t key_len,
        const uint8_t *ic_data, size_t ic_data_len,
        uint8_t *out, size_t *out_len);

    /**
     * TDES-CMAC verification for ODA ICC CRT check.
     * Computes MAC over CDOL2 + ICDN and compares with tag [9F7E].
     */
    int (*tdes_mac_verify)(
        const uint8_t *key, size_t key_len,
        const uint8_t *data, size_t data_len,
        const uint8_t *expected_mac, size_t mac_len);

    /**
     * Generate application cryptogram (ARQC, CAC, Card Authentication Code, etc.)
     */
    int (*generate_cryptogram)(
        crypto_alg_t alg,
        const uint8_t *key, size_t key_len, uint8_t key_index,
        const uint8_t *dol_data, size_t dol_len,
        uint8_t *cryptogram, size_t *cryptogram_len);

    /**
     * Extract keys from an ICA Public Key Certificate (DER).
     * @param sym_key     Output: symmetric key for DES/TDES operations (up to 16 bytes)
     * @param sym_key_len Output: actual symmetric key length
     * @param pub_key     Output: public key component (for RSA verify)
     * @param pub_key_len Output: actual public key length
     */
    int (*ica_key_extract)(
        const uint8_t *cert_der, size_t cert_len,
        uint8_t *sym_key, size_t *sym_key_len,
        uint8_t *pub_key, size_t *pub_key_len);

    uint8_t version;
} crypto_driver_t;


/* ================================================================== */
/*  Kernel Operations — per-kernel processing hooks                    */
/* ================================================================== */
/**
 * Per-kernel processing context — shared between kernel framework and ops.
 */
typedef struct {
    tx_warehouse_t *wh;               /* Transaction warehouse               */
    const crypto_driver_t *crypto;    /* Crypto driver                       */
    uint8_t online_required   : 1;    /* Set when card requests online auth  */
    uint8_t decline_required  : 1;    /* Set when card requires decline      */
    uint8_t auth_done         : 1;    /* Auth completed                      */
    auth_method_t auth_method;        /* Result of auth (SDA/ODA/NONE)       */
} kernel_hook_ctx_t;

/**
 * Per-kernel operation hooks. The kernel framework calls these at
 * specific points in the transaction flow. Each kernel implements
 * its own ops — the framework remains generic.
 *
 * Return 0 on success, negative on failure (outcome is handled
 * internally by the framework based on the return code).
 */
typedef struct kernel_ops_s {
    /**
     * Processing Restrictions check (Book C-3 §5.5).
     * Called after Card Read Complete, before Offline Data Auth.
     * @param ctx  Transaction context with full warehouse.
     * @return 0 = OK, -1 = decline, -2 = online required.
     */
    int (*check_processing_restrictions)(kernel_hook_ctx_t *ctx);

    /**
     * Offline Data Authentication (Book C-3 §5.6).
     * Called after Processing Restrictions.
     * Sets auth_done flag on success.
     * @param ctx         Transaction context.
     * @param auth_result Output: auth method (SDA/ODA/NONE).
     * @return 0 = OK, -1 = auth failed (caller decides outcome).
     */
    int (*check_offline_auth)(kernel_hook_ctx_t *ctx, auth_method_t *auth_result);

    /**
     * Cardholder Verification — build CVM results tag.
     * Called after Offline Data Auth.
     * @param ctx  Transaction context.
     * @return 0 = OK, -1 = CVM fail (decline).
     */
    int (*build_cvm_results)(kernel_hook_ctx_t *ctx);

    /**
     * Generate AC command data (Book C-3 §5.8 / §5.9).
     * Called before GENERATE AC. Populates output warehouse.
     * @param ctx      Transaction context.
     * @param out_wh   Output warehouse to populate.
     * @return 0 = OK.
     */
    int (*build_generate_ac)(const kernel_hook_ctx_t *ctx, tx_warehouse_t *out_wh);

    /**
     * Parse GENERATE AC response and determine outcome.
     * Called after GENERATE AC response is received.
     * Sets online_required / decline_required flags.
     * @param ctx  Transaction context.
     * @return 0 = OK.
     */
    int (*parse_generate_ac_response)(kernel_hook_ctx_t *ctx);

} kernel_ops_t;


/* ================================================================== */
/*  Terminal / ACQ Interface (for ARPC flow)                          */
/* ================================================================== */

typedef struct term_acq_interface_s {
    /**
     * Encrypt ARQC and format NASP for transmission to acquirer.
     * Returns the wire-format bytes that get sent back to the card.
     */
    int (*encrypt_arqc_and_build_nasp)(
        const uint8_t *arqc, size_t arqc_len,
        const uint8_t *key, size_t key_len, uint8_t key_index,
        uint8_t *nasp_out, size_t *nasp_len);

    /**
     * Parse ARPC (Acquirer Release Process Code) response from acquirer.
     * Extracts outcome decision and terminal verification data.
     */
    int (*parse_arpc_response)(
        const uint8_t *arpc_data, size_t arpc_len,
        uint8_t *tvr_out, size_t *tvr_len,
        outcome_code_t *outcome_out);

    uint8_t version;
} term_acq_interface_t;


/* ================================================================== */
/*  Kernel Context — passed to all plugin callbacks                   */
/* ================================================================== */

typedef struct {
    /* Data warehouse with all TLV data collected so far */
    tx_warehouse_t *input_wh;
    tx_warehouse_t *output_wh;         /* For building TC/NASP           */

    /* Terminal parameters (loaded by orchestrator before kernel run) */
    const void *pos_params;            /* Platform-defined POS config    */

    /* ICCDB state (caller-owned persistent card data) */
    void *iccdb;

    /* Auth result (set by entry point before kernel execution) */
    auth_method_t auth_method;
    uint8_t has_verified_sda : 1;
    uint8_t has_verified_oda : 1;

    /* Cached ICA symmetric key (from ODA DNL step) */
    uint8_t ica_sym_key[16];
    uint8_t ica_sym_key_len;

    /* Plugin handles */
    const crypto_driver_t *crypto;
    const term_acq_interface_t *acq_iface;

    /* Outcome result being assembled */
    struct outcome_result_s *outcome;
} kernel_context_t;

#endif /* EMV_KERNEL_KERNEL_INTERFACE_H */
