/**
 * @file examples/ref_k3/k3_ref_crypto.c
 * @brief Kernel 3 reference: sample crypto driver implementation.
 *
 * This file provides a MOCK crypto driver for integrators to understand
 * the expected I/O format. Replace each function body with real HW calls
 * on your platform.
 *
 * Integration guide:
 *  - rsa_pkpad_verify()   → call your RSA accelerator or soft RSA library
 *  - des_decrypt()        → call DES accelerator / soft DES
 *  - tdes_mac_verify()    → call TDES-CMAC accelerator
 *  - generate_cryptogram→ call TDES-CMAC on DOL data (ARQC)
 *  - ica_key_extract()    → parse DER ICA cert, extract symmetric + public keys
 */

#include "emv_kernel/types.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ================================================================== */
/*  Example: RSA-PKP verify (SDA path)                                */
/* ================================================================== */
/**
 * Expected flow:
 * 1. Parse ACM(A) certificate chain — verify ACM(A) signed by EMVCo root
 * 2. Decrypt DDIC using ACM(A) private key (RSA-2048 PK padding)
 * 3. Hash the DOL data (tags from kernel dictionary verification list)
 * 4. Compare hash with decrypted DDIC content
 * 5. Return 0 if match → card is genuine
 */
static int ref_rsa_pkpad_verify(const uint8_t *cert_der, size_t cert_len,
                                const uint8_t *ddic, size_t ddic_len,
                                const uint8_t *data, size_t data_len)
{
    /* INTEGRATOR: Replace body with:
     *
     * Step 1: Verify ACM(A) signature against EMVCo root
     *         acm_cert = load_acm_certificate(acm_id);
     *         rsa_verify(acm_cert->sig, acm_cert->pubkey, data_hash);
     *
     * Step 2: Decrypt DDIC from ICA certificate
     *         decrypted = rsa_decrypt_pkcs1(ic_cert);
     *
     * Step 3: Hash DOL data per kernel spec
     *         sha1_result = sha1(data, data_len);
     *         sha256_result = sha256(data, data_len);  // modern
     *
     * Step 4: Compare DDIC with hash
     *         return memcmp(ddic, hash, ddic_len) == 0 ? 0 : -1;
     *
     * Mock: Just validate buffer sizes and return success
     */
    if (!cert_der || cert_len == 0) return CRYPTO_E_INVAL;
    if (!ddic || ddic_len == 0) return CRYPTO_E_INVAL;
    if (!data || data_len == 0) return CRYPTO_E_INVAL;
    return 0;  // Mock: assume verification passes
}

/* ================================================================== */
/*  Example: DES decrypt (ODA DNL step)                               */
/* ================================================================== */
/**
 * Expected flow:
 * 1. Card sends ICData in SET ATTRIBUTE response [9F8C]
 * 2. Terminal has ICA symmetric key from cert extraction
 * 3. DES decrypt(ICData) → raw dynamic number
 * 4. Unpad result to get the unpredictable number from card
 */
static int ref_des_decrypt(const uint8_t *key, size_t key_len,
                           const uint8_t *ic_data, size_t ic_data_len,
                           uint8_t *out, size_t *out_len)
{
    /* INTEGRATOR: Replace body with:
     *
     * Step 1: DES-ECB decrypt ICData block by block
     *         for each 8-byte block:
     *             des_ecb_decrypt(block, key, out_block)
     *
     * Step 2: Remove padding (ISO/IEC 7816-4 unpadding)
     *         Find first non-0x80 byte from end of result
     *         Truncate after that point
     *
     * Step 3: Result is the Dynamic Number (DN)
     *         DN length is typically 4 bytes (for CDOL1 unpredictable num)
     */
    if (!key || !ic_data || !out || !out_len) return CRYPTO_E_INVAL;
    if (key_len != 8 && key_len != 16) return CRYPTO_E_INVAL;  // DES or TDES key
    if (ic_data_len == 0) return CRYPTO_E_INVAL;

    /* Mock: copy input to output as-is (real impl would actually decrypt) */
    size_t copy_len = ic_data_len < *out_len ? ic_data_len : *out_len;
    memcpy(out, ic_data, copy_len);
    *out_len = (size_t)copy_len;
    return 0;
}

/* ================================================================== */
/*  Example: TDES-MAC verify (ODA ICC CRT check)                      */
/* ================================================================== */
/**
 * Expected flow:
 * 1. Build CDOL2 data from GPO response + decrypted dynamic number
 * 2. Compute TDES-CMAC over CDOL2 + dynamic number using ICA key
 * 3. Compare MAC with [9F7E] (ICC CRT) from card response
 * 4. Match = ODA authentication passed
 */
static int ref_tdes_mac_verify(const uint8_t *key, size_t key_len,
                               const uint8_t *data, size_t data_len,
                               const uint8_t *expected_mac, size_t mac_len)
{
    /* INTEGRATOR: Replace body with:
     *
     * Step 1: Build the MAC input
     *         mac_input = cdol2_data + dynamic_number_from_DNL
     *
     * Step 2: Compute TDES-CMAC (ANSI X9.19 CBC-MAC)
     *         computed_mac = tdes_cmac(key, mac_input, input_len)
     *
     * Step 3: Compare with ICC CRT [9F7E] from card
     *         return memcmp(computed_mac, expected_mac, mac_len) == 0 ? 0 : -1;
     */
    if (!key || !data || !expected_mac) return CRYPTO_E_INVAL;
    if (key_len != 16) return CRYPTO_E_INVAL;  // Must be 3DES key (2-key or 3-key TDES)

    /* Mock: compare expected with a dummy value (0xAA repeated) */
    uint8_t dummy_mac[8];
    memset(dummy_mac, 0xAA, sizeof(dummy_mac));
    return memcmp(expected_mac, dummy_mac, mac_len < 8 ? mac_len : 8);
}

/* ================================================================== */
/*  Example: Generate cryptogram (ARQC for K3)                       */
/* ================================================================== */
/**
 * Expected flow for ARQC (Application Cryptogram — Authorise):
 * 1. Build DOL data per kernel's TDOL:
 *    [9F16] TN (4B) + [9F02] Amount (6B) + [9F36] Amt Other (2B)
 *    + [9F03] Default Amt (6B) + [5F2A] Currency (2B) + [9F66] TQ (4B)
 * 2. Pad DOL data to 8-byte boundary (ISO/IEC 9797-1 Method 3 padding)
 * 3. Compute TDES-CMAC using application cryptogram key
 * 4. First 8 bytes = ARQC
 */
static int ref_generate_cryptogram(crypto_alg_t alg,
                                   const uint8_t *key, size_t key_len,
                                   uint8_t key_index,
                                   const uint8_t *dol_data, size_t dol_len,
                                   uint8_t *cryptogram, size_t *cryptogram_len)
{
    /* INTEGRATOR: Replace body with:
     *
     * Step 1: Pad DOL to 8-byte boundary
     *         padding_byte = 0x80
     *         while (dol_len % 8 != 0) { dol[dol_len++] = 0x00; }
     *         dol[--dol_len] |= 0x80;  // OR the last padding byte
     *
     * Step 2: Get the correct application key
     *         app_key = lookup_app_key(key_index, pan_or_aid)
     *         // Keys may be per-application or global
     *
     * Step 3: Compute TDES-CMAC (CBC-MAC with last block)
     *         arqc = tdes_cmac(app_key, padded_dol, padded_len)
     *         // Result is already 8 bytes (single DES-CBC-MAC block)
     *
     * Step 4: For 3DES variant, use 3-key TDES
     *         arqc = tdes3_cmac(app_key_3key, padded_dol, padded_len)
     *
     * For CAC (Kernel 5), the process is similar but uses a different key.
     */
    (void)key_index;
    if (!key || !dol_data || dol_len == 0) return CRYPTO_E_INVAL;

    /* Mock: produce a dummy 8-byte cryptogram */
    memset(cryptogram, 0xDE, 8);  /* 0xDEADBEEF... pattern */
    *cryptogram_len = 8;
    return 0;
}

/* ================================================================== */
/*  Example: Extract keys from ICA certificate (DER)                  */
/* ================================================================== */
/**
 * Expected flow:
 * 1. Parse DER-encoded ICA Public Key Certificate
 * 2. Extract the symmetric key (used for DES/TDES operations)
 *    - This is stored within the certificate (tag-specific to EMV)
 * 3. Extract RSA public key (used for SDA verification)
 */
static int ref_ica_key_extract(const uint8_t *cert_der, size_t cert_len,
                               uint8_t *sym_key, size_t *sym_key_len,
                               uint8_t *pub_key, size_t *pub_key_len)
{
    /* INTEGRATOR: Replace body with:
     *
     * Step 1: Parse ASN.1 DER structure
     *         Sequence {
     *           AlgorithmIdentifier (rsaEncryption)
     *           BIT STRING (certificate content)
     *         }
     *
     * Step 2: Within certificate content, find symmetric key field
     *         The symmetric key encoding varies by country/payment system:
     *         - China: GM/T 160 format — key at offset ~20 bytes into cert
     *         - International: Key embedded in certificate body
     *
     * Step 3: Copy symmetric key to sym_key buffer
     *         Typical sizes: 8 bytes (DES) or 16 bytes (TDES)
     *
     * Step 4: Extract RSA modulus and exponent for pub_key
     *         DER-sequence { moduli: INTEGER, exponent: INTEGER }
     *         Typically 256 bytes modulus (RSA-2048)
     */
    if (!cert_der || cert_len == 0) return CRYPTO_E_INVAL;
    if (!sym_key_len || !pub_key_len) return CRYPTO_E_INVAL;

    /* Mock: fill with placeholder keys */
    if (*sym_key_len >= 8) {
        memset(sym_key, 0xBB, 8);  // 8-byte mock DES key
        *sym_key_len = 8;
    }

    if (*pub_key_len >= 256) {
        memset(pub_key, 0xCC, 256);  // 256-byte mock RSA public key
        *pub_key_len = 256;
    }

    return 0;
}

/* ================================================================== */
/*  Crypto Driver instance                                            */
/* ================================================================== */

const crypto_driver_t ref_crypto_driver = {
    .rsa_pkpad_verify = ref_rsa_pkpad_verify,
    .des_decrypt      = ref_des_decrypt,
    .tdes_mac_verify  = ref_tdes_mac_verify,
    .generate_cryptogram = ref_generate_cryptogram,
    .ica_key_extract  = ref_ica_key_extract,
    .version          = 1,
};
