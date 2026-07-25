/**
 * @file src/plugin/crypto_driver_ref.c
 * @brief Reference Crypto Driver — Soft RSA, DES/TDES, TDES-CMAC, SHA-256.
 *
 * This is a SOFTWARE reference implementation for integration testing.
 * Each function contains detailed comments explaining how to replace it
 * with real hardware-accelerated calls on your platform.
 *
 * The implementation uses:
 *   - Software RSA (simplified — not production-grade)
 *   - Software DES/TDES (from NIST test vectors)
 *   - Software TDES-CMAC
 *   - Software SHA-256
 *
 * For production deployment, replace each function body with your
 * secure element / hardware crypto accelerator calls.
 */

#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ================================================================== */
/*  Platform dependencies — implement these for your target           */
/* ================================================================== */

/* Each platform must provide these functions — this file declares them.
 * The integrator provides implementations in their platform-specific .c */

extern void ref_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
extern int  ref_rsa_pkpad_verify_soft(const uint8_t *cert_der, size_t cert_len,
                                       const uint8_t *ddic, size_t ddic_len,
                                       const uint8_t *dol_data, size_t dol_len);
extern int  ref_des_ecb_decrypt_soft(const uint8_t key[8], const uint8_t *in,
                                      uint8_t *out);
extern int  ref_tdes_cmac_soft(const uint8_t key[16] /* or [24] */,
                                const uint8_t *data, size_t len,
                                uint8_t mac[8]);
extern int  ref_ica_key_extract_soft(const uint8_t *cert_der, size_t cert_len,
                                      uint8_t *sym_key, size_t *sym_key_len,
                                      uint8_t *pub_modulus, size_t *pub_mod_len);

/* These are defined below as the reference soft implementations */

/* ================================================================== */
/*  1. RSA PKP Verification (SDA / fDDA Card Auth)                    */
/* ================================================================== */

/**
 * RSA PKP signature verification for SDA card authentication.
 *
 * This function verifies that the ICC certificate was issued by a trusted
 * ACM(A) and that the card's DDIC matches the hash of verification data.
 *
 * Flow per EMV Book C K3 §4.10:
 *   1. Parse ICA Certificate DER structure
 *   2. Extract RSA public key (modulus N, exponent E)
 *   3. Verify ACM(A) signature chain (if multi-level)
 *   4. Decrypt DDIC using ICA private key (RSA PKCS#1 / GM/T 160 padding)
 *   5. Hash the DOL data using SHA-1 (legacy) or SHA-256 (modern)
 *   6. Compare decrypted DDIC with computed hash
 *
 * Padding format varies by region:
 *   - China (GM/T 160): ASN.1 digestInfo + RSAES-PKCS1-v1_5 with
 *     specific padding byte patterns (0xB5-B8)
 *   - International (X9.31): Fixed padding pattern FF FF ... FF B0
 */
static int ref_rsa_pkpad_verify(
    const uint8_t *cert_der, size_t cert_len,
    const uint8_t *ddic, size_t ddic_len,
    const uint8_t *data, size_t data_len)
{
    if (!cert_der || !ddic || !data) return CRYPTO_E_INVAL;
    if (cert_len == 0 || ddic_len == 0 || data_len == 0) return CRYPTO_E_INVAL;

    return ref_rsa_pkpad_verify_soft(cert_der, cert_len, ddic, ddic_len, data, data_len);
}

/* ------------------------------------------------------------------ */
/*  Soft RSA implementation (simplified — use your HW accelerator)    */
/* ------------------------------------------------------------------ */

int ref_rsa_pkpad_verify_soft(const uint8_t *cert_der, size_t cert_len,
                               const uint8_t *ddic, size_t ddic_len,
                               const uint8_t *dol_data, size_t dol_len)
{
    /* INTEGRATOR: Replace this entire function with your RSA verification.
     * The soft version below is for TEST/VALIDATION ONLY.
     * It does NOT perform real RSA math — just validates input format.
     */
    (void)cert_der; (void)cert_len; (void)ddic; (void)ddic_len;
    (void)dol_data; (void)dol_len;

    /*
     * REAL IMPLEMENTATION STEPS:
     *
     * Step A: Parse DER-encoded ICA certificate.
     *   X.509-like structure:
     *     SEQUENCE {
     *       tbsCertificate TBSCertificate,
     *       signatureAlgorithm AlgorithmIdentifier,
     *       signatureValue BIT STRING
     *     }
     *     TBSCertificate contains the ICA public key (modulus + exponent).
     *
     * Step B: Extract RSA public key modulus (N) and exponent (E).
     *   - Modulus is typically 256 bytes (RSA-2048)
     *   - Exponent is typically 3 bytes (0x010001 = 65537)
     *   - Parse from ASN.1 INTEGER field inside SubjectPublicKeyInfo
     *
     * Step C: Compute hash of verification DOL data.
     *   - Concatenate all TDOL tag values in order:
     *     K3 TDOL: [9F16 TN(4B)] + [9F02 Amount(6B)] + [9F36(2B)]
     *             + [9F03(6B)] + [5F2A(2B)] + [9F66 TQ(4B)]
     *   - Apply SHA-1 hash (traditional EMV) or SHA-256 (recent EMVCo bulletins)
     *   - Output: 20 bytes (SHA-1) or 32 bytes (SHA-256)
     *
     * Step D: Decrypt DDIC using RSA private key.
     *   - Load ACM(A)'s RSA private key from terminal secure storage
     *   - Perform RSA decryption: plaintext = cipher^d mod N
     *     where d is the private exponent stored in ACM(A)
     *   - Expected format: PKCS#1 v1.5 padding
     *     FF FF FF ... FF B0 [hash_of_dol_data]
     *   - Or GM/T 160 format with country-specific padding bytes
     *
     * Step E: Compare decrypted hash with DDIC content.
     *   - DDIC from ICA cert should equal the hash computed in step C
     *   - memcmp(decrypted_hash, ddic, ddic_len) == 0 → AUTHENTICATED
     *   - Mismatch → DECLINE transaction
     *
     * HARDWARE EXAMPLES:
     * NXP AES-ACT:
     *   se_rsa_decrypt(acm_key_handle, ic_cert_der, &decrypted_ddic, &len);
     *   int match = (memcmp(ddic, decrypted_ddic, ddic_len) == 0);
     *
     * Infineon OP-TEE:
     *   optee_rsa_pkpad_verify(acm_private_key, ic_cert_der, dol_data, dol_len);
     *
     * STM32 TrustZone:
     *   TZ_RSA_Decrypt(acm_key_id, ddic_cipher, ddic_plaintext, &ddic_len);
     *   return memcmp(ddic_plaintext, sha1(dol_data), ddic_len) == 0 ? 0 : -1;
     *
     * SOFT RSA (testing only — DO NOT USE IN PRODUCTION):
     *   Use a small-bits RSA like 512-bit for unit testing.
     *   Implement modular exponentiation: c^d mod n using binary method.
     *   Pad PKCS#1 style: 0x00 || 0x02 || pseudo_random_non_zero || 0x00 || hash
     */

    return EMV_E_OK;  /* Mock: always pass for integration testing */
}

/* ================================================================== */
/*  2. DES Decryption (ODA Dynamic Number Layer)                      */
/* ================================================================== */

static int ref_des_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *ic_data, size_t ic_data_len,
    uint8_t *out, size_t *out_len)
{
    if (!key || !ic_data || !out || !out_len) return CRYPTO_E_INVAL;
    if ((key_len != 8 && key_len != 16 && key_len != 24)) {
        return CRYPTO_E_INVAL;  /* DES=8 bytes, TDES-2K=16, TDES-3K=24 */
    }
    if (ic_data_len == 0) return CRYPTO_E_INVAL;

    /* INTEGRATOR: Replace with real DES/TDES decrypt.
     *
     * Step A: Determine cipher mode.
     *   • book C specifies DES-ECB for ICData decryption in ODA
     *   • Key length determines mode: 8=DES, 16=TDES-2K, 24=TDES-3K
     *
     * Step B: Decrypt ICData block-by-block in ECB mode.
     *   • ICData is padded to 8-byte boundary before sending
     *   • Each 8-byte block: des_ecb_decrypt(block, key, out_block)
     *
     * Step C: Remove ISO/IEC 7816-4 unpadding.
     *   • Scan from end of decrypted data, find first non-0x80 byte
     *   • Everything after that (inclusive) is unpadded data
     *   • If ALL bytes are 0x80 → no meaningful data → error
     *
     * Step D: Result is the Dynamic Number (DN), typically 4 bytes.
     *
     * HARDWARE EXAMPLES:
     * NXP: se_des_ecb_decrypt(key, ic_data, ic_data_len, out, out_len);
     * Infineon: optee_cipher_des_icdata(key, ic_data, ic_data_len, out);
     * Soft: mbedtls_des_setkey_dec(&ctx, key, key_type);
     *       mbedtls_des_crypt_ecb(&ctx, ic_data, out);
     */

    /* Mock: copy ICData as-is (real DES would actually decrypt) */
    size_t copy = *out_len < ic_data_len ? *out_len : ic_data_len;
    memcpy(out, ic_data, copy);
    *out_len = copy;
    return EMV_E_OK;
}

/* ================================================================== */
/*  3. TDES-MAC Verification (ODA ICC CRT Check)                      */
/* ================================================================== */

static int ref_tdes_mac_verify(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    const uint8_t *expected_mac, size_t mac_len)
{
    if (!key || !data || !expected_mac) return CRYPTO_E_INVAL;
    if (key_len != 16 && key_len != 24) return CRYPTO_E_INVAL;
    if (mac_len != 8) return CRYPTO_E_INVAL;  /* TDES-CMAC is 8 bytes */

    /* INTEGRATOR: Replace with real TDES-CMAC.
     *
     * Step A: Build MAC input.
     *   • Collect all tags from CDOL2 template (per GPO response)
     *   • Look up each tag's value from warehouse
     *   • Concatenate values in CDOL2-specified order
     *   • Append the Dynamic Number (from DNL decryption, 4 bytes)
     *
     * Step B: Compute TDES-CMAC (ISO/IEC 9797-1 MAC Algorithm 3).
     *   • Initialize 8-byte subkeys K1, K2 from base key via DES encryption
     *   • Process input data in 8-byte blocks with CBC-MAC:
     *     intermediate[i] = DES_encrypt(previous XOR block[i], key)
     *   • Last block gets special XOR treatment (ISO/IEC 9797-1 Method 3)
     *   • Final ciphertext block = CMAC result
     *
     * Step C: Compare with ICC CRT [9F7E].
     *   • memcmp(computed_mac, icc_crt, 8) == 0 → ODA PASSED!
     *   • Mismatch → DECLINE (card is counterfeit)
     *
     * HARDWARE EXAMPLES:
     * NXP: se_aes_cmac(key, data, data_len, mac_buf);
     * Infineon: optee_tdes_cmac(key, data, data_len, result);
     * Soft: nist_mct_des_test_vector() or mbedtls_des_cmac()
     */

    /* Mock: compare with hardcoded value for testing */
    uint8_t dummy_mac[8];
    memset(dummy_mac, 0xAA, sizeof(dummy_mac));

    if (memcmp(expected_mac, dummy_mac, mac_len) == 0) {
        return EMV_E_OK;
    }
    return CRYPTO_E_MAC;
}

/* ================================================================== */
/*  4. Cryptogram Generation (ARQC / CAC)                             */
/* ================================================================== */

static int ref_generate_cryptogram(crypto_alg_t alg,
                                   const uint8_t *key, size_t key_len,
                                   uint8_t key_index,
                                   const uint8_t *dol_data, size_t dol_len,
                                   uint8_t *cryptogram, size_t *cryptogram_len)
{
    (void)key_index;

    if (!key || !dol_data || dol_len == 0) return CRYPTO_E_INVAL;
    if (!cryptogram || !cryptogram_len) return CRYPTO_E_INVAL;

    /* INTEGRATOR: Replace with real cryptogram generation.
     *
     * Step A: Select application key by key_index.
     *   Keys stored in terminal's key management system.
     *   Different keys exist per application (AID-specific).
     *
     * Step B: Pad DOL data to 8-byte boundary.
     *   • Append 0x80 byte
     *   • Fill remaining with 0x00 until divisible by 8
     *   • Per ISO/IEC 9797-1 Method 3
     *
     * Step C: Compute TDES-CMAC.
     *   • Input: padded DOL data
     *   • Key: application cryptogram key
     *   • Output: first 8 bytes of CMAC = ARQC/CAC
     *
     * KEY MANAGEMENT NOTE:
     *   • K3 (Debit/Credit): TDES-CMAC with application key
     *   • K5 (qVISA): TDES-CMAC with Q-VISA specific key
     *   • K7 (Token): May use AES-128-CMAC for token cryptograms
     *
     * HARDWARE EXAMPLES:
     * NXP: se_aes_cmac_with_key_index(key_index, dol_padded, dol_len, arqc);
     * Infineon: optee_tdes_cmac(lookup_app_key(key_index), dol_data, arqc);
     * Soft: mbedtls_des_cmac(key, dol_data, dol_len, arqc);
     */

    (void)alg;

    /* Mock: produce deterministic 8-byte ARQC for integration testing */
    memset(cryptogram, 0xDE, 8);
    if (cryptogram_len) *cryptogram_len = 8;
    return EMV_E_OK;
}

/* ================================================================== */
/*  5. ICA Key Extraction from Certificate                            */
/* ================================================================== */

static int ref_ica_key_extract(
    const uint8_t *cert_der, size_t cert_len,
    uint8_t *sym_key, size_t *sym_key_len,
    uint8_t *pub_key, size_t *pub_key_len)
{
    if (!cert_der || cert_len == 0 || !sym_key_len || !pub_key_len) {
        return CRYPTO_E_INVAL;
    }

    /* INTEGRATOR: Replace with real DER certificate parser.
     *
     * Step A: Parse DER-encoded certificate (ASN.1).
     *   Certificate ::= SEQUENCE {
     *     tbsCertificate      TBSCertificate,
     *     signatureAlgorithm  AlgorithmIdentifier,
     *     signatureValue      BIT STRING
     *   }
     *   TBSCertificate contains ICA public key + symmetric key.
     *
     * Step B: Extract RSA public key.
     *   SubjectPublicKeyInfo ::= SEQUENCE {
     *     algorithm SEQUENCE { rsaEncryption, NULL },
     *     RSAPublicKey ::= SEQUENCE { modulus INTEGER, exponent INTEGER }
     *   }
     *   • Modulus: 256 bytes (RSA-2048)
     *   • Exponent: ~3 bytes (typically 65537 = 0x010001)
     *
     * Step C: Extract symmetric key for TDES operations.
     *   • Symmetric key embedded differently per national spec:
     *     - GM/T 160 (China): tag-value structure inside TBS
     *       [9F6F] ICC Public Key Certificate Body → [XX] Symmetric Key
     *     - X9.31 (US/Europe): key at known offset in cert body (~bytes 200-215)
     *     - JIS X 6273 (Japan): separate DER field in certificate
     *
     * Step D: Validate key sizes.
     *   • Symmetric: 8 bytes (DES) or 16/24 bytes (TDES-2K/3K)
     *   • Public key: 256 bytes (RSA-2048 modulus) + 3 bytes (exponent)
     *
     * COUNTRY SPECIFIC NOTES:
     *   China (GM/T 160):
     *     • ICA cert format defined in GM/T 0018
     *     • Symmetric key uses Chinese ASN.1 tag structure
     *   Japan (JCB):
     *     • Validation per JIS X 6273 Annex specifications
     *
     * HARDWARE EXAMPLES:
     * Soft PKI: mbedtls_x509_crt_parse(der, len) → extract fields
     * NXP SE: se_parse_and_extract_ic_keys(der_cert, sym_out, pub_out)
     * Infineon: optee_der_parse_ic_cert(cert_der, cert_len, &sym_key, &pub_key)
     */

    /* Mock: fill with placeholder keys */
    if (*sym_key_len >= 8) {
        memset(sym_key, 0xBB, 8);
        *sym_key_len = 8;
    } else {
        return CRYPTO_E_BUFFER;
    }

    if (*pub_key_len >= 256) {
        memset(pub_key, 0xCC, 256);
        *pub_key_len = 256;
    } else {
        return CRYPTO_E_BUFFER;
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  Reference Crypto Driver Instance                                  */
/* ================================================================== */

const crypto_driver_t ref_crypto_driver = {
    .rsa_pkpad_verify  = ref_rsa_pkpad_verify,
    .des_decrypt       = ref_des_decrypt,
    .tdes_mac_verify   = ref_tdes_mac_verify,
    .generate_cryptogram = ref_generate_cryptogram,
    .ica_key_extract   = ref_ica_key_extract,
    .version           = 1,
};
