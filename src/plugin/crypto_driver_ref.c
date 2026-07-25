/**
 * @file src/plugin/crypto_driver_ref.c
 * @brief Reference Crypto Driver for EMV Contactless Payment Kernel.
 *
 * This is the reference implementation that integrators should adapt.
 * It provides:
 *   - RSA PKP verification (SDA card auth)
 *   - DES/3DES decrypt (ODA Dynamic Number Layer)
 *   - TDES-CMAC (ICC CRT verify + ARQC generation)
 *   - ICA key extraction from DER certificates
 *
 * Current implementations are PLACEHOLDER stubs with detailed integration
 * comments showing what real HW calls to make. Ansoft DES/TDES soft-impl
 * can be dropped in for testing (MCT DES / NIST test vectors).
 */

#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ================================================================== */
/*  Helper: simple SHA-256 placeholder                                */
/* ================================================================== */
/**
 * Placeholder: replace with a real SHA-1/SHA-256 implementation.
 * For SDA: Book C K3 uses SHA-1 for DOL hash.
 * For modern cards: EMVCo spec bulletin adds SHA-256 support.
 */
static int ref_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    /* INTEGRATOR: Call your hardware SHA-256 accelerator or soft impl.
     * Example: mbedtls_sha256_ret(data, len, out, 0);
     *          nss_SHA256(data, len, out);
     *          YOUR_HW_SHA256(data, len, out);
     */
    (void)data; (void)len; (void)out;
    memset(out, 0, 32);  /* Mock: all zeros */
    return EMV_E_OK;
}

/* ================================================================== */
/*  1. RSA-PKP Verification (SDA Card Auth)                           */
/* ================================================================== */

/**
 * Verify ICC certificate chain and DDIC against DOL hash.
 *
 * SDA Flow per Book B §6.4.2 and Book C K3 §4.10:
 *   1. Load ACM(A) from terminal parameter store
 *   2. Verify ICA Public Key Certificate signature using ACM(A) RSA key
 *      — Uses RSA public-key padding verification (GM/T 160 or X9.31 format)
 *   3. Extract ICA public key from verified certificate
 *   4. Decrypt DDIC (Decrypted Data Item for Ciphering) from [9F21] using ICA
 *      public key (PKCS#1 or GM/T RSA-PKP format)
 *   5. Hash the verification DOL data per kernel spec
 *   6. Compare DDIC content with computed hash
 *      — Match = card authentic (certificate chain valid)
 *      — Mismatch = DECLINE transaction
 */
static int ref_rsa_pkpad_verify(
    const uint8_t *cert_der, size_t cert_len,
    const uint8_t *ddic, size_t ddic_len,
    const uint8_t *data, size_t data_len)
{
    if (!cert_der || cert_len == 0 || !ddic || ddic_len == 0 ||
        !data || data_len == 0) {
        return CRYPTO_E_INVAL;
    }

    /* INTEGRATOR STEP-BY-STEP REPLACEMENT GUIDE:
     *
     * Step A: Parse the ACM(A) certificate chain from param store.
     *         The ACM(A) issuer certificate contains the signing key
     *         used to sign the ICA certificate.
     *
     * Step B: RSA-PKP verify the ICA certificate.
     *         • Extract Issuer Signature from cert (tag in ASN.1)
     *         • Use ACM(A)'s public key to verify
     *         • Padding format depends on country:
     *           - China (GM/T 160): ASN.1 digestInfo + RSAES-PKCS1-v1_5 with
     *             specific padding byte pattern (0xB5/B6/B7/B8)
     *           - International (X9.31): EMV RSA-PKP format with
     *             fixed padding: FF FF ... FF B0 followed by hash
     *         • Hash algorithm is determined by ACM(A) keyUsage field
     *
     * Step C: Extract ICA public key modulus from verified cert.
     *         Parse ASN.1 SEQUENCE { INTEGER (modulus), INTEGER (exponent) }
     *         Typically RSA-2048 → 256-byte modulus.
     *
     * Step D: Decrypt DDIC using ICA private key (stored in ACM(A)).
     *         PKCS#1 v1.5 decrypt of the DDIC ciphertext.
     *         Result = hash-of-DOL-data (SHA-1 or SHA-256 depending on kernel version).
     *
     * Step E: Hash the verification DOL data.
     *         DOL tags come from kernel dictionary:
     *         K3: TDOL = [9F16, 9F02, 9F36, 9F03, 5F2A, 9F66]
     *         Concatenate their values and hash.
     *
     * Step F: Compare DDIC hash with computed hash.
     *         return memcmp(ddic_hash, computed_hash, ddic_len) == 0 ? 0 : -1;
     *
     * REFERENCE HARDWARE EXAMPLES:
     * - NXP AES-ACT (Secure Element): se_ecrsa_verify(cert, pk_pad_type, ddic)
     * - Infineon OP-TEE: optee_rsa_verify_icv(acm_der, ic_cert_der, dol_data)
     * - STM32 TrustZone: TZ_RSA_Verify(acm_pubkey, ic_cert_sig, dol_hash)
     * - Soft RSA (testing only): mbedtls_x509_crt_parse() + pk_verify()
     */

    /* Mock: always pass SDA verification for integration testing */
    return EMV_E_OK;
}

/* ================================================================== */
/*  2. DES Decryption (ODA Dynamic Number Layer)                      */
/* ================================================================== */

/**
 * DES decrypt ICData during ODA Dynamic Number Layer (DNL).
 *
 * ODA DNL Flow per Book C K3 §4.10.3:
 *   1. Terminal sends SET ATTRIBUTE command with CDOL1 data
 *   2. Card responds with [9F8C] ICData (encrypted dynamic number)
 *   3. Terminal decrypts ICData using ICA symmetric key (extracted from cert)
 *   4. Unpad result per ISO/IEC 7816-4 standard (find last non-0x80 byte)
 *   5. Remaining bytes = Dynamic Number (typically 4 bytes)
 *   6. Use this dynamic number as input for CDOL2 TOA exchange
 */
static int ref_des_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *ic_data, size_t ic_data_len,
    uint8_t *out, size_t *out_len)
{
    if (!key || !ic_data || !out || !out_len) return CRYPTO_E_INVAL;
    if (key_len != 8 && key_len != 16 && key_len != 24) {
        return CRYPTO_E_INVAL;  /* DES requires 8, TDES-2K 16, TDES-3K 24 bytes */
    }
    if (ic_data_len == 0) return CRYPTO_E_INVAL;

    /* INTEGRATOR STEP-BY-STEP REPLACEMENT GUIDE:
     *
     * Step A: Determine cipher mode.
     *         • Book C specifies DES-ECB for ICData decryption
     *         • Some national specs may use TDES-CBC
     *         • Key length determines mode: 8=DES, 16=TDES-2K, 24=TDES-3K
     *
     * Step B: Decrypt ICData block-by-block.
     *         • ICData is padded to 8-byte boundary
     *         • Each 8-byte block: des_ecb_decrypt(block, key, out_block)
     *
     * Step C: Remove ISO/IEC 7816-4 unpadding.
     *         • Find first non-0x80 byte scanning from end of decrypted data
     *         • Truncate after that byte (inclusive)
     *         • If all bytes are 0x80 → no meaningful data, return error
     *
     * Step D: Copy unpadded result to output buffer.
     *         Result is the Dynamic Number (DN).
     *         DN length is typically 4 bytes but can vary.
     *
     * REFERENCE HARDWARE EXAMPLES:
     * - NXP DES accelerator: se_des_ecb_decrypt(key, ic_data, out, &len)
     * - Infineon OP-TEE: optee_cipher_des_icdata(key, ic_data, out)
     * - Soft DES (testing): mbedtls_des_setkey_enc() + mbedtls_des_crypt_ecb()
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

/**
 * Verify ICC CRT (Card Cryptogram) for ODA authentication.
 *
 * ODA CRT Verification per Book C K3 §4.10.3:
 *   1. After DNL decryption, terminal has Dynamic Number (DN)
 *   2. Build CDOL2 data per kernel dictionary:
 *      • Tags listed in [DF9F66] CDOL2 from GPO response
 *      • Concatenate tag values in order specified by CDOL2 template
 *   3. Append Dynamic Number to CDOL2 data
 *   4. Compute TDES-CMAC (ISO/IEC 9797-1 MAC Algorithm 3, CBC-MAC)
 *      • Key = ICA symmetric key (extracted from certificate in step 1)
 *      • Data = CDOL2 bytes + Dynamic Number bytes
 *   5. Compare computed MAC with ICC CRT [9F7E] from card's TOA response
 *      • ICC CRT is exactly 8 bytes (TDES-CMAC block size)
 *      • memcmp(computed_mac, icc_crt, 8) == 0 → ODA passed!
 *      • Mismatch → DECLINE (card is not genuine)
 */
static int ref_tdes_mac_verify(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    const uint8_t *expected_mac, size_t mac_len)
{
    if (!key || !data || !expected_mac) return CRYPTO_E_INVAL;
    if (key_len != 16 && key_len != 24) return CRYPTO_E_INVAL;  /* Must be TDES key */
    if (mac_len != 8) return CRYPTO_E_INVAL;  /* TDES-CMAC always produces 8 bytes */

    /* INTEGRATOR STEP-BY-STEP REPLACEMENT GUIDE:
     *
     * Step A: Build the MAC input.
     *         • Collect all tags from the CDOL2 template (per GPO response)
     *         • Look up each tag's value from the data warehouse
     *         • Concatenate values in CDOL2-specified order
     *         • Append the Dynamic Number (from DNL decryption)
     *
     * Step B: Compute TDES-CMAC (CBC-MAC with finalization).
     *         • Initialize 8-byte IV with zeros
     *         • Process input data in 8-byte blocks:
     *           enc_intermediate = DES_encrypt(prev_block XOR input_block, key)
     *         • Last block gets XOR with 0x8080...80 (ISO/IEC 9797-1 Method 3)
     *         • Final ciphertext block = CMAC
     *
     * Step C: Compare with ICC CRT [9F7E].
     *         • If match: return EMV_E_OK (ODA authenticated)
     *         • If mismatch: return CRYPTO_E_MAC (decline)
     *
     * REFERENCE HARDWARE EXAMPLES:
     * - NXP AES-CMAC: se_aes_cmac(key, data, len, mac_buf)
     * - Infineon OP-TEE: optee_tdes_cmac(key, data, len, result)
     * - Soft TDES-CMAC (testing): nist_mct_des_test_vector or mbedtls_des_cmac()
     */

    /* Mock: compare with hardcoded 8-byte value for testing */
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

/**
 * Generate Application Cryptogram (ARQC for K3, CAC for K5, etc.).
 *
 * Cryptogram Generation per Book C:
 *   1. Collect all TDOL tags for the kernel type
 *   2. Look up each tag's value from the data warehouse
 *   3. Pad concatenated values to 8-byte boundary using Method 3
 *      (ISO/IEC 9797-1 padding: append 0x80 then pad with 0x00)
 *   4. Compute TDES-CMAC over padded DOL data
 *      • Key = application cryptogram key (from kernel key index)
 *      • Result = 8-byte ARQC/CAC
 *   5. Store in [9F26] tag in output warehouse
 *   6. Send back to card in TERMINAL CONDUCTION (TC) command
 */
static int ref_generate_cryptogram(crypto_alg_t alg,
                                   const uint8_t *key, size_t key_len,
                                   uint8_t key_index,
                                   const uint8_t *dol_data, size_t dol_len,
                                   uint8_t *cryptogram, size_t *cryptogram_len)
{
    (void)key_index;  /* Key index selects which app key to look up */

    if (!key || !dol_data || dol_len == 0) return CRYPTO_E_INVAL;
    if (!cryptogram || !cryptogram_len) return CRYPTO_E_INVAL;

    /* INTEGRATOR STEP-BY-STEP REPLACEMENT GUIDE:
     *
     * Step A: Select the correct application key based on key_index.
     *         Keys are stored in the terminal's key management system.
     *         key_index maps to a specific application key (TDES for K3/K5).
     *         Different keys exist for different applications (AID-specific).
     *
     * Step B: Pad DOL data to 8-byte boundary.
     *         • Append 0x80 byte
     *         • Fill remaining bytes with 0x00 until divisible by 8
     *         • Per ISO/IEC 9797-1 Method 3 (same as CMAC padding)
     *
     * Step C: Compute TDES-CMAC (or AES-CMAC for newer kernels).
     *         • Input: padded DOL data
     *         • Key: application cryptogram key from Step A
     *         • Output: first 8 bytes of CMAC result = ARQC/CAC
     *
     * Step D: Validate cryptogram length.
     *         • DES/TDES-CMAC always produces 8-byte result
     *         • AES-CMAC can produce 8 or 16 bytes
     *
     * KEY MANAGEMENT NOTE:
     *   Different kernel types use different keys:
     *   • K3 (Debit/Credit):  Uses TDES-CMAC with application key
     *   • K5 (qVISA):         Uses TDES-CMAC with Q-VISA specific key
     *   • K7 (Token):         May use AES-128-CMAC for token cryptograms
     *
     * REFERENCE HARDWARE EXAMPLES:
     * - NXP: se_aes_cmac_with_key_index(key_index, dol_padded, dol_len, arqc)
     * - Infineon: optee_tdes_cmac(lookup_app_key(key_index), dol_data, arqc)
     * - Soft (testing): mbedtls_des_cmac(key, dol_data, dol_len, arqc)
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

/**
 * Extract symmetric + public keys from an ICA Public Key Certificate (DER).
 *
 * Certificate Parsing Flow per Book C:
 *   1. DER-parse the ICA Public Key Certificate tag/value pair
 *   2. Extract the RSA modulus and exponent (public key)
 *   3. Extract the embedded symmetric key (for DES/TDES operations)
 *      • Symmetric key encoding varies by national payment system:
 *        - China (GM/T 160): key follows specific ASN.1 structure within cert
 *        - International: key is at a fixed offset from cert header
 *        - Japan (JIS X 6273): different key encoding format
 *   4. Return both keys for subsequent crypto operations
 */
static int ref_ica_key_extract(
    const uint8_t *cert_der, size_t cert_len,
    uint8_t *sym_key, size_t *sym_key_len,
    uint8_t *pub_key, size_t *pub_key_len)
{
    if (!cert_der || cert_len == 0 || !sym_key_len || !pub_key_len) {
        return CRYPTO_E_INVAL;
    }

    /* INTEGRATOR STEP-BY-STEP REPLACEMENT GUIDE:
     *
     * Step A: Parse DER-encoded certificate (ASN.1 structure).
     *         The ICA certificate is a PKI/X.509-like structure:
     *         Certificate ::= SEQUENCE {
     *           tbsCertificate      TBSCertificate,    -- data being signed
     *           signatureAlgorithm  AlgorithmIdentifier,
     *           signatureValue      BIT STRING         -- ACMA(A) signature
     *         }
     *         TBSCertificate contains the ICA public key + symmetric key.
     *
     * Step B: Extract RSA public key components.
     *         Within TBSCertificate, find the SubjectPublicKeyInfo:
     *         AlgorithmIdentifier ::= SEQUENCE { rsaEncryption, NULL }
     *         RSAPublicKey ::= SEQUENCE { modulus, publicExponent }
     *         • Modulus is 256 bytes (RSA-2048)
     *         • Exponent is typically 65537 (0x010001) = 3 bytes
     *
     * Step C: Extract symmetric key for TDES operations.
     *         The symmetric key is embedded differently per spec:
     *         • GM/T 160 (China): tag-value structure inside TBS
     *           [9F6F] ICC Public Key Certificate Body
     *           Inside: [XX] Symmetric Key Tag + key bytes
     *         • X9.31 (US/Europe): key at known offset in cert body
     *           Typically bytes 200-215 in the TBS portion
     *         • JIS X 6273 (Japan): separate DER field in cert
     *
     * Step D: Validate extracted key sizes.
     *         • Symmetric key: 8 bytes (DES) or 16/24 bytes (TDES-2K/3K)
     *         • Public key: 256 bytes (RSA-2048 modulus) + 3 bytes (exponent)
     *
     * COUNTRY SPECIFIC NOTES:
     *   China (GM/T 160):
     *     • ICA certificate format is defined in GM/T 0018
     *     • Symmetric key encoding uses Chinese ASN.1 tag structure
     *     • Must use GM/T random number generator for TN generation
     *   Japan (JCB):
     *     • Additional validation required for JCB-specific fields
     *     • Key format follows JIS X 6273 Annex specifications
     *
     * REFERENCE HARDWARE EXAMPLES:
     * - Soft PKI parsing: mbedtls_x509_crt_parse() + extract_ic_keys()
     * - NXP SE: se_parse_and_extract_ic_keys(der_cert, sym_out, pub_out)
     * - Custom parser: parse_der_ic_cert(cert_der, cert_len, &sym_key, &pub_key)
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
