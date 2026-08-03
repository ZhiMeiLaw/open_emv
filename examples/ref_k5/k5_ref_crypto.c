/**
 * @file examples/ref_k5/k5_ref_crypto.c
 * @brief Kernel 5 (qVISA / Crypto) reference crypto driver.
 *
 * K5 uses CDA (Composite Data Authentication) for card authentication
 * instead of traditional SDA/fDDA. CDA verification flow:
 *
 *   1. Parse ICC Public Key Certificate [9F46] + Exponent [9F47] + Remainder [9F48]
 *   2. Parse Issuer Public Key Certificate [90] + Exponent [9F32] + Remainder [92]
 *   3. Get CA Public Key from terminal config (index from [8F])
 *   4. Verify ICC PK Certificate against CA PK (RSA-PKP)
 *   5. Verify SDAD [9F4B] against ICC PK (RSA-PKP) — produces hash of CDOL2 data
 *   6. Compare resulting hash with DDIC from ICA certificate (RSA decryption)
 *
 * This driver also implements the CAC (Cryptogram Authentication Code) generation
 * path used by K5 when the terminal has sufficient data for offline approval.
 *
 * INTEGRATOR: Replace mock implementations with real HW crypto accelerators.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ================================================================== */
/*  CDA RSA-PKP Verification                                          */
/* ================================================================== */
/**
 * CDA (Composite Data Authentication) RSA-PKP verification.
 *
 * This is the core of K5 card authentication. Unlike K3 (SDA/fDDA),
 * K5 performs CDA which combines data authentication and transaction
 * authorization into a single RSA verification step.
 *
 * Flow:
 *   1. Decrypt ICA certificate with CA private key → get DDIC
 *   2. Decrypt ICC certificate with ICA public key → get SDAD
 *   3. Hash CDOL2 data → compare with hash inside SDAD
 *   4. Compare resulting value with DDIC
 *
 * @param ca_cert_der    CA Public Key Certificate (DER)
 * @param ca_cert_len    Length of CA cert
 * @param icc_cert_der   ICC Public Key Certificate (DER)
 * @param icc_cert_len   Length of ICC cert
 * @param ddic           Decrypted DDIC from ICA cert
 * @param ddic_len       DDIC length (typically 20 bytes for SHA-1)
 * @param cdol2_data     CDOL2 data to hash
 * @param cdol2_len      CDOL2 data length
 * @param sdad           Signed Dynamic Application Data [9F4B]
 * @param sdad_len       SDAD length
 * @return 0 on success, negative on failure
 */
static int k5_cda_rsa_pkpad_verify(
    const uint8_t *ca_cert_der, size_t ca_cert_len,
    const uint8_t *icc_cert_der, size_t icc_cert_len,
    const uint8_t *ddic, size_t ddic_len,
    const uint8_t *cdol2_data, size_t cdol2_len,
    const uint8_t *sdad, size_t sdad_len)
{
    if (!ddic || !cdol2_data || !sdad) return CRYPTO_E_INVAL;
    if (ddic_len == 0 || cdol2_len == 0 || sdad_len == 0) {
        return CRYPTO_E_INVAL;
    }

    /* INTEGRATOR: Full CDA implementation per Book C-5 §4:
     *
     * Step 1 — RSA-PKP: Verify ICC certificate against CA certificate
     *   decrypted_ddic = rsa_pkpad_verify(ca_cert, icc_cert, ddic_from_ica)
     *   This simultaneously verifies the ICC cert and extracts DDIC.
     *
     * Step 2 — RSA-PKP: Verify SDAD against ICC public key
     *   extracted_hash = rsa_pkpad_verify(icc_cert, sdad, cdol2_hash)
     *
     * Step 3 — Compare:
     *   return (memcmp(extracted_hash, ddic, ddic_len) == 0) ? 0 : -1;
     *
     * Key notes for CDA:
     *   - DDIC comes from the ICA certificate (RSA decrypted)
     *   - SDAD [9F4B] contains the CDOL2 hash signed with ICC private key
     *   - CDOL2 data is built from GPO response + unpredictable number
     *   - Hash algorithm is SHA-1 per Book C-5 (can be SHA-256 for newer cards)
     */

    /* Mock: validate inputs and return success */
    (void)ca_cert_der; (void)ca_cert_len;
    (void)icc_cert_der; (void)icc_cert_len;
    (void)cdol2_data; (void)cdol2_len;
    (void)sdad; (void)sdad_len;

    return EMV_E_OK;
}

/* ================================================================== */
/*  DES/TDES Decrypt (ODA fallback path)                              */
/* ================================================================== */
/**
 * K5 supports ODA as a fallback for dual-interface cards.
 * DES decrypts ICData using the ICA symmetric key during the
 * Dynamic Number Layer (DNL) step.
 *
 * @param key          ICA symmetric key (8 bytes DES or 16 bytes TDES)
 * @param key_len      Key length
 * @param ic_data      Encrypted ICData from card [9F8C]
 * @param ic_data_len  ICData length (must be multiple of 8)
 * @param out          Output buffer for decrypted data
 * @param out_len      In: max size, Out: actual decrypted size
 * @return 0 on success
 */
static int k5_des_decrypt(const uint8_t *key, size_t key_len,
                          const uint8_t *ic_data, size_t ic_data_len,
                          uint8_t *out, size_t *out_len)
{
    if (!key || !ic_data || !out || !out_len) return CRYPTO_E_INVAL;
    if ((key_len != 8 && key_len != 16) || ic_data_len == 0) {
        return CRYPTO_E_INVAL;
    }
    if (ic_data_len % 8 != 0) return CRYPTO_E_INVAL;

    /* INTEGRATOR: Call DES-ECB decrypt block by block:
     *
     * for (size_t i = 0; i < ic_data_len; i += 8) {
     *     des_ecb_decrypt_block(key, ic_data + i, out + i);
     * }
     *
     * Then apply ISO/IEC 9797-1 padding removal:
     *   Scan from end for first 0x80 byte, truncate there.
     *
     * Result is the unpredictable number (typically 4 bytes).
     */

    size_t copy_len = ic_data_len < *out_len ? ic_data_len : *out_len;
    memcpy(out, ic_data, copy_len);
    *out_len = (size_t)copy_len;
    return EMV_E_OK;
}

/* ================================================================== */
/*  TDES-MAC Verification (ODA ICC CRT check)                         */
/* ================================================================== */
/**
 * Verify ICC CRT [9F7E] using TDES-CMAC over CDOL2 + ICDN.
 * Used in K5 ODA fallback path.
 *
 * @param key            ICA symmetric key (16 bytes TDES)
 * @param key_len        Key length
 * @param data           CDOL2 data
 * @param data_len       Data length
 * @param expected_mac   ICC CRT [9F7E] from card response
 * @param mac_len        MAC length (typically 8 bytes)
 * @return 0 if MAC matches, -1 otherwise
 */
static int k5_tdes_mac_verify(const uint8_t *key, size_t key_len,
                              const uint8_t *data, size_t data_len,
                              const uint8_t *expected_mac, size_t mac_len)
{
    if (!key || !data || !expected_mac) return CRYPTO_E_INVAL;
    if (key_len != 16) return CRYPTO_E_INVAL;

    /* INTEGRATOR: Compute TDES-CMAC (ANSI X9.19 CBC-MAC):
     *
     * mac_input = cdol2_data || unpredictable_number
     * computed_mac = tdes_cmac(key, mac_input, input_len)
     * return memcmp(computed_mac, expected_mac, mac_len) == 0 ? 0 : -1;
     */

    (void)key_len; (void)data_len; (void)mac_len;
    return EMV_E_OK;
}

/* ================================================================== */
/*  Generate CAC — K5 Cryptogram                                      */
/* ================================================================== */
/**
 * Generate the CAC (Cryptogram Authentication Code) for K5.
 *
 * K5 supports two cryptogram types:
 *   - TC (Terminal Conduction) — offline approved
 *   - ARQC (Authorise Request Cryptogram) — online required
 *
 * The TDOL structure for K5 is the same as K3:
 *   [9F16] TN (4B) + [9F02] Amount (6B) + [9F36] Amt Other (2B)
 *   + [9F03] Default Amt (6B) + [5F2A] Currency (2B) + [9F66] TQ (4B)
 *
 * @param alg            Cryptogram algorithm (TDES_CMAC or AES_CMAC)
 * @param key            Application cryptogram key
 * @param key_len        Key length (8 or 16 bytes)
 * @param key_index      Key index for key lookup
 * @param dol_data       TDOL data (padded to 8-byte boundary)
 * @param dol_len        TDOL data length
 * @param cryptogram     Output: generated cryptogram (8 bytes)
 * @param cryptogram_len Output: actual cryptogram length (8)
 * @return 0 on success
 */
static int k5_generate_cryptogram(crypto_alg_t alg,
                                  const uint8_t *key, size_t key_len,
                                  uint8_t key_index,
                                  const uint8_t *dol_data, size_t dol_len,
                                  uint8_t *cryptogram, size_t *cryptogram_len)
{
    (void)alg; (void)key_index;

    if (!key || !dol_data || dol_len == 0) return CRYPTO_E_INVAL;
    if (!cryptogram || !cryptogram_len) return CRYPTO_E_INVAL;
    if (*cryptogram_len < 8) return CRYPTO_E_INVAL;

    /* INTEGRATOR: Implement CAC generation per Book C-5 §5.8:
     *
     * Step 1 — Pad TDOL data to 8-byte boundary (ISO/IEC 9797-1 Method 3):
     *   dol[dol_len] = 0x80;
     *   while ((dol_len + 1) % 8 != 0) dol[dol_len++] = 0x00;
     *
     * Step 2 — Select correct application key:
     *   app_key = lookup_key(key_index, pan_or_aid)
     *
     * Step 3 — Compute TDES-CMAC (CBC-MAC):
     *   arqc_or_tc = tdes_cmac(app_key, padded_dol, padded_len)
     *   Result is the first 8 bytes of the MAC output.
     *
     * Step 4 — Set cryptogram type from [9F27] CID:
     *   TC  (0x08) = Terminal Conduction
     *   ARQC (0x0A) = Authorise Request Cryptogram
     *   ARPC (0x0C) = Authorise Request Process Code
     *   NASP (0x04) = No Application SDI Parameter
     */

    /* Mock: produce dummy 8-byte CAC */
    memset(cryptogram, 0xCA, 8);
    *cryptogram_len = 8;
    return EMV_E_OK;
}

/* ================================================================== */
/*  ICA Key Extraction from Certificate                               */
/* ================================================================== */
/**
 * Extract symmetric key and RSA public key from ICA certificate.
 * Used for ODA fallback in K5 (CDA is primary path).
 *
 * @param cert_der      ICA certificate (DER encoded)
 * @param cert_len      Certificate length
 * @param sym_key       Output: symmetric key (8 or 16 bytes)
 * @param sym_key_len   Output: actual symmetric key length
 * @param pub_key       Output: RSA public key modulus (256+ bytes)
 * @param pub_key_len   Output: actual public key length
 * @return 0 on success
 */
static int k5_ica_key_extract(const uint8_t *cert_der, size_t cert_len,
                              uint8_t *sym_key, size_t *sym_key_len,
                              uint8_t *pub_key, size_t *pub_key_len)
{
    if (!cert_der || cert_len == 0 || !sym_key_len || !pub_key_len) {
        return CRYPTO_E_INVAL;
    }

    /* INTEGRATOR: Parse DER ICA certificate to extract:
     *
     * Symmetric key:
     *   - Found within the certificate's content field
     *   - 8 bytes (DES) or 16 bytes (TDES) depending on issuer
     *   - China payment systems may use GM/T 160 format
     *
     * RSA public key:
     *   - Modulus: typically 256 bytes (RSA-2048)
     *   - Exponent: typically 3 bytes (0x01 0x00 0x01)
     *   - Encoded as DER SEQUENCE { INTEGER modulus, INTEGER exponent }
     */

    if (*sym_key_len >= 8) {
        memset(sym_key, 0xBB, 8);
        *sym_key_len = 8;
    }
    if (*pub_key_len >= 256) {
        memset(pub_key, 0xCC, 256);
        *pub_key_len = 256;
    }
    return EMV_E_OK;
}

/* ================================================================== */
/*  Crypto Driver instance for K5                                     */
/* ================================================================== */

const crypto_driver_t k5_ref_crypto_driver = {
    .rsa_pkpad_verify  = k5_cda_rsa_pkpad_verify,
    .des_decrypt       = k5_des_decrypt,
    .tdes_mac_verify   = k5_tdes_mac_verify,
    .generate_cryptogram = k5_generate_cryptogram,
    .ica_key_extract   = k5_ica_key_extract,
    .version           = 1,
};
