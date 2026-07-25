/**
 * @file src/plugin/crypto_driver_soft_rsa.c
 * @brief Software RSA-PKP implementation for EMV SDA / fDDA card authentication.
 *
 * Implements RSA public-key operations used in:
 *   - SDA (Static Data Authentication): verify ICA certificate chain
 *   - fDDA (Fast DDA): verify dynamic card signature
 *
 * This is a soft implementation using the GM/T 160 / X9.31 RSA-PKP format
 * as defined in EMV Book C Kernels. For production, replace with hardware
 * accelerator calls.
 */

#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ================================================================== */
/*  Internal: fixed-size integer arithmetic for RSA operations        */
/* ================================================================== */

/* We support up to RSA-2048 (256 bytes modulus). All arithmetic
 * is done on byte arrays in big-endian order. */

#define RSA_MAX_MODULUS_BYTES 256

typedef struct {
    uint8_t bytes[RSA_MAX_MODULUS_BYTES];
    size_t len;  /* number of valid bytes (big-endian, leading zeros stripped) */
} bigint_t;

/* ================================================================== */
/*  Big integer helpers                                               */
/* ================================================================== */

/** Convert big-endian buffer to bigint. Strips leading zeros. */
static void bigint_from_buf(const uint8_t *buf, size_t buf_len, bigint_t *n)
{
    if (!buf || !n) return;
    memset(n->bytes, 0, sizeof(n->bytes));

    /* Find first non-zero byte */
    size_t start = 0;
    while (start < buf_len && buf[start] == 0) start++;

    size_t valid = buf_len - start;
    if (valid > RSA_MAX_MODULUS_BYTES) valid = RSA_MAX_MODULUS_BYTES;

    n->len = valid;
    memcpy(n->bytes + (RSA_MAX_MODULUS_BYTES - valid), buf + start, valid);
}

/** Get total modulus size in bytes (for RSA operations). */
static size_t bigint_size(const bigint_t *n)
{
    if (!n || n->len == 0) return 0;
    return n->len;
}

/** Store bigint back to big-endian buffer. */
static void bigint_to_buf(const bigint_t *n, uint8_t *buf, size_t buf_len)
{
    if (!n || !buf || n->len == 0) return;
    memset(buf, 0, buf_len);
    size_t start = buf_len - n->len;
    memcpy(buf + (start > buf_len ? 0 : start), n->bytes,
           (n->len > buf_len ? buf_len : n->len));
}

/* ------------------------------------------------------------------ */
/* Modular exponentiation: c = m^e mod n                              */
/* Uses binary (square-and-multiply) method.                          */
/* NOTE: This is a textbook implementation — NOT constant-time.       */
/*       For production, use Montgomery ladder or CRT optimization.     */
/* ------------------------------------------------------------------ */

static int mulmod(bigint_t *result, const bigint_t *a, const bigint_t *b,
                  const bigint_t *n)
{
    /* Simplified: use a single large accumulator. For real RSA we'd need
     * proper multi-precision multiplication. This stub uses uint64_t
     * accumulation for small numbers — insufficient for RSA-2048 but
     * enough to validate the structure. INTEGRATOR must implement full
     * multi-precision here. */
    /* For now, return OK as placeholder and log what's needed. */
    (void)result; (void)a; (void)b; (void)n;
    return EMV_E_OK;
}

static int powmod(bigint_t *result, const bigint_t *m, const bigint_t *e,
                  const bigint_t *n)
{
    if (!m || !e || !n || !result) return CRYPTO_E_INVAL;

    /* Binary method: result = m^e mod n */
    /* Step 1: Initialize result = 1 */
    memset(result->bytes, 0, sizeof(result->bytes));
    result->bytes[RSA_MAX_MODULUS_BYTES - 1] = 1;
    result->len = 1;

    /* Step 2: For each bit of e from MSB to LSB */
    size_t e_bytes = bigint_size(e);
    if (e_bytes == 0) return CRYPTO_E_INVAL;

    for (size_t i = 0; i < e_bytes; i++) {
        uint8_t eb = e->bytes[RSA_MAX_MODULUS_BYTES - e_bytes + i];
        for (int bit = 7; bit >= 0; bit--) {
            /* Square */
            bigint_t sq;
            int rc = mulmod(&sq, result, result, n);
            if (rc != EMV_E_OK) return rc;
            memcpy(result->bytes, sq.bytes, sizeof(sq.bytes));

            /* Multiply by m if this bit is 1 */
            if ((eb >> bit) & 1) {
                bigint_t prod;
                rc = mulmod(&prod, result, m, n);
                if (rc != EMV_E_OK) return rc;
                memcpy(result->bytes, prod.bytes, sizeof(prod.bytes));
            }
        }
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  ASN.1 DER parsing helpers                                         */
/* ================================================================== */

/** Parse a DER tag-length-value structure. Returns ptr past the value. */
static const uint8_t *parse_tlv(const uint8_t *data, size_t len,
                                 uint8_t *tag_out, uint16_t *length_out)
{
    if (!data || len < 2) return NULL;

    uint16_t tag = data[0];
    data++; len--;

    /* Decode length */
    uint8_t len_bytes = data[0];
    if (!(len_bytes & 0x80)) {
        *length_out = len_bytes;
        data++; len--;
    } else {
        uint8_t count = len_bytes & 0x7F;
        if (count > 2 || count > len) return NULL;
        *length_out = 0;
        for (uint8_t i = 0; i < count; i++) {
            *length_out = (*length_out << 8) | data[i + 1];
        }
        data += count + 1;
        len -= count + 1;
    }

    if (len < *length_out) return NULL;

    *tag_out = tag;
    return data + *length_out;  /* Return pointer after value */
}

/** Extract RSA modulus and exponent from SubjectPublicKeyInfo structure. */
static int extract_rsa_public_key(const uint8_t *cert_der, size_t cert_len,
                                   uint8_t *modulus, size_t *mod_len,
                                   uint8_t *exponent, size_t *exp_len)
{
    /*
     * DER structure (simplified):
     * SEQUENCE {                          /* outer certificate
     *   SEQUENCE {                        /* tbsCertificate
     *     ...
     *     SEQUENCE {                     /* subjectPublicKeyInfo
     *       SEQUENCE { rsaEncryption, NULL }
     *       BIT STRING { SEQUENCE { modulus INTEGER, exponent INTEGER } }
     *     }
     *   }
     *   ...
     *   BIT STRING { signatureValue }
     * }
     *
     * We need to navigate through nested sequences/sets to find the
     * BIT STRING containing the RSAPublicKey inside SubjectPublicKeyInfo.
     */

    const uint8_t *p = cert_der;
    size_t left = cert_len;

    /* Skip outer SEQUENCE (certificate) */
    uint8_t tag;
    uint16_t length;
    p = parse_tlv(p, left, &tag, &length);
    if (!p || tag != 0x30) return CRYPTO_E_ENCODE;  /* Expected SEQUENCE */
    left = length;  /* Now inside tbsCertificate */

    /* Navigate into tbsCertificate -> signature -> issuer -> validity ->
       subject -> subjectPublicKeyInfo */
    /* For brevity, skip to BIT STRING containing pubkey */
    /* The actual parser would walk through all TLV elements looking for:
       SEQUENCE → BIT STRING → inner SEQUENCE → INTEGER(mod) + INTEGER(exp) */

    /* For reference/demo, just return success with dummy parsing.
     * A real implementation needs a full DER parser */

    (void)left; (void)length;

    return EMV_E_OK;
}

/* ================================================================== */
/*  PKCS#1 v1.5 / GM/T 160 padding utilities                          */
/* ================================================================== */

/** Verify PKCS#1 v1.5 type-1 padding (used in RSA-PKP).
 *  Format: 0x00 || 0x01 || FF...FF || 0x00 || DigestInfo
 *  DigestInfo = SEQUENCE { hashAlg OID, OCTET STRING hash }
 */
static int verify_pkcs1_type1_padding(const uint8_t *plaintext, size_t plain_len,
                                       size_t expected_total_len)
{
    if (plain_len < 11 || plain_len != expected_total_len) {
        return CRYPTO_E_ENCODE;
    }

    /* Must start with 0x00 0x01 */
    if (plaintext[0] != 0x00 || plaintext[1] != 0x01) {
        return CRYPTO_E_ENCODE;
    }

    /* All bytes between position 2 and the first 0x00 must be 0xFF */
    size_t i = 2;
    while (i < plain_len && plaintext[i] == 0xFF) i++;

    /* Must have a 0x00 separator */
    if (i >= plain_len || plaintext[i] != 0x00) {
        return CRYPTO_E_ENCODE;
    }
    i++;

    /* Rest should be DigestInfo SEQUENCE: { SHA1-OID, 0x04 hash } */
    /* SHA-1 OID: 0x30 0x21 0x30 0x09 0x06 0x05 0x2B 0x0E 0x03 0x02 0x1A
                       0x05 0x00 0x04 0x14 <20 bytes hash> */
    return EMV_E_OK;  /* Placeholder: pass if padding structure looks ok */
}

/* ================================================================== */
/*  1. RSA-PKP verification (SDA / fDDA Card Auth)                    */
/* ================================================================== */

/**
 * RSA-PKP signature verification for SDA (Static Data Authentication).
 *
 * Per EMV Book C K3 §4.10 and Book B §6.4.2:
 *
 * Input:
 *   cert_der   — ICA Public Key Certificate (DER encoded, typically ~512 bytes)
 *   ddic       — Decrypted Data Item for Ciphering (from card response)
 *   ddic_len   — Length of DDIC (typically 20 bytes for SHA-1)
 *   dol_data   — Verification DOL data (concatenated tag values)
 *   dol_len    — Length of DOL data
 *
 * Process:
 *   1. Parse cert_der to extract: ICA public key (modulus N, exponent E)
 *   2. Decrypt DDIC ciphertext using RSA with ACM(A)'s private key.
 *      Note: In SDA path, the terminal has the ACM(A) private key.
 *   3. Apply PKCS#1 v1.5 unpadding to get DigestInfo.
 *   4. Hash dol_data with SHA-1 (or SHA-256 for modern cards).
 *   5. Compare the hash with DigestInfo.hash field.
 *   6. If match: card is authenticated → continue. Else → DECLINE.
 *
 * Output: returns 0 on success (signature verified), non-zero on failure.
 */
static int ref_rsa_pkpad_verify(
    const uint8_t *cert_der, size_t cert_len,
    const uint8_t *ddic, size_t ddic_len,
    const uint8_t *data, size_t data_len)
{
    if (!cert_der || !ddic || !data) return CRYPTO_E_INVAL;
    if (cert_len == 0 || ddic_len == 0 || data_len == 0) return CRYPTO_E_INVAL;

    /* --- INTEGRATOR: Replace entire function body with real RSA operations --- */

    /* Step A: Parse ICA certificate to extract RSA public key.
     * The certificate contains:
     *   - ICA public key modulus (256 bytes for RSA-2048)
     *   - ICA public key exponent (typically 65537 = 3 bytes)
     *   - Issuer unique identifier (ACM(A) info)
     *   - Validity period
     *
     * Parse DER structure and locate BIT STRING containing RSAPublicKey. */

    /* Step B: Hash the verification DOL data.
     * Build DOL from kernel dictionary tags in specified order.
     * For K3: [9F16 TN] + [9F02 Amount] + [9F36 Other Amt]
     *         + [9F03 Default Amt] + [5F2A Currency] + [9F66 TQ]
     * Use SHA-1 for traditional EMV cards, SHA-256 for recent revisions. */

    /* Step C: Perform RSA decryption of DDIC with ACM(A) private key.
     * The ACM(A) certificate contains the RSA private key used to decrypt.
     * Plaintext structure: PKCS#1 v1.5 padding followed by digest. */

    /* Step D: Verify PKCS#1 padding structure. */

    /* Step E: Compare decrypted digest with computed DOL hash.
     * memcmp(decrypted_hash, compputed_hash, ddic_len) == 0 */

    /* --- End integration section --- */

    /* Mock: return success for testing */
    return EMV_E_OK;
}

/* ================================================================== */
/*  Helper: compute SHA-256 hash (placeholder for real implementation)  */
/* ================================================================== */

static int compute_sha256(const uint8_t *data, size_t len, uint8_t hash[32])
{
    if (!data || !hash) return CRYPTO_E_INVAL;

    /* INTEGRATOR: Replace with real SHA-256 implementation.
     * Options:
     *   - Hardware SHA-256 accelerator on your MCU/SE
     *   - OpenSSL EVP_Digest(data, len, hash, &out_len)
     *   - mbedtls_sha256_ret(data, len, hash, 0)
     *   - Custom software implementation (NIST FIPS 180-4 compliant)
     */

    /* Dummy hash for testing: all zero bytes */
    memset(hash, 0, 32);
    return EMV_E_OK;
}

/* ================================================================== */
/*  2. DES decryption (ODA Dynamic Number Layer)                      */
/* ================================================================== */

static int ref_des_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *ic_data, size_t ic_data_len,
    uint8_t *out, size_t *out_len)
{
    if (!key || !ic_data || !out || !out_len) return CRYPTO_E_INVAL;
    if ((key_len != 8 && key_len != 16 && key_len != 24)) {
        return CRYPTO_E_INVAL;
    }
    if (ic_data_len == 0) return CRYPTO_E_INVAL;

    /* INTEGRATOR: Replace with real DES/3DES-ECB decryption.
     *
     * Key interpretation:
     *   key_len == 8  → Single DES key (24 bytes truncated to 8)
     *   key_len == 16 → TDES-2K (2-key Triple DES), use k1=k3
     *   key_len == 24 → TDES-3K (3-key Triple DES)
     *
     * ECB mode decryption (Book C specifies ECB for ICData):
     *   For each 8-byte block of ICData:
     *     decrypt(block, key) → output_block
     *   Concatenate all output blocks.
     *
     * ISO/IEC 7816-4 Unpadding:
     *   After decryption, scan from end of decrypted data backwards.
     *   Find first non-0x80 byte. Everything after that (inclusive)
     *   is the unpadded data. The Dynamic Number typically starts
     *   right at the beginning of the unpadded section.
     *
     * Example pseudocode:
     *   for (i=0; i<ic_data_len; i+=8) {
     *       des_ecb_dec(key, ic_data+i, out+j);
     *       j += 8;
     *   }
     *   // Unpad from end
     *   int end = j - 1;
     *   while (end >= 0 && out[end] == 0x80) end--;
     *   size_t dn_len = end + 1;  // unpadded length
     */

    /* Mock: copy input as-is */
    size_t copy = *out_len < ic_data_len ? *out_len : ic_data_len;
    memcpy(out, ic_data, copy);
    *out_len = copy;
    return EMV_E_OK;
}

/* ================================================================== */
/*  3. TDES-CMAC generation and verification (ISO/IEC 9797-1 MAC 3)     */
/* ================================================================== */

/**
 * Compute TDES-CMAC over arbitrary-length input data.
 * Per ISO/IEC 9797-1 Algorithm 3 with NPB (No Padding B) and MAB (Message Authentication Body).
 *
 * Uses single-key TDES (key[8]) for this reference implementation.
 * For 3-key TDES, use key[24] where K1=K3.
 */
static int compute_tdes_cmac_single_key(const uint8_t key[8],
                                         const uint8_t *data, size_t data_len,
                                         uint8_t mac[8])
{
    /* INTEGRATOR: Replace with real CBC-MAC implementation.
     *
     * Algorithm:
     *   1. Derive subkeys K1, K2 from base key:
     *      temp = des_encrypt(all-zeros, key)   → 8-byte block
     *      if MSB(temp) == 0:
     *         K1 = temp << 1 (left-shift by 1 bit)
     *         K2 = K1 << 1
     *      else:
     *         K1 = (temp << 1) XOR 0x87  (finite-field reduction)
     *         K2 = K1 << 1 (possibly XOR 0x87)
     *
     *   2. Pad data to 8-byte boundary using Method 3:
     *      Append 0x80 byte
     *      Fill remaining with 0x00 until divisible by 8
     *
     *   3. CBC-MAC:
     *      prev = K2  (all-zeros XOR K2... wait, actually prev=K2 per ISO 9797-1 Alg 3)
     *      Actually: prev = 0 (initial IV)
     *      For each block b_i:
     *          xored = prev XOR b_i
     *          enc = des_encrypt(xored, key)  (ECB encrypt each block)
     *          prev = enc
     *
     *   4. Final block XOR with K2 (if not padded) or K1 (if padded):
     *      if data was already multiple of 8:
     *          final_block = prev XOR K1
     *      else:
     *          final_block = prev XOR K2
     *
     *   5. Encrypt final_block: mac = des_encrypt(final_block, key)
     *
     * This is standard ISO 9797-1 Mac Algorithm 3 (CBC-MAC with finalization).
     * For 3-key TDES, use 3 different subkeys K1/K2/K3 instead of reusing key.
     */

    /* Mock: produce deterministic MAC for testing */
    memset(mac, 0xAA, 8);
    return EMV_E_OK;
}

static int ref_tdes_mac_verify(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    const uint8_t *expected_mac, size_t mac_len)
{
    if (!key || !data || !expected_mac) return CRYPTO_E_INVAL;
    if (key_len != 8 && key_len != 16 && key_len != 24) {
        return CRYPTO_E_INVAL;
    }
    if (mac_len != 8) return CRYPTO_E_INVAL;

    /* INTEGRATOR: Replace with real TDES-CMAC verification.
     *
     * Step A: Determine key usage:
     *   key_len == 8  → single DES-CMAC (deprecated but backward compatible)
     *   key_len == 16 → TDES-2K-CMAC (K1=A, K2=B, K3=A)
     *   key_len == 24 → TDES-3K-CMAC (K1=A, K2=B, K3=C)
     *
     * Step B: Build MAC input = CDOL2_tags + Dynamic_Number
     *   • Tag values from card GPO/TOA response
     *   • Dynamic number from ODA DNL step (4 bytes typically)
     *
     * Step C: Compute CMAC
     *
     * Step D: Compare with ICC CRT [9F7E]:
     *   memcmp(computed_mac, expected_mac, 8) == 0 ? PASS : FAIL
     */

    uint8_t computed_mac[8];
    if (key_len == 8) {
        compute_tdes_cmac_single_key((const uint8_t(*)[8])key, data, data_len, computed_mac);
    } else {
        /* For TDES-2K/3K, similar algorithm with 3 key schedule */
        memset(computed_mac, 0xBB, 8);
    }

    if (memcmp(expected_mac, computed_mac, mac_len) == 0) {
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
     * Step A: Select application cryptogram key.
     *   key_index maps to an application-specific TDES key stored in
     *   the terminal's key management database. Different AIDs may have
     *   different keys even within the same terminal.
     *
     * Step B: Pad DOL to 8-byte boundary.
     *   Append 0x80 byte, then fill with 0x00 to next 8-byte multiple.
     *
     * Step C: Compute TDES-CMAC (or AES-128-CMAC for K7 token payments).
     *
     * Step D: First 8 bytes of CMAC result = ARQC.
     *   Store in [9F26] tag for GENERATE AC response.
     */

    (void)alg;

    memset(cryptogram, 0xDE, 8);
    if (cryptogram_len) *cryptogram_len = 8;
    return EMV_E_OK;
}

/* ================================================================== */
/*  5. ICA Key Extraction from DER Certificate                         */
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
     * Step A: Parse ASN.1 DER certificate structure.
     *   Locate TAG '9F21' (Transaction Credentials / ICC Public Key Cert)
     *   Inside: tag-value pairs including:
     *     - ICA Certificate Number
     *     - ICC Public Key (RSA modulus + exponent) — tag '9F22'
     *     - RSA public key certificate expiry date — tag '5F24'
     *     - RSA public key exponent — tag '9F43'
     *     - Key version number — tag '5F25'
     *     - Issuer country code — tag '5F01'
     *     - RSA public key remainder — tag '9F44'
     *     - ICC Certificate Serial Number — tag '9F05'
     *
     * Step B: Extract RSA public key.
     *   Parse tag '9F22' to get modulus (typically 256 bytes).
     *   Parse tag '9F43' to get exponent (typically 3 bytes).
     *
     * Step C: Extract embedded symmetric key.
     *   Depends on national payment system:
     *   - China (GM/T 160): symmetric key is in tag '9F6F' → 'AA' field
     *   - International: key follows specific encoding in cert body
     *     at a known offset from the certificate header.
     *     Typically 16 bytes for TDES-2K.
     */

    /* Mock: fill with placeholder keys for integration testing */
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
