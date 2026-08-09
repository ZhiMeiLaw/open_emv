/**
 * @file examples/ref_k6/k6_ref_crypto.c
 * @brief Kernel 6 reference: minimal crypto (no DDA/CDA needed).
 */

#include "emv_kernel/crypto_driver.h"
#include "emv_kernel/errors.h"
#include <string.h>

static int ref_des_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
    (void)key; (void)in; (void)out;
    return CRYPTO_E_OK;
}

static int ref_tdes_cmac(const uint8_t *key, const uint8_t *data, size_t len, uint8_t *mac)
{
    (void)key; (void)data; (void)len; (void)mac;
    return CRYPTO_E_OK;
}

static int ref_rsa_pkpad_verify(const uint8_t *cert, size_t cert_len,
                                 const uint8_t *ddic, size_t ddic_len,
                                 const uint8_t *data, size_t data_len)
{
    (void)cert; (void)cert_len; (void)ddic; (void)ddic_len;
    (void)data; (void)data_len;
    return CRYPTO_E_OK;
}

const crypto_driver_t ref_crypto_driver_k6 = {
    .des_encrypt           = ref_des_encrypt,
    .tdes_cmac_compute     = ref_tdes_cmac,
    .rsa_pkpad_verify      = ref_rsa_pkpad_verify,
    .version               = 1,
};
