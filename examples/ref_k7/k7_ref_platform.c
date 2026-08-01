/**
 * @file examples/ref_k7/k7_ref_platform.c
 * @brief Kernel 7 reference platform implementation.
 *
 * Provides dummy/placeholder implementations for platform hooks required
 * by the EMV kernel framework. These should be replaced with platform-specific
 * code during integration.
 *
 * For token payments (K7), includes token-specific extensions:
 *   - Token PAN storage and retrieval
 *   - SDS code management
 *   - Token usage counter persistence
 */

#include "emv_kernel/types.h"
#include "emv_kernel/platform.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/errors.h"
#include <string.h>
#include <stdlib.h>

/* ================================================================== */
/*  Platform storage for token parameters                             */
/* ================================================================== */

/* Global store for token-specific POS parameters - integrator should
 * provide secure storage implementation. */
static struct {
    int initialized;
    pos_params_k7_t pos_params;
    uint8_t iccdb[1024];  /* Simulated ICCDB storage for token card */
    uint32_t hf_counter;  /* High frequency counter */
    uint32_t online_counter;
    uint32_t transaction_count;
} k7_platform_store;

/* ================================================================== */
/*  STEP 1: Platform initialization                                   */
/* ================================================================== */

int platform_init(void)
{
    /* Initialize the platform store */
    memset(&k7_platform_store, 0, sizeof(k7_platform_store));
    k7_platform_store.initialized = 1;

    /* Load token card data from secure storage here if available */
    /* iccdb_load(&k7_platform_store.iccdb); */

    return 0;
}

/* ================================================================== */
/*  param_read / param_write - Terminal parameter access              */
/* ================================================================== */

int param_read(uint16_t tag, uint8_t *buf, uint8_t *len)
{
    if (!k7_platform_store.initialized) return -1;
    if (!buf || !len) return -1;

    switch (tag) {
    case 0x9F1A: /* Terminal Currency Code */
        if (*len < 2) {
            *len = 2;
            return -1;
        }
        buf[0] = 0x35; /* Example: EUR */
        buf[1] = 0x38;
        *len = 2;
        break;

    case 0x9F02: /* Amount, Authorised (terminal default) */
        if (*len < 6) {
            *len = 6;
            return -1;
        }
        /* Zero amount by default */
        memset(buf, 0, 6);
        *len = 6;
        break;

    case 0x5F2A: /* Transaction Currency Code */
        if (*len < 2) {
            *len = 2;
            return -1;
        }
        buf[0] = 0x35;
        buf[1] = 0x38;
        *len = 2;
        break;

    case 0x9F66: /* Terminal Qualifiers */
        if (*len < 4) {
            *len = 4;
            return -1;
        }
        /* Default terminal qualifiers (token-capable) */
        buf[0] = 0x00; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00;
        *len = 4;
        break;

    default:
        /* Unknown tag - return not found */
        return -1;
    }

    return 0;
}

int param_write(uint16_t tag, const uint8_t *value, uint8_t len)
{
    (void)tag; (void)value; (void)len;
    /* In production, write persistent parameters to secure storage */
    /* For now, token parameters are read-only */
    return -1;
}

/* ================================================================== */
/*  iccdb_read / iccdb_write - ICC database access for token cards    */
/* ================================================================== */

int iccdb_read(const uint8_t *card_hash, uint8_t field_id,
               uint8_t *buf, uint8_t *len)
{
    (void)card_hash;
    if (!k7_platform_store.initialized) return -1;
    if (!buf || !len) return -1;

    switch (field_id) {
    case ICCDB_FIELD_HF_COUNTER:
        if (*len < 2) {
            *len = 2;
            return -1;
        }
        buf[0] = (uint8_t)((k7_platform_store.hf_counter >> 8) & 0xFF);
        buf[1] = (uint8_t)(k7_platform_store.hf_counter & 0xFF);
        *len = 2;
        break;

    case ICCDB_FIELD_ONLINE_COUNTER:
        if (*len < 2) {
            *len = 2;
            return -1;
        }
        buf[0] = (uint8_t)((k7_platform_store.online_counter >> 8) & 0xFF);
        buf[1] = (uint8_t)(k7_platform_store.online_counter & 0xFF);
        *len = 2;
        break;

    default:
        return -1;
    }

    return 0;
}

int iccdb_write(const uint8_t *card_hash, uint8_t field_id,
                const uint8_t *value, uint8_t len)
{
    (void)card_hash;
    if (!k7_platform_store.initialized) return -1;

    switch (field_id) {
    case ICCDB_FIELD_HF_COUNTER:
        if (len >= 2) {
            k7_platform_store.hf_counter = (value[0] << 8) | value[1];
        }
        break;

    case ICCDB_FIELD_ONLINE_COUNTER:
        if (len >= 2) {
            k7_platform_store.online_counter = (value[0] << 8) | value[1];
        }
        break;

    default:
        return -1;
    }

    return 0;
}

/* ================================================================== */
/*  PRNG - Pseudo-random number generator (for token transactions)    */
/* ================================================================== */

int platform_prng(uint8_t *buf, uint16_t len)
{
    if (!buf || len == 0) return -1;

    /* Simple LBG PRNG - for integration, replace with hardware RNG */
    static uint32_t rng_state = 1;
    for (size_t i = 0; i < len; i++) {
        rng_state = rng_state * 1103515245UL + 12345;
        buf[i] = (uint8_t)(rng_state >> 24);
    }

    return 0;
}

/* ================================================================== */
/*  Time functions                                                    */
/* ================================================================== */

uint32_t platform_time_get_ms(void)
{
    /* Return a stable timestamp - in production use system clock */
    return 1000000; /* Example: 1 second */
}

/* ================================================================== */
/*  Crypto registration (for K7)                                      */
/* ================================================================== */

/* Note: platform_register_crypto is implemented in core platform.c.
   Integrator calls platform_register_crypto directly from their code. */

void platform_register_acq(const term_acq_interface_t *iface)
{
    (void)iface;
}

/* ================================================================== */
/*  K7-specific POS parameter initialization                          */
/* ================================================================== */

void pos_params_init_defaults_k7(void)
{
    /* Initialize default POS parameters for K7 token payments */
    k7_platform_store.pos_params.sds_code = 0x01;      /* Default SDS */
    k7_platform_store.pos_params.tip_signature_supported = 0;
    k7_platform_store.pos_params.tip_online_pin_supported = 1;
    k7_platform_store.pos_params.unsigned_limit = 0;   /* No unsigned limit */
    k7_platform_store.pos_params.signed_limit = 5000;  /* PIN required > 5000 */
    k7_platform_store.pos_params.pin_key_index = 0;

    /* Initialize counters */
    k7_platform_store.hf_counter = 1;
    k7_platform_store.online_counter = 0;
    k7_platform_store.transaction_count = 0;

    k7_platform_store.initialized = 1;
}

/* ================================================================== */
/*  IC Reader Provider mock for testing (alternative to full HW)      */
/* ================================================================== */

/* See k7_ref_icr_mock.c for separate mock implementation */
