/**
 * @file tests/host/host_platform.c
 * @brief Platform hook stubs for the POSIX/Windows host test harness.
 *
 * These functions implement the platform interface declared in
 * emv_kernel/platform.h. They are intentionally simple — tests use
 * mock card data and do not exercise real hardware paths.
 *
 * Call host_platform_init() before running any test to register
 * the reference crypto driver and seed the platform state.
 */

#include "emv_kernel/platform.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/errors.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* ================================================================== */
/*  POS parameter store                                               */
/* ================================================================== */

#define MAX_HOST_PARAMS  64

typedef struct {
    uint16_t tag;
    uint8_t  value[16];
    uint8_t  len;
} host_param_entry_t;

static host_param_entry_t g_params[MAX_HOST_PARAMS];
static uint8_t g_param_count = 0;
static int g_params_initialized = 0;

/* ================================================================== */
/*  ICCDB stub — tests never need real card DB data                   */
/* ================================================================== */

int iccdb_read(const uint8_t *card_hash, uint8_t field_id,
               uint8_t *buf, uint8_t *len)
{
    (void)card_hash; (void)field_id;
    if (!buf || !len) return PLAT_E_INVAL;
    return PLAT_E_NOTSTORED;
}

int iccdb_write(const uint8_t *card_hash, uint8_t field_id,
                const uint8_t *value, uint8_t len)
{
    (void)card_hash; (void)field_id; (void)value; (void)len;
    return PLAT_E_NOTSTORED;
}

int iccdb_delete(const uint8_t *card_hash)
{
    (void)card_hash;
    return PLAT_E_NOTSTORED;
}

/* ================================================================== */
/*  param_read / param_write                                          */
/* ================================================================== */

int param_read(uint16_t tag, uint8_t *buf, uint8_t *len)
{
    if (!buf || !len) return PLAT_E_INVAL;
    if (!g_params_initialized) return PLAT_E_NOTCONF;

    for (uint8_t i = 0; i < g_param_count; i++) {
        if (g_params[i].tag == tag) {
            uint8_t copy_len = g_params[i].len < *len ?
                               g_params[i].len : *len;
            memcpy(buf, g_params[i].value, copy_len);
            *len = copy_len;
            return PLAT_E_OK;
        }
    }
    return PLAT_E_NOTCONF;
}

int param_write(uint16_t tag, const uint8_t *value, uint8_t len)
{
    if (!value || len == 0 || len > 16) return PLAT_E_INVAL;
    if (!g_params_initialized) return PLAT_E_NOTCONF;

    for (uint8_t i = 0; i < g_param_count; i++) {
        if (g_params[i].tag == tag) {
            g_params[i].len = len;
            memcpy(g_params[i].value, value, len);
            return PLAT_E_OK;
        }
    }
    if (g_param_count >= MAX_HOST_PARAMS) return PLAT_E_STORE_FULL;
    g_params[g_param_count].tag = tag;
    g_params[g_param_count].len = len;
    memcpy(g_params[g_param_count].value, value, len);
    g_param_count++;
    return PLAT_E_OK;
}

/* ================================================================== */
/*  PRNG — deterministic for reproducible tests                       */
/* ================================================================== */

int platform_prng(uint8_t *buf, uint16_t len)
{
    if (!buf) return PLAT_E_INVAL;
    /* LCG — not cryptographically secure, but deterministic for tests */
    static uint32_t state = 0x12345678;
    for (uint16_t i = 0; i < len; i++) {
        state = state * 1103515245u + 12345u;
        buf[i] = (uint8_t)((state >> 16) & 0xFF);
    }
    return PLAT_E_OK;
}

/* ================================================================== */
/*  Time — millisecond clock                                          */
/* ================================================================== */

uint32_t platform_time_get_ms(void)
{
#if defined(_WIN32)
    return (uint32_t)GetTickCount();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
#endif
}

/* ================================================================== */
/*  Host parameter defaults — sensible EMV terminal config            */
/* ================================================================== */

static void host_param_init(void)
{
    if (g_params_initialized) return;

    /* Terminal Currency Code — USD = 840 */
    uint8_t tc[] = { 0x08, 0x40 };
    param_write(0x9F1A, tc, sizeof(tc));

    /* Transaction Currency Code — USD */
    param_write(0x5F2A, tc, sizeof(tc));

    /* Amount, Authorised — 0.00 */
    uint8_t amt[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    param_write(0x9F02, amt, sizeof(amt));

    /* Amount, Other — 0 */
    uint8_t amt_other[] = { 0x00 };
    param_write(0x9F36, amt_other, sizeof(amt_other));

    /* Terminal Qualifiers — contactless, no CVM, ARQC required */
    uint8_t tq[] = { 0xF8, 0x00, 0x05, 0x80 };
    param_write(0x9F66, tq, sizeof(tq));

    /* Amount, Default (for TDOL) */
    param_write(0x9F03, amt, sizeof(amt));

    g_params_initialized = 1;
}

/* ================================================================== */
/*  Public: initialise host platform                                  */
/* ================================================================== */

void host_platform_init(void)
{
    host_param_init();
}
