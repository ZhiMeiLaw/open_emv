/**
 * @file examples/ref_k5/k5_ref_platform.c
 * @brief Kernel 5 (qVISA / Crypto) reference platform implementation.
 *
 * Provides placeholder implementations for platform hooks required
 * by the EMV kernel framework. These should be replaced with
 * platform-specific code during integration.
 *
 * K5-specific notes:
 *   - CDA-based card authentication (primary path)
 *   - No PIN CVM — amount-only verification (unsigned_limit enforced)
 *   - Supports both TC (offline) and ARQC (online) flows
 *   - TDOL structure same as K3: TN+Amount+Cur+TQ etc.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/platform.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/errors.h"
#include <string.h>
extern void pos_params_init_defaults_k5(void);

/* ================================================================== */
/*  POS Terminal Parameters — static store                            */
/* ================================================================== */

#define MAX_POS_PARAMS    64

typedef struct {
    uint16_t tag;
    uint8_t  value[16];
    uint8_t  len;
} pos_param_entry_t;

static pos_param_entry_t g_pos_params[MAX_POS_PARAMS];
static uint8_t g_pos_param_count = 0;

/* ================================================================== */
/*  K5-specific POS parameters                                        */
/* ================================================================== */

typedef struct {
    uint32_t unsigned_limit;      /* Amount ≤ this → No-CVM (approved) */
    uint32_t signed_limit;        /* Not used in K5 (no PIN path) */
    uint8_t  pin_key_index;       /* Reserved for K5 (no PIN support) */
} pos_params_k5_t;

static pos_params_k5_t g_k5_params;

/* ================================================================== */
/*  Platform storage                                                  */
/* ================================================================== */

static struct {
    int initialized;
    uint8_t iccdb[1024];          /* Simulated ICCDB storage */
    uint32_t hf_counter;          /* High frequency counter */
    uint32_t online_counter;
    uint32_t transaction_count;
} k5_platform_store;

/* ================================================================== */
/*  STEP 1: Platform initialization                                   */
/* ================================================================== */

int platform_init(void)
{
    memset(&k5_platform_store, 0, sizeof(k5_platform_store));
    k5_platform_store.initialized = 1;

    /* Load default ICCDB from secure storage here if available */
    /* iccdb_load(&k5_platform_store.iccdb); */

    pos_params_init_defaults_k5();
    return EMV_E_OK;
}

/* ================================================================== */
/*  param_read / param_write                                          */
/* ================================================================== */

int param_read(uint16_t tag, uint8_t *buf, uint8_t *len)
{
    if (!k5_platform_store.initialized) return PLAT_E_INVAL;
    if (!buf || !len) return PLAT_E_INVAL;

    /* Check terminal-specific param store first */
    for (uint8_t i = 0; i < g_pos_param_count; i++) {
        if (g_pos_params[i].tag == tag) {
            uint8_t copy_len = g_pos_params[i].len < *len ?
                               g_pos_params[i].len : *len;
            memcpy(buf, g_pos_params[i].value, copy_len);
            *len = copy_len;
            return EMV_E_OK;
        }
    }

    /* K5-specific default tags */
    switch (tag) {
    case 0x9F1A: /* Terminal Currency Code */
        if (*len < 2) return PLAT_E_INVAL;
        buf[0] = 0x35; buf[1] = 0x38; /* EUR */
        *len = 2;
        break;

    case 0x5F2A: /* Transaction Currency Code */
        if (*len < 2) return PLAT_E_INVAL;
        buf[0] = 0x35; buf[1] = 0x38; /* EUR */
        *len = 2;
        break;

    case 0x9F02: /* Amount, Authorised — set by POS */
        if (*len < 6) return PLAT_E_INVAL;
        /* Default to zero — POS should set this before transaction */
        memset(buf, 0, 6);
        *len = 6;
        break;

    case 0x9F66: /* Terminal Qualifiers */
        if (*len < 4) return PLAT_E_INVAL;
        /* K5-capable contactless terminal */
        /* Byte 1: online credentials available (bit 0), TVR byte 1 */
        /* Byte 2: CVM supported (no — K5 has no PIN), contactless warm reset */
        /* Byte 3: POS entry mode = contactless (0x05) */
        /* Byte 4: ARQC required (bit 7 set) */
        buf[0] = 0xF8; buf[1] = 0x00;
        buf[2] = 0x05; buf[3] = 0x80;
        *len = 4;
        break;

    default:
        return PLAT_E_NOTCONF;
    }

    return EMV_E_OK;
}

int param_write(uint16_t tag, const uint8_t *value, uint8_t len)
{
    if (!value || len == 0 || len > 16) return PLAT_E_INVAL;

    /* Try to update existing entry */
    for (uint8_t i = 0; i < g_pos_param_count; i++) {
        if (g_pos_params[i].tag == tag) {
            g_pos_params[i].len = len;
            memcpy(g_pos_params[i].value, value, len);
            return EMV_E_OK;
        }
    }

    /* Add new entry */
    if (g_pos_param_count >= MAX_POS_PARAMS) return PLAT_E_STORE_FULL;

    g_pos_params[g_pos_param_count].tag = tag;
    g_pos_params[g_pos_param_count].len = len;
    memcpy(g_pos_params[g_pos_param_count].value, value, len);
    g_pos_param_count++;
    return EMV_E_OK;
}

/* ================================================================== */
/*  ICCDB access                                                      */
/* ================================================================== */

int iccdb_read(const uint8_t *card_hash, uint8_t field_id,
               uint8_t *buf, uint8_t *len)
{
    (void)card_hash;
    if (!k5_platform_store.initialized) return PLAT_E_INVAL;
    if (!buf || !len) return PLAT_E_INVAL;

    switch (field_id) {
    case ICCDB_FIELD_HF_COUNTER:
        if (*len < 2) return PLAT_E_INVAL;
        buf[0] = (uint8_t)((k5_platform_store.hf_counter >> 8) & 0xFF);
        buf[1] = (uint8_t)(k5_platform_store.hf_counter & 0xFF);
        *len = 2;
        break;

    case ICCDB_FIELD_ONLINE_COUNTER:
        if (*len < 2) return PLAT_E_INVAL;
        buf[0] = (uint8_t)((k5_platform_store.online_counter >> 8) & 0xFF);
        buf[1] = (uint8_t)(k5_platform_store.online_counter & 0xFF);
        *len = 2;
        break;

    default:
        return PLAT_E_NOTSTORED;
    }

    return EMV_E_OK;
}

int iccdb_write(const uint8_t *card_hash, uint8_t field_id,
                const uint8_t *value, uint8_t len)
{
    (void)card_hash;
    if (!k5_platform_store.initialized) return PLAT_E_INVAL;
    if (!value || len == 0) return PLAT_E_INVAL;

    switch (field_id) {
    case ICCDB_FIELD_HF_COUNTER:
        if (len >= 2) {
            k5_platform_store.hf_counter = (value[0] << 8) | value[1];
        }
        break;

    case ICCDB_FIELD_ONLINE_COUNTER:
        if (len >= 2) {
            k5_platform_store.online_counter = (value[0] << 8) | value[1];
        }
        break;

    default:
        return PLAT_E_NOTSTORED;
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  PRNG                                                              */
/* ================================================================== */

int platform_prng(uint8_t *buf, uint16_t len)
{
    if (!buf || len == 0) return PLAT_E_INVAL;

    /* INTEGRATOR: Replace with hardware RNG:
     *   - MCU built-in TRNG: HAL_RNG_GetRandomNumber()
     *   - Secure Element TRNG: SE_APDU_TRNG(cmd, buf, len)
     *   - Thermal noise / jitter collection
     */
    static uint32_t rng_state = 0xDEADBEEF;
    for (uint16_t i = 0; i < len; i++) {
        rng_state = rng_state * 1103515245u + 12345;
        buf[i] = (uint8_t)((rng_state >> 16) & 0xFF);
    }
    return EMV_E_OK;
}

/* ================================================================== */
/*  Time                                                              */
/* ================================================================== */

uint32_t platform_time_get_ms(void)
{
    /* INTEGRATOR: Replace with platform clock:
     *   POSIX: (uint32_t)(clock() * 1000 / CLOCKS_PER_SEC)
     *   Windows: (uint32_t)GetTickCount()
     *   MCU: (uint32_t)systick_counter
     */
    static uint32_t mock_time = 1000000;
    mock_time += 10;
    return mock_time;
}

/* ================================================================== */
/*  K5-specific: POS parameter defaults                               */
/* ================================================================== */

void pos_params_init_defaults_k5(void)
{
    /* K5 (qVISA Crypto) does not support PIN CVM.
     * The unsigned_limit controls the threshold below which
     * transactions are approved without any cardholder verification. */
    g_k5_params.unsigned_limit = 10000;  /* e.g., ¢100.00 in minor units */
    g_k5_params.signed_limit = 0;        /* Unused in K5 */
    g_k5_params.pin_key_index = 0;       /* Unused in K5 */

    k5_platform_store.initialized = 1;
}

/* ================================================================== */
/*  Helper: Load terminal-known tags into the transaction warehouse   */
/* ================================================================== */

int k5_load_pos_params_to_warehouse(tx_warehouse_t *wh)
{
    if (!wh) return PLAT_E_INVAL;

    /* K5 TDOL tags — same structure as K3 (Book C-5 references Book C-3 TDOL) */
    uint16_t tdol_tags[] = { 0x9F16, 0x9F02, 0x9F36, 0x9F03, 0x5F2A, 0x9F66 };

    for (int i = 0; i < 6; i++) {
        uint8_t buf[16];
        uint8_t blen = sizeof(buf);
        int rc = param_read(tdol_tags[i], buf, &blen);
        if (rc == 0 && blen > 0) {
            tlv_store_set(wh, tdol_tags[i], buf, blen);
        }
        /* If not configured, skip — terminal may generate TN (0x9F16) later */
    }

    return EMV_E_OK;
}

/* ================================================================== */
/*  K5-specific: enforce unsigned limit in CVM context                */
/* ================================================================== */

/**
 * Check whether the transaction amount is within the unsigned limit.
 * K5 only supports No-CVM (amount check) — no PIN path.
 *
 * @param amount           Transaction amount in minor units
 * @param unsigned_limit   Terminal's unsigned limit
 * @return 0 if amount ≤ limit (CVM passes), -1 if amount exceeds limit
 */
int k5_check_unsigned_limit(uint32_t amount, uint32_t unsigned_limit)
{
    if (amount <= unsigned_limit) {
        return EMV_E_OK;
    }
    /* Amount exceeds unsigned limit — K5 cannot do PIN, must go online */
    return -1;
}
