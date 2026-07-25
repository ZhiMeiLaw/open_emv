/**
 * @file examples/ref_k3/k3_ref_platform.c
 * @brief Kernel 3 reference: platform hooks implementation.
 *
 * This file shows how an integrator should implement the platform
 * hook functions declared in emv_kernel/platform.h.
 *
 * Each function has a MOCK implementation + detailed comments showing
 * what the real integration should look like for different platforms.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/platform.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ================================================================== */
/*  POS Terminal Parameters — static store for reference               */
/* ================================================================== */
/**
 * In production, these live in flash / NV storage / secure element.
 * Here we use a static map for demonstration.
 */
#define MAX_POS_PARAMS    64

typedef struct {
    uint16_t tag;
    uint8_t  value[16];
    uint8_t  len;
} pos_param_entry_t;

static pos_param_entry_t g_pos_params[MAX_POS_PARAMS];
static uint8_t g_pos_param_count = 0;

/**
 * Load default POS parameters at startup.
 * INTEGRATOR: Replace with your terminal's config loading logic.
 */
static void pos_params_init_defaults(void)
{
    /* Terminal country code: China = 608 (BCD: 0x60, 0x08 → stored as raw) */
    uint8_t country[] = { 0x06, 0x08 };  /* GB = UK, CN = 608 */
    param_write(0x9F1A, country, sizeof(country));

    /* Transaction currency: CNY = 156 (0x01, 0x56) */
    uint8_t currency[] = { 0x01, 0x56 };
    param_write(0x5F2A, currency, sizeof(currency));

    /* Amount, Authorised — default 0 for interactive entry */
    uint8_t amount[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    param_write(0x9F02, amount, sizeof(amount));

    /* Amount, Other (default 0) */
    uint8_t amt_other[6] = { 0x00 };
    param_write(0x9F36, amt_other, sizeof(amt_other));

    /* Terminal Qualifiers (9F66) — 4 bytes */
    /* Byte 1: B1=online credentials available, B2=CVM supported, etc. */
    /* Byte 2: B9=default terminal (yes), B10=contactless warm reset, etc. */
    /* Byte 3: POS entry mode (contactless = 0x05) */
    /* Byte 4: Cryptogram decision (ARQC required = bit 7) */
    uint8_t tq[] = { 0xF8, 0x00, 0x05, 0x80 };
    param_write(0x9F66, tq, sizeof(tq));

    /* Signed/Unsigned amount limits (custom terminal-specific data) */
    // Unsigned limit: ¥1000 → store as 3-byte BCD 0x00 0x01 0x00 = param_write CUSTOM tag
    // Signed limit: ¥3000 → 0x00 0x03 0x00
}

/* ---- param_read implementation ---- */
int param_read(uint16_t tag, uint8_t *buf, uint8_t *len)
{
    if (!buf || !len) return PLAT_E_INVAL;

    for (uint8_t i = 0; i < g_pos_param_count; i++) {
        if (g_pos_params[i].tag == tag) {
            uint8_t copy_len = g_pos_params[i].len < *len ? g_pos_params[i].len : *len;
            memcpy(buf, g_pos_params[i].value, copy_len);
            *len = copy_len;
            return EMV_E_OK;
        }
    }

    return PLAT_E_NOTCONF;
}

/* ---- param_write implementation ---- */
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
    return 0;
}

/* ================================================================== */
/*  ICCDB Reference Implementation                                    */
/* ================================================================== */
/**
 * Simple hash-table-based ICCDB stored in RAM.
 * In production: replace with NV flash / SE storage / SQLite.
 */
#define MAX_ICCDB_ENTRIES   32

typedef struct {
    uint8_t card_hash[16];   /* SHA-256 of PAN or card identifier     */
    uint8_t fields[ICCDB_FIELD_MAX]; /* Per-field storage (variable size) */
    uint8_t field_lens[ICCDB_FIELD_MAX];
    int     in_use;
} iccdb_entry_t;

static iccdb_entry_t g_iccdb_store[MAX_ICCDB_ENTRIES];

/* Find ICCDB entry by card hash */
static iccdb_entry_t *iccdb_find(const uint8_t *card_hash)
{
    for (int i = 0; i < MAX_ICCDB_ENTRIES; i++) {
        if (!g_iccdb_store[i].in_use) continue;
        if (memcmp(card_hash, g_iccdb_store[i].card_hash, 16) == 0) {
            return &g_iccdb_store[i];
        }
    }
    return NULL;
}

/* Get a free ICCDB slot */
static iccdb_entry_t *iccdb_get_free_slot(void)
{
    for (int i = 0; i < MAX_ICCDB_ENTRIES; i++) {
        if (!g_iccdb_store[i].in_use) return &g_iccdb_store[i];
    }
    return NULL;
}

/* ---- iccdb_read implementation ---- */
int iccdb_read(const uint8_t *card_hash, uint8_t field_id,
               uint8_t *buf, uint8_t *len)
{
    if (!card_hash || !buf || !len) return PLAT_E_INVAL;

    iccdb_entry_t *entry = iccdb_find(card_hash);
    if (!entry) return PLAT_E_NOTSTORED;  /* Card not found */

    if (field_id >= ICCDB_FIELD_MAX || entry->field_lens[field_id] == 0) {
        return PLAT_E_NOTSTORED;  /* Field not set */
    }

    uint8_t copy_len = entry->field_lens[field_id] < *len ?
                       entry->field_lens[field_id] : *len;
    memcpy(buf, entry->fields + field_id * 8, copy_len);  /* 8 bytes per field max */
    *len = copy_len;
    return 0;
}

/* ---- iccdb_write implementation ---- */
int iccdb_write(const uint8_t *card_hash, uint8_t field_id,
                const uint8_t *value, uint8_t len)
{
    if (!card_hash || !value || len == 0) return PLAT_E_INVAL;
    if (field_id >= ICCDB_FIELD_MAX) return PLAT_E_INVAL;

    iccdb_entry_t *entry = iccdb_find(card_hash);
    if (!entry) {
        entry = iccdb_get_free_slot();
        if (!entry) return PLAT_E_STORE_FULL;  /* Store full */

        memset(entry, 0, sizeof(*entry));
        memcpy(entry->card_hash, card_hash, 16);
        entry->in_use = 1;
    }

    /* Simple: store first 'len' bytes in field slot */
    memcpy(entry->fields + field_id * 8, value, len < 8 ? len : 8);
    entry->field_lens[field_id] = len < 8 ? len : 8;
    return 0;
}

/* ---- iccdb_delete implementation ---- */
int iccdb_delete(const uint8_t *card_hash)
{
    if (!card_hash) return PLAT_E_INVAL;

    iccdb_entry_t *entry = iccdb_find(card_hash);
    if (!entry) return PLAT_E_NOTSTORED;

    memset(entry, 0, sizeof(*entry));
    entry->in_use = 0;
    return 0;
}

/* ================================================================== */
/*  PRNG Reference Implementation                                     */
/* ================================================================== */
/**
 * Mock PRNG using a simple LCG. Replace with true RNG / hardware RNG.
 */
static uint32_t g_prng_state = 0xDEADBEEF;

int platform_prng(uint8_t *buf, uint16_t len)
{
    if (!buf) return PLAT_E_INVAL;

    for (uint16_t i = 0; i < len; i++) {
        /* Linear congruential generator (NOT cryptographically secure!) */
        g_prng_state = g_prng_state * 1103515245u + 12345u;
        buf[i] = (uint8_t)((g_prng_state >> 16) & 0xFF);
    }

    /* INTEGRATOR: Replace with real entropy source:
     *
     * Option A — Hardware RNG (MCU built-in):
     *   for (i=0; i<len; i++) buf[i] = HAL_RNG_GetRandomNumber();
     *
     * Option B — Thermal noise / oscillator jitter:
     *   gather_jitter_samples(buf, len);
     *
     * Option C — TRNG via Secure Element:
     *   se_apdu_send(TRNG_CMD, buf, len);
     */

    return 0;
}

/* ================================================================== */
/*  Time Reference Implementation                                     */
/* ================================================================== */
uint32_t platform_time_get_ms(void)
{
    /* INTEGRATOR: Replace with your platform's timer:
     *
     * Option A — POSIX: return (uint32_t)(clock() * 1000 / CLOCKS_PER_SEC);
     * Option B — Windows: return (uint32_t)GetTickCount();
     * Option C — MCU tick: return (uint32_t)systick_counter;
     * Option D — Real-time clock: convert RTC to ms epoch
     */

    /* Mock: incrementing counter (not realistic — just for compilation) */
    static uint32_t mock_time = 1000000;
    mock_time += 10;
    return mock_time;
}

/* ================================================================== */
/*  Integration helper: load all POS params into warehouse            */
/* ================================================================== */
/**
 * Helper function called by the orchestrator after GPO succeeds.
 * Takes all terminal-known tags from the param store and populates
 * the input warehouse so the kernel can use them.
 */
int k3_load_pos_params_to_warehouse(tx_warehouse_t *wh)
{
    if (!wh) return PLAT_E_INVAL;

    /* K3 TDOL tags that come from terminal */
    uint16_t tdol_tags[] = { 0x9F16, 0x9F02, 0x9F36, 0x9F03, 0x5F2A, 0x9F66 };

    for (int i = 0; i < 6; i++) {
        uint8_t buf[16];
        uint8_t blen = sizeof(buf);
        int rc = param_read(tdol_tags[i], buf, &blen);
        if (rc == 0 && blen > 0) {
            tlv_store_set(wh, tdol_tags[i], buf, blen);
        }
        /* If tag not found (param_read returns -2), skip — terminal
           may generate it later (e.g., TN for 9F16) */
    }

    return 0;
}
