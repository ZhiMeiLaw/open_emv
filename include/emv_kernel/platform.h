/**
 * @file emv_kernel/platform.h
 * @brief Platform abstraction interface — parameters, ICCDB, crypto registration.
 *
 * These functions are declared here but implemented by the integrator.
 * They provide access to terminal configuration, persistent card state,
 * and register external drivers.
 */

#ifndef EMV_KERNEL_PLATFORM_H
#define EMV_KERNEL_PLATFORM_H

#include "emv_kernel/types.h"
#include "emv_kernel/kernel_interface.h"

/* ------------------------------------------------------------------ */
/*  POSIX/Windows optional includes                                   */
/* ------------------------------------------------------------------ */
#ifdef __unix__
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

/* ------------------------------------------------------------------ */
/*  Parameter I/O (POS terminal configuration)                        */
/* ------------------------------------------------------------------ */

/**
 * Read a POS terminal parameter by EMV tag.
 * @param tag   EMV tag number (e.g., 0x9F02, 0x9F66)
 * @param buf   Output buffer
 * @param len   In: max bytes; Out: actual bytes read
 * @return 0 on success, -ENOENT if tag not configured, other negative on error.
 *
 * Integrator implements this to read from flash, NV storage, config file, etc.
 */
int param_read(uint16_t tag, uint8_t *buf, uint8_t *len);

/**
 * Write a POS terminal parameter by EMV tag.
 * @param tag   EMV tag number
 * @param value Data to write
 * @param len   Length of data
 * @return 0 on success.
 */
int param_write(uint16_t tag, const uint8_t *value, uint8_t len);


/* ------------------------------------------------------------------ */
/*  ICCDB (Intrinsic Card Data Base)                                  */
/* ------------------------------------------------------------------ */

/**
 * ICCDB field identifiers for standard fields.
 */
enum {
    ICCDB_FIELD_HF_COUNTER      = 0x01,   /* High-frequency transaction counter     */
    ICCDB_FIELD_ONLINE_COUNTER  = 0x02,   /* Online transaction count               */
    ICCDB_FIELD_TXN_DATE        = 0x03,   /* Last transaction date (YYYYMMDD)       */
    ICCDB_FIELD_TXN_TIME        = 0x04,   /* Last transaction time (HHMMSS)         */
    ICCDB_FIELD_RETRIEVAL_DATE  = 0x05,   /* Last ERQ retrieval date                */
    ICCDB_FIELD_VEL_AMT_SUM     = 0x06,   /* Velocity amount sum                    */
    ICCDB_FIELD_VEL_AMT_DATE    = 0x07,   /* Velocity amount sum date               */
    ICCDB_FIELD_VEL_COUNT       = 0x08,   /* Frequency velocity count               */
    ICCDB_FIELD_VEL_COUNT_DATE  = 0x09,   /* Frequency velocity count date          */
    ICCDB_FIELD_CRM_LIMIT_1     = 0x0A,   /* CRM limit set 1                      */
    ICCDB_FIELD_CRM_LIMIT_2     = 0x0B,   /* CRM limit set 2                      */
    ICCDB_FIELD_TERM_EXPIRY     = 0x0C,   /* Terminal expiry date                   */
    ICCDB_FIELD_MAX             = 0xFF,   /* Sentinel                              */
};

/**
 * Read an ICCDB field for a specific card.
 * @param card_hash  Unique identifier for the card (SHA-256 or PAN hash, 16+ bytes)
 * @param field_id   Field identifier from ICCDB_FIELD_*
 * @param buf        Output buffer
 * @param len        In: max bytes; Out: actual bytes read
 * @return 0 on success, -ENOENT if card/hash not found.
 */
int iccdb_read(const uint8_t *card_hash, uint8_t field_id,
               uint8_t *buf, uint8_t *len);

/**
 * Write an ICCDB field for a specific card.
 */
int iccdb_write(const uint8_t *card_hash, uint8_t field_id,
                const uint8_t *value, uint8_t len);

/**
 * Delete all ICCDB data for a card.
 */
int iccdb_delete(const uint8_t *card_hash);


/* ------------------------------------------------------------------ */
/*  PRNG (Pseudo-Random Number Generator)                             */
/* ------------------------------------------------------------------ */

/**
 * Generate cryptographically secure random bytes.
 * Used for CDOL1 unpredictable number generation (ISO 14443-4).
 * @param buf Output buffer
 * @param len Number of bytes required
 * @return 0 on success, non-zero if entropy unavailable.
 */
int platform_prng(uint8_t *buf, uint16_t len);


/* ------------------------------------------------------------------ */
/*  Time                                                              */
/* ------------------------------------------------------------------ */

/**
 * Get current time in milliseconds since an epoch.
 * Monotonically increasing, at least millisecond resolution.
 */
uint32_t platform_time_get_ms(void);


/* ------------------------------------------------------------------ */
/*  Driver Registration                                               */
/* ------------------------------------------------------------------ */

/**
 * Register the crypto driver provided by the integrator.
 * Must be called before any kernel execution.
 * @return 0 on success.
 */
int platform_register_crypto(const crypto_driver_t *driver);

/**
 * Register the terminal/acquirer interface.
 * @return 0 on success.
 */
int platform_register_acq_iface(const term_acq_interface_t *iface);

/**
 * Get the registered crypto driver.
 * Returns NULL if not yet registered.
 */
const crypto_driver_t *platform_get_crypto(void);

/**
 * Get the registered acquirer interface.
 */
const term_acq_interface_t *platform_get_acq_iface(void);

/* ------------------------------------------------------------------ */
/*  Internal — caller should NOT call these directly                  */
/* ------------------------------------------------------------------ */

/* Backing storage for registered drivers (defined in platform.c) */
extern const crypto_driver_t *g_crypto_driver;
extern const term_acq_interface_t *g_acq_interface;

#endif /* EMV_KERNEL_PLATFORM_H */
