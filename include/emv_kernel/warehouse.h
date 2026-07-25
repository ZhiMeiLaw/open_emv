/**
 * @file emv_kernel/warehouse.h
 * @brief Transaction-scoped TLV data warehouse interface.
 *
 * Provides a zero-copy key-value store backed by a flat memory pool.
 * All values are pointers into the pool — no heap allocation ever.
 */

#ifndef EMV_KERNEL_WAREHOUSE_H
#define EMV_KERNEL_WAREHOUSE_H

#include "emv_kernel/types.h"
#include "emv_kernel/errors.h"

/* ------------------------------------------------------------------ */
/*  Initialization / lifecycle                                        */
/* ------------------------------------------------------------------ */

/**
 * Initialize or reset a warehouse for a new transaction.
 * @param wh        Pointer to caller-owned tx_warehouse_t
 * @param pool_ptr  Pointer to caller-owned byte buffer (must be >= pool_size)
 * @param pool_size Size of pool_ptr in bytes
 */
void tlv_warehouse_init(tx_warehouse_t *wh, uint8_t *pool_ptr, uint16_t pool_size);

/** Reset warehouse state without re-assigning pool pointer. */
void tlv_warehouse_clear(tx_warehouse_t *wh);

/* ------------------------------------------------------------------ */
/*  Core operations                                                   */
/* ------------------------------------------------------------------ */

/**
 * Allocate bytes from the warehouse pool.
 * @return Pointer into pool, or NULL if OOM.
 */
uint8_t *tlv_alloc(tx_warehouse_t *wh, uint16_t bytes);

/**
 * Store a value in the warehouse under the given tag.
 * If tag already exists, replaces the old entry.
 * @return WH_E_OK on success, WH_E_OOM on OOM, WH_E_INVAL on invalid arg.
 */
int tlv_store_set(tx_warehouse_t *wh, uint32_t tag, const uint8_t *src, uint16_t len);

/**
 * Store a value with an explicit index (for duplicate tags).
 * @return WH_E_OK on success, WH_E_OOM on OOM, WH_E_INVAL on invalid arg.
 */
int tlv_store_set_indexed(tx_warehouse_t *wh, uint32_t tag, uint8_t index,
                          const uint8_t *src, uint16_t len);

/**
 * Retrieve a value by tag. Copies into dst buffer.
 * @param wh       Warehouse pointer
 * @param tag      Tag number
 * @param dst      Output buffer
 * @param out_len  In: max bytes; Out: actual bytes copied
 * @return WH_E_OK on success, WH_E_NOTFOUND if tag not found.
 */
int tlv_store_get(const tx_warehouse_t *wh, uint32_t tag, uint8_t *dst, uint16_t *out_len);

/**
 * Retrieve a value by tag and index.
 */
int tlv_store_get_indexed(const tx_warehouse_t *wh, uint32_t tag, uint8_t index,
                          uint8_t *dst, uint16_t *out_len);

/**
 * Delete an entry by tag.
 * @return WH_E_OK on success, WH_E_NOTFOUND if not found.
 */
int tlv_store_delete(tx_warehouse_t *wh, uint32_t tag);

/**
 * Delete an entry by tag and index.
 */
int tlv_store_delete_indexed(tx_warehouse_t *wh, uint32_t tag, uint8_t index);

/**
 * Find a matching entry by tag.
 * @returns pointer to tlv_entry_t, or NULL if not found.
 */
const tlv_entry_t *tlv_find(const tx_warehouse_t *wh, uint32_t tag);

/* ------------------------------------------------------------------ */
/*  Convenience helpers                                               */
/* ------------------------------------------------------------------ */

/** Check if a tag exists in the warehouse. */
int tlv_contains(const tx_warehouse_t *wh, uint32_t tag);

/** Get the current number of entries. */
static inline uint8_t tlv_count(const tx_warehouse_t *wh)
{
    return wh->count;
}

#endif /* EMV_KERNEL_WAREHOUSE_H */
