/**
 * @file src/core/warehouse.c
 * @brief Transaction-scoped TLV data warehouse — zero-copy flat pool implementation.
 */

#include "emv_kernel/warehouse.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ---- Internal helpers -------------------------------------------------- */

static int warehouse_find(const tx_warehouse_t *wh, uint32_t tag)
{
    for (uint8_t i = 0; i < wh->count; i++) {
        if (wh->entries[i].tag == tag) {
            return (int)i;
        }
    }
    return -1;  /* Internal helper returns raw int for index */
}

static int warehouse_find_free_slot(tx_warehouse_t *wh)
{
    for (uint8_t i = 0; i < MAX_TLV_ENTRIES; i++) {
        if (i >= wh->count) {
            return (int)i;
        }
        if (!wh->entries[i].value) {
            return (int)i;
        }
    }
    return -1;  /* No free slots */
}

/* ---- Initialization ---------------------------------------------------- */

void tlv_warehouse_init(tx_warehouse_t *wh, uint8_t *pool_ptr, uint16_t pool_size)
{
    memset(wh, 0, sizeof(*wh));
    wh->pool_used = 0;
    memcpy(wh->pool, pool_ptr, pool_size < MAX_POOL_SIZE ? pool_size : MAX_POOL_SIZE);
}

void tlv_warehouse_clear(tx_warehouse_t *wh)
{
    memset(wh->entries, 0, sizeof(wh->entries));
    wh->pool_used = 0;
    wh->count = 0;
}

/* ---- Bump allocator ---------------------------------------------------- */

uint8_t *tlv_alloc(tx_warehouse_t *wh, uint16_t bytes)
{
    if (bytes == 0 || bytes > MAX_POOL_SIZE) {
        return NULL;
    }
    if (wh->pool_used + bytes > MAX_POOL_SIZE) {
        return NULL;
    }
    uint8_t *ptr = &wh->pool[wh->pool_used];
    wh->pool_used += bytes;
    return ptr;
}

/* ---- Store operations ------------------------------------------------- */

int tlv_store_set(tx_warehouse_t *wh, uint32_t tag, const uint8_t *src, uint16_t len)
{
    if (!wh || !src) return WH_E_INVAL;
    if (len == 0 || len > MAX_POOL_SIZE) return WH_E_INVAL;

    int idx = warehouse_find(wh, tag);
    if (idx < 0) {
        uint8_t *dst = tlv_alloc(wh, len);
        if (!dst) return WH_E_OOM;
        memcpy(dst, src, len);

        int slot = warehouse_find_free_slot(wh);
        if (slot < 0) return WH_E_OOM;

        wh->entries[(uint8_t)slot].tag = tag;
        wh->entries[(uint8_t)slot].value = dst;
        wh->entries[(uint8_t)slot].len = len;
        if ((uint8_t)(slot + 1) > wh->count) {
            wh->count = (uint8_t)(slot + 1);
        }
    } else {
        tlv_entry_t *e = &wh->entries[(uint8_t)idx];
        if (e->len >= len) {
            memcpy(e->value, src, len);
            e->len = len;
        } else {
            uint8_t *new_val = tlv_alloc(wh, len);
            if (!new_val) return WH_E_OOM;
            memcpy(new_val, src, len);
            e->value = new_val;
            e->len = len;
        }
    }

    return WH_E_OK;
}

int tlv_store_set_indexed(tx_warehouse_t *wh, uint32_t tag, uint8_t index,
                          const uint8_t *src, uint16_t len)
{
    if (!wh || !src || len == 0 || len > MAX_POOL_SIZE) return WH_E_INVAL;
    if (index == 0) {
        return tlv_store_set(wh, tag, src, len);
    }

    for (uint8_t i = 0; i < wh->count; i++) {
        const tlv_entry_t *e = &wh->entries[i];
        if (e->tag == tag && e->value != NULL) {
            uint32_t tagged_tag = EMV_TAG4((tag >> 24) & 0xFF,
                                           (tag >> 16) & 0xFF,
                                           index,
                                           (tag) & 0xFF);
            for (uint8_t j = 0; j < wh->count; j++) {
                if (wh->entries[j].tag == tagged_tag) {
                    tlv_entry_t *ex = &wh->entries[j];
                    if (ex->len >= len) {
                        memcpy(ex->value, src, len);
                        ex->len = len;
                    } else {
                        uint8_t *nv = tlv_alloc(wh, len);
                        if (!nv) return WH_E_OOM;
                        memcpy(nv, src, len);
                        ex->value = nv;
                        ex->len = len;
                    }
                    return WH_E_OK;
                }
            }
        }
    }

    uint32_t tagged_tag = EMV_TAG4((tag >> 24) & 0xFF,
                                   (tag >> 16) & 0xFF,
                                   index,
                                   (tag) & 0xFF);
    uint8_t *dst = tlv_alloc(wh, len);
    if (!dst) return WH_E_OOM;
    memcpy(dst, src, len);

    int slot = warehouse_find_free_slot(wh);
    if (slot < 0) return WH_E_OOM;

    wh->entries[(uint8_t)slot].tag = tagged_tag;
    wh->entries[(uint8_t)slot].value = dst;
    wh->entries[(uint8_t)slot].len = len;
    if ((uint8_t)(slot + 1) > wh->count) {
        wh->count = (uint8_t)(slot + 1);
    }

    return WH_E_OK;
}

/* ---- Get operations --------------------------------------------------- */

int tlv_store_get(const tx_warehouse_t *wh, uint32_t tag, uint8_t *dst, uint16_t *out_len)
{
    if (!wh || !dst || !out_len) return WH_E_INVAL;

    const tlv_entry_t *e = tlv_find(wh, tag);
    if (!e) return WH_E_NOTFOUND;

    uint16_t copy_len = *out_len < e->len ? *out_len : e->len;
    memcpy(dst, e->value, copy_len);
    *out_len = copy_len;
    return WH_E_OK;
}

int tlv_store_get_indexed(const tx_warehouse_t *wh, uint32_t tag, uint8_t index,
                          uint8_t *dst, uint16_t *out_len)
{
    if (!wh || !dst || !out_len) return WH_E_INVAL;
    if (index == 0) {
        return tlv_store_get(wh, tag, dst, out_len);
    }

    uint32_t tagged_tag = EMV_TAG4((tag >> 24) & 0xFF,
                                   (tag >> 16) & 0xFF,
                                   index,
                                   (tag) & 0xFF);
    return tlv_store_get(wh, tagged_tag, dst, out_len);
}

/* ---- Delete operations ------------------------------------------------ */

int tlv_store_delete(tx_warehouse_t *wh, uint32_t tag)
{
    int idx = warehouse_find(wh, tag);
    if (idx < 0) return WH_E_NOTFOUND;

    wh->entries[(uint8_t)idx].tag = 0;
    wh->entries[(uint8_t)idx].value = NULL;
    wh->entries[(uint8_t)idx].len = 0;

    return WH_E_OK;
}

int tlv_store_delete_indexed(tx_warehouse_t *wh, uint32_t tag, uint8_t index)
{
    if (index == 0) return tlv_store_delete(wh, tag);

    uint32_t tagged_tag = EMV_TAG4((tag >> 24) & 0xFF,
                                   (tag >> 16) & 0xFF,
                                   index,
                                   (tag) & 0xFF);
    int idx = warehouse_find(wh, tagged_tag);
    if (idx < 0) return WH_E_NOTFOUND;

    wh->entries[(uint8_t)idx].tag = 0;
    wh->entries[(uint8_t)idx].value = NULL;
    wh->entries[(uint8_t)idx].len = 0;

    return WH_E_OK;
}

/* ---- Lookup / query --------------------------------------------------- */

const tlv_entry_t *tlv_find(const tx_warehouse_t *wh, uint32_t tag)
{
    if (!wh) return NULL;

    for (uint8_t i = 0; i < wh->count; i++) {
        if (wh->entries[i].tag == tag && wh->entries[i].value != NULL) {
            return &wh->entries[i];
        }
    }
    return NULL;
}

int tlv_contains(const tx_warehouse_t *wh, uint32_t tag)
{
    return tlv_find(wh, tag) != NULL;
}
