/**
 * @file src/core/dict_validate.c
 * @brief Dictionary validation — check mandatory tags and constraints.
 */

#include "emv_kernel/dict_validate.h"
#include <string.h>

int tlv_validate_dict(const kernel_dict_t *dict, const tx_warehouse_t *wh)
{
    if (!dict || !wh) return -1;

    for (uint8_t i = 0; i < dict->item_count; i++) {
        const dict_item_t *item = &dict->items[i];

        /* Check mandatory tags only */
        if (!item->mandatory) continue;

        /* Find the tag in warehouse */
        const tlv_entry_t *entry = tlv_find(wh, item->tag);
        if (!entry) {
            return -1;  /* Mandatory tag missing */
        }

        /* Validate length constraints */
        if (entry->len < item->min_len || entry->len > item->max_len) {
            return -1;  /* Length out of range */
        }
    }

    return 0;
}

int tlv_validate_tag_length(const dict_item_t *item, const tx_warehouse_t *wh)
{
    if (!item || !wh) return -1;

    const tlv_entry_t *entry = tlv_find(wh, item->tag);
    if (!entry) return -1;

    if (entry->len < item->min_len || entry->len > item->max_len) {
        return -1;
    }
    return 0;
}

const char *dict_get_tag_description(const kernel_dict_t *dict, uint32_t tag)
{
    if (!dict) return "(null dict)";

    for (uint8_t i = 0; i < dict->item_count; i++) {
        if (dict->items[i].tag == tag) {
            return dict->items[i].description[0] != '\0'
                   ? dict->items[i].description
                   : "unnamed tag";
        }
    }
    return "tag not found in dictionary";
}
