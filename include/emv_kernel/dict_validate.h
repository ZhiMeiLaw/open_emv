/**
 * @file emv_kernel/dict_validate.h
 * @brief Dictionary validation for kernel data dictionaries.
 */

#ifndef EMV_KERNEL_DICT_VALIDATE_H
#define EMV_KERNEL_DICT_VALIDATE_H

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Validate that all mandatory tags in the dictionary are present
 * in the warehouse with valid lengths.
 * @param dict  Kernel dictionary to validate against.
 * @param wh    Warehouse to check.
 * @return 0 on success, -1 if a mandatory tag is missing or invalid.
 */
int tlv_validate_dict(const kernel_dict_t *dict, const tx_warehouse_t *wh);

/**
 * Validate a single tag's length constraints.
 * @param item  Dictionary item describing the tag.
 * @param wh    Warehouse containing the actual value.
 * @return 0 if valid, -1 if length out of range.
 */
int tlv_validate_tag_length(const dict_item_t *item, const tx_warehouse_t *wh);

/**
 * Get the description string for a tag from dictionary (for error reporting).
 */
const char *dict_get_tag_description(const kernel_dict_t *dict, uint32_t tag);

#ifdef __cplusplus
}
#endif

#endif /* EMV_KERNEL_DICT_VALIDATE_H */
