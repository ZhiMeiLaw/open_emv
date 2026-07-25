/**
 * @file emv_kernel/kernel_registry.h
 * @brief Kernel dispatch table — static array with runtime registration.
 */

#ifndef EMV_KERNEL_KERNEL_REGISTRY_H
#define EMV_KERNEL_KERNEL_REGISTRY_H

#include "emv_kernel/types.h"
#include "emv_kernel/errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register a kernel configuration into the dispatch table.
 * @param config Pointer to caller-owned kernel_config_t (or kernel_dict_t).
 * @return KREG_E_OK on success, KREG_E_FULL if table is full, KREG_E_DUP if duplicate kernel_id.
 */
int kernel_register(const kernel_config_t *config);

/**
 * Lookup a kernel config by ID.
 * @returns pointer to config, or NULL if not found.
 */
const kernel_config_t *kernel_lookup(uint8_t kernel_id);

/**
 * Get the total number of registered kernels.
 */
uint8_t kernel_count(void);

/**
 * Iterate over all registered kernels (caller provides buffer and max count).
 * Returns number of kernels written to out[].
 */
uint8_t kernel_list(kernel_config_t *out, uint8_t max_count);

#ifdef __cplusplus
}
#endif

#endif /* EMV_KERNEL_KERNEL_REGISTRY_H */
