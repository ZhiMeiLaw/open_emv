/**
 * @file src/core/kernel_registry.c
 * @brief Kernel dispatch table — runtime registration into static array.
 */

#include "emv_kernel/kernel_registry.h"
#include "emv_kernel/errors.h"
#include <string.h>

static kernel_config_t g_table[MAX_KERNEL_ENTRIES];
static uint8_t g_count = 0;

int kernel_register(const kernel_config_t *config)
{
    if (!config || config->kernel_id == 0) return KREG_E_INVAL;

    for (uint8_t i = 0; i < g_count; i++) {
        if (g_table[i].kernel_id == config->kernel_id) {
            return KREG_E_DUP;
        }
    }

    if (g_count >= MAX_KERNEL_ENTRIES) {
        return KREG_E_FULL;
    }

    g_table[g_count] = *config;
    g_count++;
    return KREG_E_OK;
}

const kernel_config_t *kernel_lookup(uint8_t kernel_id)
{
    for (uint8_t i = 0; i < g_count; i++) {
        if (g_table[i].kernel_id == kernel_id) {
            return &g_table[i];
        }
    }
    return NULL;
}

uint8_t kernel_count(void)
{
    return g_count;
}

uint8_t kernel_list(kernel_config_t *out, uint8_t max_count)
{
    uint8_t n = g_count < max_count ? g_count : max_count;
    memcpy(out, g_table, n * sizeof(kernel_config_t));
    return n;
}
