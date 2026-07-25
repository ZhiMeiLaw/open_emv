/**
 * @file src/core/platform.c
 * @brief Platform hooks implementations — driver registration and dispatch.
 *
 * Integrators implement param_read/write, iccdb_read/write, platform_prng,
 * and platform_time_get externally. This file provides the driver registry.
 */

#include "emv_kernel/platform.h"

/* Registered drivers (set once at startup) */
const crypto_driver_t *g_crypto_driver = NULL;
const term_acq_interface_t *g_acq_interface = NULL;

int platform_register_crypto(const crypto_driver_t *driver)
{
    if (!driver) return -1;
    g_crypto_driver = driver;
    return 0;
}

int platform_register_acq_iface(const term_acq_interface_t *iface)
{
    if (!iface) return -1;
    g_acq_interface = iface;
    return 0;
}

const crypto_driver_t *platform_get_crypto(void)
{
    return g_crypto_driver;
}

const term_acq_interface_t *platform_get_acq_iface(void)
{
    return g_acq_interface;
}
