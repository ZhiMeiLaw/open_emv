/**
 * @file src/core/platform.c
 * @brief Platform hooks implementation — driver registration and dispatch.
 */

#include "emv_kernel/platform.h"
#include "emv_kernel/errors.h"

const crypto_driver_t *g_crypto_driver = NULL;
const term_acq_interface_t *g_acq_interface = NULL;

int platform_register_crypto(const crypto_driver_t *driver)
{
    if (!driver) return PLAT_E_INVAL;
    g_crypto_driver = driver;
    return EMV_E_OK;
}

int platform_register_acq_iface(const term_acq_interface_t *iface)
{
    if (!iface) return PLAT_E_INVAL;
    g_acq_interface = iface;
    return EMV_E_OK;
}

const crypto_driver_t *platform_get_crypto(void)
{
    return g_crypto_driver;
}

const term_acq_interface_t *platform_get_acq_iface(void)
{
    return g_acq_interface;
}
