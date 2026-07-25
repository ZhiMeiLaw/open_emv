/**
 * @file examples/ref_k3/kernel3_process.c
 * @brief Kernel 3 reference: wires config, CVM/Risk plugins, and registers.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/kernel_registry.h"
#include "emv_kernel/orchestrator.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/errors.h"

/* Forward declarations — symbols are defined in src/plugin/ */
extern struct cvm_plugin_s kernel3_cvm_plugin;
extern struct risk_plugin_s kernel3_risk_plugin;
extern kernel_dict_t kernel3_dict;
extern const kernel_config_t *kernel3_get_config(void);

void kernel3_init(void)
{
    /* Wire CVM + Risk into the dictionary */
    kernel3_dict.cvm_plugin = &kernel3_cvm_plugin;
    kernel3_dict.risk_plugin = &kernel3_risk_plugin;

    /* Register with global dispatch table */
    const kernel_config_t *cfg = kernel3_get_config();
    kernel_register(cfg);
}
