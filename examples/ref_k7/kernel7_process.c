/**
 * @file examples/ref_k7/kernel7_process.c
 * @brief Kernel 7 reference: wires config, CVM/Risk plugins, and registers.
 *
 * EMV Contactless Book C-7: Token-Based Transaction Processing.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/kernel_registry.h"
#include "emv_kernel/orchestrator.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/errors.h"

/* Forward declarations — symbols are defined in src/plugin/ */
extern struct cvm_plugin_s kernel7_cvm_plugin;
extern struct risk_plugin_s kernel7_risk_plugin;
extern kernel_dict_t kernel7_dict;
extern const kernel_config_t *kernel7_get_config(void);

void kernel7_init(void)
{
    /* Wire CVM + Risk into the dictionary */
    kernel7_dict.cvm_plugin = &kernel7_cvm_plugin;
    kernel7_dict.risk_plugin = &kernel7_risk_plugin;

    /* Register with global dispatch table */
    const kernel_config_t *cfg = kernel7_get_config();
    kernel_register(cfg);
}
