/**
 * @file examples/ref_k7/kernel7_process.c
 * @brief Kernel 7 reference: wires config, CVM/Risk plugins, and kernel ops.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/kernel_registry.h"
#include "emv_kernel/orchestrator.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/errors.h"

/* Forward declarations */
extern struct cvm_plugin_s kernel7_cvm_plugin;
extern struct risk_plugin_s kernel7_risk_plugin;
extern kernel_dict_t kernel7_dict;
extern const kernel_config_t *kernel7_get_config(void);
extern const struct kernel_ops_s *k7_get_kernel_ops(void);

void kernel7_init(void)
{
    kernel7_dict.cvm_plugin = &kernel7_cvm_plugin;
    kernel7_dict.risk_plugin = &kernel7_risk_plugin;
    kernel7_dict.ops = k7_get_kernel_ops();

    const kernel_config_t *cfg = kernel7_get_config();
    kernel_register(cfg);
}
