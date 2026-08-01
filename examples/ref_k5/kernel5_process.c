/**
 * @file examples/ref_k5/kernel5_process.c
 * @brief Kernel 5 (qVISA) reference: wires config, CVM/Risk plugins, and kernel ops.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/kernel_registry.h"
#include "emv_kernel/orchestrator.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/errors.h"

extern struct cvm_plugin_s kernel5_cvm_plugin;
extern struct risk_plugin_s kernel5_risk_plugin;
extern kernel_dict_t kernel5_dict;
extern const kernel_config_t *kernel5_get_config(void);
extern const struct kernel_ops_s *k5_get_kernel_ops(void);

void kernel5_init(void)
{
    kernel5_dict.cvm_plugin = &kernel5_cvm_plugin;
    kernel5_dict.risk_plugin = &kernel5_risk_plugin;
    kernel5_dict.ops = k5_get_kernel_ops();

    const kernel_config_t *cfg = kernel5_get_config();
    kernel_register(cfg);
}
