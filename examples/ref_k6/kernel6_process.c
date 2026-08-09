/**
 * @file examples/ref_k6/kernel6_process.c
 * @brief Kernel 6 reference: wires config, CVM/Risk plugins, and kernel ops.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/kernel_registry.h"
#include "emv_kernel/orchestrator.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/errors.h"

/* Forward declarations — symbols are defined in src/plugin/ */
extern const struct cvm_plugin_s kernel6_cvm_plugin;
extern const struct risk_plugin_s kernel6_risk_plugin;
extern kernel_dict_t kernel6_dict;
extern const kernel_config_t *kernel6_get_config(void);
extern const struct kernel_ops_s *k6_get_kernel_ops(void);

void kernel6_init(void)
{
    /* Wire CVM + Risk + ops into the dictionary */
    kernel6_dict.cvm_plugin = (struct cvm_plugin_s *)&kernel6_cvm_plugin;
    kernel6_dict.risk_plugin = (struct risk_plugin_s *)&kernel6_risk_plugin;
    kernel6_dict.ops = k6_get_kernel_ops();

    /* Register with global dispatch table */
    const kernel_config_t *cfg = kernel6_get_config();
    kernel_register(cfg);
}
