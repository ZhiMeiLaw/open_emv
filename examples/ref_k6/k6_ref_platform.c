/**
 * @file examples/ref_k6/k6_ref_platform.c
 * @brief Kernel 6 reference: platform-specific implementations.
 */

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* ================================================================== */
/*  POS Terminal Parameters — static store                            */
/* ================================================================== */

typedef struct {
    uint8_t  sds_code;
    uint8_t  tip_signature_supported:1;
    uint8_t  tip_online_pin_supported:1;
    uint32_t unsigned_limit;
    uint32_t signed_limit;
} pos_params_k6_t;

static pos_params_k6_t g_pos_params;

void pos_params_init_defaults_k6(void)
{
    memset(&g_pos_params, 0, sizeof(g_pos_params));
    g_pos_params.unsigned_limit = 100000000;  /* 1000.00 in minor units */
    g_pos_params.signed_limit = 500000000;    /* 5000.00 in minor units */
    g_pos_params.tip_signature_supported = 1;
    g_pos_params.tip_online_pin_supported = 1;
}

const pos_params_k6_t *pos_params_get_k6(void)
{
    return &g_pos_params;
}
