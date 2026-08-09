/**
 * @file examples/ref_k6/k6_ref_icr_mock.c
 * @brief Kernel 6 reference: mock IC Reader for testing.
 */

#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/errors.h"
#include <string.h>

/* Mock IC Reader for K6 testing */
static int mock_k6_select_apdu(const ep_context_t *ctx, uint8_t cla, uint8_t ins,
                               uint8_t p1, uint8_t p2,
                               const uint8_t *data, uint16_t data_len,
                               uint8_t *resp, uint16_t *resp_len)
{
    (void)ctx;
    /* Return success with minimal response */
    if (!resp || !resp_len) return EP_E_INVAL;

    /* SW1 SW2 = 9000 (success) */
    resp[0] = 0x90;
    resp[1] = 0x00;
    *resp_len = 2;
    return EP_E_OK;
}

static const struct ic_reader_provider_s mock_k6_icr = {
    .send_apdu = mock_k6_select_apdu,
};

const struct ic_reader_provider_s *k6_get_mock_icr(void)
{
    return &mock_k6_icr;
}
