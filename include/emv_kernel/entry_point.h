/**
 * @file emv_kernel/entry_point.h
 * @brief Book B Entry Point handler interface — Protocol Activation + Application Selection.
 *
 * The Entry Point is responsible for the book-level flow BEFORE kernel activation:
 *   1. Pre-Processing (Start A)
 *   2. Protocol Activation — ISO-14443 ATR, PPS, SAP (Start B)
 *   3. Combination Selection — SELECT PPSE → SPI → Directory parse (Start C)
 *   4. Final Combination Selection — SELECT AID (Start C continued)
 *   5. Kernel Activation — handover to kernel (Start D)
 *
 * After Kernel Activation, the KERNEL takes over for GPO → Read Records →
 * SDA/ODA → CVM → GENERATE AC → Outcome.
 */

#ifndef EMV_KERNEL_ENTRY_POINT_H
#define EMV_KERNEL_ENTRY_POINT_H

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/kernel_interface.h"

/* ---- ERP Profiling Response flags (for reference) ---- */
#define ESR_TAG_SUPPORTED           0x01

/* ---- Entry Point error codes ---- */
#define EP_E_OK                    0   /**< Full entry point flow succeeded         */
#define EP_E_NO_CARD              -40   /**< Card not detected within timeout        */
#define EP_E_COMM                 -41   /**< APDU / ISO-DEP communication error      */
#define EP_E_AUTH                 -42   /**< SDA/ODA card authentication failed      */
#define EP_E_SELECT               -43   /**< Application select (AID match) fail     */
#define EP_E_GPO                  -44   /**< Get Processing Options failed           */
#define EP_E_PROFILE              -45   /**< PPSE/SPI/Directory parsing failed       */
#define EP_E_UNSUPPORTED          -46   /**< Card lacks required capabilities        */
#define EP_E_INVAL                -1   /**< Null context or IC reader provider      */

/* Forward declaration of IC reader provider interface */
struct ic_reader_provider_s;

/* ================================================================== */
/*  Entry Point Context                                               */
/* ================================================================== */

typedef struct {
    /* Input/output warehouse */
    tx_warehouse_t *wh;

    /* IC Reader Provider pointer (set by caller) */
    const struct ic_reader_provider_s *icr;

    /* Output: kernel_id determined by AID matching */
    uint8_t selected_kernel_id;

    /* Output: AID of selected application */
    uint8_t selected_aid[16];
    uint8_t selected_aid_len;

    /* Output: SDA/ODA auth method (set by kernel later) */
    auth_method_t auth_method;

    /* Internal */
    uint8_t sfi;                  /* Selected File Index for read records */
    uint8_t sdfi_count;           /* Start DF Identifier (number of records) */
} ep_context_t;

/* ================================================================== */
/*  IC Reader Provider Interface                                      */
/* ================================================================== */

struct ic_reader_provider_s {
    int (*init)(void);
    int (*poll_card)(uint32_t timeout_ms);
    int (*transceive)(const uint8_t *send_buf, uint16_t send_len,
                      uint8_t *recv_buf, uint16_t recv_max,
                      uint16_t *recv_len);
    void (*deactivate)(void);
};

/* ================================================================== */
/*  Public API                                                        */
/* ================================================================== */

/** Run the complete Book B Entry Point flow. */
int entry_point_run(ep_context_t *ctx, const void *pos_params);

/** Execute individual steps for fine-grained control. */
int entry_point_step_init(ep_context_t *ctx);
int entry_point_step_poll(ep_context_t *ctx, uint32_t timeout_ms);
int entry_point_step_pps(ep_context_t *ctx);
int entry_point_step_select_ppse(ep_context_t *ctx);
int entry_point_step_spi(ep_context_t *ctx);
int entry_point_step_select_app(ep_context_t *ctx,
                                 const uint8_t *aid, uint8_t aid_len,
                                 const uint8_t *ext_sel, uint8_t ext_len);
int entry_point_parse_ppse_response(ep_context_t *ctx,
                                     const uint8_t *resp, uint16_t resp_len);
int entry_point_activate_kernel(ep_context_t *ctx);

#endif /* EMV_KERNEL_ENTRY_POINT_H */
