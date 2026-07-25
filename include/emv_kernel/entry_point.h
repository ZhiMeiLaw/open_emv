/**
 * @file emv_kernel/entry_point.h
 * @brief Book B Entry Point handler interface.
 *
 * Handles the complete non-contact card initiator flow:
 * ATS parse → PPS → ERP → Select → Card Auth (SDA/ODA) → GPO.
 *
 * All APDU-level I/O goes through the IC Reader Provider, which
 * is implemented by the integrator.
 */

#ifndef EMV_KERNEL_ENTRY_POINT_H
#define EMV_KERNEL_ENTRY_POINT_H

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/kernel_interface.h"

/* ---- ERP Profiling Response flags ---- */
#define ESR_TAG_SUPPORTED           0x01   /* Application preferred name supported   */
#define ESR_LOG_RECORD_SUPPORTED    0x02   /* Log record entry supported             */

/* ---- Entry Point error codes (Book B flow) ---- */
#define EP_E_OK                    0   /**< Full entry point flow succeeded       */
#define EP_E_NO_CARD              -40   /**< Card not detected within timeout     */
#define EP_E_COMM                 -41   /**< APDU / ISO-DEP communication error   */
#define EP_E_AUTH                 -42   /**< SDA/ODA card authentication failed   */
#define EP_E_SELECT               -43   /**< Application select (AID match) fail  */
#define EP_E_GPO                  -44   /**< Get Processing Options failed        */
#define EP_E_PROFILE              -45   /**< ERP profile exchange failed          */
#define EP_E_UNSUPPORTED          -46   /**< Card lacks required capabilities     */
#define EP_E_INVAL                -1   /**< Null context or IC reader provider   */

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

    /* Output: Application Label */
    uint8_t app_label[32];
    uint8_t app_label_len;

    /* Output: SDA/ODA auth method */
    auth_method_t auth_method;

    /* Output: AIP from ERP exchange */
    uint8_t aip[2];
    uint8_t aip_len;

    /* Output: AUC from GPO response */
    uint8_t auc[2];
    uint8_t auc_len;

    /* Internal */
    uint8_t sfi;                  /* Selected File Index for read records */
    uint8_t sdfi_count;           /* Start DF Identifier (number of records) */
    uint8_t ppss_buf[32];         /* PPS request buffer (temporary) */
} ep_context_t;

/* ================================================================== */
/*  IC Reader Provider Interface                                      */
/* ================================================================== */

struct ic_reader_provider_s {
    /** Initialize RF subsystem and power on. Returns 0 on success. */
    int (*init)(void);

    /** Poll for card presence within timeout_ms. Returns 0 if card found. */
    int (*poll_card)(uint32_t timeout_ms);

    /** Send raw data to card and receive response.
     * @param send_buf    Data to send
     * @param send_len    Bytes to send
     * @param recv_buf    Output buffer
     * @param recv_max    Max receive buffer size
     * @param recv_len    Out: actual bytes received
     * @return 0 on success, or SW1:SW2 encoded as int on error.
     */
    int (*transceive)(const uint8_t *send_buf, uint16_t send_len,
                      uint8_t *recv_buf, uint16_t recv_max,
                      uint16_t *recv_len);

    /** Deactivate field (remove card power). */
    void (*deactivate)(void);
};

/* ================================================================== */
/*  Public API — Entry Point Flow                                     */
/* ================================================================== */

/**
 * Run the complete non-contact card initiator flow:
 *   Init → Poll → ATS Parse → ERP → Select → Card Auth → GPO
 * @param ctx        Pre-initialized context (caller allocates)
 * @param pos_params POS terminal parameters (pre-loaded)
 * @return 0 on full success, negative error code on failure.
 */
int entry_point_run(ep_context_t *ctx, const void *pos_params);

/**
 * Execute just one phase of the entry point flow.
 * Use for fine-grained control over the transaction lifecycle.
 */
int entry_point_step_init(ep_context_t *ctx);
int entry_point_step_pps(ep_context_t *ctx);
int entry_point_step_erp(ep_context_t *ctx);
int entry_point_step_select(ep_context_t *ctx);
int entry_point_step_auth_sda(ep_context_t *ctx);
int entry_point_step_auth_oda(ep_context_t *ctx);
int entry_point_step_gpo(ep_context_t *ctx);

#endif /* EMV_KERNEL_ENTRY_POINT_H */
