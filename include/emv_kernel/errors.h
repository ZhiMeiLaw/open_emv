/**
 * @file emv_kernel/errors.h
 * @brief Unified error codes for EMV Contactless Payment Kernel.
 *
 * All modules MUST use these macros instead of magic -1/-2/-3 values.
 * Error codes are organized by layer so the caller can narrow down
 * where a failure originated.
 */

#ifndef EMV_KERNEL_ERRORS_H
#define EMV_KERNEL_ERRORS_H

/* ================================================================== */
/*  Generic / Common errors (used across all layers)                  */
/* ================================================================== */
#define EMV_E_OK             0   /**< Success                                        */
#define EMV_E_INVAL         -1   /**< Invalid argument or null pointer                */
#define EMV_E_NOMEM         -2   /**< Memory exhausted / pool full                    */
#define EMV_E_NOTFOUND      -3   /**< Tag/entry/kernel not found                      */
#define EMV_E_STATE         -4   /**< Operation not valid in current state            */
#define EMV_E_UNAVAILABLE   -5   /**< Required resource unavailable (e.g. no RNG)     */

/* ================================================================== */
/*  TLV Warehouse errors (src/core/warehouse.c)                       */
/* ================================================================== */
#define WH_E_OK                EMV_E_OK        /**< Success                            */
#define WH_E_OOM               EMV_E_NOMEM     /**< Pool out of space                  */
#define WH_E_INVAL             EMV_E_INVAL     /**< Null ptr, zero len, invalid tag    */
#define WH_E_NOTFOUND          -5               /**< Tag not found in warehouse         */

/* ================================================================== */
/*  TLV Encode / Decode errors (src/utils/tlv_encode.c)              */
/* ================================================================== */
#define TLVE_E_OK              EMV_E_OK        /**< Success                            */
#define TLVE_E_INVAL           EMV_E_INVAL     /**< Bad buffer, tag==0, too small      */
#define TLVE_E_TRUNCATED       -10             /**< Input data truncated               */
#define TLVE_E_BAD_FORMAT      -11             /**< Invalid BER-TLV encoding           */

/* ================================================================== */
/*  Dictionary validation errors (src/core/dict_validate.c)          */
/* ================================================================== */
#define DICT_E_OK              EMV_E_OK        /**< All checks passed                */
#define DICT_E_MISSING         EMV_E_NOTFOUND /**< Mandatory tag missing in warehouse */
#define DICT_E_BAD_LENGTH      -20             /**< Tag length outside constraints   */
#define DICT_E_INVAL           EMV_E_INVAL     /**< Null dict or warehouse          */

/* ================================================================== */
/*  Kernel Registry errors (src/core/kernel_registry.c)              */
/* ================================================================== */
#define KREG_E_OK              EMV_E_OK        /**< Success                            */
#define KREG_E_FULL           -30              /**< Dispatch table is full              */
#define KREG_E_DUP            -31              /**< Duplicate kernel_id                 */
#define KREG_E_INVAL          EMV_E_INVAL     /**< Null config or zero kernel_id       */

/* ================================================================== */
/*  Entry Point / Book B flow errors (src/core/entry_point.c)        */
/* ================================================================== */
#define EP_E_OK              0                 /**< Full entry point flow succeeded     */
#define EP_E_NO_CARD         -40               /**< Card not detected within timeout    */
#define EP_E_COMM            -41               /**< APDU / ISO-DEP communication error  */
#define EP_E_AUTH            -42               /**< SDA/ODA card authentication failed  */
#define EP_E_SELECT          -43               /**< Application select (AID match) fail  */
#define EP_E_GPO             -44               /**< Get Processing Options failed       */
#define EP_E_PROFILE         -45               /**< ERP profile exchange failed         */
#define EP_E_UNSUPPORTED     -46               /**< Card lacks required capabilities    */
#define EP_E_INVAL           EMV_E_INVAL      /**< Null context or IC reader provider  */

/* ================================================================== */
/*  Orchestrator / Kernel execution errors (src/core/orchestrator.c) |
/* ================================================================== */
#define ORCH_E_OK            0                 /**< Kernel executed successfully        */
#define ORCH_E_NO_CONFIG     -50               /**< Kernel not registered               */
#define ORCH_E_DICT_FAIL     -51               /**< Dictionary validation failed        */
#define ORCH_E_CVM_FAIL      -52               /**< CVM plugin returned FAIL            */
#define ORCH_E_RISK_FAIL     -53               /**< Risk plugin returned FAIL           */
#define ORCH_E_CRYPTO        -54               /**< Cryptogram generation failed        */
#define ORCH_E_INVAL         EMV_E_INVAL      /**< Null orchestrator context           */

/* ================================================================== */
/*  Platform Hooks errors (param_read/write, iccdb_*)                */
/* ================================================================== */
#define PLAT_E_OK            0
#define PLAT_E_INVAL         -60               /**< Null pointer or bad length      */
#define PLAT_E_NOTCONF       -61               /**< Parameter tag not configured    */
#define PLAT_E_NOTSTORED     -62               /**< ICCDB entry/field not stored     */
#define PLAT_E_STORE_FULL    -63               /**< ICCDB store has no free slots   */

/* ================================================================== */
/*  Crypto Driver errors (crypto_driver_t)                           */
/* ================================================================== */
#define CRYPTO_E_OK          0
#define CRYPTO_E_INVAL       -70               /**< Null key, bad key length, etc  */
#define CRYPTO_E_VERIFY      -71               /**< Signature/certificate verify  */
#define CRYPTO_E_MAC         -72               /**< MAC/CRC/CMAC mismatch         */
#define CRYPTO_E_ENCODE      -73               /**< PKCS/RSA-PKP padding format   */
#define CRYPTO_E_BUFFER      -74               /**< Output buffer too small        */

/* ================================================================== */
/*  Outcome determination errors                                     */
/* ================================================================== */
#define OUTCOME_E_OK         0                 /**< No outcome issue                */
#define OUTCOME_E_DECLINE    -80               /**< Transaction declined            */
#define OUTCOME_E_ERROR      -81               /**< Unrecoverable error             */

#endif /* EMV_KERNEL_ERRORS_H */
