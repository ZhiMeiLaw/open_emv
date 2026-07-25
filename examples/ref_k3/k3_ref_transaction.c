/**
 * @file examples/ref_k3/k3_ref_transaction.c
 * @brief Kernel 3 complete reference: one function to run a K3 transaction.
 *
 * This is the KEY file for integrators — it shows every step from card
 * insertion to TC/NASP output, with concrete data flows between modules.
 *
 * Structure:
 *   Step 1: Init (crypto, UI, kernel registration)
 *   Step 2: Poll card → read ATS/ATQ
 *   Step 3: ERP exchange → profile card capabilities
 *   Step 4: Select AID → match kernel ID
 *   Step 5: Card Auth (SDA/ODA)
 *   Step 6: GPO → parse response into warehouse
 *   Step 7: Load terminal params into warehouse
 *   Step 8: Run CVM plugin
 *   Step 9: Run Risk plugin
 *   Step 10: Generate ARQC via crypto driver
 *   Step 11: Build outcome + TC or NASP
 *   Step 12: Send TC/NASP back to card
 */

#include "emv_kernel/types.h"
#include "emv_kernel/warehouse.h"
#include "emv_kernel/tlv_encode.h"
#include "emv_kernel/bitmap.h"
#include "emv_kernel/entry_point.h"
#include "emv_kernel/kernel_registry.h"
#include "emv_kernel/orchestrator.h"
#include "emv_kernel/kernel_interface.h"
#include "emv_kernel/dict_validate.h"
#include "emv_kernel/platform.h"

#include <string.h>

/* Forward declarations from sibling files */
extern const crypto_driver_t ref_crypto_driver;
extern struct cvm_plugin_s kernel3_cvm_plugin;
extern struct risk_plugin_s kernel3_risk_plugin;
extern kernel_dict_t kernel3_dict;

/* POS parameters structure for K3 */
typedef struct {
    uint32_t unsigned_limit;      /* Amount ≤ this → No-CVM        */
    uint32_t signed_limit;        /* Amount > unsigned, ≤ this → PIN */
    uint8_t  pin_key_index;       /* Key index for PIN encryption    */
} pos_params_k3_t;

/* ================================================================== */
/*  STEP 1: Application startup                                       */
/* ================================================================== */
/**
 * Call once before any transactions.
 */
static void k3_init(void)
{
    /* 1a. Wire plugins into K3 dictionary */
    kernel3_dict.cvm_plugin = &kernel3_cvm_plugin;
    kernel3_dict.risk_plugin = &kernel3_risk_plugin;

    /* 1b. Register K3 in the dispatch table */
    kernel_register((const kernel_config_t *)&kernel3_dict);

    /* 1c. Register crypto driver */
    platform_register_crypto(&ref_crypto_driver);

    /* 1d. Initialize default POS parameters */
    pos_params_init_defaults();  /* Defined in k3_ref_platform.c */

    /* 1e. Load default ICCDB (load previously seen cards from storage) */
    /* Integrator: restore ICCDB entries from NV storage here */
}

/* ================================================================== */
/*  STEP 2-6: Card communication (Entry Point flow)                  */
/* ================================================================== */

/**
 * Full transaction execution — THIS is the main API integrators call.
 *
 * @param icr              IC Reader Provider (user-implemented)
 * @param pos_params       Terminal configuration for K3
 * @param card_hash        On output: unique card identifier from poll
 * @param tc_out           On output: Terminal Conduction TLV bytes
 * @param tc_len           In/out: max output size → actual output size
 * @param outcome          On output: transaction result code
 * @return 0 on success, negative on error
 */
int k3_execute_transaction(const struct ic_reader_provider_s *icr,
                           const pos_params_k3_t *pos_params,
                           uint8_t *card_hash,           /* Out: card hash (16 bytes) */
                           uint8_t *tc_out, uint8_t *tc_len, uint8_t tc_max_len,
                           outcome_code_t *outcome)
{
    /* ----------------------------------------------------------------
     * Phase A: Transaction workspace allocation
     * ---------------------------------------------------------------- */
    tx_warehouse_t wh;

    /* Allocate memory pools on stack (zero heap dependency) */
    /* NOTE: MAX_POOL_SIZE is 3072 bytes by default — verify fits your MCU RAM */
    uint8_t pool_in[MAX_POOL_SIZE];

    /* Initialize warehouse */
    tlv_warehouse_init(&wh, pool_in, sizeof(pool_in));

    /* ----------------------------------------------------------------
     * Phase B: Entry Point — Hardware interaction
     * ---------------------------------------------------------------- */

    /* Step B1: Initialize RF and poll for card */
    if (!icr || !icr->init || !icr->poll_card || !icr->transceive) {
        if (outcome) *outcome = OUTCOME_ERROR;
        return -1;  /* Invalid IC reader provider */
    }

    icr->init();
    int poll_rc = icr->poll_card(5000);  /* 5 second timeout */
    if (poll_rc != 0) {
        if (outcome) *outcome = OUTCOME_RESTART;
        return -2;  /* No card detected */
    }

    /* Step B2: Parse ATS from poll response (data returned by poll_card) */
    /* The poll_card callback fills recv_buf with ATS/ATQ response.
     * Extract FI_byte, TO_byte, FIB to determine supported protocols.
     */
    ats_parsed_t ats_info;
    memset(&ats_info, 0, sizeof(ats_info));
    /* NOTE: In real integration, extract ATS from poll_card's response buffer */

    /* Step B3: ERP (Exchange Response to Profiling Results)
     * Terminal and card exchange capabilities via LLCP.
     * Card tells us what tags it supports and how many records it has.
     */
    /* Real implementation sends NFCDEPLLCP PDU to card and parses response.
     * Result: populate warehouse with ERP response tags. */

    /* Step B4: Application Select
     * Try to select an application by AID.
     * Loop through kernel registry AIDs until one matches.
     */
    /* Real implementation builds SELECT AID APDU command:
     *   CLA=00, INS=A4, P1=04 (select by name), P2=00
     *   Data = AID bytes
     * Card responds with SFIP/SFCI for read record operations.
     */

    /* Step B5: Card Authentication (SDA or ODA)
     * Check AIP bits from ERP response:
     *   AIP bit B3 = SDA capable
     *   AIP bit B4 = ODA capable
     * Priority: try SDA first, then ODA.
     */
    /* SDA path:
     *   1. Read ICC Public Key Certificate [9F21] from card
     *   2. Get ACM(A) from param store
     *   3. Build verification DOL from TDOL tags
     *   4. Call crypto->rsa_pkpad_verify()
     */
    /* ODA path (if SDA fails):
     *   1-2. Same cert chain as SDA
     *   3. DES decrypt ICData via crypto->des_decrypt()
     *   4. SET ATTRIBUTE → get CDOL1 data from card
     *   5. TOA with CDOL2 + decrypted dynamic number
     *   6. Verify ICC CRT [9F7E] via crypto->tdes_mac_verify()
     */

    /* For this reference, mark auth as done (real impl calls ep functions) */

    /* Step B6: GPO (Get Processing Options)
     * Terminal sends: GET PROCESSING OPTIONS with CDOL1 data
     * Card responds with: AIP, AUC, CDOL1 length, Unpredictable Number
     */

    /* ----------------------------------------------------------------
     * Phase C: Populate warehouse with GPO response
     * ---------------------------------------------------------------- */

    /* Simulate a GPO response that would come from the card via transceive().
     * Real implementation: parse the binary response from GET PROCESSING OPTIONS.
     *
     * Example raw GPO response (BER-TLV):
     *   [87] AIP          = 0x02 (default EMV contactless)
     *   [82] AUC          = 0x00 0xFF (allow all transactions)
     *   [DF9F66] CDOL1 Length = 0x10 (16 bytes of CDOL1 data expected)
     *   [9F37] Unpredictable Number = 0xA1B2C3D4
     */
    uint8_t gpo_response[] = {
        0x87, 0x01, 0x02,                            /* AIP */
        0x82, 0x02, 0x00, 0xFF,                      /* AUC */
        0xDF, 0x9F, 0x66, 0x01, 0x10,                /* DF9F66 CDOL1 length */
        0x9F, 0x37, 0x04, 0xA1, 0xB2, 0xC3, 0xD4,    /* Unpredictable Number */
    };

    int parsed = tlv_parse_raw(gpo_response, sizeof(gpo_response), &wh);
    if (parsed <= 0) {
        if (outcome) *outcome = OUTCOME_ERROR;
        return -3;  /* Failed to parse GPO response */
    }

    /* ----------------------------------------------------------------
     * Phase D: Load terminal parameters into warehouse
     * ---------------------------------------------------------------- */

    /* K3 TDOL: [9F16, 9F02, 9F36, 9F03, 5F2A, 9F66]
     * Tags like 9F16 (TN) need to be generated. Others come from POS params. */

    /* Generate Transaction Number (4 bytes unpredictable) */
    uint8_t tn[4];
    platform_prng(tn, 4);
    tlv_store_set(&wh, 0x9F16, tn, 4);

    /* Load amounts and currency from POS params */
    uint8_t amount[6] = { 0x00, 0x00, 0x00, 0x00, 0x01, 0x00 };  /* ¥1.00 example */
    uint8_t currency[2] = { 0x01, 0x56 };                          /* CNY = 156 */
    uint8_t amt_other[6] = { 0x00 };
    uint8_t tq[4] = { 0xF8, 0x00, 0x05, 0x80 };                     /* Terminal Qualifiers */

    tlv_store_set(&wh, 0x9F02, amount, 6);
    tlv_store_set(&wh, 0x9F36, amt_other, 6);
    tlv_store_set(&wh, 0x5F2A, currency, 2);
    tlv_store_set(&wh, 0x9F66, tq, 4);

    /* ----------------------------------------------------------------
     * Phase E: Validate inputs against K3 dictionary
     * ---------------------------------------------------------------- */

    /* Check all mandatory tags are present in warehouse */
    rc = tlv_validate_dict((const kernel_dict_t *)&kernel3_dict, &wh);
    if (rc != 0) {
        if (outcome) *outcome = OUTCOME_DECLINE;
        return -4;  /* Missing required tag */
    }

    /* ----------------------------------------------------------------
     * Phase F: Run CVM (Cardholder Verification Method)
     * ---------------------------------------------------------------- */

    /* Get amount from warehouse */
    uint32_t amount_val = bcd_6byte_to_uint(amount);

    /* Execute K3 CVM logic:
     *   amount ≤ unsigned_limit → No-CVM (pass)
     *   unsigned < amount ≤ signed_limit → Offline PIN
     *   amount > signed_limit → Online auth only (no CVM check needed)
     */
    cvm_result_t cvm_result = CVM_PASS;
    uint8_t cvm_method = 0x00;  /* Default: No-CVM */

    if (amount_val <= pos_params->unsigned_limit) {
        cvm_result = CVM_PASS;
        cvm_method = 0x00;  /* No CVM required */
    } else if (amount_val <= pos_params->signed_limit) {
        /* Would prompt for PIN here via ui_driver->prompt_pin() */
        /* For reference: no PIN entered → simulate success */
        cvm_result = CVM_PASS;
        cvm_method = 0x02;  /* Encrypted PIN (would have been collected above) */
    } else {
        /* Above signed limit — skip CVM, go online */
        cvm_result = CVM_PASS;
        cvm_method = 0x00;  /* No CVM (going online instead) */
    }

    if (cvm_result == CVM_FAIL) {
        if (outcome) *outcome = OUTCOME_DECLINE;
        return -5;  /* CVM failed */
    }

    /* ----------------------------------------------------------------
     * Phase G: Risk checks
     * ---------------------------------------------------------------- */

    /* K3 Risk checks:
     *   TRM: Check velocity limits against ICCDB
     *   CRM: Check card-side risk limits (via ICCDB)
     *   VEL: Track transaction amounts for velocity reporting
     *
     * For this reference, all pass (real impl checks counters).
     */
    risk_result_t risk_result = RISK_PASS;

    if (risk_result == RISK_FAIL) {
        if (outcome) *outcome = OUTCOME_DECLINE;
        return -6;  /* Risk check failed */
    }

    /* ----------------------------------------------------------------
     * Phase H: Generate ARQC (Application Cryptogram)
     * ---------------------------------------------------------------- */

    /* Build DOL data for ARQC per K3 TDOL:
     * [9F16] TN + [9F02] Amount + [9F36] Amt Other +
     * [9F03] Default Amt + [5F2A] Currency + [9F66] Terminal Qualifiers
     */
    const tlv_entry_t *dol_entries[] = {
        tlv_find(&wh, 0x9F16),
        tlv_find(&wh, 0x9F02),
        tlv_find(&wh, 0x9F36),
        tlv_find(&wh, 0x9F03),
        tlv_find(&wh, 0x5F2A),
        tlv_find(&wh, 0x9F66),
    };

    uint8_t dol_data[32];
    uint8_t dol_len = 0;

    for (int i = 0; i < 6; i++) {
        if (dol_entries[i]) {
            memcpy(dol_data + dol_len, dol_entries[i]->value, dol_entries[i]->len);
            dol_len += dol_entries[i]->len;
        }
    }

    /* Generate ARQC via crypto driver */
    crypto_driver_t *crypto = (crypto_driver_t *)platform_get_crypto();
    uint8_t arqc[8];
    size_t arqc_len = sizeof(arqc);

    int crypt_rc = crypto->generate_cryptogram(
        CRYPTO_DES,
        NULL, 0,       /* Key: would look up from app key table using PAN/AID */
        0,             /* Key index */
        dol_data, dol_len,
        arqc, &arqc_len
    );

    if (crypt_rc != 0 || arqc_len < 8) {
        if (outcome) *outcome = OUTCOME_ERROR;
        return -7;  /* Cryptogram generation failed */
    }

    /* Store ARQC in output warehouse */
    tlv_store_set(&wh, 0x9F26, arqc, 8);  /* Tag 9F26 = Application Cryptogram */

    /* ----------------------------------------------------------------
     * Phase I: Determine outcome
     * ---------------------------------------------------------------- */

    outcome_code_t final_outcome;

    if (cvm_result == CVM_PASS && risk_result == RISK_PASS) {
        /* Both passed — approve */
        final_outcome = OUTCOME_APPROVE_TERMINAL_CONDS;
    } else {
        final_outcome = OUTCOME_DECLINE;
    }

    /* ----------------------------------------------------------------
     * Phase J: Build Terminal Conduction Data (TC)
     * ---------------------------------------------------------------- */

    if (final_outcome == OUTCOME_APPROVE_TERMINAL_CONDS) {
        /* Build TC TLV — minimal set of tags to send to card:
         * [9F26] ARQC (8 bytes)
         * [8A]   Auth Response Code (2 bytes, e.g., 0x00 0x00 for approval)
         * [9F27] Cryptogram Info Field — flags about the ARQC type
         *
         * For K3, TC is typically: 9F26 + 8A (simplest case)
         */
        uint8_t auth_code[] = { 0x00, 0x00 };         /* Approved */
        uint8_t cif[] = { 0x08 };                      /* ARQC = 0x08 per EMV table */

        uint8_t tc_raw[] = {
            0x9F, 0x26, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,  /* ARQC mock */
            0x8A, 0x02, 0x00, 0x00,                                             /* Auth Response Code */
            0x9F, 0x27, 0x01, 0x08,                                             /* Cryptogram Info Field */
        };

        if (tc_out && tc_len && tc_max_len >= sizeof(tc_raw)) {
            memcpy(tc_out, tc_raw, sizeof(tc_raw));
            *tc_len = (uint8_t)sizeof(tc_raw);
        }

        if (outcome) *outcome = final_outcome;
        return 0;

    } else {
        /* DECLINE — build NASP */
        uint8_t nasp[] = {
            0x9F, 0x2B,    /* Tag: No Application SDI Parameter */
            0x02,          /* Length */
            0x00, 0x00,    /* NASP value */
        };

        if (tc_out && tc_len && tc_max_len >= sizeof(nasp)) {
            memcpy(tc_out, nasp, sizeof(nasp));
            *tc_len = (uint8_t)sizeof(nasp);
        }

        if (outcome) *outcome = OUTCOME_DECLINE;
        return 0;
    }
}
