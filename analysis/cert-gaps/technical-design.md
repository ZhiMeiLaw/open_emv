# EMV Certification - Technical Design for Remaining Tasks

## Purpose
This document provides the technical design for implementing the remaining features required for EMV Co certification. It should be reviewed against the OpenSpec `emv-payment-kernel` change before implementation begins.

## Architecture Review

The current architecture follows the plan defined in the design.md:
- Core: Transaction-scoped TLV warehouse, kernel registry, orchestrator
- User-implemented: Crypto driver, platform hooks, IC reader provider, UI
- Reference implementations: K3 full transaction, K5 CVM/Risk plugins

The architecture is sound and follows the EMV specification requirements. No architectural changes are needed - only feature completion.

## Detailed Design for Remaining Features

### 1. Cryptographic Driver (Critical)

**Location**: `src/plugin/crypto_driver_ref.c` + `include/emv_kernel/crypto_driver.h`

**Required Algorithms**:
- RSA-PKP verification for SDA/fDDA (Book C-3 §5.6.2.2)
- DES decryption for ODA DNL (Book C-3 §5.6.2.4)
- TDES-CMAC verification for ICC CRT (Book C-3 §5.6.2.4)
- TDES-CMAC generation for ARQC (Book C-3 §5.9)
- ICA key extraction from DER certificates

**Design**:
```c
typedef struct {
    int (*rsa_pkpad_verify)(const uint8_t *cert_der, size_t cert_len,
                            const uint8_t *ddic, size_t ddic_len,
                            const uint8_t *data, size_t data_len);
    int (*des_decrypt)(const uint8_t *key, size_t key_len,
                       const uint8_t *ic_data, size_t ic_data_len,
                       uint8_t *out, size_t *out_len);
    int (*tdes_mac_verify)(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           const uint8_t *expected_mac, size_t mac_len);
    int (*generate_cryptogram)(crypto_alg_t alg, const uint8_t *key,
                               size_t key_len, uint8_t key_index,
                               const uint8_t *dol_data, size_t dol_len,
                               uint8_t *cryptogram, size_t *cryptogram_len);
    int (*ica_key_extract)(const uint8_t *cert_der, size_t cert_len,
                           uint8_t *sym_key, size_t *sym_key_len,
                           uint8_t *pub_key, size_t *pub_key_len);
    uint8_t version;
} crypto_driver_t;
```

**Implementation Strategy**:
- Start with reference implementation (soft crypto) using external library (e.g., OpenSSL, mbedTLS) or simple algorithm implementation for testing
- Interface designed so HW accelerator can be swapped in later
- All operations must handle padding correctly (PKCS#1 v1.5 for RSA, ISO/IEC 7816-4 for DES unpadding)

### 2. CAPK Management (Critical)

**Location**: `src/core/capk.c`, `include/emv_kernel/capk.h`

**Required Functions** (matching EMV spec):
```c
uint32_t CAPK_GetCount(uint32_t *pCount);
uint32_t CAPK_Add(const char *RID, const char *Index, const char *Modules,
                  const char *Exponents, const char *Checksum);
uint32_t CAPK_Delete(const char *RID, const char *Index);
uint32_t CAPK_GetItem(uint32_t Index, char *RID, uint32_t *RIDLen,
                      char *CPKIndex, uint32_t *CPKIndexLen,
                      char *Modules, uint32_t *ModulesLen,
                      char *Exponents, uint32_t *ExponentsLen,
                      char *Checksum, uint32_t *ChecksumLen);
uint32_t CAPK_Clear(void);
```

**Data Structure**:
```c
typedef struct {
    uint8_t rid[10];           // RID (up to 5 bytes) + TR (up to 5 bytes)
    uint8_t rid_len;
    uint8_t cpk_index[4];      // CPK index (up to 4 bytes)
    uint8_t cpk_index_len;
    uint8_t modules[20];       // RSA modulus exponent
    uint8_t modules_len;
    uint8_t exponents[64];     // RSA exponent
    uint8_t exponents_len;
    uint8_t checksum[2];       // CAPK checksum (2 bytes)
    uint8_t valid;
} capk_entry_t;

#define MAX_CAPK_ENTRIES 16
static capk_entry_t g_capk_table[MAX_CAPK_ENTRIES];
static uint8_t g_capk_count = 0;
```

**Integration**: CAPK table must be accessible from `kernel_offline_data_auth()` for ACM(A) certificate chain verification.

### 3. Revocation List Management (Critical)

**Location**: `src/core/revocation.c`, `include/emv_kernel/revocation.h`

**Required Functions**:
```c
uint32_t RevocationIPK_GetCount(uint32_t *pCount);
uint32_t RevocationIPK_Add(const char *RID, const char *CapkIndex, const char *SerialNo);
uint32_t RevocationIPK_Delete(const char *RID, const char *CapkIndex);
uint32_t RevocationIPK_GetItem(uint32_t Index, char *RID, uint32_t *RIDLen,
                               char *CapkIndex, uint32_t *CapkIndexLen,
                               char *SerialNo, uint32_t *SerialNoLen);
uint32_t RevocationIPK_Clear(void);
```

**Integration**: Must be checked during CAPK validation in SDA verification.

### 4. TDOL/PDOL Processing (High)

**Location**: Improve `src/core/kernel_core.c` `build_dol_data_from_pdol()`

**Requirements**:
- Support variable-length tags (1-3 bytes)
- Support variable-length lengths (1-3 bytes)
- Parse nested templates
- Validate against kernel dictionary constraints

**Parsing Algorithm**:
```
While template not exhausted:
  Read tag byte(s) until byte with high bit = 0
  Read length byte(s) until byte with high bit = 0
  If length < 0x80: single byte length
  If 0x81-0xFE: length is following byte(s)
  If 0xFF: indefinite length (not used in EMV)
  Extract value of specified length
```

### 5. Processing Restrictions (High)

**Location**: Complete `kernel_processing_restrictions()` in `kernel_core.c`

**Per Book C-3 §5.4**:
- **Application Expiry**: Compare 5F24 (App Expiry Date) with current date
- **Usage Control**: Check AIP bits for usage restrictions (bits B1-B4)
- **Terminal Exception File**: Check if card is in TEF (via 9F3A TVR)

### 6. GENERATE AC Completion (High)

**Location**: Complete `kernel_generate_ac()` in `kernel_core.c`

**Three Paths**:
1. **TC (Terminal Conduction)**: Offline approved - minimal TDOL
2. **ARQC (Application Cryptogram)**: Online required - full TDOL with cryptographic processing
3. **NASP (No SDI Parameter)**: Decline - empty template with [83][00]

**Per Book C-3 §5.9.3**:
```
Generate AC Command: CLA=00, INS=A6, P1=00, P2=00, LC=TDOL_LEN, Data=TDOL
Response: [9F26] Cryptogram, [8A] Auth Response Code, [9F27] Cryptogram Info, [9F2B] NASP
```

### 7. ODA Dynamic Number Layer (High)

**Location**: Enhance `kernel_offline_data_auth()` for ODA path

**Per Book C-3 §5.6.2.4**:
1. Card returns ICC CRT [9F7E] in GPO response
2. Terminal sends SET ATTRIBUTE [84] with ICData (encrypted dynamic number)
3. Terminal decrypts ICData using ICA symmetric key → dynamic number
4. Terminal sends TOA (Terminal Action Analysis) with CDOL2 data + dynamic number
5. Card verifies TDES-MAC of CDOL2 + dynamic number against [9F7E]

### 8. Online Authorization Path (High)

**Location**: `examples/ref_k3/k3_ref_transaction.c` + `src/plugin/cvm_plugin_kernel3.c`

**Flow**:
1. ARQC generated via `crypto_driver->generate_cryptogram()`
2. ARQC encrypted and sent to acquirer (via platform hook)
3. ARPC response received and parsed
4. Outcome determined based on ARPC response
5. TC or NASP built accordingly

### 9. Full Entry Point Completion (Medium)

**Location**: `src/core/entry_point.c`

**Remaining Tasks**:
- Full ERP exchange (LLCP protocol activation)
- Complete PPS negotiation (default 106 kbps only currently)
- Application priority selection algorithm
- Handle empty candidate list per Book B §3.3.1.2

### 10. State Machine (Medium)

**Location**: New `src/core/state_machine.c`

**States**:
- EMV_STATE_IDLE
- EMV_STATE_POLLING
- EMV_STATE_PPSE_SELECT
- EMV_STATE_APP_SELECT
- EMV_STATE_GPO
- EMV_STATE_READ_APP_DATA
- EMV_STATE_CARD_READ_COMPLETE
- EMV_STATE_PROCESSING_RESTRICTIONS
- EMV_STATE_AUTHENTICATION
- EMV_STATE_CVM
- EMV_STATE_GENERATE_AC
- EMV_STATE_OUTCOME
- EMV_STATE_COMPLETE
- EMV_STATE_ERROR

Each state transition must be validated and error recovery implemented.

### 11. UI Integration (Medium)

**Location**: `include/emv_kernel/ui_driver.h` + reference implementation

**Per Book C-3 §5.7**:
- PIN prompt with encryption (PIN block format)
- Transaction amount display
- Confirmation prompts
- Signature capture (if supported)

### 12. Logging/Audit Trail (Medium)

**Location**: New `src/core/logger.c` + `include/emv_kernel/logger.h`

**Per Book A §7.2**:
- Circular log buffer (minimum 10 entries)
- Timestamped entries with event type
- Persistent storage where available
- Log dump capability

### 13. Error Code Standardization (Medium)

**Location**: `include/emv_kernel/errors.h`

**Required EMV Error Codes** (from official reference):
- EMV_OK, EMV_APPROVED_OFFLINE, EMV_APPROVED_ONLINE
- EMV_DECLINED_OFFLINE, EMV_DECLINED_ONLINE
- EMV_NO_ACCEPTED, EMV_TERMINATED
- EMV_CARD_BLOCKED, EMV_APP_BLOCKED
- EMV_NO_APP, EMV_CAPK_EXPIRED, EMV_CAPK_CHECKSUM_ERROR
- EMV_AID_DUPLICATE, EMV_CERT_RECOVER_FAILED
- EMV_DATA_AUTH_FAILED, EMV_UN_RECOGNIZED_TAG
- EMV_DATA_NOT_EXISTS, EMV_DATA_LENGTH_ERROR
- EMV_INVALID_TLV, EMV_INVALID_RESPONSE
- EMV_DATA_DUPLICATE, EMV_MEMORY_NOT_ENOUGH, EMV_MEMORY_OVERFLOW
- EMV_PARAMETER_ERROR, EMV_ICC_ERROR, EMV_NO_MORE_DATA
- EMV_CAPK_NO_FOUND, EMV_APP_NOT_ALLOW

### 14. Test Suite Expansion (Ongoing)

**Tests Needed**:
- Cryptographic algorithm unit tests (RSA, DES, TDES)
- CAPK and revocation list integration tests
- Full transaction end-to-end tests using mock IC reader
- Error injection tests for all failure paths
- Memory footprint verification (stack/static only)

### 15. Documentation (Ongoing)

**Required for EMV Co Submission**:
- Implementation Security Policy (ISP) template
- Technical Summary (TS) per EMV requirements
- Security Target (ST) draft
- Test results summary
- Configuration control records

---

## Build System Updates

**File**: `build/Android.mk` (already present in workspace)

Current Android.mk supports basic build. Need to add:
- Test executable targets
- Reference implementation build targets
- Platform abstraction layer selection

## Makefile for Desktop Testing

Create a Makefile for unit test compilation on desktop platforms (Linux/Windows).

```makefile
CFLAGS = -Iinclude -Wall -Wextra
LDLIBS = 

all: test_warehouse test_bitmap test_tlv_encode

test_warehouse: tests/unit/test_warehouse.c src/core/warehouse.c
	$(CC) $(CFLAGS) -o $@ $^ -lm

test_bitmap: tests/unit/test_bitmap.c src/utils/bitmap.c
	$(CC) $(CFLAGS) -o $@ $^

test_tlv_encode: tests/unit/test_tlv_encode.c src/utils/tlv_encode.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f test_warehouse test_bitmap test_tlv_encode
```

---

## Implementation Order

The following order minimizes dependencies and maximizes parallel development:

**Week 1-2**: Cryptographic Driver + CAPK + Revocation List (Phase 1)
**Week 3-4**: TDOL/PDOL Processing + Processing Restrictions (Phase 2.1)
**Week 5-6**: GENERATE AC + ODA DNL + Online Authorization (Phase 2.2)
**Week 7-8**: State Machine + UI Integration + Logging (Phase 3)
**Ongoing**: Test Suite Expansion + Documentation (Phase 4)

---

## Quality Gates for Certification Readiness

1. ✅ All core kernel functions implement EMV-specified behavior per Book C
2. ✅ Cryptographic primitives verified against known test vectors
3. ✅ Error codes mapped to EMV standard values
4. ✅ Memory footprint verified (≤ specified limits)
5. ✅ All mandatory tags validated per dictionary
6. ✅ Full test suite coverage (unit + integration)
7. ✅ Documentation package complete
8. ✅ Third-party security review (if required by certification body)
