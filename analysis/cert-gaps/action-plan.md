# EMV Certification Action Plan

## Priority-Driven Development Approach

This plan outlines the sequence of work needed to achieve EMV certification readiness.

### Phase 1: Foundation (Critical) - 2-3 weeks
**Goal**: Implement the cryptographic and data structures that form the foundation of all security operations.

### Phase 2: Core Kernel Completeness (High) - 3-4 weeks  
**Goal**: Complete the core kernel transaction flows with proper error handling.

### Phase 3: Infrastructure & Integration (Medium) - 2-3 weeks
**Goal**: Add CAPK, revocation lists, persistent storage, and UI hooks.

### Phase 4: Testing & Documentation (Ongoing)
**Goal**: Comprehensive test suite and EMV Co documentation package.

---

## Phase 1: Foundation (Critical Priority)

### Task 1: Cryptographic Driver Implementation
**File**: `src/plugin/crypto_driver_ref.c` → expand with real algorithms
- [ ] Implement RSA-PKP verify using ACM(A) certificate chain verification
- [ ] Implement DES decryption for ODA Dynamic Number Layer  
- [ ] Implement TDES-CMAC for ICC CRT check (tag 9F7E)
- [ ] Implement ARQC generation via TDES-MAC on TDOL data
- [ ] Implement ICA key extraction from DER certificates (RSA modulus + symmetric key)
- [ ] Add error code mapping per EMV standard

**Dependencies**: None - standalone implementation

**Expected Output**: Production-ready crypto driver that can be replaced with HW accelerator later

---

### Task 2: CAPK Management
**Files**: Add `src/core/capk.c`, `include/emv_kernel/capk.h`
- [ ] CAPK table management (RID + CPK Index pairs)
- [ ] CAPK checksum verification (per Book C-3 §4.1)
- [ ] EMV_CAPK_GetCount, EMV_CAPK_Add, EMV_CAPK_Delete, EMV_CAPK_GetItem APIs
- [ ] Integration with fDDA signature verification (ACM lookup)

**Dependencies**: Crypto driver (for checksum verification)

---

### Task 3: Revocation List Management
**Files**: Add `src/core/revocation.c`, `include/emv_kernel/revocation.h`
- [ ] Issuer Public Key Revocation list storage
- [ ] EMV_RevocationIPK_GetCount, EMV_RevocationIPK_Add, EMV_RevocationIPK_Delete, EMV_RevocationIPK_GetItem APIs
- [ ] Integration with CAPK validation flow

**Dependencies**: CAPK management

---

### Task 4: Standardized Error Code Mapping
**File**: Update `include/emv_kernel/errors.h` and all modules
- [ ] Map all internal error codes to EMV standard error codes
- [ ] Create EMV error code translation layer
- [ ] Ensure all return paths use standardized codes

**Dependencies**: All modules that return error codes

---

## Phase 2: Core Kernel Completeness (High Priority)

### Task 5: Full TDOL/PDOL Processing
**File**: Improve `src/core/kernel_core.c` build_dol_data_from_pdol()
- [ ] Full BER-TLV template parsing for PDOL/TDOL
- [ ] Tag length decoding support (1-3 byte lengths)
- [ ] Nested template support for complex DOLs
- [ ] Validation against dictionary constraints

**Dependencies**: TLV encode/decode utilities

---

### Task 6: Processing Restrictions Check
**File**: Complete `kernel_processing_restrictions()` in `kernel_core.c`
- [ ] Application expiry date check (5F24 vs current date)
- [ ] AIP bit checking (offline decryption, SDA support)
- [ ] AUC usage control checks (domestic/international)
- [ ] Terminal Exception File (TEF) check

**Dependencies**: Date/time from platform

---

### Task 7: Cardholder Verification Tree Completion
**File**: Improve `kernel_cvm()` in `kernel_core.c`
- [ ] Full priority ordering per Book C-3 §5.7.1.2
- [ ] Online PIN required path integration
- [ ] CDCVM confirmation code validation
- [ ] Signature requirement path
- [ ] No-CVM fallback handling

**Dependencies**: UI plugin for PIN capture, ICCDB for CRM

---

### Task 8: GENERATE AC Completion
**File**: Complete `kernel_generate_ac()` in `kernel_core.c`
- [ ] Build TDOL data with correct BER-TLV encoding
- [ ] Send APDU CLA=00 INS=A6 for TC case
- [ ] Handle NASP (No SDI Parameter) for decline
- [ ] Parse GENERATE AC response (cryptogram info, auth response code)
- [ ] Set output tags (9F26 ARQC, 8A Auth Response, 9F27 CIF, 9F2B NASP)

**Dependencies**: IC Reader Provider for APDU transmission

---

### Task 9: Dynamic Number Layer (ODA) Flow
**File**: Enhance `kernel_offline_data_auth()` for ODA path
- [ ] SET ATTRIBUTE command for DNL data
- [ ] DES decryption of ICData using ICA symmetric key
- [ ] Unpadding to extract dynamic number
- [ ] TOA (Terminal Action Analysis) with CDOL2 data + dynamic number
- [ ] TDES-MAC verification against 9F7E (ICC CRT)

**Dependencies**: Crypto driver (des_decrypt, tdes_mac_verify)

---

### Task 10: Online Authorization Path
**File**: Add online ARQC processing in `k3_ref_transaction.c` or orchestrator
- [ ] Build ARQC request with encrypted data
- [ ] Interface to acquirer online authorization system (placeholder)
- [ ] Parse ARPC response
- [ ] Update outcome based on issuer decision
- [ ] Handle NSP (No SDI Parameter) vs TC outcomes

**Dependencies**: Crypto driver (generate_cryptogram), ACQ interface

---

## Phase 3: Infrastructure & Integration (Medium Priority)

### Task 11: Persistent ICCDB
**File**: Improve `k3_ref_platform.c` iccdb implementation
- [ ] Flash-backed persistent storage instead of RAM-only
- [ ] CRC/checksum protection for stored card state
- [ ] Atomic update semantics for counters
- [ ] Secure delete for card removal

**Dependencies**: Platform-specific flash/EEPROM drivers

---

### Task 12: Full Transaction State Machine
**File**: Create `src/core/state_machine.c`
- [ ] Define transaction states (IDLE, POLLING, SELECTION, AUTHENTICATION, CVM, ONLINE, COMPLETE)
- [ ] State transitions on events
- [ ] Recovery from intermediate failures
- [ ] Timeout handling per ISO 14443-4

**Dependencies**: Entry point, kernel execution

---

### Task 13: UI Integration
**File**: Implement `examples/ref_k3/k3_ref_ui.c`
- [ ] PIN entry with encryption (pin_block generation)
- [ ] Transaction status display
- [ ] Confirmation prompts
- [ ] Signature capture interface

**Dependencies**: Platform UI hardware

---

### Task 14: Logging & Audit Trail
**File**: Add `src/core/logger.c`, `include/emv_kernel/logger.h`
- [ ] Circular buffer for audit trail entries
- [ ] Per-EMV spec §7.2 log format (timestamp, event type, data references)
- [ ] Flash-backed persistent logging where available
- [ ] Log dump for debugging/certification review

**Dependencies**: Time source, persistent storage

---

## Phase 4: Testing & Documentation (Ongoing)

### Task 15: Test Suite Expansion
**Directory**: `tests/unit/`, `tests/integration/`
- [ ] Unit tests for new cryptographic implementations
- [ ] CAPK integration tests
- [ ] Full transaction end-to-end simulation tests
- [ ] Mock-based regression tests using k3_ref_icr_mock.c
- [ ] Fuzz testing for edge cases

**Dependencies**: All implemented features

### Task 16: EMV Co Documentation Package
**Directory**: `docs/certification/`
- [ ] Implementation Security Policy (ISP) - draft template
- [ ] Technical Summary (TS) - completed per EMV requirements
- [ ] Security Target (ST) - draft template
- [ ] Test Results Summary - from test suite
- [ ] Configuration Control Board (CCB) records

**Dependencies**: Final implementation state

---

## Timeline Estimation

| Phase | Tasks | Estimated Effort | Notes |
|-------|-------|------------------|-------|
| Phase 1 | 1-4 | 2-3 weeks | Most critical, parallelizable where possible |
| Phase 2 | 5-10 | 3-4 weeks | Depends on crypto completion |
| Phase 3 | 11-14 | 2-3 weeks | Can overlap with Phase 2 |
| Phase 4 | 15-16 | Ongoing | Parallel throughout development |

**Total Estimate**: 7-10 weeks for core certification readiness (excluding actual EMV Co testing fees and timeline)

---

## Critical Path

The critical path is: **Crypto Driver → CAPK/Revocation → ODA/SDA Authentication → GENERATE AC → Online ARQC Path**

All other features are either independent or have less severe impact on certification.

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Crypto algorithm bugs | High (security-critical) | Third-party review, unit tests covering edge cases |
| Error code mismatches | Medium (certification rejection) | Cross-reference with official reference implementation |
| Memory leaks/buffer overflows | High (security) | Static analysis tools, rigorous bounds checking |
| Performance on target hardware | Medium | Profile on actual MCU/SE before submission |
| Missing compliance item | High (certification failure) | Use official reference as checklist during design |
