# EMV Co Certification Gap Analysis (By Specification)

## Document Status
- **Prepared for**: EMV Co Certification Readiness
- **Current State**: emv-payment-kernel (32 tasks completed)
- **Goal**: Certification-ready implementation

## Methodology
This analysis compares our implementation against:
1. EMV Contactless Book A (Architecture & General Requirements) v2.12
2. EMV Contactless Book B (Entry Point Specification) v2.12
3. EMV Contactless Book C-3 (Kernel 3 Specification) v2.12
4. EMV Contactless Book C-5 (Kernel 5/qVISA Specification) v2.12
5. Official Visa Core Reference Implementation

## Legend
- 🔴 = Critical - Must be implemented for certification
- 🟠 = High - Important for completeness
- 🟡 = Medium - Recommended for production use
- 🟢 = Low - Edge case or future work

---

## Book A: Architecture & General Requirements

### ✅ Pass: Core Architecture
- **Memory Model**: Stack/static only - No malloc/free ✓
- **Zero Copy**: TLV warehouse uses flat pool with zero-copy pointers ✓
- **Deterministic Memory**: Per-transaction workspace defined ✓

### 🟠 Required: Error Handling
| Gap | Description | Severity |
|-----|-------------|----------|
| Error code mapping | Our error codes (WH_E_*, DICT_E_*, etc.) don't fully map to EMV standard error codes (EMV_E_*) in Book A | High |
| Error recovery | No comprehensive state machine for recovery from intermediate errors | High |

### 🟡 Recommended: Logging & Debug
| Gap | Description | Severity |
|-----|-------------|----------|
| Audit trail | Missing EMV-compliant logging as required by Book A §7.2 | Medium |
| Debug hooks | No standardized debug output interface | Medium |

### 🟢 Optional: International Support
- Country code support (9F1A) - Implemented but limited to reference platform

---

## Book B: Entry Point Specification

### ✅ Pass: Basic Flow
- **ATS Parsing**: Implemented in `entry_point.c` ✓
- **PPSE Selection**: SELECT PPSE [2PAY.SYS.DDF01] implemented ✓
- **Application Selection**: SELECT AID with extended selection stub ✓
- **SPI (Send POI Information)**: Placeholder implemented ✓

### 🟠 Required: Full Entry Point
| Gap | Description | Severity |
|-----|-------------|----------|
| Full ERP exchange | Entry point only has `entry_point_run()` - lacks complete ERP exchange per Book B §3.1.4 | High |
| Complete PPS handling | PPS is optional but requires full negotiation handling | High |
| Application priority selection | Candidate list prioritization by 5F2A and 9F2A not fully implemented | High |
| Terminal Action Analysis (TOA) | Missing ODA dynamic number layer TOA flow | High |

### 🟠 Required: Card Authentication
| Gap | Description | Severity |
|-----|-------------|----------|
| SDA verification | `kernel_offline_data_auth()` has placeholder - actual RSA-PKP verify is stub | High |
| ODA verification | ODA path detected but MAC verification with 9F7E not implemented | High |
| Dynamic Number Layer | DES decryption for ODA DNL not fully integrated | High |

### 🟡 Recommended: UI & Interaction
- PIN entry hook (via `ui_driver.h`) - Interface exists but no reference implementation
- Display status messages - Interface exists but no implementation

---

## Book C-3: Kernel 3 Specification

### ✅ Pass: Core Structure
- **TDOL Definition**: Kernel 3 TDOL defined with [9F16, 9F02, 9F36, 9F03, 5F2A, 9F66] ✓
- **Dictionary Items**: Complete with sources, types, min/max lengths ✓
- **GPO Processing**: Implemented with PDOL handling ✓
- **Read Application Data**: READ RECORD per AFL implemented ✓
- **Card Read Complete**: Validation via dictionary ✓

### 🟠 Required: Full Transaction Flow
| Gap | Description | Severity |
|-----|-------------|----------|
| Processing restrictions | `kernel_processing_restrictions()` is a stub - missing expiry, TEF checks | High |
| fDDA/SDA signature verification | RSA-PKP verify stub - needs real implementation with ACM(A) chain | Critical |
| ODA with TDES-MAC | ICC CRT check against 9F7E needs real crypto implementation | Critical |
| CTQ decision tree | Implemented but basic - needs full priority handling per §5.7.1.2 | High |
| GENERATE AC | Build and send with proper TDOL encoding - partially implemented | High |

### 🟠 Required: Cryptogram Handling
| Gap | Description | Severity |
|-----|-------------|----------|
| ARQC generation | `generate_cryptogram` stub in crypto driver - needs real implementation | Critical |
| Cryptogram processing | Handling of different cryptogram types (ARQC, TC, CAC) | High |

### 🟡 Required: Risk Management
| Gap | Description | Severity |
|-----|-------------|----------|
| TRM (Terminal Risk Mgmt) | Placeholder risk checks - needs actual velocity/frequency limits | Medium |
| CRM (Card Risk Mgmt) | Placeholder - needs ICCDB-based checks | Medium |
| VEL (Velocity Enforcement) | Placeholder - needs counter-based limits | Medium |

---

## Book C-5: Kernel 5/qVISA Specification

### ✅ Pass: Basic Structure
- **TDOL Definition**: Simplified K5 TDOL [9F02, 5F2A] ✓
- **CVM Plugin**: K5 CVM with 9F50 handling implemented ✓

### 🟠 Required: Full K5 Flow
| Gap | Description | Severity |
|-----|-------------|----------|
| Crypto CVM | Full implementation per §3.8 - basic stub present | Medium |
| qVSDC integration | No qVSDC (Signature Delegation) flow support | High |

---

## Official Reference Implementation Gaps

### Missing Features from Visa Core

| Feature | Status | Severity |
|---------|--------|----------|
| CAPK Management (EMV_CAPK_*) | Not implemented | Critical |
| Revocation IPK List | Not implemented | Critical |
| Exception File (EMV_ExceptionFile_*) | Not implemented | High |
| Full AID Table with TAC parameters | Basic AID list stub only | High |
| Online Financial Transaction (full ARPC flow) | Placeholder only | Critical |
| Full ICCDB persistent storage | RAM-based mock only | High |
| Multi-language support | Not implemented | Medium |
| Receipt printing interface | Not implemented | Medium |
| Script processing (Card Script Commands) | Not implemented | High |

---

## Priority Action Items for Certification

### 🔴 Critical (Must Fix for Certification)
1. **Cryptographic Implementation**: Real RSA-PKP verify, TDES-CMAC, DES decryption in crypto driver
2. **CAPK Management**: Add EMV_CAPK_GetCount, EMV_CAPK_Add, EMV_CAPK_Delete, EMV_CAPK_GetItem
3. **Revocation List**: Implement EMV_RevocationIPK_* functions
4. **ARPC Online Flow**: Complete online authorization path with acquirer communication
5. **Error Code Standardization**: Map all internal errors to EMV standard codes

### 🟠 High (Important for Certification)
6. **ODAL Processing**: Full BER-TLV parsing for PDOL/TDOL
7. **ICCDB Persistent Storage**: Replace RAM mock with flash/secure element backed storage
8. **Processing Restrictions**: Implement expiry, TEF, usage control checks
9. **Online Financial Trans**: Implement Fn_Callback_OnlineFinancialTransReq equivalent
10. **Script Processing**: Card Script Commands (SET ATTRIBUTE, GENERATE AC responses)

### 🟡 Medium (Recommended)
11. **Logging/Audit Trail**: Implement EMV-compliant logging per Book A §7.2
12. **UI Integration**: PIN prompt, display messages, signature capture
13. **Multi-language Support**: Language selection callbacks
14. **Receipt Printing**: Print receipt callbacks
15. **Debug Hooks**: Standardized debug output interface

### 🟢 Low (Future Work)
16. **qVSDC**: Signature delegation flow
17. **Token Support (K7)**: Full token processing
18. **POS Host Test Harness**: For regression testing