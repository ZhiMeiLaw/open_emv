# EMV Certification Readiness Plan (v1.0)

## Executive Summary

This document outlines the complete plan to achieve EMV Co certification readiness for the EMV Contactless Payment Kernel implementation. The current codebase (`emv-payment-kernel` change) implements 32 tasks covering core functionality but requires additional features for certification compliance.

---

## Current State Assessment

**Implemented (✅)**: TLV Warehouse, Kernel Registry, Dictionary Validation, Data Dictionaries (K3/K5/K7), Entry Point Handler (PPSE), Orchestrator Skeleton, K3 Reference Transaction, Platform/Hal Implementation, CVM/Risk Plugins, Mock IC Reader Provider, Unit Tests.

**Required for Certification (🔴🟠)**: Cryptographic Driver, CAPK Management, Revocation List, Full TDOL/PDOL Processing, Processing Restrictions, GENERATE AC, ODA DNL Flow, Online Authorization Path, Error Code Standardization, State Machine, UI Integration, Logging/Audit Trail.

---

## Phased Implementation Approach

### Phase 1: Foundation (Critical) - 2-3 Weeks

| # | Task | Location | Priority | Dependencies |
|---|------|----------|----------|--------------|
| 1.1 | RSA-PKP Verification (SDA/fDDA) | `src/plugin/crypto_driver_ref.c` | 🔴 | None |
| 1.2 | DES Decryption (ODA DNL) | `src/plugin/crypto_driver_ref.c` | 🔴 | None |
| 1.3 | TDES-CMAC Verify & Generate | `src/plugin/crypto_driver_ref.c` | 🔴 | None |
| 1.4 | ICA Key Extraction from DER | `src/plugin/crypto_driver_ref.c` | 🔴 | None |
| 1.5 | CAPK Management | `src/core/capk.c`, `include/emv_kernel/capk.h` | 🔴 | Crypto (for checksum) |
| 1.6 | Revocation IPK List | `src/core/revocation.c`, `include/emv_kernel/revocation.h` | 🔴 | CAPK |
| 1.7 | Error Code Standardization | `include/emv_kernel/errors.h` | 🟠 | All modules |

### Phase 2: Core Kernel Completeness (High) - 3-4 Weeks

| # | Task | Location | Priority | Dependencies |
|---|------|----------|----------|--------------|
| 2.1 | Full TDOL/PDOL Parser | `src/core/kernel_core.c` - improve `build_dol_data_from_pdol()` | 🟠 | None |
| 2.2 | Processing Restrictions Check | `kernel_processing_restrictions()` in `kernel_core.c` | 🟠 | Time source |
| 2.3 | GENERATE AC Completion | `kernel_generate_ac()` in `kernel_core.c` | 🟠 | TDOL parser |
| 2.4 | ODA Dynamic Number Layer | `kernel_offline_data_auth()` enhancement | 🟠 | Crypto driver |
| 2.5 | Online Authorization Path | `k3_ref_transaction.c`, orchestrator | 🟠 | Crypto driver |
| 2.6 | CTQ Decision Tree Completion | `kernel_cvm()` enhancement | 🟠 | ICCDB |

### Phase 3: Infrastructure (Medium) - 2-3 Weeks

| # | Task | Location | Priority | Dependencies |
|---|------|----------|----------|--------------|
| 3.1 | Persistent ICCDB | `examples/ref_k3/k3_ref_platform.c` | 🟡 | Flash/storage drivers |
| 3.2 | Full Entry Point | `src/core/entry_point.c` | 🟡 | None |
| 3.3 | Transaction State Machine | New module | 🟡 | Entry point, kernel |
| 3.4 | UI Integration | `examples/ref_k3/k3_ref_ui.c` | 🟡 | Platform display/PIN |
| 3.5 | Logging/Audit Trail | New module | 🟡 | Time source, storage |

### Phase 4: Testing & Documentation (Ongoing)

| # | Task | Location | Priority |
|---|------|----------|----------|
| 4.1 | Expanded Test Suite | `tests/unit/`, `tests/integration/` | 🟢 |
| 4.2 | EMV Co Documentation Package | `docs/certification/` | 🟢 |
| 4.3 | Third-party Security Review | External | 🔴 |

---

## Critical Risk Areas

### Risk 1: Cryptographic Algorithm Implementation (Impact: HIGH)
- **Description**: Incorrect crypto implementation could compromise security or fail certification tests
- **Mitigation**: Use established cryptographic library (OpenSSL, mbedTLS, BoringSL) rather than implementing from scratch; perform independent review; use known answer test vectors from EMVCo

### Risk 2: Error Code Mismatches (Impact: MEDIUM-HIGH)
- **Description**: Non-standard error codes may cause certification rejection
- **Mitigation**: Map all internal errors to EMV standard codes using official reference implementation as reference

### Risk 3: Memory Limit Exceedance (Impact: MEDIUM)
- **Description**: Additional code may exceed target memory constraints
- **Mitigation**: Profile memory usage at each phase; modular design allows removing unused features

### Risk 4: Missing Certification Requirements (Impact: HIGH)
- **Description**: EMV Co has specific requirements not immediately obvious from spec reading
- **Mitigation**: Conduct thorough gap analysis against official reference; consult with accredited testing laboratory early in process

---

## Recommended Next Steps

1. **Week 1**: Implement crypto driver reference software (use OpenSSL/mbedTLS as starting point) + CAPK management
2. **Week 2**: Implement revocation list + error code standardization  
3. **Week 3-4**: Complete TDOL/PDOL processing + processing restrictions
4. **Week 5-6**: Complete GENERATE AC + ODA DNL flow
5. **Week 7-8**: Implement online authorization path + CTQ decision tree completion
6. **Week 9-10**: Add persistent ICCDB + state machine + logging
7. **Week 11+**: Comprehensive testing + documentation + prepare for accreditation review

---

## OpenSpec Workflow Integration

To track this work using the OpenSpec system:

```bash
# Create a new change for certification enhancements
opsx:propose emv-certification-enhancement

# This will generate:
# - proposal.md (requirements)
# - specs/ directory (detailed specifications per module)
# - design.md (technical design)
# - tasks.md (implementable tasks)

# After planning, iterate through tasks with:
opsx:apply emv-certification-enhancement

# Once complete:
opsx:archive emv-certification-enhancement
```

**Key files created during this process**:
- `openspec/new-changes/emv-certification-enhancement/proposal.md`
- `openspec/new-changes/emv-certification-enhancement/design.md`
- `openspec/new-changes/emv-certification-enhancement/tasks.md`
- `openspec/new-changes/emv-certification-enhancement/specs/` (one subdirectory per module)

---

## Quality Criteria for Certification Readiness

All of the following must be satisfied before submission to EMV Co:

1. ✅ All EMV Book A, B, C-3, C-5 specified functions implemented
2. ✅ Error handling produces EMV-standard error codes
3. ✅ Cryptographic operations verified against test vectors
4. ✅ Memory footprint documented and within limits
5. ✅ Zero heap allocation in production build
6. ✅ Full unit test coverage (>90%)
7. ✅ Regression tests pass for all scenarios
8. ✅ Implementation Security Policy drafted
9. ✅ Technical Summary completed
10. ✅ Configuration control records maintained

---

## Contact & Escalation

For questions about this plan or encountered blockers:
- Project Lead: [Your Name]
- Architecture Review Required: [EMV Accredited Reviewer]
- Cryptography Review Required: [Security Engineer]
