## Context

The EMV kernel has complete positive-path coverage (TC outcome for K3/K5/K7)
but no negative-path tests. Production EMV terminals must correctly decline
transactions for expired cards, failed CVM, SDS mismatches, and other
error conditions. Without tests for these paths, regressions could go
undetected.

The orchestrator also lacked verification that risk plugin callbacks
(build_tc_risk_data, update_iccdb) are actually invoked during execution.
Tonight's wiring fixes this, but there is no test proving the wiring works.

Current test counts:
- Unit tests: 6 (warehouse, tlv_encode, bitmap, ctq_parse, sha1, risk_k7)
- Integration tests: 4 (k3_e2e, k5_e2e, k7_e2e, iccdb_update) — all positive paths
- Reference examples: 3 (ref_k3, ref_k5, ref_k7)

## Goals / Non-Goals

**Goals:**
- Cover all failure branches in K3, K5, K7 integration tests
- Verify orchestrator wires risk plugin callbacks correctly
- Add boundary/robustness tests for null inputs and warehouse overflow
- Maintain zero regressions in existing tests

**Non-Goals:**
- No changes to kernel logic (orchestrator, CVM, risk plugins)
- No new public APIs
- No performance tests
- No certification testing (out of scope per original spec)

## Decisions

### Decision 1: New test file per area, not per kernel
Created `tests/integration/test_negative_paths.c` (K3/K5/K7 negative cases)
and `tests/unit/test_kernel_boundary.c` (null/overflow safety).

**Rationale:** Keeps each test file focused on a single concern. Negative
paths for all 3 kernels share the same mock infrastructure, so one file is
appropriate. Boundary tests are kernel-agnostic, so a separate unit test is
cleaner.

**Alternative considered:** One large test file with all cases. Rejected
because it would be harder to maintain and each kernel's negative path is
independent.

### Decision 2: Mock card data per test case, not per kernel
Each test function sets up its own mock card responses inline, rather than
having a shared `build_mock_*` function.

**Rationale:** Negative-path tests need slightly different mock data
(expiry date, CTQ bits, SDS code). A shared builder would require complex
parameterisation. Inline mocks are clearer for reading and debugging.

**Alternative considered:** Parameterised mock builder. Rejected as over-engineered
for 6-8 test cases.

### Decision 3: Warehouse overflow test uses deliberately tiny pool
The overflow test creates a transaction workspace with a 1-byte pool to
guarantee overflow on the first tag store.

**Rationale:** This is the simplest way to trigger the overflow path without
needing a large mock dataset. The test asserts the error code, not specific
behavior.

## Risks / Trade-offs

- Mock card data is simplified — real card responses are more complex.
  Tests verify kernel logic, not card behaviour.
  → Mitigation: docstrings explain what each mock represents.

- Warehouse overflow test with 1-byte pool is artificial.
  → Mitigation: it verifies the safety invariant (no crash, valid error),
    not production behaviour.

## Migration Plan

This is a pure test addition. No production code changes, no API changes,
no migration needed. Existing `make test` output will simply show more
passing tests.

## Open Questions

None. All test cases are derived from existing kernel logic and spec
requirements.
