## Why

The EMV kernel's positive-path coverage is solid (happy-path TC/ARQC for each kernel),
but the negative paths — the failure modes that matter most in production — have no
integration tests. A card that should be declined is never verified as declined;
a CVV failure, an expired card, or an amount exceeding the unsigned limit are all
untested. This leaves a critical confidence gap before any integrator deploys the
kernel.

## What Changes

- Add negative-path integration tests for K3 (CVM fail → DECLINE, expired card → DECLINE)
- Add negative-path integration tests for K5 (amount exceeds limit → ARQC/online)
- Add negative-path integration tests for K7 (SDS mismatch → DECLINE)
- Add orchestrator test verifying build_tc_risk_data populates TVR in TC output
- Add kernel boundary tests: missing mandatory tag → dictionary validation fail,
  null context → safe error return, warehouse overflow → rejected
- No API changes; all new tests link against existing libraries

## Capabilities

### New Capabilities
- `negative-paths`: Integration tests covering failure branches across K3/K5/K7 —
  CVM failures, expired cards, amount over-limit, SDS validation, ARQC path
- `orchestrator-verification`: Tests that orchestrator correctly wires risk plugin
  callbacks (build_tc_risk_data) and produces expected TC/NASP data structures

### Modified Capabilities
<!-- None — no existing spec requirements are changing -->

## Impact

- `tests/integration/` — 2 new test files (~300 lines)
- `tests/unit/` — 1 new test file for boundary cases (~150 lines)
- `src/core/orchestrator.c` — no changes (already correct from tonight's work)
- `src/core/entry_point.c` — no changes
- Build: Makefile updated with 3 new test targets
- No breaking changes to any public API or existing tests
