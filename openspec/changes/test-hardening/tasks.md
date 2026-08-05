# Tasks: EMV Kernel Test Hardening

## 1. Negative-path integration tests

- [ ] 1.1 Create `tests/integration/test_negative_paths.c` with mock card helpers
  - Helper: `build_mock_select_resp(status, aid, aip, pdol)` — SELECT AID response
  - Helper: `build_mock_gpo(cid_type, tvr, ctq, afl, tvr_bytes)` — GPO response
  - Helper: `build_mock_readrec(card_data)` — READ RECORD response with ICC cert/SDAD
  - Helper: `build_mock_genac(cod_type)` — GENERATE AC response
- [ ] 1.2 K3: CVM_FAIL → DECLINE test
  - Set CTQ with online_pin_required=1 and no CDCVM confirmation
  - Assert ep_ctx->outcome == OUTCOME_DECLINE
  - Assert NASP tag present in warehouse
- [ ] 1.3 K3: Expired card → DECLINE test
  - Set 5F24 expiry date in past (YYMMDD before 9A transaction date)
  - Assert ep_ctx->outcome == OUTCOME_DECLINE
- [ ] 1.4 K5: Amount exceeds unsigned_limit → ARQC test
  - Set unsigned_limit=100, transaction amount=500
  - Assert ep_ctx->outcome == OUTCOME_APPROVE_ISSUER_AUTH
  - Assert CID indicates ARQC (0x0A)
- [ ] 1.5 K7: SDS mismatch → DECLINE test
  - Set 9F36 SDS code in card data different from terminal expected
  - Assert ep_ctx->outcome == OUTCOME_DECLINE

## 2. Orchestrator verification tests

- [ ] 2.1 Add orchestrator test: build_tc_risk_data writes TVR into TC
  - Run kernel_execute with mock card that includes TVR (0x9F3A)
  - Call orchestrator_build_tc() and verify 0x9F3A is in output bytes
  - Verify 0x9F66 (Terminal Qualifiers) is also present
- [ ] 2.2 Add orchestrator test: NASP produced on DECLINE
  - Trigger a DECLINE outcome (missing mandatory tag)
  - Call orchestrator_build_nasp() and verify [9F2B][02][00][00]
- [ ] 2.3 Add orchestrator test: build_tc round-trip through TLV parser
  - Build TC bytes, parse them back with tlv_parse_raw()
  - Assert all expected tags are present and values match

## 3. Kernel boundary tests

- [ ] 3.1 Add `tests/unit/test_kernel_boundary.c` with assert helpers
  - ASSERT_EQ, ASSERT_NEQ, ASSERT_NULL, ASSERT_NONNULL macros
- [ ] 3.2 Kernel boundary: null context → safe error
  - Call kernel_execute(3, NULL), assert returns negative
  - Call orchestrator_init(NULL, NULL, NULL, NULL, NULL), assert ORCH_E_INVAL
- [ ] 3.3 Kernel boundary: missing mandatory PAN → validation fail
  - Populate warehouse without tag 0x5A (PAN)
  - Call tlv_validate_dict() with K3 dict (PAN is mandatory)
  - Assert returns non-zero error
- [ ] 3.4 Kernel boundary: warehouse pool overflow → handled
  - Create tx_warehouse_t with 1-byte pool
  - Call tlv_store_set() with any entry
  - Assert returns WH_E_INVAL, no crash

## 4. Build system and verification

- [ ] 4.1 Update Makefile with new test targets
  - Add `test_negative_paths` and `test_kernel_boundary` rules
  - Add them to `unit` and `integration` phony targets
- [ ] 4.2 Run full test suite and verify all green
  - `make unit` — all 7 unit tests pass
  - `make integration` — all 7 integration tests pass
  - `make ref` — all 3 ref examples run without crash
- [ ] 4.3 Commit and push
