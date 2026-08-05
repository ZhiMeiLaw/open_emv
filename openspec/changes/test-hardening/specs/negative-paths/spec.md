## ADDED Requirements

### Requirement: K3 CVM failure causes DECLINE outcome
When the K3 CVM plugin evaluates a card and the result is CVM_FAIL (e.g.,
wrong PIN, missing CTQ with mandatory CVM), the kernel MUST set the final
outcome to OUTCOME_DECLINE and the TC/NASP builder MUST produce a NASP.

#### Scenario: CVM_FAIL → DECLINE
- **WHEN** kernel_execute(3, ctx) runs with a mock card that triggers CVM_FAIL
  (CTQ byte1 bit8 = 1 with no matching CDCVM confirmation code)
- **THEN** ep_ctx->outcome equals OUTCOME_DECLINE
- **AND** the warehouse contains tag 0x9F2B (NASP) instead of 0x9F26 (AC)

#### Scenario: Expired card → DECLINE
- **WHEN** kernel_execute(3, ctx) runs with a mock card whose 5F24 expiry date
  is before the transaction date 9A
- **THEN** ep_ctx->outcome equals OUTCOME_DECLINE
- **AND** the TVR bit for expired card is set in the warehouse

### Requirement: K5 amount-exceeds-limit causes online path
When the K5 CVM plugin evaluates a transaction whose amount exceeds the
unsigned_limit configured in pos_params, the kernel MUST require online
authorisation (ARQC) since K5 has no PIN path.

#### Scenario: Amount > unsigned_limit → ARQC
- **WHEN** kernel_execute(5, ctx) runs with amount 0x00000001F4 (500) and
  unsigned_limit = 0x0000000064 (100)
- **THEN** ep_ctx->outcome equals OUTCOME_APPROVE_ISSUER_AUTH
- **AND** the CID [9F27] indicates ARQC type

### Requirement: K7 SDS mismatch causes DECLINE
When the K7 risk plugin validates the Signature Data Set and the token SDS
code stored in the terminal does not match the value from the card, the
kernel MUST decline the transaction.

#### Scenario: SDS code mismatch → DECLINE
- **WHEN** kernel_execute(7, ctx) runs with a mock card whose SDS code (9F36)
  does not match the terminal's expected SDS code
- **THEN** ep_ctx->outcome equals OUTCOME_DECLINE

### Requirement: build_tc_risk_data populates TC with TVR and Terminal Qualifiers
When the orchestrator reaches an APPROVE outcome, it MUST call the active
kernel's risk_plugin->build_tc_risk_data() callback, which writes risk
tags into the output warehouse.

#### Scenario: TC includes TVR after APPROVE
- **WHEN** kernel_execute(3, ctx) completes with outcome APPROVE_TERMINAL_CONDS
  and the mock card includes a TVR entry (0x9F3A) in its data
- **THEN** orchestrator_build_tc() produces bytes containing tag 0x9F3A
- **AND** tag 0x9F66 (Terminal Qualifiers) is also present in the TC output

#### Scenario: NASP produced on DECLINE
- **WHEN** kernel_execute(3, ctx) completes with outcome DECLINE
- **THEN** orchestrator_build_nasp() produces the standard [9F2B][02][00][00] bytes
- **AND** no TC data is produced

### Requirement: Kernel handles missing mandatory dictionary tags gracefully
When the dictionary validator encounters a warehouse missing a mandatory tag,
it MUST return a failure code and the orchestrator MUST set outcome to DECLINE
without crashing or accessing null pointers.

#### Scenario: Missing mandatory PAN → DECLINE
- **WHEN** the warehouse is populated without tag 0x5A (PAN) but the dictionary
  marks it as mandatory (mandatory=1)
- **THEN** tlv_validate_dict() returns a non-zero error code
- **AND** the orchestrator does not proceed to CVM/risk evaluation

#### Scenario: Null context passed to kernel_execute → safe error
- **WHEN** kernel_execute(3, NULL) is called
- **THEN** the function returns a negative error code (ORCH_E_INVAL)
- **AND** the process does not crash or access freed memory

#### Scenario: Null orchestrator_init context → safe error
- **WHEN** orchestrator_init(NULL, driver, NULL, params, NULL) is called
- **THEN** the function returns ORCH_E_INVAL
- **AND** no global state is corrupted

### Requirement: Kernel handles warehouse pool overflow
When the transaction warehouse pool is exhausted during tag storage,
all tlv_store_set operations MUST return WH_E_INVAL and the kernel MUST
gracefully handle the overflow without writing beyond the pool boundary.

#### Scenario: Overflow during GPO → handled
- **WHEN** the warehouse pool is sized to 1 byte (intentionally small) and
  kernel_execute runs with a normal mock card
- **THEN** the function returns a non-zero error code
- **AND** no buffer overrun occurs (verifiable via sanitiser)
