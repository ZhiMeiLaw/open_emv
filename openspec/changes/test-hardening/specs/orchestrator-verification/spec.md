## ADDED Requirements

### Requirement: Orchestrator risk plugin lifecycle
The orchestrator MUST call risk plugin callbacks in the correct order
during a successful transaction: first build_tc_risk_data to populate the
TC warehouse, then update_iccdb to persist card state counters.

#### Scenario: build_tc_risk_data called before update_iccdb on APPROVE
- **WHEN** orchestrator_execute() completes with APPROVE_TERMINAL_CONDS
- **THEN** risk_plugin->build_tc_risk_data() is invoked before
  risk_plugin->update_iccdb()
- **AND** the TC warehouse contains the risk data written by build_tc_risk_data

#### Scenario: update_iccdb not called on DECLINE
- **WHEN** orchestrator_execute() completes with OUTCOME_DECLINE
- **THEN** risk_plugin->update_iccdb() is NOT invoked
- **AND** no ICCDB fields are written for this transaction

#### Scenario: build_tc_risk_data called only on APPROVE outcomes
- **WHEN** the outcome is OUTCOME_DECLINE or OUTCOME_RESTART
- **THEN** risk_plugin->build_tc_risk_data() is NOT invoked
- **AND** risk_plugin->update_iccdb() is NOT invoked

### Requirement: Orchestrator build_tc produces valid BER-TLV
When orchestrator_build_tc() serialises the output warehouse into TLV
bytes, the result MUST be valid BER-TLV encoding that can be parsed
back without error.

#### Scenario: TC bytes round-trip through TLV parser
- **WHEN** orchestrator_build_tc(tc_buf, &tc_len, sizeof(tc_buf)) is called
  after a successful APPROVE transaction
- **THEN** tc_len > 0 and tc_buf contains valid BER-TLV
- **AND** parsing tc_buf with tlv_parse_raw() produces the same tags that
  were written by build_tc_risk_data and generate_cryptogram

#### Scenario: NASP bytes are well-formed
- **WHEN** orchestrator_build_nasp(nasp_buf, &nasp_len, sizeof(nasp_buf))
  is called after a DECLINE outcome
- **THEN** nasp_len equals 5 and nasp_buf contains exactly
  [0x9F, 0x2B, 0x02, 0x00, 0x00]
