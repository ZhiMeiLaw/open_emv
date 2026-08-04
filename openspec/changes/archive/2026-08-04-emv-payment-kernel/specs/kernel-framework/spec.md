# Spec: Kernel Framework & Plugin System

## Purpose
Extensible, dictionary-driven execution framework for EMV Contactless payment kernels. Supports SDA and ODA card authentication, per-kernel CVM strategies, and risk management plugins.

## ADDED Requirements

### Requirement: Runtime Kernel Registration
The system SHALL register kernels at runtime via a pluggable registration API against a static dispatch table of configurable size (`MAX_KERNEL_ENTRIES`, default 16).

#### Scenario: Register a kernel config at startup
- **WHEN** `kernel_register(&config)` is called with a valid `kernel_config_t`
- **THEN** the config is stored in the dispatch table
- **AND** subsequent `kernel_run(kernel_id, ctx)` finds and dispatches to it

#### Scenario: Register more than available slots
- **WHEN** `kernel_register()` is called when the table is full (count >= MAX_KERNEL_ENTRIES)
- **THEN** it returns -1 (registration failed)
- **AND** the table state is unchanged

#### Scenario: Lookup unknown kernel id returns error
- **WHEN** `kernel_run(99, ctx)` is called with an unregistered kernel id
- **THEN** it returns -1
- **AND** no plugin callbacks are invoked

### Requirement: Kernel Data Dictionary
Each kernel SHALL have a Data Dictionary that defines every TLV tag used during its transaction flow.

#### Scenario: Dictionary defines tag attributes
- **WHEN** a `dict_item_t` entry is defined for tag `0x9F02`
- **THEN** it specifies source (`TAG_SRC_TERMINAL`), type (`TAG_TYPE_NUMERIC`), min/max length, mandatory flag, and description

#### Scenario: Dictionary supports per-kernel tag variations
- **WHEN** Kernel 3's dictionary lists TDOL tags `[9F16, 9F02, 9F36, 9F03, 5F2A, 9F66]`
- **AND** Kernel 5's dictionary lists TDOL tags `[9F02, 5F2A]`
- **THEN** each kernel has independent tag definitions
- **AND** the orchestrator uses only the active kernel's dictionary

### Requirement: Dictionary-Based Validation
The system SHALL validate input completeness before kernel execution by cross-referencing warehouse contents with the kernel's required dictionary items.

#### Scenario: All mandatory tags present → validation passes
- **WHEN** `tlv_validate_dict(dict, wh)` is called
- **AND** all entries marked `mandatory = 1` exist in the warehouse
- **THEN** it returns 0 (pass)

#### Scenario: Missing mandatory tag → validation fails
- **WHEN** `tlv_validate_dict(dict, wh)` is called
- **AND** entry `0x9F02` is marked mandatory but not found in warehouse
- **THEN** it returns -1 (fail)
- **AND** the error indicates which tag was missing

#### Scenario: Tag length outside allowed range → validation fails
- **WHEN** `tlv_validate_dict(dict, wh)` is called
- **AND** tag `0x9F02` has max_len=6 but warehouse contains 7 bytes
- **THEN** it returns -1 (length violation)

### Requirement: Plugin Dispatch per Kernel
Each kernel SHALL be driven by three plugins: CVM, Risk, and configuration.

#### Scenario: Orchestrator invokes CVM plugin
- **WHEN** `orchestrator_execute(kernel_id, ctx)` runs a kernel
- **AND** the kernel's config has a non-null `cvm_plugin`
- **THEN** `cvm_plugin->evaluate(ctx)` is called
- **AND** the result determines whether to proceed, decline, or restart

#### Scenario: Orchestrator invokes Risk plugin
- **WHEN** the orchestrator runs after CVM passes
- **THEN** `risk_plugin->check(ctx, RISK_CHECK_TRM)` is called
- **AND** if it returns `RISK_FAIL`, outcome is set to DECLINE

#### Scenario: Orchestrator builds TC with risk data
- **WHEN** the outcome is APPROVE
- **THEN** `risk_plugin->build_tc_risk_data(ctx, tc_wh)` is called
- **AND** the TC TLV includes risk parameters from the risk plugin

### Requirement: Card Authentication Before GPO
Card Authentication (SDA and ODA) SHALL occur in the Entry Point Handler, after application select and before GPO.

#### Scenario: SDA verification succeeds
- **WHEN** `entry_point_sda_verify(ddic, dol_data, cert, acm)` is called
- **AND** the RSA-PKP signature verifies correctly
- **THEN** the result is SDA_SUCCESS
- **AND** `ctx->has_verified_sda` is set to 1

#### Scenario: SDA verification fails — card rejected
- **WHEN** `entry_point_sda_verify(...)` detects a DDIC/hash mismatch
- **THEN** the result is SDA_FAIL
- **AND** the transaction outcome is DECLINE

#### Scenario: ODA dynamic number layer executes correctly
- **WHEN** `entry_point_oda_verify(ic_data, cdol2_data, card_cryptogram, ica_key)` is called
- **AND** DES decryption of ICData produces valid dynamic number
- **AND** TDES-MAC of CDOL2 + ICDN matches ICC CRT [9F7E]
- **THEN** the result is ODA_SUCCESS
- **AND** `ctx->has_verified_oda` is set to 1

#### Scenario: ODA fails — MAC mismatch
- **WHEN** the computed TDES-MAC does not match `[9F7E]`
- **THEN** the result is ODA_FAIL
- **AND** the transaction outcome is DECLINE

### Requirement: Outcome Model Per Book A §6
The system SHALL support the EMV contactless outcome model.

#### Scenario: Approve with issuer authorization
- **WHEN** ARQC is generated and outcome determination yields approval
- **THEN** outcome code is `OUTCOME_APPROVE_ISSUER_AUTHORISATION`
- **AND** Terminal Qualifiers (9F66) include online authentication flag
- **AND** TC (Terminal Conduction) data is built

#### Scenario: Approve with terminal conditions
- **WHEN** all risk checks pass and amount is below online threshold
- **THEN** outcome code is `OUTCOME_APPROVE_TERMINAL_CONDITIONS`
- **AND** TC is built without online auth requirement

#### Scenario: Decline due to failed CVM
- **WHEN** CVM plugin returns CVM_FAIL
- **THEN** outcome code is `OUTCOME_DECLINE`
- **AND** NASP (No Application SDI Parameter) is built instead of TC

#### Scenario: Restart recommended
- **WHEN** card is removed unexpectedly or protocol error occurs
- **THEN** outcome code is `OUTCOME_RESTART`
- **AND** Entry Point Handler may re-initiate card poll

#### Scenario: Error condition
- **WHEN** an unrecoverable error occurs (e.g., crypto operation failure)
- **THEN** outcome code is `OUTCOME_ERROR`
- **AND** transaction terminates immediately

### Requirement: Platform Abstraction
Platform abstraction SHALL be achieved via hooks with no OS dependencies.

#### Scenario: POS parameter read via hook
- **WHEN** the orchestrator needs terminal currency code (9F1A)
- **THEN** it calls `param_read(0x9F1A, buf, &len)`
- **AND** the actual implementation may read from flash, NV storage, or runtime config

#### Scenario: ICCDB update after successful transaction
- **WHEN** a transaction completes with outcome APPROVE
- **THEN** `iccdb_write(card_hash, FIELD_HF_COUNTER, counter_bytes, 2)` is called
- **AND** `iccdb_write(card_hash, FIELD_ONLINE_COUNTER, online_bytes, 2)` is called

## Kernel-Specific Variations

| Aspect | K3 (Debit/Credit) | K5 (qVISA) | K7 (Token) |
|--------|-------------------|------------|------------|
| CVM Strategy | Offline PIN or No-CVM based on amount limits | Crypto CVM only (amount check, no PIN) | Token-specific CVM rules |
| TDOL | [9F16, 9F02, 9F36, 9F03, 5F2A, 9F66] | [9F02, 5F2A] | Token tags + 9F66 |
| Risk Management | Full TRM + CRM + VEL + SDS | Simplified (no CRM, no VEL) | SDS focus |
| Auth Preference | SDA or ODA | ODA preferred | SDA or ODA |
| Cryptogram Type | ARQC | CAC (Card Auth Code) | Token cryptogram |

## Constraints
- All kernel logic is driven by data dictionaries and plugins — no hard-coded per-kernel branches in orchestrator
- Zero external dependencies
- Compiles under C99 standard
