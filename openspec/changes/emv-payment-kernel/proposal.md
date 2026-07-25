# Change: EMV Contactless Payment Kernel

## Why

Build an open-source, platform-independent EMV Contactless payment kernel core in C. It must support multiple kernel types (K3/K5/K7...), be easily ported to embedded HW through abstraction layers, and handle both SDA and ODA card authentication. This enables terminal manufacturers and SE/TEE vendors to integrate EMV-compliant payment processing without reinventing the protocol stack.

## Scope

### In Scope
- TLV data warehouse (transaction-scoped, zero-copy, flat memory pool)
- IC Reader Provider interface (abstracts ISO-14443 / NFC hardware)
- Platform Hooks interface (param read/write, ICCDB persist, crypto, PRNG, time)
- Kernel dispatch framework (static table + runtime registration)
- Kernel Data Dictionary system (tag type, source, mandatory, encoding)
- Entry Point Handler per Book B (ERP, Select, Card Auth, GPO)
- Card Authentication: SDA and ODA (Book B §6.4)
- CVM Plugin interface (per-kernel CVM strategy)
- Risk Management Plugin interface (TRM, CRM, VEL, SDS)
- Crypto Driver interface (DES/TDES, RSA-PKP, AES-CMAC — user-implemented)
- Kernel skeleton implementations for K3 and K5 as reference

### Out of Scope
- K6, K7, K8 detailed implementations (interface-ready only)
- Token Request Infrastructure (SASP full flow) — kernel context ready
- Hardware-specific crypto acceleration — abstracted via plugin
- POSIX/Windows host test harness — future work
- EMV Contact (Book C Contact Kernel) — contactless only

## Goals
- Zero external dependencies; compiles on any C99 compiler
- Memory-deterministic: all allocation is static/fixed-size per transaction
- Extensible: adding a new kernel = new .c file + register
- Clean separation: core logic vs. HW integration is one plugin boundary away

## What Changes

### New Capabilities
1. **TLV Data Warehouse** — transaction-scoped, zero-copy KV store for EMV tags with flat memory pool
2. **Kernel Framework** — dictionary-driven orchestrator with pluggable CVM, Risk, and Crypto plugins
3. **Platform HAL** — IC Reader Provider, parameter hooks, ICCDB persistence, crypto/UI driver interfaces

### Modifications to Existing
- N/A — this is a new project

### Removals
- N/A
- Not a full terminal application (no UI, no receipt printing)
- Not a certification-ready product (needs EMVCo validation separately)
- Does not implement every Kernel variant to completion in this change
