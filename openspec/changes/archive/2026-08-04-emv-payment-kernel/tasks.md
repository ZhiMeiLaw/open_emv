# Tasks: EMV Contactless Payment Kernel

## Phase 1: Foundation — Types, Warehouse, Utilities

- [x] **1.1** Define core type headers (`include/emv_kernel/types.h`)
  - Tag types, tag sources, tag data types enums
  - `tlv_entry_t`, `tx_warehouse_t` struct definitions
  - `kernel_id_t`, `outcome_code_t`, `cvm_result_t`, `risk_result_t` enums
  - Platform-independent integer helpers (big-endian, BCD encode/decode)

- [x] **1.2** Implement TLV Data Warehouse (`src/core/warehouse.c`)
  - `tlv_warehouse_init()` — reset pool and count
  - `tlv_alloc()` — bump allocator from pool, returns ptr or NULL on OOM
  - `tlv_store_set()` / `tlv_store_set_indexed()` — lookup or insert entry
  - `tlv_store_get()` / `tlv_store_get_indexed()` — lookup by tag
  - `tlv_store_delete()` — remove entry
  - `tlv_warehouse_clear()` — full reset

- [x] **1.3** Implement TLV serialization/deserialization (`src/utils/tlv_encode.c`)
  - BER-TLV tag encoding/decoding (1/2/3/4-byte tags)
  - `tlv_dump_raw()` — serialize all entries to raw bytes
  - `tlv_dump_ordered()` — serialize in specific tag order
  - `tlv_parse_raw()` — parse incoming TLV into warehouse
  - BCD numeric encode/decode helpers

- [x] **1.4** Implement bitmap utilities (`src/utils/bitmap.c`)
  - Bitmap set/check/clear/get_bit helpers
  - AIP bit parser (Book A §6.2)
  - TVR field extractor
  - Terminal Qualifiers (9F66) parser

- [x] **1.5** Write unit tests for warehouse, TLV encode/decode, bitmap

## Phase 2: Plugin Interfaces & Registry

- [x] **2.1** Define plugin interface headers (`src/plugin/*.h` → `emv_kernel/kernel_interface.h`)
  - `cvm_interface.h` — CVM plugin struct with evaluate + get_method
  - `risk_interface.h` — Risk plugin struct with check + build_tc_risk_data
  - `crypto_interface.h` — Crypto driver struct with RSA/DES/TDES/CMAC

- [x] **2.2** Define UI driver interface (`include/emv_kernel/ui_driver.h`)
  - PIN prompt callback
  - Display message callback
  - Amount entry callback

- [x] **2.3** Implement Kernel Registry (`src/core/kernel_registry.c`)
  - `kernel_register()` — add kernel config to table
  - `kernel_get_config()` — lookup by kernel_id
  - `kernel_run()` — dispatch to correct plugin set

- [x] **2.4** Implement Platform Hooks interface (`include/emv_kernel/platform.h` + `src/core/platform.c`)
  - `param_read(tag, buf, len)` declaration
  - `param_write(tag, value, len)` declaration
  - `iccdb_read(card_hash, field, buf, len)` declaration
  - `iccdb_write(card_hash, field, value, len)` declaration
  - Driver registration (crypto, acq interface)

## Phase 3: Data Dictionary System

- [x] **3.1** Implement dictionary validator (`src/core/dict_validate.c`)
  - `tlv_validate_dict(dict, wh)` — check all mandatory tags present
  - `tlv_check_type_compatibility(tag, type, len)` — validate size constraints
  - Dictionary error reporting

- [x] **3.2** Create Kernel 3 data dictionary (`src/dict/kernel3_dict.c`)
- [x] **3.3** Create Kernel 5 data dictionary (`src/dict/kernel5_dict.c`)
- [x] **3.4** Create Kernel 7 skeleton dictionary (`src/dict/kernel7_dict.c`)

## Phase 4: Entry Point Handler (Book B)

- [x] **4.1** Implement ATS parsing and PPS (`src/core/entry_point.c`)
- [x] **4.2** Implement ERP exchange (`src/core/entry_point.c`)
- [x] **4.3** Implement Application Select flow (`src/core/entry_point.c`)
- [x] **4.4** Implement Card Authentication: SDA (`src/core/entry_point.c`)
- [x] **4.5** Implement Card Authentication: ODA (`src/core/entry_point.c`)
- [x] **4.6** Implement GPO processing (`src/core/entry_point.c`)

## Phase 5: Kernel Orchestrator

- [x] **5.1** Implement generic orchestration loop (`src/core/orchestrator.c`)
- [x] **5.2** Implement outcome determination logic
- [x] **5.3** Implement TC (Terminal Conduction) building
- [x] **5.4** Implement ARPC (Acquirer Release Process Code) path

## Phase 6: Reference Kernel Implementations

- [x] **6.1** Implement K3 reference CVM plugin (`examples/ref_k3/kernel3_cvm.c`)
- [x] **6.2** Implement K3 reference Risk plugin (`examples/ref_k3/kernel3_risk.c`)
- [x] **6.3** Implement K3 full processing flow (`examples/ref_k3/kernel3_process.c`)
- [x] **6.4** Implement K5 reference CVM plugin (`examples/ref_k5/kernel5_cvm.c`)
- [x] **6.5** Implement K5 reference Risk plugin (`examples/ref_k5/kernel5_risk.c`)

## Phase 7: Full Integration Reference (K3 end-to-end)

- [x] **7.1** Reference crypto driver with detailed integration comments (`examples/ref_k3/k3_ref_crypto.c`)
- [x] **7.2** Reference platform hooks implementation (param store, ICCDB, PRNG, time) (`examples/ref_k3/k3_ref_platform.c`)
- [x] **7.3** Complete K3 transaction flow with every step documented (`examples/ref_k3/k3_ref_transaction.c`)
- [x] **7.4** Mock IC Reader Provider for hardware-free testing (`examples/ref_k3/k3_ref_icr_mock.c`)

---

## Execution Order

```
Phase 1 (Foundation)    →  Core plumbing, needed by everything
Phase 2 (Plugin Intf)   →  Interfaces + registry, needed before phases 3-5
Phase 3 (Dictionaries)  →  Per-kernel tag definitions
Phase 4 (Entry Point)   →  Book B flow, runs before kernel execution
Phase 5 (Orchestrator)  →  Ties entry point + plugins together
Phase 6 (Ref Impl)      →  Concrete K3/K5 implementations as examples
```

Phases within a phase can run in parallel where dependencies allow (e.g., 1.1 and 1.5 are independent).
