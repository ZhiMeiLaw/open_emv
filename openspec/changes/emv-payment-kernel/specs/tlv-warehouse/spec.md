# Spec: TLV Data Warehouse

## Purpose
Transaction-scoped, zero-copy storage for all EMV contactless TLV data exchanged during a single payment transaction.

## ADDED Requirements

### Requirement: Flat Pool Zero-Copy Storage
The system SHALL store TLV data in a flat memory pool with zero-copy pointers — all values are `uint8_t*` pointing into the pool region.

#### Scenario: Entry stores a value from source buffer
- **WHEN** `tlv_store_set(wh, 0x5A, pan_indicator, 1)` is called with 1 byte of data
- **THEN** the system allocates 1 byte from the pool, copies the data, and returns the pointer
- **AND** the entry's `value` field points to the allocated pool memory (not the source)

#### Scenario: Warehouse has fixed maximum capacity
- **WHEN** an attempt is made to store a value when the pool is full
- **THEN** `tlv_store_set` returns -1 (OOM error)
- **AND** no data is modified

#### Scenario: Tag lookup returns value by uint32_t key
- **WHEN** `tlv_store_get(wh, 0x9F02, buf, &len)` is called
- **THEN** the system searches all entries for tag `0x9F02`
- **AND** copies up to `len` bytes to `buf`, updates `len` to actual copy size
- **AND** returns 0 on success, -1 if tag not found

### Requirement: Tag Attributes
Each tag SHALL be stored with these attributes:
- `tag`: `uint32_t` EMV tag number (supports 1–4 byte tags)
- `value`: `uint8_t*` pointer into shared pool
- `len`: `uint16_t` value length in bytes

#### Scenario: Supports multi-byte EMV tags
- **WHEN** entry for tag `0x9F66` (2-byte tag) is stored
- **THEN** the uint32_t key correctly represents the tag value `0x00009F66`
- **AND** lookups using either `0x9F66` or `0x00009F66` match the same entry

#### Scenario: Entry structure is zero-copy compatible
- **WHEN** a new `tlv_entry_t` is created via `tlv_store_set`
- **THEN** its `value` field is a pointer into the warehouse's internal `pool[]` array
- **AND** the entry does not own or free the memory independently

### Requirement: Warehouse Operations
The system SHALL provide the following operations:

#### Scenario: Initialize warehouse resets state
- **WHEN** `tlv_warehouse_init(wh, pool_size)` is called on a fresh or cleared warehouse
- **THEN** `pool_used` is set to 0
- **AND** `count` is set to 0
- **AND** all entry slots are zeroed

#### Scenario: Store and retrieve same value
- **WHEN** `tlv_store_set(wh, 0x1A, "abc", 3)` is called
- **AND** then `tlv_store_get(wh, 0x1A, out, &out_len)` is called
- **THEN** `out` contains `"abc"` and `out_len` is 3

#### Scenario: Delete removes an entry
- **WHEN** `tlv_store_delete(wh, 0x5A)` is called
- **THEN** the entry for tag `0x5A` is removed
- **AND** subsequent `tlv_store_get(wh, 0x5A, ...)` returns -1

#### Scenario: Clear resets entire warehouse
- **WHEN** `tlv_warehouse_clear(wh)` is called
- **THEN** all entries are removed
- **AND** `pool_used` resets to 0
- **AND** `count` resets to 0

### Requirement: TLV Serialization
The system SHALL serialize warehouse contents to raw TLV bytes.

#### Scenario: Dump raw serializes all entries as BER-TLV
- **WHEN** `tlv_dump_raw(wh, out, out_len)` is called after storing multiple entries
- **THEN** the output contains valid BER-TLV encoded bytes for each entry
- **AND** entries are serialized in their insertion order
- **AND** the total serialized length does not exceed `out_len`

#### Scenario: Dump ordered serializes in specified tag order
- **WHEN** `tlv_dump_ordered(wh, tag_order, n, out, out_len)` is called
- **THEN** entries are serialized only if they appear in `tag_order[]`
- **AND** the serialization follows the order of `tag_order`
- **AND** entries not in `tag_order` are excluded from output

#### Scenario: Parse raw input into warehouse
- **WHEN** `tlv_parse_raw(in_buf, in_len, wh)` is called with BER-TLV bytes
- **THEN** the system decodes each TLV tag-value pair
- **AND** allocates pool space and populates warehouse entries
- **AND** returns the number of entries parsed, or -1 on parse error

### Requirement: Indexed Storage
The system SHALL support indexed storage for duplicate tags.

#### Scenario: Same tag can be stored with different indices
- **WHEN** `tlv_store_set_indexed(wh, 0x9F34, 0, data_a, len_a)` is called
- **AND** then `tlv_store_set_indexed(wh, 0x9F34, 1, data_b, len_b)` is called
- **THEN** both entries exist and are retrievable by index
- **AND** `tlv_store_get_indexed(wh, 0x9F34, 0, out, &olen)` returns `data_a`

## Constraints
- No heap allocation (`malloc`/`free`) at any point
- All memory is caller-owned (stack or static)
- Thread-unsafe by design (one transaction at a time)
