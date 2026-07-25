# Spec: Platform Abstraction Layer (HAL)

## Purpose
Define the abstraction interfaces that separate kernel framework logic from hardware-specific and platform-specific implementations. Enables porting to any MCU, SE, TEE, or host OS.

## ADDED Requirements

### Requirement: IC Reader Provider
The system SHALL define an interface for communicating with NFC/hardware that abstracts ISO-DEP protocol exchange.

#### Scenario: Initialize RF subsystem
- **WHEN** `icr_init()` is called at the start of a transaction session
- **THEN** the NFC controller and RF field are initialized
- **AND** returns 0 on success, non-zero on failure

#### Scenario: Start EMV field to power card
- **WHEN** `icr_start_field()` is called before polling
- **THEN** the terminal begins emitting the 13.56 MHz field
- **AND** returns 0 on success

#### Scenario: Poll for card presence with timeout
- **WHEN** `icr_poll_card(5000)` is called (5 second timeout)
- **THEN** if a card is detected within timeout, it returns 0 and sets the ICC ID
- **AND** if no card is present after timeout, it returns -ETIMEDOUT

#### Scenario: Transmit APDU and receive response
- **WHEN** `icr_transmit_recv(in_buf, in_len, out_buf, &out_len)` is called
- **THEN** the system sends the raw data to the card via ISO-DEP
- **AND** receives the response into `out_buf`, updating `out_len`
- **AND** returns 0 on success, or SW bytes if card returned error status

#### Scenario: Deactivate field after card removal
- **WHEN** `icr_deactivate()` is called
- **THEN** the RF field is stopped
- **AND** any ongoing transmission is aborted cleanly

### Requirement: Platform Parameter Interface
POS terminal parameters SHALL be accessed via tag-based read/write hooks.

#### Scenario: Read terminal country code
- **WHEN** `param_read(0x9F1A, buf, &len)` is called
- **THEN** the system retrieves the terminal country code (e.g., 608 for China)
- **AND** stores it as a 2-byte BCD value in `buf`
- **AND** returns 0 on success

#### Scenario: Read terminal capabilities (TA tags)
- **WHEN** `param_read(0xDF84, buf, &len)` is called
- **THEN** the system retrieves the terminal capabilities bitmap
- **AND** returns 0 on success, -ENOENT if not configured

#### Scenario: Write outcome parameter
- **WHEN** `param_write(0x9F66, tc_bytes, 4)` is called during TC building
- **THEN** the system stores terminal qualifiers for TC construction
- **AND** returns 0 on success

### Requirement: ICCDB Persistence Interface
Intrinsic Card Data Base SHALL be managed via hash-keyed read/write hooks.

#### Scenario: Read card state by hash
- **WHEN** `iccdb_read(card_hash, FIELD_HF_COUNTER, buf, &len)` is called
- **THEN** the system looks up the card entry by hash
- **AND** retrieves the HF counter value
- **AND** returns 0 on success, -ENOENT if card not found

#### Scenario: Write card state after transaction
- **WHEN** `iccdb_write(card_hash, FIELD_ONLINE_COUNTER, counter, 2)` is called
- **THEN** the system updates the online transaction counter for this card
- **AND** persists the change to the underlying storage backend

#### Scenario: Delete card state on reset
- **WHEN** `iccdb_delete(card_hash)` is called
- **THEN** the card entry is removed from persistent storage
- **AND** subsequent `iccdb_read` returns -ENOENT

### Requirement: Crypto Driver Interface
Cryptographic operations SHALL be provided by a pluggable crypto driver.

#### Scenario: RSA PKP verify (SDA)
- **WHEN** `crypto->rsa_pkpad_verify(cert_der, cert_len, ddic, ddic_len, data, data_len)` is called
- **THEN** the system verifies the ACM(A) certificate chain using RSA-PKP padding
- **AND** computes SHA-1/SHA-256 hash of `data` and compares with DDIC
- **AND** returns 0 on match, -1 on mismatch or crypto error

#### Scenario: DES decrypt for ODA Dynamic Number Layer
- **WHEN** `crypto->des_decrypt(key, key_len, ic_data, ic_data_len, out, &out_len)` is called
- **THEN** the system performs DES decryption using the ICA symmetric key
- **AND** unpad the result to extract the dynamic number
- **AND** return 0 on success

#### Scenario: TDES-MAC verify (ICC CRT check)
- **WHEN** `crypto->tdes_mac_verify(key, key_len, data, data_len, expected_mac, mac_len)` is called
- **THEN** the system computes TDES-CMAC over `data` using `key`
- **AND** compares the result byte-by-byte with `expected_mac`
- **AND** returns 0 on match, -1 on mismatch

#### Scenario: Generate cryptogram (ARQC/CAC)
- **WHEN** `crypto->generate_cryptogram(CRYPTO_DES, key, key_len, dol_data, dol_len, arqc, &arqc_len)` is called
- **THEN** the system computes the application cryptogram (TDES-MAC)
- **AND** writes the 8-byte result to `arqc`
- **AND** sets `arqc_len` to 8

#### Scenario: Extract keys from ICA certificate
- **WHEN** `crypto->ica_key_extract(cert_der, cert_len, sym_key, &sym_key_len, pub_key, &pub_key_len)` is called
- **THEN** the system parses the DER-encoded ICA certificate
- **AND** extracts both the symmetric key (for DES/TDES operations) and public key (for RSA verification)
- **AND** returns key sizes via output parameters

### Requirement: PRNG Interface
Cryptographically secure random numbers SHALL be provided via a platform hook.

#### Scenario: Generate unpredictable number for CDOL1
- **WHEN** `platform_prng(buf, 4)` is called before GPO
- **THEN** the system fills `buf` with 4 bytes of unpredictable random data
- **AND** meets ISO 14443-4 unpredictability number requirements
- **AND** returns 0 on success, non-zero on failure (no entropy available)

### Requirement: Time Interface
System time SHALL be provided via a platform hook.

#### Scenario: Get current timestamp
- **WHEN** `platform_time_get()` is called
- **THEN** the system returns the current time in milliseconds since an epoch
- **AND** the value is monotonically increasing
- **AND** provides at least millisecond resolution

### Requirement: UI Driver Interface
User interaction SHALL be abstracted through an optional UI driver.

#### Scenario: Prompt for PIN during K3 Offline CVM
- **WHEN** `ui->prompt_pin(pan, pan_len, pin_block, &pin_block_len, key_index)` is called
- **THEN** the system displays a PIN prompt to the cardholder
- **AND** collects the entered PIN, encrypts it into a PIN block
- **AND** returns 0 on successful entry, -1 on timeout/cancel, -2 on wrong PIN

#### Scenario: Display transaction status message
- **WHEN** `ui->display_message("Please wait...")` is called
- **THEN** the message is shown on the terminal display
- **AND** the function returns immediately (non-blocking)

## Constraints
- No OS API calls (no POSIX, no Windows APIs, no stdio, no file I/O)
- All functions return int status codes: 0 = success, negative = error
- No dynamic memory allocation — all caller-provided buffers must be pre-allocated
- Thread-unsafe by default (single-threaded embedded assumption)
- No floating-point operations
