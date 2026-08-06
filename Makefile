# ====================================================================
# EMV Contactless Payment Kernel — Host Build (POSIX / Windows)
#
# Build on Linux, macOS, or Windows (MinGW / MSYS2 / Cygwin / WSL).
# Requires a C99 compiler: gcc, clang, or tcc.
#
# Targets:
#   make test         — build + run all tests (unit + integration)
#   make unit         — build + run unit tests only
#   make integration  — build + run integration tests only
#   make ref          — build + run all reference examples
#   make ref-k3       — build + run K3 reference transaction
#   make ref-k5       — build + run K5 reference transaction
#   make ref-k7       — build + run K7 reference transaction
#   make clean        — remove build artifacts
#
# Examples:
#   make test            # run everything
#   make unit            # unit tests only
#   make test_k3_e2e     # build and run a single integration test
# ====================================================================

CC      := gcc
CFLAGS  := -std=c99 -pedantic -Wall -Wextra -Wno-unused-parameter \
           -Wno-unused-variable -Iinclude
LDFLAGS :=

ROOT    := $(CURDIR)
SRC     := $(ROOT)/src
INC     := $(ROOT)/include
TEST_H  := $(ROOT)/tests/host
UNIT    := $(ROOT)/tests/unit
INTEG   := $(ROOT)/tests/integration
REF     := $(ROOT)/examples

# ---- Core sources ----
CORE_SRC := \
	$(SRC)/core/warehouse.c \
	$(SRC)/core/kernel_registry.c \
	$(SRC)/core/platform.c \
	$(SRC)/core/dict_validate.c \
	$(SRC)/core/entry_point.c \
	$(SRC)/core/orchestrator.c \
	$(SRC)/core/kernel_core.c

UTIL_SRC := \
	$(SRC)/utils/tlv_encode.c \
	$(SRC)/utils/bitmap.c \
	$(SRC)/utils/apdu_tlv_parser.c

DICT_SRC := \
	$(SRC)/dict/kernel3_dict.c \
	$(SRC)/dict/kernel5_dict.c \
	$(SRC)/dict/kernel7_dict.c

PLUGIN_SRC := \
	$(SRC)/plugin/crypto_driver_ref.c \
	$(SRC)/plugin/cvm_plugin_kernel3.c \
	$(SRC)/plugin/cvm_plugin_kernel5.c \
	$(SRC)/plugin/cvm_plugin_kernel7.c \
	$(SRC)/plugin/risk_plugin_kernel3.c \
	$(SRC)/plugin/risk_plugin_kernel5.c \
	$(SRC)/plugin/risk_plugin_kernel7.c \
	$(SRC)/plugin/kernel_ops_kernel3.c \
	$(SRC)/plugin/kernel_ops_kernel5.c \
	$(SRC)/plugin/kernel_ops_kernel7.c

# ---- Library for integration + lightweight unit tests ----
# Uses host_platform.c (minimal stubs: param_read returns defaults,
# iccdb_read/write/delete return NOTSTORED, prng is deterministic LCG)
HOST_LIB := $(CORE_SRC) $(UTIL_SRC) $(DICT_SRC) $(PLUGIN_SRC) \
            $(TEST_H)/host_platform.c

# ---- Minimal library for lightweight unit tests ----
LIGHT_LIB := $(SRC)/core/warehouse.c \
             $(SRC)/utils/bitmap.c \
             $(TEST_H)/host_platform.c

# ---- Build directory ----
BUILD := build

# ---- Platform detection ----
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  CFLAGS += -D_POSIX_C_SOURCE=200112L
endif
ifeq ($(UNAME_S),Darwin)
  CFLAGS += -D_DARWIN_C_SOURCE
endif
ifeq ($(OS),Windows_NT)
  CFLAGS  += -D_WIN32
  LDFLAGS += -lkernel32 -lwinmm
endif

# ====================================================================
# Phony targets
# ====================================================================
.PHONY: all test unit integration ref ref-k3 ref-k5 ref-k7 clean

all: test

# ---- Main: build + run everything ----
test: unit integration ref

# ---- Unit tests ----
unit: $(BUILD)/test_warehouse $(BUILD)/test_tlv_encode \
      $(BUILD)/test_bitmap $(BUILD)/test_ctq_parse \
      $(BUILD)/test_sha1 $(BUILD)/test_risk_k7 $(BUILD)/test_kernel_boundary
	@echo ""
	@echo "=== Unit Tests ==="
	@failed=0; \
	for t in $(BUILD)/test_warehouse $(BUILD)/test_tlv_encode \
	         $(BUILD)/test_bitmap $(BUILD)/test_ctq_parse \
	         $(BUILD)/test_sha1 $(BUILD)/test_risk_k7 $(BUILD)/test_kernel_boundary; do \
	  if $$t > /dev/null 2>&1; then \
	    echo "  PASS  $$t"; \
	  else \
	    echo "  FAIL  $$t"; failed=1; \
	  fi; \
	done; \
	echo ""; echo "Unit: 7 passed, $$failed failed"; \
	exit $$failed

# ---- Integration tests ----
integration: $(BUILD)/test_k3_e2e $(BUILD)/test_k5_e2e $(BUILD)/test_k7_e2e \
             $(BUILD)/test_iccdb_update $(BUILD)/test_negative_paths \
             $(BUILD)/test_orchestrator_verify
	@echo ""
	@echo "=== Integration Tests ==="
	@failed=0; \
	for t in $(BUILD)/test_k3_e2e $(BUILD)/test_k5_e2e $(BUILD)/test_k7_e2e \
	         $(BUILD)/test_iccdb_update $(BUILD)/test_negative_paths \
	         $(BUILD)/test_orchestrator_verify; do \
	  if $$t > /dev/null 2>&1; then \
	    echo "  PASS  $$t"; \
	  else \
	    echo "  FAIL  $$t"; failed=1; \
	  fi; \
	done; \
	echo ""; echo "Integration: 6 passed, $$failed failed"; \
	exit $$failed

# ---- Reference examples ----
ref: ref-k3 ref-k5 ref-k7

ref-k3: $(BUILD)/ref_k3
	@echo ""
	@echo "=== Reference: K3 Transaction ==="
	$(BUILD)/ref_k3

ref-k5: $(BUILD)/ref_k5
	@echo ""
	@echo "=== Reference: K5 Transaction ==="
	$(BUILD)/ref_k5

ref-k7: $(BUILD)/ref_k7
	@echo ""
	@echo "=== Reference: K7 Transaction ==="
	$(BUILD)/ref_k7

# ====================================================================
# Build rules
# ====================================================================
$(BUILD):
	mkdir -p $(BUILD)

# ---- Lightweight unit tests (core + bitmap only) ----
$(BUILD)/test_warehouse: $(UNIT)/test_warehouse.c $(LIGHT_LIB) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/test_tlv_encode: $(UNIT)/test_tlv_encode.c $(LIGHT_LIB) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/test_bitmap: $(UNIT)/test_bitmap.c $(LIGHT_LIB) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/test_ctq_parse: $(UNIT)/test_ctq_parse.c $(LIGHT_LIB) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ---- test_sha1 is self-contained (inline SHA-1) ----
$(BUILD)/test_sha1: $(UNIT)/test_sha1.c $(TEST_H)/host_platform.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ---- test_risk_k7 needs kernel7 risk plugin ----
$(BUILD)/test_risk_k7: $(UNIT)/test_risk_plugin_k7.c \
                       $(SRC)/plugin/risk_plugin_kernel7.c \
                       $(SRC)/core/warehouse.c \
                       $(SRC)/utils/bitmap.c \
                       $(TEST_H)/host_platform.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/test_kernel_boundary: $(UNIT)/test_kernel_boundary.c $(HOST_LIB) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ---- Integration tests (full kernel library) ----
$(BUILD)/test_k3_e2e: $(INTEG)/test_k3_e2e.c $(HOST_LIB) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/test_k5_e2e: $(INTEG)/test_k5_e2e.c $(HOST_LIB) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/test_k7_e2e: $(INTEG)/test_k7_e2e.c $(HOST_LIB) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/test_iccdb_update: $(INTEG)/test_iccdb_update.c $(HOST_LIB) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/test_negative_paths: $(INTEG)/test_negative_paths.c $(HOST_LIB) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/test_orchestrator_verify: $(INTEG)/test_orchestrator_verify.c $(HOST_LIB) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ---- Reference examples (full kernel library + ref-specific files) ----
$(BUILD)/ref_k3: \
	$(REF)/ref_k3/k3_ref_transaction.c \
	$(REF)/ref_k3/k3_ref_crypto.c \
	$(REF)/ref_k3/k3_ref_platform.c \
	$(REF)/ref_k3/k3_ref_icr_mock.c \
	$(REF)/ref_k3/kernel3_process.c \
	$(CORE_SRC) $(UTIL_SRC) $(DICT_SRC) $(PLUGIN_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/ref_k5: \
	$(REF)/ref_k5/k5_ref_transaction.c \
	$(REF)/ref_k5/k5_ref_crypto.c \
	$(REF)/ref_k5/k5_ref_platform.c \
	$(REF)/ref_k5/k5_ref_icr_mock.c \
	$(REF)/ref_k5/kernel5_process.c \
	$(CORE_SRC) $(UTIL_SRC) $(DICT_SRC) $(PLUGIN_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/ref_k7: \
	$(REF)/ref_k7/k7_ref_transaction.c \
	$(REF)/ref_k7/k7_ref_crypto.c \
	$(REF)/ref_k7/k7_ref_platform.c \
	$(REF)/ref_k7/k7_ref_icr_mock.c \
	$(REF)/ref_k7/kernel7_process.c \
	$(CORE_SRC) $(UTIL_SRC) $(DICT_SRC) $(PLUGIN_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ---- Single test shortcut: make test_k3_e2e ----
test_%: $(BUILD)/test_%
	@echo ""
	@echo "=== Running test_$* ==="
	$(BUILD)/test_$*

# ---- Clean ----
clean:
	rm -rf $(BUILD)
