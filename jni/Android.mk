# EMV Contactless Payment Kernel
# Android NDK build file — compiles for arm64-v8a / armeabi-v7a / x86 / x86_64

LOCAL_PATH := $(call my-dir)

# ====================================================================
# Core shared library (default output: libemv_kernel.so)
# ====================================================================
include $(CLEAR_VARS)

LOCAL_MODULE    := emv_kernel

# All source files — public core + utils + dictionaries + plugins
LOCAL_SRC_FILES := \
    src/core/warehouse.c \
    src/core/kernel_registry.c \
    src/core/platform.c \
    src/core/dict_validate.c \
    src/core/entry_point.c \
    src/core/orchestrator.c \
    src/utils/tlv_encode.c \
    src/utils/bitmap.c \
    src/utils/apdu_tlv_parser.c \
    src/dict/kernel3_dict.c \
    src/dict/kernel5_dict.c \
    src/dict/kernel7_dict.c \
    src/plugin/crypto_driver_ref.c \
    src/plugin/cvm_plugin_kernel3.c \
    src/plugin/cvm_plugin_kernel5.c \
    src/plugin/cvm_plugin_kernel7.c \
    src/plugin/risk_plugin_kernel3.c \
    src/plugin/risk_plugin_kernel5.c

# Public include directory
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include

# Compiler flags — strict C99, no warnings
LOCAL_CFLAGS += -std=c99 -pedantic -Wall -Wextra -Werror=return-type

# Shared library properties
LOCAL_LDLIBS :=

include $(BUILD_SHARED_LIBRARY)

# ====================================================================
# Static library (for static linking into other shared libs or host)
# ====================================================================
include $(CLEAR_VARS)

LOCAL_MODULE    := emv_kernel_static
LOCAL_SRC_FILES := $(LOCAL_SRC_FILES)
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_CFLAGS   += -std=c99 -pedantic -Wall -Wextra -Werror=return-type
LOCAL_CFLAGS   += -fPIC

include $(BUILD_STATIC_LIBRARY)

# ====================================================================
# Host test executables (cross-compilation, run on target device)
# ====================================================================
include $(CLEAR_VARS)

LOCAL_MODULE    := test_warehouse
LOCAL_SRC_FILES := tests/unit/test_warehouse.c
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_CFLAGS    += -std=c99 -pedantic -Wall
LOCAL_STATIC_LIBRARIES := emv_kernel_static

# Remove pedantic errors just for test targets (allow unused params etc.)
LOCAL_CFLAGS += -Wno-unused-parameter -Wno-unused-variable

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE    := test_tlv_encode
LOCAL_SRC_FILES := tests/unit/test_tlv_encode.c
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_CFLAGS    += -std=c99 -pedantic -Wall
LOCAL_STATIC_LIBRARIES := emv_kernel_static
LOCAL_CFLAGS   += -Wno-unused-parameter -Wno-unused-variable

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE    := test_bitmap
LOCAL_SRC_FILES := tests/unit/test_bitmap.c
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_CFLAGS    += -std=c99 -pedantic -Wall
LOCAL_STATIC_LIBRARIES := emv_kernel_static
LOCAL_CFLAGS   += -Wno-unused-parameter -Wno-unused-variable

include $(BUILD_EXECUTABLE)

# ====================================================================
# Reference example: K3 full transaction flow
# ====================================================================
include $(CLEAR_VARS)

LOCAL_MODULE    := ref_k3_transaction
LOCAL_SRC_FILES := \
    examples/ref_k3/k3_ref_transaction.c \
    examples/ref_k3/k3_ref_crypto.c \
    examples/ref_k3/k3_ref_platform.c \
    examples/ref_k3/k3_ref_icr_mock.c
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_CFLAGS    += -std=c99 -pedantic -Wall -Wno-unused-parameter -Wno-unused-variable
LOCAL_STATIC_LIBRARIES := emv_kernel_static

include $(BUILD_EXECUTABLE)
