# EMV Contactless Payment Kernel
# Android NDK build file — compiles for arm64-v8a / armeabi-v7a / x86 / x86_64

LOCAL_PATH := $(call my-dir)

# Base path — Android.mk lives in jni/, source tree is one level up
ROOT_PATH := $(LOCAL_PATH)/..

# ====================================================================
# Core shared library (default output: libemv_kernel.so)
# ====================================================================
include $(CLEAR_VARS)

LOCAL_MODULE    := emv_kernel

LOCAL_SRC_FILES := \
    $(ROOT_PATH)/src/core/warehouse.c \
    $(ROOT_PATH)/src/core/kernel_registry.c \
    $(ROOT_PATH)/src/core/platform.c \
    $(ROOT_PATH)/src/core/dict_validate.c \
    $(ROOT_PATH)/src/core/entry_point.c \
    $(ROOT_PATH)/src/core/orchestrator.c \
    $(ROOT_PATH)/src/core/kernel_core.c \
    $(ROOT_PATH)/src/utils/tlv_encode.c \
    $(ROOT_PATH)/src/utils/bitmap.c \
    $(ROOT_PATH)/src/utils/apdu_tlv_parser.c \
    $(ROOT_PATH)/src/dict/kernel3_dict.c \
    $(ROOT_PATH)/src/dict/kernel5_dict.c \
    $(ROOT_PATH)/src/dict/kernel7_dict.c \
    $(ROOT_PATH)/src/plugin/crypto_driver_ref.c \
    $(ROOT_PATH)/src/plugin/cvm_plugin_kernel3.c \
    $(ROOT_PATH)/src/plugin/cvm_plugin_kernel5.c \
    $(ROOT_PATH)/src/plugin/cvm_plugin_kernel7.c \
    $(ROOT_PATH)/src/plugin/risk_plugin_kernel3.c \
    $(ROOT_PATH)/src/plugin/risk_plugin_kernel5.c \
    $(ROOT_PATH)/src/plugin/risk_plugin_kernel7.c \
    $(ROOT_PATH)/src/plugin/kernel_ops_kernel3.c \
    $(ROOT_PATH)/src/plugin/kernel_ops_kernel5.c \
    $(ROOT_PATH)/src/plugin/kernel_ops_kernel7.c

LOCAL_C_INCLUDES += $(ROOT_PATH)/include

LOCAL_CFLAGS += -std=c99 -pedantic -Wall -Wextra -Werror=return-type
LOCAL_LDLIBS :=

include $(BUILD_SHARED_LIBRARY)

# ====================================================================
# Static library (for test executables and linking into other shared libs)
# ====================================================================
include $(CLEAR_VARS)

LOCAL_MODULE    := emv_kernel_static
LOCAL_SRC_FILES := \
    $(ROOT_PATH)/src/core/warehouse.c \
    $(ROOT_PATH)/src/core/kernel_registry.c \
    $(ROOT_PATH)/src/core/platform.c \
    $(ROOT_PATH)/src/core/dict_validate.c \
    $(ROOT_PATH)/src/core/entry_point.c \
    $(ROOT_PATH)/src/core/orchestrator.c \
    $(ROOT_PATH)/src/core/kernel_core.c \
    $(ROOT_PATH)/src/utils/tlv_encode.c \
    $(ROOT_PATH)/src/utils/bitmap.c \
    $(ROOT_PATH)/src/utils/apdu_tlv_parser.c \
    $(ROOT_PATH)/src/dict/kernel3_dict.c \
    $(ROOT_PATH)/src/dict/kernel5_dict.c \
    $(ROOT_PATH)/src/dict/kernel7_dict.c \
    $(ROOT_PATH)/src/plugin/crypto_driver_ref.c \
    $(ROOT_PATH)/src/plugin/cvm_plugin_kernel3.c \
    $(ROOT_PATH)/src/plugin/cvm_plugin_kernel5.c \
    $(ROOT_PATH)/src/plugin/cvm_plugin_kernel7.c \
    $(ROOT_PATH)/src/plugin/risk_plugin_kernel3.c \
    $(ROOT_PATH)/src/plugin/risk_plugin_kernel5.c \
    $(ROOT_PATH)/src/plugin/risk_plugin_kernel7.c \
    $(ROOT_PATH)/src/plugin/kernel_ops_kernel3.c \
    $(ROOT_PATH)/src/plugin/kernel_ops_kernel5.c \
    $(ROOT_PATH)/src/plugin/kernel_ops_kernel7.c

LOCAL_C_INCLUDES += $(ROOT_PATH)/include
LOCAL_CFLAGS   += -std=c99 -pedantic -Wall -Wextra -Werror=return-type -fPIC

include $(BUILD_STATIC_LIBRARY)

# ====================================================================
# Host test executables (cross-compiled, run on target device)
# ====================================================================
include $(CLEAR_VARS)

LOCAL_MODULE    := test_warehouse
LOCAL_SRC_FILES := $(ROOT_PATH)/tests/unit/test_warehouse.c
LOCAL_C_INCLUDES += $(ROOT_PATH)/include
LOCAL_CFLAGS    += -std=c99 -pedantic -Wall -Wno-unused-parameter -Wno-unused-variable
LOCAL_STATIC_LIBRARIES := emv_kernel_static

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE    := test_tlv_encode
LOCAL_SRC_FILES := $(ROOT_PATH)/tests/unit/test_tlv_encode.c
LOCAL_C_INCLUDES += $(ROOT_PATH)/include
LOCAL_CFLAGS    += -std=c99 -pedantic -Wall -Wno-unused-parameter -Wno-unused-variable
LOCAL_STATIC_LIBRARIES := emv_kernel_static

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE    := test_ctq_parse
LOCAL_SRC_FILES := $(ROOT_PATH)/tests/unit/test_ctq_parse.c $(ROOT_PATH)/src/utils/bitmap.c
LOCAL_C_INCLUDES += $(ROOT_PATH)/include
LOCAL_CFLAGS    += -std=c99 -pedantic -Wall -Wno-unused-parameter -Wno-unused-variable
LOCAL_STATIC_LIBRARIES := emv_kernel_static

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE    := test_sha1
LOCAL_SRC_FILES := $(ROOT_PATH)/tests/unit/test_sha1.c
LOCAL_C_INCLUDES += $(ROOT_PATH)/include
LOCAL_CFLAGS    += -std=c99 -pedantic -Wall -Wno-unused-parameter -Wno-unused-variable

include $(BUILD_EXECUTABLE)

# ====================================================================
# Reference example: K3 full transaction flow
# ====================================================================
include $(CLEAR_VARS)

LOCAL_MODULE    := ref_k3_transaction
LOCAL_SRC_FILES := \
    $(ROOT_PATH)/examples/ref_k3/k3_ref_transaction.c \
    $(ROOT_PATH)/examples/ref_k3/k3_ref_crypto.c \
    $(ROOT_PATH)/examples/ref_k3/k3_ref_platform.c \
    $(ROOT_PATH)/examples/ref_k3/k3_ref_icr_mock.c \
    $(ROOT_PATH)/examples/ref_k3/kernel3_process.c
LOCAL_C_INCLUDES += $(ROOT_PATH)/include
LOCAL_CFLAGS    += -std=c99 -pedantic -Wall -Wno-unused-parameter -Wno-unused-variable
LOCAL_STATIC_LIBRARIES := emv_kernel_static

include $(BUILD_EXECUTABLE)

# ====================================================================
# Reference example: K7 full transaction flow (Token Payment)
# ====================================================================
include $(CLEAR_VARS)

LOCAL_MODULE    := ref_k7_transaction
LOCAL_SRC_FILES := \
    $(ROOT_PATH)/examples/ref_k7/k7_ref_transaction.c \
    $(ROOT_PATH)/examples/ref_k7/k7_ref_platform.c \
    $(ROOT_PATH)/examples/ref_k7/k7_ref_icr_mock.c \
    $(ROOT_PATH)/examples/ref_k7/kernel7_process.c
LOCAL_C_INCLUDES += $(ROOT_PATH)/include
LOCAL_CFLAGS    += -std=c99 -pedantic -Wall -Wno-unused-parameter -Wno-unused-variable
LOCAL_STATIC_LIBRARIES := emv_kernel_static

include $(BUILD_EXECUTABLE)

# ====================================================================
# Test: Kernel 7 Risk Plugin
# ====================================================================
include $(CLEAR_VARS)

LOCAL_MODULE    := test_risk_plugin_k7
LOCAL_SRC_FILES := $(ROOT_PATH)/tests/unit/test_risk_plugin_k7.c $(ROOT_PATH)/src/plugin/risk_plugin_kernel7.c $(ROOT_PATH)/src/core/warehouse.c $(ROOT_PATH)/src/utils/bitmap.c
LOCAL_C_INCLUDES += $(ROOT_PATH)/include
LOCAL_CFLAGS    += -std=c99 -pedantic -Wall -Wno-unused-parameter -Wno-unused-variable
LOCAL_STATIC_LIBRARIES := emv_kernel_static



include $(CLEAR_VARS)

LOCAL_MODULE    := test_k3_e2e
LOCAL_SRC_FILES := $(ROOT_PATH)/tests/integration/test_k3_e2e.c
LOCAL_C_INCLUDES += $(ROOT_PATH)/include
LOCAL_CFLAGS    += -std=c99 -pedantic -Wall -Wno-unused-parameter -Wno-unused-variable
LOCAL_STATIC_LIBRARIES := emv_kernel_static

include $(BUILD_EXECUTABLE)include $(BUILD_EXECUTABLE)
