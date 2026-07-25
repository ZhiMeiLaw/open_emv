# EMV Contactless Payment Kernel — Build Guide

## Prerequisites
- **Android NDK** r21+ — you have r27d at: `/c/tools/Dev/android-ndk-r27d`
- No CMake needed — pure `ndk-build`

## Quick Start

### Cross-compile for all ABIs
```bash
cd c:\work\open_emv
/c/tools/Dev/android-ndk-r27d/ndk-build -j4
```

Output:
- `obj/local/arm64-v8a/libemv_kernel.so` — ARM64 shared library
- `obj/local/armeabi-v7a/libemv_kernel.so` — ARM32 shared library
- `obj/local/x86_64/test_warehouse` — Test executables (x86_64 ABI)
- `obj/local/arm64-v8a/test_warehouse` — Host-like test on target device

### Target specific ABI only
```bash
/c/tools/Dev/android-ndk-r27d/ndk-build NDK_APP_ABI=arm64-v8a -j4
```

### Run tests on Android device/emulator
```bash
# 1. Push to device
adb push obj/local/arm64-v8a/test_warehouse /data/local/tmp/
adb push obj/local/arm64-v8a/libemv_kernel.so /data/local/tmp/

# 2. Set LD_LIBRARY_PATH and run
adb shell "export LD_LIBRARY_PATH=/data/local/tmp && cd /data/local/tmp && ./test_warehouse"
```

## Integration into Android Studio Project

Add this as a module in your app's `build.gradle`:
```gradle
android {
    externalNativeBuild {
        ndkBuild {
            path = file("path/to/open_emv/jni/Android.mk")
        }
    }
}
// or use CMakeLists.txt if you prefer cmake
```

## Building with NDK standalone toolchain (manual compile)

```bash
# Setup standalone toolchain
$c/tools/Dev/android-ndk-r27d/build/tools/make_standalone_toolchain.py \
    --api 21 --arch arm64 --install-dir /tmp/emv-toolchain

# Compile
/tmp/emv-toolchain/bin/aarch64-linux-android21-clang \
    -I include \
    -std=c99 -Wall -Wextra \
    -c src/core/warehouse.c -o obj/warehouse.o \
    ...
# Link
ar rcs libemv_kernel.a obj/*.o
```
