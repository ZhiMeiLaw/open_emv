# EMV Contactless Payment Kernel — Build Guide

## Prerequisites

### Host build (local test run)
- **A C99 compiler**: `gcc`, `clang`, or `tcc`
- **GNU Make** (3.81+)

### Android build (embedded target)
- **Android NDK** r21+ — tested with r27d at `/c/tools/Dev/android-ndk-r27d`
- Pure `ndk-build`, no CMake needed

---

## Quick Start

### Build and run all tests locally

```bash
cd /path/to/open_emv

# Linux / macOS
make test

# Windows (MinGW / MSYS2 / WSL)
make test
```

This builds and runs:
- **6 unit tests**: warehouse, tlv_encode, bitmap, ctq_parse, sha1, risk_plugin_k7
- **3 integration tests**: k3_e2e, k5_e2e, k7_e2e
- **3 reference examples**: ref_k3, ref_k5, ref_k7

### Build a single test

```bash
make test_k3_e2e   # build + run K3 end-to-end test
make test_warehouse # build + run warehouse unit test
make ref_k5         # build + run K5 reference transaction
```

### Run tests separately

```bash
make unit          # unit tests only
make integration   # integration tests only
make ref           # reference examples only
```

### Clean build artifacts

```bash
make clean
```

---

## Cross-compile for Android (all ABIs)

```bash
cd /path/to/open_emv
/c/tools/Dev/android-ndk-r27d/ndk-build -j4
```

Output:
- `obj/local/arm64-v8a/libemv_kernel.so` — ARM64 shared library
- `obj/local/armeabi-v7a/libemv_kernel.so` — ARM32 shared library
- `obj/local/x86_64/test_warehouse` — x86_64 test executable
- `obj/local/arm64-v8a/test_warehouse` — ARM64 test executable

### Target specific ABI only

```bash
/c/tools/Dev/android-ndk-r27d/ndk-build NDK_APP_ABI=arm64-v8a -j4
```

### Run tests on Android device/emulator

```bash
# 1. Push test binary and shared library
adb push obj/local/arm64-v8a/test_warehouse /data/local/tmp/
adb push obj/local/arm64-v8a/libemv_kernel.so /data/local/tmp/

# 2. Set library path and run
adb shell "export LD_LIBRARY_PATH=/data/local/tmp && cd /data/local/tmp && ./test_warehouse"
```

---

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

---

## Makefile Targets Reference

| Target | Description |
|--------|-------------|
| `make` / `make all` | Build and run all tests + examples |
| `make test` | Build and run all tests |
| `make unit` | Build and run unit tests only |
| `make integration` | Build and run integration tests only |
| `make ref` | Build and run all reference examples |
| `make ref-k3` | Build and run K3 reference transaction |
| `make ref-k5` | Build and run K5 reference transaction |
| `make ref-k7` | Build and run K7 reference transaction |
| `make test_<name>` | Build and run a single test |
| `make clean` | Remove `build/` directory |
| `make CC=clang test` | Use clang instead of gcc |

---

## Platform Notes

### Windows
- Requires **MinGW-w64**, **MSYS2**, or **WSL** for native `make` + `gcc`
- Set `CC=clang` to use an alternate compiler if available
- The Makefile auto-detects Windows and adds `-D_WIN32`

### Linux
- Works with `gcc` (4.9+) or `clang` (3.5+)
- No special flags needed

### macOS
- Works with `clang` (Xcode CLT) or `gcc` via Homebrew
- No special flags needed

---

## Architecture

```
open_emv/
├── Makefile              ← Host build (POSIX/Windows)
├── jni/
│   └── Android.mk        ← Android NDK build
├── src/                  ← Kernel source
├── include/emv_kernel/   ← Public headers
├── tests/
│   ├── host/
│   │   └── host_platform.c   ← Platform stubs for host build
│   ├── unit/               ← 6 unit tests
│   └── integration/        ← 3 e2e tests
└── examples/ref_k{3,5,7}/ ← Reference implementations
```
