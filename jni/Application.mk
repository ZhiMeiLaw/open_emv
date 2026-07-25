# EMV Contactless Payment Kernel — NDK Application Configuration
# Defines build targets and platform settings for ndk-build

APP_STL := c++_static
APP_CPPFLAGS := -std=c++11 -fexceptions -frtti

# Build all ABIs by default; override with: APP_ABI=arm64-v8a
APP_ABI := arm64-v8a armeabi-v7a x86 x86_64

# Minimum SDK — EMV spec requires API 21+ (Android 5.0)
APP_PLATFORM := android-21
