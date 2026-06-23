#!/bin/sh

set -x
set -e

# Vars
export NDK_PROJECT_PATH=$PWD
export NDK_TARGET=arm-none-linux-android21
export NDK_HOST=arm-linux-androideabi

if [ $(basename $PWD) = build ]; then
    echo Please run this script from liblo main directory:
    echo "   build/android_build.sh"
    exit 1
fi

# Directory containing ndk-build
NDK=$PWD/android-ndk-r21

if ! which ndk-build; then
    if ! [ -d android-ndk-r21 ]; then

        echo "Could not find ndk-build on PATH, or the Android NDK"
        echo "locally, so downloading (~1GB)."
        echo
        echo "  hit Ctrl-C if this is not what you want!"
        echo
        sleep 2
        wget https://dl.google.com/android/repository/android-ndk-r21-linux-x86_64.zip
        if ! [ "$(md5sum android-ndk-r21-linux-x86_64.zip)" = "d2598b112f077f6d1f4d8d79363d6a96  android-ndk-r21-linux-x86_64.zip" ]; then
            echo "Downloaded zip file did not match expected MD5 checksum!"
            exit 1
        fi
        echo "Checksum OK."
        echo "Unzipping NDK.."
        unzip -q android-ndk-r21-linux-x86_64.zip
    fi

    # Ensure ndk-build as well as clang/clang++ are on the PATH.
    # The NDK clang must take precedence.
    export PATH=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH:$NDK
fi

if [ -f configure ]; then
    CONF=./configure
else
    CONF=./autogen.sh
fi

# We must run configure to get liblo's config.h and lo.h.
echo Running configure
$CONF --host $NDK_HOST CC=`which clang` CXX=`which clang++` CFLAGS="-target $NDK_TARGET --sysroot $NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot -nostdinc++ -DANDROID -fdata-sections -ffunction-sections -fstack-protector-strong -funwind-tables -no-canonical-prefixes"

if ! [ -f Application.mk ]; then
  cat >Application.mk <<EOF
APP_ABI := arm64-v8a
APP_PLATFORM := android-21
APP_STL := c++_static
APP_BUILD_SCRIPT := Android.mk
EOF
  echo Wrote Application.mk
fi

if ! [ -f Android.mk ]; then
  cat >Android.mk <<EOF
LOCAL_PATH := \$(call my-dir)
include \$(CLEAR_VARS)
LOCAL_MODULE := liblo
LOCAL_CFLAGS := -DHAVE_CONFIG_H
LOCAL_SRC_FILES := src/address.c src/method.c src/server_thread.c   \\
  src/timetag.c src/blob.c src/pattern_match.c src/subtest.c        \\
  src/version.c src/bundle.c src/send.c src/message.c src/server.c
include \$(BUILD_SHARED_LIBRARY)
EOF
  echo Wrote Android.mk
fi

ndk-build NDK_APPLICATION_MK=./Application.mk V=1
