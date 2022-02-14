#!/bin/bash
set -x

rm -rf libevent/native
rm -rf libevent/*linux-android*
rm -rf libevent/*apple*
rm -rf blocksruntime/*linux-android*
rm -rf libutp/libutp.a
rm -rf libutp/*linux-android*
rm -rf libutp/*apple*
rm -rf android-toolchain*
cd libsodium && git clean -fxd
cd ..
#rm libsodium/configure
rm -rf libsodium/native
rm -rf libsodium/libsodium-ios*
rm -rf libsodium/libsodium-apple*
rm -rf libsodium/libsodium-android*
rm -rf libsodium/android-toolchain*
rm -rf bugsnag-cocoa/iOS/*apple*
rm -rf bugsnag-cocoa/*apple*
rm -rf android/src/main/jniLibs
rm -rf libunwind-ndk/*linux-android*
rm *.o || true
cd android
rm -rf build
gradle wrapper
./gradlew clean
cd examples/WebViewSample
rm -rf build
gradle wrapper
./gradlew clean
cd ../..
cd vpn
rm -rf build
gradle wrapper
./gradlew clean
