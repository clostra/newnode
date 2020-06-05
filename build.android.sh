#!/bin/bash
set -euxo pipefail


function build_android {
    HOST_OS=$(uname -s)
    HOST_ARCH=$(uname -m)
    HOST_TAG=$(echo "$HOST_OS-$HOST_ARCH" | tr '[:upper:]' '[:lower:]')
    TRIPLE=$NDK_TRIPLE

    export TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/$HOST_TAG
    export AR=$TOOLCHAIN/bin/$NDK_TRIPLE-ar
    export AS=$TOOLCHAIN/bin/$NDK_TRIPLE-as
    export CC=$TOOLCHAIN/bin/$NDK_CLANG_TRIPLE-clang
    export CXX=$TOOLCHAIN/bin/$NDK_CLANG_TRIPLE-clang++
    export LD=$TOOLCHAIN/bin/$NDK_TRIPLE-ld
    export OBJDUMP=$TOOLCHAIN/bin/$NDK_TRIPLE-objdump
    export RANLIB=$TOOLCHAIN/bin/$NDK_TRIPLE-ranlib
    export STRIP=$TOOLCHAIN/bin/$NDK_TRIPLE-strip

    cd Libevent
    if [ ! -f $TRIPLE/lib/libevent.a ]; then
        ./autogen.sh
        CFLAGS="-fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all" ./configure --disable-shared --disable-openssl --with-pic $LIBEVENT_CONFIG --host=$TRIPLE --prefix=$(pwd)/$TRIPLE
        make clean
        make -j3
        make install
    fi
    cd ..
    LIBEVENT_CFLAGS=-ILibevent/$TRIPLE/include
    LIBEVENT="Libevent/$TRIPLE/lib/libevent.a Libevent/$TRIPLE/lib/libevent_pthreads.a"


    export ANDROID_NDK_HOME=$NDK
    cd libsodium
    test -f configure || ./autogen.sh
    test -f libsodium-android-$CPU_ARCH/lib/libsodium.a || ./dist-build/android-$SODIUM_SCRIPT.sh
    cd ..
    LIBSODIUM_CFLAGS=-Ilibsodium/libsodium-android-$CPU_ARCH/include
    LIBSODIUM=libsodium/libsodium-android-$CPU_ARCH/lib/libsodium.a


    cd libutp
    if [ ! -f $TRIPLE/libutp.a ]; then
        make clean
        OPT=-O0 CPPFLAGS="-fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all" make -j3 libutp.a
        mkdir $TRIPLE
        mv libutp.a $TRIPLE
    fi
    cd ..
    LIBUTP_CFLAGS=-Ilibutp
    LIBUTP=libutp/$TRIPLE/libutp.a


    cd blocksruntime
    if [ ! -f $TRIPLE/libBlocksRuntime.a ]; then
        ./buildlib
        mkdir $TRIPLE
        mv libBlocksRuntime.a $TRIPLE
    fi
    cd ..
    LIBBLOCKSRUNTIME_CFLAGS=-Iblocksruntime/BlocksRuntime
    LIBBLOCKSRUNTIME=blocksruntime/$TRIPLE/libBlocksRuntime.a


    cd libunwind-ndk
    if [ ! -f $TRIPLE/libunwind.a ]; then
        mkdir $TRIPLE
        cd $TRIPLE
        cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
            -DANDROID_NDK=$NDK -DANDROID_ABI=$ABI -DANDROID_PLATFORM=android-$NDK_API ../cmake
        make
        cd ..
    fi
    cd ..
    LIBUNWIND_CFLAGS="-Ilibunwind-ndk/include -Ilibunwind-ndk/include/tdep -Ilibunwind-ndk/src"
    LIBUNWIND="libunwind-ndk/$TRIPLE/libunwind.a libunwind-ndk/$TRIPLE/lzma/liblzma.a"


    FLAGS="-g -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Werror=shadow -Wfatal-errors \
      -fPIC -fblocks -fdata-sections -ffunction-sections \
      -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
      -D__FAVOR_BSD -D_BSD_SOURCE -D_DEFAULT_SOURCE -DANDROID"
    #-fvisibility=hidden -fvisibility-inlines-hidden -flto \
    if [ ! -z ${DEBUG+x} ]; then
        FLAGS="$FLAGS -O0 -DDEBUG=1"
    else
        FLAGS="$FLAGS -O0"
    fi

    CFLAGS="$FLAGS -std=gnu11"

    rm *.o || true
    $CC $CFLAGS -c dht/dht.c -o dht_dht.o
    for file in android.c bev_splice.c base64.c client.c dht.c http.c log.c lsd.c \
                icmp_handler.c hash_table.c merkle_tree.c network.c obfoo.c sha1.c thread.c timer.c utp_bufferevent.c \
                bugsnag/bugsnag_ndk.c \
                bugsnag/bugsnag_ndk_report.c \
                bugsnag/bugsnag_unwind.c \
                bugsnag/deps/bugsnag/report.c \
                bugsnag/deps/bugsnag/serialize.c \
                bugsnag/deps/deps/parson/parson.c; do
        $CC $CFLAGS $LIBUTP_CFLAGS $LIBEVENT_CFLAGS $LIBSODIUM_CFLAGS $LIBBLOCKSRUNTIME_CFLAGS $LIBUNWIND_CFLAGS -c $file
    done
    #$CC $CFLAGS -shared -Wl,--version-script=android_export_list -o libnewnode.so *.o -lm -llog $LIBUTP $LIBEVENT $LIBSODIUM $LIBBLOCKSRUNTIME $LIBUNWIND
    $CC $CFLAGS -shared -o libnewnode.so *.o -lm -llog $LIBUTP $LIBEVENT $LIBSODIUM $LIBBLOCKSRUNTIME $LIBUNWIND
    # -fuse-ld=gold
    OUT=android/src/main/jniLibs/$ABI
    test -d $OUT || mkdir -p $OUT
    mv libnewnode.so $OUT
    $OBJDUMP --disassemble --demangle --line-numbers --section=.text $OUT/libnewnode.so > $OUT/mapping.txt
    ls -ld $OUT/*
}

NDK_API=16
ARCH=arm
ABI=armeabi-v7a
CPU_ARCH=armv7-a
NDK_TRIPLE=arm-linux-androideabi
NDK_CLANG_TRIPLE=armv7a-linux-androideabi$NDK_API
SODIUM_SCRIPT=$CPU_ARCH
# large file support doesn't work for sendfile until API 21
# https://github.com/android-ndk/ndk/issues/536#issuecomment-333197557
LIBEVENT_CONFIG=--disable-largefile
build_android
LIBEVENT_CONFIG=

NDK_API=21
ARCH=arm64
ABI=arm64-v8a
CPU_ARCH=armv8-a
NDK_TRIPLE=aarch64-linux-android
NDK_CLANG_TRIPLE=$NDK_TRIPLE$NDK_API
SODIUM_SCRIPT=$CPU_ARCH
build_android

NDK_API=21
ARCH=x86
ABI=x86
CPU_ARCH=i686
NDK_TRIPLE=i686-linux-android
NDK_CLANG_TRIPLE=$NDK_TRIPLE$NDK_API
SODIUM_SCRIPT=$ABI
build_android

NDK_API=21
ARCH=x86_64
ABI=x86_64
CPU_ARCH=westmere
NDK_TRIPLE=x86_64-linux-android
NDK_CLANG_TRIPLE=$NDK_TRIPLE$NDK_API
SODIUM_SCRIPT=$ABI
build_android
