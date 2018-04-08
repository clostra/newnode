#!/bin/bash
set -e


function build_android {
    TRIPLE=`python -c "import sys; sys.path.append(sys.argv[1]); import make_standalone_toolchain; print(make_standalone_toolchain.get_triple(sys.argv[2]))" $ANDROID_NDK_HOME/build/tools $ARCH`
    TOOLCHAIN="$(pwd)/android-toolchain-$TRIPLE"
    if [ ! -d $TOOLCHAIN ]; then
        $ANDROID_NDK_HOME/build/tools/make_standalone_toolchain.py --force --api=$NDK_API --arch=$ARCH --stl=libc++ --install-dir="$TOOLCHAIN"
    fi
    export PATH="$TOOLCHAIN/bin/":"$TOOLCHAIN/$TRIPLE/bin/":"$PATH"
    export CC=clang
    export CXX=clang++


    cd Libevent
    if [ ! -f $TRIPLE/lib/libevent.a ]; then
        ./autogen.sh
        ./configure --disable-shared --disable-openssl $LIBEVENT_CONFIG --host=$TRIPLE --prefix=$(pwd)/$TRIPLE
        make clean
        make -j3
        make install
    fi
    cd ..
    LIBEVENT_CFLAGS=-ILibevent/$TRIPLE/include
    LIBEVENT="Libevent/$TRIPLE/lib/libevent.a Libevent/$TRIPLE/lib/libevent_pthreads.a"


    cd libsodium
    test -f configure || ./autogen.sh
    test -f libsodium-android-$CPU_ARCH/lib/libsodium.a || ./dist-build/android-$SODIUM_SCRIPT.sh
    cd ..
    LIBSODIUM_CFLAGS=-Ilibsodium/libsodium-android-$CPU_ARCH/include
    LIBSODIUM=libsodium/libsodium-android-$CPU_ARCH/lib/libsodium.a


    if [ "$ABI" = "mips64" ]; then
        ABI_FLAGS="-fintegrated-as"
    fi

    cd libutp
    if [ ! -f $TRIPLE/libutp.a ]; then
        make clean
        CPPFLAGS=$ABI_FLAGS make -j3 libutp.a
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


    FLAGS="-g -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Werror=shadow -Wfatal-errors \
      -fPIC -fblocks -fdata-sections -ffunction-sections \
      -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
      -fvisibility=hidden -fvisibility-inlines-hidden -flto \
      -D__FAVOR_BSD -D_BSD_SOURCE -DANDROID $ABI_FLAGS"
    if [ ! -z "$DEBUG" ]; then
        FLAGS="$FLAGS -O0 -DDEBUG=1"
    else
        FLAGS="$FLAGS -O3"
    fi

    CFLAGS="$FLAGS -std=gnu11"
    CPPFLAGS="$FLAGS -std=c++14"

    rm *.o || true
    clang $CFLAGS -c dht/dht.c -o dht_dht.o
    for file in android.c bev_splice.c base64.c client.c dht.c http.c log.c lsd.c icmp_handler.c hash_table.c network.c obfoo.c sha1.c timer.c utp_bufferevent.c; do
        clang $CFLAGS $LIBUTP_CFLAGS $LIBEVENT_CFLAGS $LIBBTDHT_CFLAGS $LIBSODIUM_CFLAGS $LIBBLOCKSRUNTIME_CFLAGS -c $file
    done
    clang++ $CPPFLAGS -shared -o libnewnode.so *.o -static-libstdc++ -fuse-ld=gold -lm -llog $LIBUTP $LIBBTDHT $LIBEVENT $LIBSODIUM $LIBBLOCKSRUNTIME
    if [ -z "$DEBUG" ]; then
        strip -x libnewnode.so
    fi
    OUT=android/src/main/jniLibs/$ABI
    test -d $OUT || mkdir -p $OUT
    cp libnewnode.so $OUT
    ls -ld $OUT/*
}

NDK_API=14
ARCH=arm
ABI=armeabi-v7a
CPU_ARCH=armv7-a
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
SODIUM_SCRIPT=$CPU_ARCH
build_android

NDK_API=21
ARCH=x86
ABI=x86
CPU_ARCH=i686
SODIUM_SCRIPT=$ABI
build_android

NDK_API=21
ARCH=x86_64
ABI=x86_64
CPU_ARCH=westmere
SODIUM_SCRIPT=$ABI
build_android

NDK_API=21
ARCH=mips
ABI=mips
CPU_ARCH=mips32
SODIUM_SCRIPT=$CPU_ARCH
build_android

NDK_API=21
ARCH=mips64
ABI=mips64
CPU_ARCH=mips64r6
SODIUM_SCRIPT=$ABI
build_android
