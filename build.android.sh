#!/bin/bash
set -e

NDK_API=27


function build_android {
    TRIPLE=`python -c "import sys; sys.path.append(sys.argv[1]); import make_standalone_toolchain; print make_standalone_toolchain.get_triple(sys.argv[2])" $ANDROID_NDK_HOME/build/tools $ARCH`
    TOOLCHAIN="$(pwd)/android-toolchain-$TRIPLE"
    if [ ! -d $TOOLCHAIN ]; then
        $ANDROID_NDK_HOME/build/tools/make_standalone_toolchain.py --force --api=$NDK_API --arch=$ARCH --stl=libc++ --install-dir="$TOOLCHAIN"
    fi
    export PATH="$TOOLCHAIN/bin/":"$TOOLCHAIN/$TRIPLE/bin/":"$PATH"


    cd Libevent
    if [ ! -f $TRIPLE/libevent.a ]; then
        ./autogen.sh
        ./configure --disable-shared --disable-openssl --host=$TRIPLE --prefix="$(pwd)/$TRIPLE"
        make clean
        make -j3
        make install
    fi
    cd ..
    LIBEVENT_CFLAGS=-ILibevent/$TRIPLE/include
    LIBEVENT="Libevent/$TRIPLE/lib/libevent.a Libevent/$TRIPLE/lib/libevent_pthreads.a"


    cd libsodium
    LIBSODIUM_DIR="$(pwd)/libsodium-android-$CPU_ARCH"
    test -f configure || ./autogen.sh
    test -f ${LIBSODIUM_DIR}/lib/libsodium.a || ./dist-build/android-$SODIUM_SCRIPT.sh
    cd ..
    LIBSODIUM_CFLAGS=-I${LIBSODIUM_DIR}/include
    LIBSODIUM=${LIBSODIUM_DIR}/lib/libsodium.a

    if [ "$ABI" = "mips64" ]; then
        ABI_FLAGS="-fintegrated-as"
    fi

    cd libutp
    if [ ! -f $TRIPLE/libutp.a ]; then
        make clean
        CC=clang CXX=clang++ CPPFLAGS=$ABI_FLAGS make -j3 libutp.a
        mkdir $TRIPLE
        mv libutp.a $TRIPLE
    fi
    cd ..
    LIBUTP_CFLAGS=-Ilibutp
    LIBUTP=libutp/$TRIPLE/libutp.a


    cd blocksruntime
    LIBBLOCKSRUNTIME_DIR="$(pwd)/blocksruntime-$TRIPLE"
    if [ ! -f ${LIBBLOCKSRUNTIME_DIR}/libBlocksRuntime.a ]; then
        CC=clang ./buildlib
        mkdir $LIBBLOCKSRUNTIME_DIR
        mv libBlocksRuntime.a $LIBBLOCKSRUNTIME_DIR
    fi
    cd ..
    LIBBLOCKSRUNTIME_CFLAGS=-Iblocksruntime/BlocksRuntime
    LIBBLOCKSRUNTIME=${LIBBLOCKSRUNTIME_DIR}/libBlocksRuntime.a


    FLAGS="-g -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Werror=shadow -Wfatal-errors \
      -fPIC -fblocks -fdata-sections -ffunction-sections \
      -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
      -D__FAVOR_BSD -D_BSD_SOURCE -DANDROID $ABI_FLAGS"
    if [ ! -z "$DEBUG" ]; then
        FLAGS="$FLAGS -O0 -DDEBUG=1"
    else
        FLAGS="$FLAGS -O3"
    fi

    CFLAGS="$FLAGS -std=gnu11"
    CPPFLAGS="$FLAGS -std=c++14"

    clang $CFLAGS -c dht/dht.c -o dht_dht.o
    for file in android.c bev_splice.c base64.c client.c dht.c http.c log.c lsd.c icmp_handler.c hash_table.c network.c sha1.c timer.c utp_bufferevent.c; do
        clang $CFLAGS $LIBUTP_CFLAGS $LIBEVENT_CFLAGS $LIBBTDHT_CFLAGS $LIBSODIUM_CFLAGS $LIBBLOCKSRUNTIME_CFLAGS -c $file
    done
    clang++ $FLAGS -shared -o libdcdn.so *.o -static-libstdc++ -lm $LIBUTP $LIBBTDHT $LIBEVENT $LIBSODIUM $LIBBLOCKSRUNTIME -llog
    if [ -z "$DEBUG" ]; then
        strip -x libdcdn.so
    fi
    test -d android/libs/$ABI || mkdir -p android/libs/$ABI
    cp libdcdn.so android/libs/$ABI
    ls -ld android/libs/$ABI/*
}

ARCH=arm
ABI=armeabi-v7a
CPU_ARCH=armv7-a
SODIUM_SCRIPT=$CPU_ARCH
build_android

ARCH=arm64
ABI=arm64-v8a
CPU_ARCH=armv8-a
SODIUM_SCRIPT=$CPU_ARCH
build_android

ARCH=x86
ABI=x86
CPU_ARCH=i686
SODIUM_SCRIPT=$ABI
build_android

ARCH=x86_64
ABI=x86_64
CPU_ARCH=westmere
SODIUM_SCRIPT=$ABI
build_android

ARCH=mips
ABI=mips
CPU_ARCH=mips32
SODIUM_SCRIPT=$CPU_ARCH
build_android

ARCH=mips64
ABI=mips64
CPU_ARCH=mips64r6
SODIUM_SCRIPT=$ABI
build_android
