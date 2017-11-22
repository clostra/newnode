#!/bin/bash
set -e

NDK_API=27


function build_android {
    TRIPLE=`python -c "import sys; sys.path.append(sys.argv[1]); import make_standalone_toolchain; print make_standalone_toolchain.get_triple(sys.argv[2])" $ANDROID_NDK_HOME/build/tools $ARCH`
    echo $TRIPLE
    TOOLCHAIN="$(pwd)/android-toolchain-$TRIPLE"
    if [ ! -d $TOOLCHAIN ]; then
        $ANDROID_NDK_HOME/build/tools/make_standalone_toolchain.py --force --api=$NDK_API --arch=$ARCH --stl=libc++ --install-dir="$TOOLCHAIN"
    fi
    export PATH="$TOOLCHAIN/bin/":"$TOOLCHAIN/$TRIPLE/bin/":"$PATH"


    cd openssl
    OPENSSL_DIR="$(pwd)/$TRIPLE"
    if [ ! -d $OPENSSL_DIR ]; then
        export SYSTEM=android
        export SYSROOT="$TOOLCHAIN/sysroot"
		export CROSS_SYSROOT="$SYSROOT"
        export ANDROID_DEV="$SYSROOT/usr"
        export MACHINE=$CPU_ARCH
        export CROSS_COMPILE=$TRIPLE-
        CFLAGS="-isystem$SYSROOT/usr/include/$TRIPLE -I$SYSROOT/usr/include -I$SYSROOT/usr/include/$TRIPLE"
        perl -pi -e 's/install: all install_docs install_sw/install: install_docs install_sw/g' Makefile.org
        #./config -v no-shared -no-ssl2 -no-ssl3 -no-comp -no-hw -no-engine --prefix=$OPENSSL_DIR $CFLAGS
        echo "./Configure no-shared no-ssl2 no-ssl3 no-comp no-hw no-engine --prefix=$OPENSSL_DIR $OPENSSL_TARGET $CFLAGS"
        ./Configure no-shared no-ssl2 no-ssl3 no-comp no-hw no-engine --prefix=""$OPENSSL_DIR"" $OPENSSL_TARGET $CFLAGS
        make clean
        make depend
        make -j3 all
        make install_sw
    fi
    cd ..
    OPENSSL_CFLAGS=-I$OPENSSL_DIR/include
    OPENSSL="$OPENSSL_DIR/lib/libssl.a $OPENSSL_DIR/lib/libcrypto.a"


    cd Libevent
    if [ ! -f $TRIPLE/libevent.a ]; then
        ./autogen.sh
	    export OPENSSL_LIBS="$OPEN_SSL"
        ./configure --disable-shared --host=$TRIPLE CFLAGS="-g $OPENSSL_CFLAGS" LDFLAGS="$OPENSSL"
        make clean
        make -j3
        mv .libs $TRIPLE
    fi
    cd ..
    LIBEVENT_CFLAGS=-ILibevent/include
    LIBEVENT="Libevent/$TRIPLE/libevent.a Libevent/$TRIPLE/libevent_pthreads.a"


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


    BTFLAGS="-D_UNICODE -DLINUX -DANDROID"
    if [ ! -z "$DEBUG" ]; then
        BTFLAGS="$BTFLAGS -D_DEBUG"
    fi
    cd libbtdht/btutils
    if [ ! -f $TRIPLE/libbtutils.a ]; then
        for f in src/*.cpp; do
            clang++ -MD -g -pipe -Wall -O0 $BTFLAGS -std=c++14 -fPIC $ABI_FLAGS -c $f
        done
        mkdir $TRIPLE
        ar rs $TRIPLE/libbtutils.a *.o
    fi
    cd ..
    if [ ! -f $TRIPLE/libbtdht.a ]; then
        for f in src/*.cpp; do
            clang++ -MD -g -pipe -Wall -O0 $BTFLAGS -std=c++14 -fPIC $ABI_FLAGS -I btutils/src -I src -c $f
        done
        mkdir $TRIPLE
        ar rs $TRIPLE/libbtdht.a *.o
    fi
    cd ..
    LIBBTDHT_CFLAGS="-Ilibbtdht/src -Ilibbtdht/btutils/src $BTFLAGS"
    LIBBTDHT="libbtdht/$TRIPLE/libbtdht.a libbtdht/btutils/$TRIPLE/libbtutils.a"


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
      -D__FAVOR_BSD -D_BSD_SOURCE $ABI_FLAGS"
    if [ ! -z "$DEBUG" ]; then
        FLAGS="$FLAGS -O0 -DDEBUG=1"
    else
        FLAGS="$FLAGS -O3"
    fi

    CFLAGS="$FLAGS -std=gnu11"
    CPPFLAGS="$FLAGS -std=c++14"

    clang++ $CPPFLAGS $LIBBTDHT_CFLAGS $LIBSODIUM_CFLAGS $LIBBLOCKSRUNTIME_CFLAGS -c dht.cpp
    for file in android.c bev_splice.c base64.c client.c http.c log.c icmp_handler.c hash_table.c network.c sha1.c timer.c utp_bufferevent.c; do
        clang $CFLAGS $OPENSSL_CFLAGS $LIBUTP_CFLAGS $LIBEVENT_CFLAGS $LIBBTDHT_CFLAGS $LIBSODIUM_CFLAGS $LIBBLOCKSRUNTIME_CFLAGS -c $file
    done
    clang++ $FLAGS -shared -o libdcdn.so *.o -static-libstdc++ -lm $OPENSSL $LIBUTP $LIBBTDHT $LIBEVENT $LIBSODIUM $LIBBLOCKSRUNTIME -llog
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
OPENSSL_TARGET=android-armeabi
SODIUM_SCRIPT=$CPU_ARCH
build_android

ARCH=arm64
ABI=arm64-v8a
CPU_ARCH=armv8-a
OPENSSL_TARGET=android64-aarch64
SODIUM_SCRIPT=$CPU_ARCH
build_android

ARCH=x86
ABI=x86
CPU_ARCH=i686
OPENSSL_TARGET=android-x86
SODIUM_SCRIPT=$ABI
build_android

ARCH=x86_64
ABI=x86_64
CPU_ARCH=westmere
OPENSSL_TARGET=android64
SODIUM_SCRIPT=$ABI
build_android

ARCH=mips
ABI=mips
CPU_ARCH=mips32
OPENSSL_TARGET=android-mips
SODIUM_SCRIPT=$CPU_ARCH
build_android

ARCH=mips64
ABI=mips64
CPU_ARCH=mips64r6
OPENSSL_TARGET=linux-generic64
SODIUM_SCRIPT=$ABI
build_android