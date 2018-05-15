#!/bin/bash
set -e


function build_ios {

    cd Libevent
    if [ ! -f $TRIPLE/lib/libevent.a ]; then
        ./autogen.sh
        ./configure --disable-shared --disable-openssl $LIBEVENT_CONFIG --host=$TRIPLE --prefix=$(pwd)/$TRIPLE CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS"
        make clean
        make -j3
        make install
    fi
    cd ..
    LIBEVENT_CFLAGS=-ILibevent/$TRIPLE/include
    LIBEVENT="Libevent/$TRIPLE/lib/libevent.a Libevent/$TRIPLE/lib/libevent_pthreads.a"


    cd libutp
    if [ ! -f $TRIPLE/libutp.a ]; then
        make clean
        CPPFLAGS=$CFLAGS make -j3 libutp.a
        mkdir $TRIPLE
        mv libutp.a $TRIPLE
    fi
    cd ..
    LIBUTP_CFLAGS=-Ilibutp
    LIBUTP=libutp/$TRIPLE/libutp.a


    FLAGS="$CFLAGS -g -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Werror=shadow -Wfatal-errors \
      -fPIC -fblocks \
      -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
      -flto"
    if [ ! -z "$DEBUG" ]; then
        FLAGS="$FLAGS -DDEBUG=1"
    fi

    CFLAGS="$FLAGS -std=gnu11"

    rm *.o || true
    rm libsodium.a || true
    clang $CFLAGS -c dht/dht.c -o dht_dht.o
    for file in bev_splice.c base64.c client.c dht.c http.c log.c lsd.c icmp_handler.c ios.m hash_table.c network.c obfoo.c sha1.c timer.c utp_bufferevent.c; do
        clang $CFLAGS $LIBUTP_CFLAGS $LIBEVENT_CFLAGS $LIBSODIUM_CFLAGS $LIBBLOCKSRUNTIME_CFLAGS -c $file
    done

    rm -rf objects || true

    mkdir -p objects/libutp
    cd objects/libutp
    ar x ../../$LIBUTP
    cd ../..
    mkdir -p objects/libevent
    cd objects/libevent
    ar x ../../Libevent/$TRIPLE/lib/libevent.a
    cd ../..
    mkdir -p objects/libevent
    cd objects/libevent
    ar x ../../Libevent/$TRIPLE/lib/libevent_pthreads.a
    cd ../..

    lipo $LIBSODIUM -thin $ARCH -o libsodium.a

    mkdir -p objects/libsodium
    cd objects/libsodium
    ar x ../../libsodium.a
    cd ../..

    rm -rf $TRIPLE || true
    mkdir -p $TRIPLE

    ld $LDFLAGS -r *.o objects/libutp/*.o objects/libevent/*.o objects/libsodium/*.o -o libnewnode.o
    ar -rcs $TRIPLE/libnewnode.a libnewnode.o
}

cd libsodium
test -f configure || ./autogen.sh
test -f libsodium-ios/lib/libsodium.a || ./dist-build/ios.sh
cd ..
LIBSODIUM_CFLAGS=-Ilibsodium/libsodium-ios/include
LIBSODIUM=libsodium/libsodium-ios/lib/libsodium.a


XCODEDIR=$(xcode-select -p)


BASEDIR="${XCODEDIR}/Platforms/iPhoneSimulator.platform/Developer"
SDK="${BASEDIR}/SDKs/iPhoneSimulator.sdk"
IOS_SIMULATOR_VERSION_MIN=${IOS_SIMULATOR_VERSION_MIN-"7.0.0"}

ARCH=x86_64
CFLAGS="-O3 -arch $ARCH -isysroot ${SDK} -mios-simulator-version-min=${IOS_SIMULATOR_VERSION_MIN} -flto"
LDFLAGS="-arch $ARCH"
TRIPLE=x86_64-apple-darwin10
build_ios


BASEDIR="${XCODEDIR}/Platforms/iPhoneOS.platform/Developer"
SDK="${BASEDIR}/SDKs/iPhoneOS.sdk"
IOS_VERSION_MIN=${IOS_VERSION_MIN-"7.0.0"}

ARCH=arm64
CFLAGS="-O3 -arch $ARCH -isysroot ${SDK} -mios-version-min=${IOS_VERSION_MIN} -fembed-bitcode -flto"
LDFLAGS="-arch $ARCH"
TRIPLE=arm-apple-darwin10
build_ios


rm libnewnode.a || true
lipo -create -output libnewnode.a "x86_64-apple-darwin10/libnewnode.a" "arm-apple-darwin10/libnewnode.a"
ls -la libnewnode.a


FRAMEWORK="NewNode.framework"
rm -rf $FRAMEWORK || true
mkdir -p "${FRAMEWORK}/Modules"
echo -e "framework module NewNode {\n    header \"NewNode.h\"\n    export *\n}" > "${FRAMEWORK}/Modules/module.modulemap"
mkdir -p "${FRAMEWORK}/Versions/A/Headers"
ln -sfh A "${FRAMEWORK}/Versions/Current"
ln -sfh Versions/Current/Headers "${FRAMEWORK}/Headers"
ln -sfh "Versions/Current/NewNode" "${FRAMEWORK}/NewNode"
cp -a ios.h "${FRAMEWORK}/Versions/A/Headers/NewNode.h"
cp -a libnewnode.a "${FRAMEWORK}/Versions/A/NewNode"
du -ch $FRAMEWORK
