#!/bin/bash
set -euo pipefail


function build_apple {

    PARSON_CFLAGS=-Iparson

    cd libevent
    if [ ! -f $TRIPLE/lib/libevent.a ]; then
        ./autogen.sh
        ./configure --disable-debug-mode --disable-shared --disable-openssl --disable-samples --disable-libevent-regress --host=$TRIPLE --prefix=$(pwd)/$TRIPLE CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS"
        echo "#define HAVE_WORKING_KQUEUE 1" >> $(pwd)/config.h
        make clean
        make -j`nproc`
        make install
    fi
    cd ..
    LIBEVENT_CFLAGS=-Ilibevent/$TRIPLE/include
    LIBEVENT="libevent/$TRIPLE/lib/libevent.a libevent/$TRIPLE/lib/libevent_pthreads.a"


    cd libutp
    if [ ! -f $TRIPLE/libutp.a ]; then
        make clean
        OPT=-O2 CPPFLAGS=$CFLAGS make -j`nproc` libutp.a
        mkdir -p $TRIPLE
        mv libutp.a $TRIPLE
    fi
    cd ..
    LIBUTP_CFLAGS=-Ilibutp
    LIBUTP=libutp/$TRIPLE/libutp.a


    cd bugsnag-cocoa
    if [ ! -f $TRIPLE/libBugsnagStatic.a ]; then
        xcodebuild -project Bugsnag.xcodeproj -scheme BugsnagStatic -configuration Release \
            -arch $ARCH -sdk $SDK CONFIGURATION_BUILD_DIR=$TRIPLE TARGET_BUILD_DIR=$TRIPLE archive
    fi
    cd ..
    LIBBUGSNAG_CFLAGS=-Ibugsnag-cocoa/$TRIPLE/include
    LIBBUGSNAG=bugsnag-cocoa/$TRIPLE/libBugsnagStatic.a
    cp $LIBBUGSNAG $LIBBUGSNAG.tmp
    mv $LIBBUGSNAG.tmp $LIBBUGSNAG


    FLAGS="$CFLAGS -g -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Werror=shadow -Wfatal-errors \
      -fPIC -fblocks \
      -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
      -fvisibility-inlines-hidden \
      -I."
    if [ ! -z ${DEBUG+x} ]; then
        FLAGS="$FLAGS -DDEBUG=1"
    fi

    CFLAGS="$FLAGS -std=gnu17"

    rm -rf $TRIPLE || true
    rm *.o || true
    clang $CFLAGS -c dht/dht.c -o dht_dht.o
    for file in bev_splice.c backtrace.c base64.c client.c dht.c d2d.c dns_prefetch.c dns_prefetch_macos.c http.c log.c lsd.c \
                icmp_handler.c hash_table.c merkle_tree.c network.c \
                obfoo.c sha1.c timer.c thread.c bufferevent_utp.c \
                parson/parson.c; do
        clang $CFLAGS $LIBUTP_CFLAGS $LIBEVENT_CFLAGS $LIBSODIUM_CFLAGS $LIBBUGSNAG_CFLAGS $PARSON_CFLAGS -c $file
    done
    clang -fobjc-arc -fobjc-weak -fmodules $CFLAGS $LIBUTP_CFLAGS $LIBEVENT_CFLAGS $LIBSODIUM_CFLAGS $LIBBUGSNAG_CFLAGS -I ios -c ios/NetService.m ios/Bluetooth.m ios/HTTPSRequest.m ios/Framework/NewNode.m
    mkdir -p $TRIPLE/objects
    mv *.o $TRIPLE/objects

    lipo $LIBSODIUM -thin $ARCH -o libsodium.a

    function arx {
        o=`pwd`
        mkdir -p $1
        (cd $1 && ar x $o/$2)
    }

    arx $TRIPLE/objects/libutp $LIBUTP
    arx $TRIPLE/objects/libevent libevent/$TRIPLE/lib/libevent.a
    arx $TRIPLE/objects/libevent libevent/$TRIPLE/lib/libevent_pthreads.a
    arx $TRIPLE/objects/libbugsnag $LIBBUGSNAG
    arx $TRIPLE/objects/libsodium libsodium.a

    clang++ $CFLAGS -dynamiclib \
        -install_name @rpath/NewNode.framework/NewNode \
        -Xlinker -rpath -Xlinker @executable_path/Frameworks \
        -Xlinker -rpath -Xlinker @loader_path/Frameworks \
        -dead_strip \
        -exported_symbols_list ios/Framework/export_list \
        -Xlinker -export_dynamic \
        -Xlinker -no_deduplicate \
        -Xlinker -objc_abi_version -Xlinker 2 \
        -framework Foundation \
        $TRIPLE/objects/*.o $TRIPLE/objects/libutp/*.o $TRIPLE/objects/libevent/*.o $TRIPLE/objects/libbugsnag/*.o $TRIPLE/objects/libsodium/*.o \
        -o $TRIPLE/libnewnode.dylib

    ar rcs $TRIPLE/libnewnode.a $TRIPLE/objects/*.o $TRIPLE/objects/libutp/*.o $TRIPLE/objects/libevent/*.o $TRIPLE/objects/libbugsnag/*.o $TRIPLE/objects/libsodium/*.o
}

cd libsodium
test -d libsodium-apple/Clibsodium.xcframework || ./dist-build/apple-xcframework.sh
cd ..
LIBSODIUM_XCF=libsodium/libsodium-apple/Clibsodium.xcframework


XCODEDIR=$(xcode-select -p)


LIBSODIUM_CFLAGS=-I$LIBSODIUM_XCF/ios-arm64_i386_x86_64-simulator/Headers
LIBSODIUM=$LIBSODIUM_XCF/ios-arm64_i386_x86_64-simulator/libsodium.a
BASEDIR="${XCODEDIR}/Platforms/iPhoneSimulator.platform/Developer"
SDK="${BASEDIR}/SDKs/iPhoneSimulator.sdk"
IOS_SIMULATOR_VERSION_MIN=11
ARCH=x86_64
CFLAGS="-arch $ARCH -isysroot ${SDK} -mios-simulator-version-min=${IOS_SIMULATOR_VERSION_MIN}"
LDFLAGS="-arch $ARCH"
TRIPLE=x86_64-apple-darwin
build_apple

LIBSODIUM_CFLAGS=-I$LIBSODIUM_XCF/ios-arm64_i386_x86_64-simulator/Headers
LIBSODIUM=$LIBSODIUM_XCF/ios-arm64_i386_x86_64-simulator/libsodium.a
BASEDIR="${XCODEDIR}/Platforms/iPhoneSimulator.platform/Developer"
SDK="${BASEDIR}/SDKs/iPhoneSimulator.sdk"
IOS_SIMULATOR_VERSION_MIN=11
ARCH=arm64
CFLAGS="-arch $ARCH -isysroot ${SDK} -mios-simulator-version-min=${IOS_SIMULATOR_VERSION_MIN}"
LDFLAGS="-arch $ARCH"
TRIPLE=arm64-apple-darwin
build_apple

LIBSODIUM_CFLAGS=-I$LIBSODIUM_XCF/ios-arm64_armv7_armv7s/Headers
LIBSODIUM=$LIBSODIUM_XCF/ios-arm64_armv7_armv7s/libsodium.a
BASEDIR="${XCODEDIR}/Platforms/iPhoneOS.platform/Developer"
SDK="${BASEDIR}/SDKs/iPhoneOS.sdk"
IOS_VERSION_MIN=11
ARCH=arm64
CFLAGS="-O3 -arch $ARCH -isysroot ${SDK} -mios-version-min=${IOS_VERSION_MIN} -fembed-bitcode"
LDFLAGS="-arch $ARCH"
TRIPLE=arm-apple-darwin
build_apple

LIBSODIUM_CFLAGS=-I$LIBSODIUM_XCF/ios-arm64_x86_64-maccatalyst/Headers
LIBSODIUM=$LIBSODIUM_XCF/ios-arm64_x86_64-maccatalyst/libsodium.a
BASEDIR="${XCODEDIR}/Platforms/MacOSX.platform/Developer"
SDK="${BASEDIR}/SDKs/MacOSX.sdk"
ARCH=x86_64
CFLAGS="-O3 -arch $ARCH -isysroot ${SDK} -target $ARCH-apple-ios-macabi -fembed-bitcode -iframework $SDK/System/iOSSupport/System/Library/Frameworks"
LDFLAGS="-arch $ARCH  -target $ARCH-apple-ios-macabi"
TRIPLE=x86_64-apple-ios
build_apple


FRAMEWORK="NewNode.framework"
rm -rf $FRAMEWORK || true
mkdir -p $FRAMEWORK/Modules
cp ios/Framework/module.modulemap $FRAMEWORK/Modules/module.modulemap
mkdir -p $FRAMEWORK/Headers
cp ios/Framework/NewNode-iOS.h $FRAMEWORK/Headers/NewNode.h
VERSION=`grep "VERSION " constants.h | sed -n 's/.*"\(.*\)"/\1/p'`
sed "s/\$(CURRENT_PROJECT_VERSION)/$VERSION/" ios/Framework/Info.plist > $FRAMEWORK/Info.plist
LIPO_ARGS=""
for triple in x86_64-apple-darwin arm-apple-darwin; do
    LIPO_ARGS+=" $triple/libnewnode.dylib"
done
lipo -create -output $FRAMEWORK/NewNode $LIPO_ARGS
rm -rf $FRAMEWORK.dSYM || true
dsymutil $FRAMEWORK/NewNode -o $FRAMEWORK.dSYM
strip -x $FRAMEWORK/NewNode
du -ch $FRAMEWORK
du -ch $FRAMEWORK.dSYM

rm -rf simulator-apple-darwin || true
mkdir -p simulator-apple-darwin
lipo -create -output simulator-apple-darwin/libnewnode.a x86_64-apple-darwin/libnewnode.a arm64-apple-darwin/libnewnode.a

headers=$(mktemp -d)
cp ios/Framework/NewNode-iOS.h $headers/NewNode.h
echo 'module NewNode {
    header "NewNode.h"
    export *
}' > $headers/module.modulemap
XCFRAMEWORK="NewNode.xcframework"
rm -rf $XCFRAMEWORK || true
XCFRAMEWORK_ARGS=""
for triple in simulator-apple-darwin arm-apple-darwin x86_64-apple-ios; do
  XCFRAMEWORK_ARGS+=" -library $triple/libnewnode.a"
  XCFRAMEWORK_ARGS+=" -headers $headers"
done
xcodebuild -create-xcframework ${XCFRAMEWORK_ARGS} -output $XCFRAMEWORK
rm -rf $headers
