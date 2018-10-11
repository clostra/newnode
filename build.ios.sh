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


    cd bugsnag-cocoa
    # XXX: clean bugsnag, since it seems to symlink iOS/$TRIPLE/libBugsnagStatic.a to the IntermediateBuildFilesPath
    xcodebuild -workspace iOS.xcworkspace -scheme BugsnagStatic -configuration Release \
        -arch $ARCH -sdk $SDK CONFIGURATION_BUILD_DIR=$TRIPLE TARGET_BUILD_DIR=$TRIPLE clean
    if [ ! -f iOS/$TRIPLE/libBugsnagStatic.a ]; then
        xcodebuild -workspace iOS.xcworkspace -scheme BugsnagStatic -configuration Release \
            -arch $ARCH -sdk $SDK CONFIGURATION_BUILD_DIR=$TRIPLE TARGET_BUILD_DIR=$TRIPLE $ACTION
    fi
    cd ..
    LIBBUGSNAG_CFLAGS=-Ibugsnag-cocoa/iOS/$TRIPLE/include
    LIBBUGSNAG=bugsnag-cocoa/iOS/$TRIPLE/libBugsnagStatic.a


    FLAGS="$CFLAGS -g -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Werror=shadow -Wfatal-errors \
      -fPIC -fblocks \
      -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
      -fvisibility-inlines-hidden \
      -I."
    if [ ! -z "$DEBUG" ]; then
        FLAGS="$FLAGS -DDEBUG=1"
    fi

    CFLAGS="$FLAGS -std=gnu11"

    rm -rf $TRIPLE || true
    rm *.o || true
    clang $CFLAGS -c dht/dht.c -o dht_dht.o
    for file in bev_splice.c base64.c client.c dht.c http.c log.c lsd.c icmp_handler.c ios/Framework/NewNode.m hash_table.c network.c obfoo.c sha1.c timer.c utp_bufferevent.c; do
        clang $CFLAGS $LIBUTP_CFLAGS $LIBEVENT_CFLAGS $LIBSODIUM_CFLAGS $LIBBLOCKSRUNTIME_CFLAGS $LIBBUGSNAG_CFLAGS -c $file
    done
    mkdir -p $TRIPLE/objects
    mv *.o $TRIPLE/objects

    function arx {
        o=`pwd`
        mkdir -p $1
        (cd $1 && ar x $o/$2)
    }

    arx $TRIPLE/objects/libutp $LIBUTP
    arx $TRIPLE/objects/libevent Libevent/$TRIPLE/lib/libevent.a
    arx $TRIPLE/objects/libevent Libevent/$TRIPLE/lib/libevent_pthreads.a
    arx $TRIPLE/objects/libbugsnag $LIBBUGSNAG

    lipo $LIBSODIUM -thin $ARCH -o libsodium.a

    arx $TRIPLE/objects/libsodium libsodium.a

    clang++ $CFLAGS -dynamiclib \
        -install_name @rpath/NewNode.framework/NewNode \
        -Xlinker -rpath -Xlinker @executable_path/Frameworks \
        -Xlinker -rpath -Xlinker @loader_path/Frameworks \
        -dead_strip \
        -exported_symbols_list ios/Framework/export_list \
        -Xlinker -object_path_lto -Xlinker $TRIPLE/objects/lto.o \
        -Xlinker -export_dynamic \
        -Xlinker -no_deduplicate \
        -Xlinker -objc_abi_version -Xlinker 2 \
        -framework Foundation \
        $TRIPLE/objects/*.o $TRIPLE/objects/libutp/*.o $TRIPLE/objects/libevent/*.o $TRIPLE/objects/libbugsnag/*.o $TRIPLE/objects/libsodium/*.o \
        -o $TRIPLE/libnewnode.dylib
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
IOS_SIMULATOR_VERSION_MIN=${IOS_SIMULATOR_VERSION_MIN-"8.0.0"}
ACTION=build

ARCH=x86_64
CFLAGS="-arch $ARCH -isysroot ${SDK} -mios-simulator-version-min=${IOS_SIMULATOR_VERSION_MIN}"
LDFLAGS="-arch $ARCH"
TRIPLE=x86_64-apple-darwin10
build_ios


BASEDIR="${XCODEDIR}/Platforms/iPhoneOS.platform/Developer"
SDK="${BASEDIR}/SDKs/iPhoneOS.sdk"
IOS_VERSION_MIN=${IOS_VERSION_MIN-"8.0.0"}
ACTION=archive

ARCH=armv7
CFLAGS="-O3 -arch $ARCH -isysroot ${SDK} -mios-version-min=${IOS_VERSION_MIN} -fembed-bitcode -flto"
LDFLAGS="-arch $ARCH"
TRIPLE=armv7-apple-darwin10
build_ios

ARCH=arm64
CFLAGS="-O3 -arch $ARCH -isysroot ${SDK} -mios-version-min=${IOS_VERSION_MIN} -fembed-bitcode -flto"
LDFLAGS="-arch $ARCH"
TRIPLE=arm-apple-darwin10
build_ios


VERSION=`grep "VERSION " constants.h | sed -n 's/.*"\(.*\)"/\1/p'`

FRAMEWORK="NewNode.framework"
rm -rf $FRAMEWORK || true
mkdir -p $FRAMEWORK/Modules
cp ios/Framework/module.modulemap $FRAMEWORK/Modules/module.modulemap
mkdir -p $FRAMEWORK/Headers
cp ios/Framework/NewNode-iOS.h $FRAMEWORK/Headers/NewNode.h
sed "s/\$(CURRENT_PROJECT_VERSION)/$VERSION/" ios/Framework/Info.plist > $FRAMEWORK/Info.plist
lipo -create -output $FRAMEWORK/NewNode x86_64-apple-darwin10/libnewnode.dylib arm-apple-darwin10/libnewnode.dylib armv7-apple-darwin10/libnewnode.dylib
rm -rf $FRAMEWORK.dSYM || true
dsymutil $FRAMEWORK/NewNode -o $FRAMEWORK.dSYM
strip -x $FRAMEWORK/NewNode
du -ch $FRAMEWORK
du -ch $FRAMEWORK.dSYM
