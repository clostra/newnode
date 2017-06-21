#!/bin/bash
set -e

cd openssl
OPENSSL_DIR="$(pwd)/.native"
if [ ! -d $OPENSSL_DIR ]; then
    KERNEL_BITS=64 ./config no-shared -no-ssl2 -no-ssl3 -no-comp -no-hw -no-engine --openssldir="$OPENSSL_DIR"
    make clean
    make depend
    make all
    make install_sw
fi
cd ..
OPENSSL_CFLAGS=-I$OPENSSL_DIR/include
OPENSSL_LDFLAGS="-L$OPENSSL_DIR/lib -lssl -lcrypto"


cd Libevent
if [ ! -d .libs ]; then
    ./autogen.sh
    ./configure --disable-shared CFLAGS="-g $OPENSSL_CFLAGS" LDFLAGS="$OPENSSL_LDFLAGS"
    make clean
    make -j3
fi
cd ..
LIBEVENT_CFLAGS=-ILibevent/include
LIBEVENT="$LIBEVENT_CFLAGS Libevent/.libs/libevent.a Libevent/.libs/libevent_pthreads.a Libevent/.libs/libevent_openssl.a"


cd libsodium
LIBSODIUM_DIR="$(pwd)/native"
if [ ! -d $LIBSODIUM_DIR ]; then
    ./autogen.sh
    mkdir -p $LIBSODIUM_DIR
    ./configure --enable-minimal --disable-shared --prefix=$LIBSODIUM_DIR
    make -j3 check
    make -j3 install
fi
cd ..
LIBSODIUM_CFLAGS=-I${LIBSODIUM_DIR}/include
LIBSODIUM="$LIBSODIUM_CFLAGS ${LIBSODIUM_DIR}/lib/libsodium.a"


cd libutp
test -f libutp.a || (make clean && make -j3 libutp.a)
cd ..
LIBUTP_CFLAGS=-Ilibutp
LIBUTP=libutp/libutp.a


BTFLAGS="-D_UNICODE -DLINUX -D_DEBUG"
cd libbtdht/btutils
if [ ! -f libbtutils.a ]; then
    for f in src/*.cpp; do
        clang++ -MD -g -pipe -Wall -O0 $BTFLAGS -std=c++14 -fPIC -c $f
    done
    ar rs libbtutils.a *.o
fi
cd ..
if [ ! -f libbtdht.a ]; then
    for f in src/*.cpp; do
        clang++ -MD -g -pipe -Wall -O0 $BTFLAGS -std=c++14 -fPIC -I btutils/src -I src -c $f
    done
    ar rs libbtdht.a *.o
fi
cd ..
LIBBTDHT_CFLAGS="-Ilibbtdht/src -Ilibbtdht/btutils/src $BTFLAGS"
LIBBTDHT="libbtdht/libbtdht.a libbtdht/btutils/libbtutils.a"


FLAGS="-g -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Werror=shadow -Wfatal-errors \
  -fPIC -fblocks -fdata-sections -ffunction-sections \
  -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
  -D__FAVOR_BSD -D_BSD_SOURCE"
FLAGS="$FLAGS -O0 -fsanitize=address -DDEBUG=1"

CFLAGS="$FLAGS -std=gnu11"
CPPFLAGS="$FLAGS -std=c++14"

echo "int main() {}"|clang -x c - -lrt 2>/dev/null && LRT="-lrt"
echo -e "#include <math.h>\nint main() { log(2); }"|clang -x c - 2>/dev/null || LM="-lm"
echo -e "#include <Block.h>\nint main() { Block_copy(^{}); }"|clang -x c -fblocks - 2>/dev/null || LIBBLOCKSRUNTIME="-lBlocksRuntime"

clang++ $CPPFLAGS $LIBBTDHT_CFLAGS $LIBSODIUM_CFLAGS $LIBBLOCKSRUNTIME_CFLAGS -c dht.cpp
for file in client.c injector.c bev_splice.c base64.c http.c log.c icmp_handler.c hash_table.c network.c sha1.c timer.c utp_bufferevent.c; do
    clang $CFLAGS $LIBUTP_CFLAGS $LIBEVENT_CFLAGS $LIBBTDHT_CFLAGS $LIBSODIUM_CFLAGS -c $file
done
mv client.o client.o.tmp
clang++ $FLAGS -o injector *.o $LRT $LM $LIBUTP $LIBBTDHT $LIBEVENT $LIBSODIUM $LIBBLOCKSRUNTIME
mv injector.o injector.o.tmp
mv client.o.tmp client.o
clang++ $FLAGS -o client *.o $LRT $LM $LIBUTP $LIBBTDHT $LIBEVENT $LIBSODIUM $LIBBLOCKSRUNTIME
