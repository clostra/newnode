#!/bin/bash
set -e

export CC=clang
export CXX=clang++


cd Libevent
if [ ! -d native ]; then
    ./autogen.sh
    ./configure --disable-shared --disable-openssl --prefix=$(pwd)/native
    make clean
    make -j3
    make install
fi
cd ..
LIBEVENT_CFLAGS=-ILibevent/native/include
LIBEVENT="Libevent/native/lib/libevent.a Libevent/native/lib/libevent_pthreads.a"


cd libsodium
if [ ! -d native ]; then
    ./autogen.sh
    mkdir -p native
    ./configure --enable-minimal --disable-shared --prefix=$(pwd)/native
    make clean
    make -j3 check
    make -j3 install
fi
cd ..
LIBSODIUM_CFLAGS=-Ilibsodium/native/include
LIBSODIUM=libsodium/native/lib/libsodium.a


cd libutp
test -f libutp.a || (make clean && OPT=-O0 CPPFLAGS="-fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all" make -j3 libutp.a)
cd ..
LIBUTP_CFLAGS=-Ilibutp
LIBUTP=libutp/libutp.a


if ! echo -e "#include <Block.h>\nint main() { Block_copy(^{}); }"|clang -x c -fblocks - 2>/dev/null; then
    cd blocksruntime
    if [ ! -f $TRIPLE/libBlocksRuntime.a ]; then
        ./buildlib
        mkdir $TRIPLE
        mv libBlocksRuntime.a $TRIPLE
    fi
    cd ..
    LIBBLOCKSRUNTIME_CFLAGS=-Iblocksruntime/BlocksRuntime
    LIBBLOCKSRUNTIME="-lBlocksRuntime"
fi

FLAGS="-g -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Wno-error=shadow -Wfatal-errors \
  -fPIC -fblocks -fdata-sections -ffunction-sections \
  -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
  -D__FAVOR_BSD -D_BSD_SOURCE -D_DEFAULT_SOURCE"
# -fvisibility=hidden -fvisibility-inlines-hidden -flto=thin \
if [ ! -z "$DEBUG" ]; then
    FLAGS="$FLAGS -O0 -DDEBUG=1 -fsanitize=address -fsanitize=undefined --coverage"
else
    FLAGS="$FLAGS -O0 -fsanitize=address -fsanitize=undefined"
fi

CFLAGS="$FLAGS -std=gnu11"

echo "int main() {}"|clang -x c - -lrt 2>/dev/null && LRT="-lrt"
echo -e "#include <math.h>\nint main() { log(2); }"|clang -x c - 2>/dev/null || LM="-lm"

rm *.o || true
clang $CFLAGS -c dht/dht.c -o dht_dht.o
for file in client.c client_main.c injector.c dht.c bev_splice.c base64.c http.c log.c lsd.c icmp_handler.c hash_table.c \
            merkle_tree.c network.c obfoo.c sha1.c timer.c utp_bufferevent.c; do
    clang $CFLAGS $LIBUTP_CFLAGS $LIBEVENT_CFLAGS $LIBSODIUM_CFLAGS $LIBBLOCKSRUNTIME_CFLAGS -c $file
done
mv client.o client.o.tmp
mv client_main.o client_main.o.tmp
clang $CFLAGS -o injector *.o $LRT $LM $LIBUTP $LIBEVENT $LIBSODIUM $LIBBLOCKSRUNTIME -lpthread
mv injector.o injector.o.tmp
mv client.o.tmp client.o
mv client_main.o.tmp client_main.o
clang $CFLAGS -o client *.o $LRT $LM $LIBUTP $LIBEVENT $LIBSODIUM $LIBBLOCKSRUNTIME -lpthread
