#!/bin/bash
set -e

export CC=clang
export CXX=clang++


cd Libevent
if [ ! -d native ]; then
    ./autogen.sh
    ./configure --disable-shared --disable-openssl --prefix="$(pwd)/native"
    make clean
    make -j3
    make install
fi
cd ..
LIBEVENT_CFLAGS=-ILibevent/native/include
LIBEVENT="$LIBEVENT_CFLAGS Libevent/native/lib/libevent.a Libevent/native/lib/libevent_pthreads.a"


cd libsodium
if [ ! -d native ]; then
    ./autogen.sh
    mkdir -p native
    ./configure --enable-minimal --disable-shared --prefix=native
    make -j3 check
    make -j3 install
fi
cd ..
LIBSODIUM_CFLAGS=-Ilibsodium/native/include
LIBSODIUM="$LIBSODIUM_CFLAGS libsodium/native/lib/libsodium.a"


cd libutp
test -f libutp.a || (make clean && make -j3 libutp.a)
cd ..
LIBUTP_CFLAGS=-Ilibutp
LIBUTP=libutp/libutp.a


FLAGS="-g -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Wno-error=shadow -Wfatal-errors \
  -fPIC -fblocks -fdata-sections -ffunction-sections \
  -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
  -D__FAVOR_BSD -D_BSD_SOURCE"
if [ ! -z "$DEBUG" ]; then
    FLAGS="$FLAGS -O0 -DDEBUG=1 -fsanitize=address --coverage"
else
    FLAGS="$FLAGS -O3"
fi

CFLAGS="$FLAGS -std=gnu11"
CPPFLAGS="$FLAGS -std=c++14"

echo "int main() {}"|clang -x c - -lrt 2>/dev/null && LRT="-lrt"
echo -e "#include <math.h>\nint main() { log(2); }"|clang -x c - 2>/dev/null || LM="-lm"
echo -e "#include <Block.h>\nint main() { Block_copy(^{}); }"|clang -x c -fblocks - 2>/dev/null || LIBBLOCKSRUNTIME="-lBlocksRuntime"

rm *.o || true
clang $CFLAGS -c dht/dht.c -o dht_dht.o
for file in client.c injector.c dht.c bev_splice.c base64.c http.c log.c lsd.c icmp_handler.c hash_table.c network.c sha1.c timer.c utp_bufferevent.c; do
    clang $CFLAGS $LIBUTP_CFLAGS $LIBEVENT_CFLAGS $LIBSODIUM_CFLAGS -c $file
done
mv client.o client.o.tmp
clang++ $CPPFLAGS -o injector *.o -stdlib=libc++ $LRT $LM $LIBUTP $LIBEVENT $LIBSODIUM $LIBBLOCKSRUNTIME -lpthread
mv injector.o injector.o.tmp
mv client.o.tmp client.o
clang++ $CPPFLAGS -o client *.o -stdlib=libc++ $LRT $LM $LIBUTP $LIBEVENT $LIBSODIUM $LIBBLOCKSRUNTIME -lpthread
