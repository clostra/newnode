#!/bin/bash
set -e

cd Libevent
if [ ! -f Makefile ]; then ./autogen.sh; CFLAGS="`pkg-config libssl --cflags --silence-errors`" ./configure --disable-shared; fi
make
cd ..

cd libsodium
if [ ! -f Makefile ]; then ./autogen.sh; ./configure; fi
make
cd ..

cd libutp
make
cd ..

cd libbtdht/btutils
# XXX: how do you specify the output dir for bjam?
bjam toolset=clang cxxflags="-std=c++14"
cp `find bin -name libbtutils.a` .
cd ..
bjam toolset=clang cxxflags="-std=c++14"
cp `find bin -name libbtdht.a` .
cd ..

FLAGS="-g -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Werror=shadow -Wfatal-errors \
  -fPIC -fblocks -fdata-sections -ffunction-sections \
  -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
  -D__FAVOR_BSD -D_BSD_SOURCE"
# debug
FLAGS="$FLAGS -O0 -fsanitize=address -DDEBUG=1"
#release
#FLAGS="$FLAGS -O3"

CFLAGS="$FLAGS -std=gnu11"
CPPFLAGS="$FLAGS -std=c++14"

echo "int main() {}"|clang -x c - -lrt 2>/dev/null && LRT="-lrt"
echo -e "#include <math.h>\nint main() { log(2); }"|clang -x c - 2>/dev/null || LM="-lm"
echo -e "#include <Block.h>\nint main() { Block_copy(^{}); }"|clang -x c -fblocks - 2>/dev/null || LB="-lBlocksRuntime"

clang $CPPFLAGS -c dht.cpp -I ./libbtdht/src -I ./libbtdht/btutils/src

clang $CFLAGS -o injector bev_splice.c base64.c injector.c http.c log.c icmp_handler.c hash_table.c network.c sha1.c timer.c utp_bufferevent.c dht.o \
  -I ./libutp libutp/libutp.a \
  ./libbtdht/libbtdht.a ./libbtdht/btutils/libbtutils.a \
  -I ./Libevent/include ./Libevent/.libs/libevent.a ./Libevent/.libs/libevent_pthreads.a ./Libevent/.libs/libevent_openssl.a \
  -I ./libsodium/src/libsodium/include ./libsodium/src/libsodium/.libs/libsodium.a \
  -lstdc++ $LRT $LM $LB

clang $CFLAGS -o client bev_splice.c base64.c client.c http.c log.c icmp_handler.c hash_table.c network.c sha1.c timer.c utp_bufferevent.c dht.o \
  -I ./libutp libutp/libutp.a \
  ./libbtdht/libbtdht.a ./libbtdht/btutils/libbtutils.a \
  -I ./Libevent/include ./Libevent/.libs/libevent.a ./Libevent/.libs/libevent_pthreads.a ./Libevent/.libs/libevent_openssl.a \
  -I ./libsodium/src/libsodium/include ./libsodium/src/libsodium/.libs/libsodium.a \
  -lstdc++ $LRT $LM $LB
