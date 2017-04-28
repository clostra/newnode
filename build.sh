#!/bin/bash
set -e

cd libutp
make
cd ..

cd Libevent
if [ ! -f configure ]; then ./autogen.sh; fi
if [ ! -f Makefile ]; then ./configure; fi
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

FLAGS="-g -O0 -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Wno-error=shadow -Wfatal-errors \
  -fPIC -fblocks -fdata-sections -ffunction-sections \
  -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
  -std=gnu11 -D__FAVOR_BSD -D_BSD_SOURCE"

CFLAGS="$FLAGS -std=gnu11"
CPPFLAGS="$FLAGS -std=c++14"

echo "int main() {}"|clang -x c - -lrt 2>/dev/null && LRT="-lrt"
echo -e "#include <math.h>\nint main() { log(2); }"|clang -x c - 2>/dev/null || LM="-lm"
echo -e "#include <Block.h>\nint main() { Block_copy(^{}); }"|clang -x c -fblocks - 2>/dev/null || LB="-lBlocksRuntime"

if [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    CFLAGS="$CFLAGS -lstdc++ -lm -lBlocksRuntime -lpthread"
fi

clang $CPPFLAGS -c dht.cpp -I ./libbtdht/src -I ./libbtdht/btutils/src
clang $CFLAGS -o injector injector.c log.c icmp_handler.c network.c sha1.c timer.c utp_bufferevent.c dht.o \
  -I ./libutp libutp/libutp.a \
  -I ./Libevent/include ./Libevent/.libs/libevent.a ./Libevent/.libs/libevent_pthreads.a \
  ./libbtdht/libbtdht.a ./libbtdht/btutils/libbtutils.a \
  `pkg-config --cflags libsodium` `pkg-config --libs libsodium` \
  `pkg-config --cflags libevent` \
  -lc++ $LRT $LM $LB
