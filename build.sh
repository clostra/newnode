#!/bin/bash
set -e

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

FLAGS="-g -O3 -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Werror=shadow -Wfatal-errors \
  -fPIC -fblocks -fdata-sections -ffunction-sections \
  -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
  -std=gnu11 -D__FAVOR_BSD -D_BSD_SOURCE"

CFLAGS="$FLAGS -std=gnu11"
CPPFLAGS="$FLAGS -std=c++14"

echo "int main() {}"|clang -x c - -lrt 2>/dev/null && LRT="-lrt"

if [ "$(expr substr $(uname -s) 1 5)" = "Linux" ]; then
    CFLAGS="$CFLAGS -lstdc++ -lm -lBlocksRuntime"
fi

clang $CPPFLAGS -c dht.cpp -I ./libbtdht/src -I ./libbtdht/btutils/src
clang $CFLAGS -o injector injector.c log.c icmp_handler.c network.c sha1.c timer.c dht.o \
  -I ./libutp libutp/libutp.a \
  ./libbtdht/libbtdht.a ./libbtdht/btutils/libbtutils.a \
  `pkg-config --cflags libsodium` `pkg-config --libs libsodium` \
  `pkg-config --cflags libevent` `pkg-config --libs libevent libevent_pthreads` \
  -lc++ $LRT
