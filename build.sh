#!/bin/bash
set -e

echo "Building libutp..."
cd libutp
make
cd ..

echo "Building Libevent..."
cd Libevent
if [ ! -f configure ]; then ./autogen.sh; fi
if [ ! -f Makefile ]; then ./configure --disable-openssl; fi
make
cd ..

echo "Building libbtdht..."
cd libbtdht/btutils
# XXX: how do you specify the output dir for bjam?
bjam toolset=clang cxxflags="-std=c++1y"
cp `find bin -name libbtutils.a` .
cd ..
bjam toolset=clang cxxflags="-std=c++1y"
cp `find bin -name libbtdht.a` .
cd ..

echo "Building libsodium..."
cd libsodium
if [ ! -f configure ]; then ./autogen.sh; fi
if [ ! -f Makefile ]; then ./configure; fi
make
cd ..

echo "int main() {}"|clang -x c - -fsanitize-address-use-after-scope 2>/dev/null && SANITIZE_SCOPE="-fsanitize-address-use-after-scope"
echo "int main() {}"|clang -x c - -fsanitize=undefined 2>/dev/null && SANITIZE_UNDEFINED="-fsanitize=undefined -fno-sanitize=vptr"

FLAGS="-g -O0 -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Wno-error=shadow -Wfatal-errors \
  -fPIC -fblocks -fdata-sections -ffunction-sections \
  -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
  -std=gnu11 -D__FAVOR_BSD -D_BSD_SOURCE -fsanitize=address $SANITIZE_SCOPE $SANITIZE_UNDEFINED --coverage"

CFLAGS="$FLAGS -std=gnu11"
CPPFLAGS="$FLAGS -std=c++1y"

echo "int main() {}"|clang -x c - -lrt 2>/dev/null && LRT="-lrt"
echo -e "#include <math.h>\nint main() { log(2); }"|clang -x c - 2>/dev/null || LM="-lm"
echo -e "#include <Block.h>\nint main() { Block_copy(^{}); }"|clang -x c -fblocks - 2>/dev/null || LB="-lBlocksRuntime"

echo "Building dht.o..."
clang++ $CPPFLAGS -c dht.cpp -I ./libbtdht/src -I ./libbtdht/btutils/src -I ./libsodium/src/libsodium/include

echo "Building HTTP test server..."
clang $CFLAGS -o test_server test_server.c \
  -I ./Libevent/include ./Libevent/.libs/libevent.a

echo "Building injector..."
clang $CFLAGS -o injector injector.c log.c icmp_handler.c network.c sha1.c timer.c utp_bufferevent.c http_util.c dht.o \
  -I ./libutp libutp/libutp.a \
  -I ./Libevent/include ./Libevent/.libs/libevent.a ./Libevent/.libs/libevent_pthreads.a \
  -I ./libsodium/src/libsodium/include ./libsodium/src/libsodium/.libs/libsodium.a \
  ./libbtdht/libbtdht.a ./libbtdht/btutils/libbtutils.a \
  `pkg-config --cflags libevent` \
  -lstdc++ $LRT $LM $LB

echo "Building injector_helper..."
clang $CFLAGS -o injector_helper injector_helper.c log.c icmp_handler.c network.c sha1.c timer.c utp_bufferevent.c http_util.c dht.o \
  -I ./libutp libutp/libutp.a \
  -I ./Libevent/include ./Libevent/.libs/libevent.a ./Libevent/.libs/libevent_pthreads.a \
  -I ./libsodium/src/libsodium/include ./libsodium/src/libsodium/.libs/libsodium.a \
  ./libbtdht/libbtdht.a ./libbtdht/btutils/libbtutils.a \
  `pkg-config --cflags libevent` \
  -lstdc++ $LRT $LM $LB
