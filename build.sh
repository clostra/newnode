#!/bin/bash
set -euo pipefail


export CC=clang
export CXX=clang++


PARSON_CFLAGS="-Iparson"

cd libevent
if [ ! -d native ]; then
    ./configure --disable-shared --disable-openssl --disable-samples --disable-libevent-regress --prefix=$(pwd)/native
    make clean
    make -j`nproc`
    make install
fi
cd ..
LIBEVENT_CFLAGS=-Ilibevent/native/include
LIBEVENT="libevent/native/lib/libevent.a libevent/native/lib/libevent_pthreads.a"


cd libsodium
if [ ! -d native ]; then
    ./autogen.sh
    mkdir -p native
    ./configure --enable-minimal --disable-shared --prefix=$(pwd)/native
    make clean
    make -j`nproc` check
    make -j`nproc` install
fi
cd ..
LIBSODIUM_CFLAGS=-Ilibsodium/native/include
LIBSODIUM=libsodium/native/lib/libsodium.a


cd libutp
test -f libutp.a || (make clean && OPT=-O2 CPPFLAGS="-fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all" make -j`nproc` libutp.a)
cd ..
LIBUTP_CFLAGS=-Ilibutp
LIBUTP=libutp/libutp.a


LIBBLOCKSRUNTIME_CFLAGS=
LIBBLOCKSRUNTIME=
if ! echo -e "#include <Block.h>\nint main() { Block_copy(^{}); }"|clang -x c -fblocks - 2>/dev/null; then
    cd blocksruntime
    if [ ! -f native/libBlocksRuntime.a ]; then
        ./buildlib
        mkdir native
        mv libBlocksRuntime.a native
    fi
    cd ..
    LIBBLOCKSRUNTIME_CFLAGS=-Iblocksruntime/BlocksRuntime
    LIBBLOCKSRUNTIME=blocksruntime/native/libBlocksRuntime.a
fi

FLAGS="-g -Werror -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -Wno-error=shadow -Wfatal-errors \
  -fPIC -fblocks -fdata-sections -ffunction-sections \
  -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
  -D__FAVOR_BSD -D_BSD_SOURCE -D_DEFAULT_SOURCE"
# -fvisibility=hidden -fvisibility-inlines-hidden -flto=thin \
if [ ! -z ${DEBUG+x} ]; then
    FLAGS="$FLAGS -O0 -DDEBUG=1 -fsanitize=address -fsanitize=undefined --coverage"
else
    FLAGS="$FLAGS -O0 -fsanitize=address -fsanitize=undefined"
fi

CFLAGS="$FLAGS -std=gnu17"
if uname|grep -i Darwin >/dev/null; then
    CFLAGS="$CFLAGS -fobjc-arc -fmodules"
fi

LRT=
echo "int main() {}"|clang -x c - -lrt 2>/dev/null && LRT="-lrt"
LM=
echo -e "#include <math.h>\nint main() { log(2); }"|clang -x c - 2>/dev/null || LM="-lm"

CDEPS="$PARSON_CFLAGS $LIBUTP_CFLAGS $LIBEVENT_CFLAGS $LIBSODIUM_CFLAGS $LIBBLOCKSRUNTIME_CFLAGS"
CLIBS="$LRT $LM $LIBUTP $LIBEVENT $LIBSODIUM $LIBBLOCKSRUNTIME -lpthread"

rm -f *.o || true
clang $CFLAGS -c dht/dht.c -o dht_dht.o
clang $CFLAGS -c parson/parson.c -o parson.o
for file in backtrace.c d2d.c dht.c bev_splice.c base64.c http.c log.c lsd.c icmp_handler.c hash_table.c \
            merkle_tree.c network.c obfoo.c sha1.c stall_detector.c timer.c thread.c bufferevent_utp.c; do
    clang $CFLAGS $CDEPS -c $file
done

clang $CFLAGS $CDEPS -o injector injector.c *.o $CLIBS

clang $CFLAGS $CDEPS -c dns_prefetch.c
case $(uname -s):$(uname -m) in
    Darwin:*) 
        clang $CFLAGS $CDEPS -c dns_prefetch_macos.c
        clang $CFLAGS $CDEPS -I. -c ios/HTTPSRequest.m
        CLIBS="$CLIBS -framework Foundation"
        ;;
    *)
        clang $CFLAGS $CDEPS -c https_wget.c
        ;;
esac
clang $CFLAGS $CDEPS -c client.c
clang $CFLAGS $CDEPS -o client client_main.c *.o $CLIBS
