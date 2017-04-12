cd libutp
make
cd ..

cd libbtdht
bjam toolset=clang cxxflags="-std=c++14"
# XXX: how do you specify the output dir for bjam?
cp `find bin -name libbtdht.a` .
cd ..

FLAGS="-g -O3 -Werror -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Werror=shadow \
  -fPIC -fblocks -fdata-sections -ffunction-sections \
  -fno-rtti -fno-exceptions -fno-common -fno-inline -fno-optimize-sibling-calls -funwind-tables -fno-omit-frame-pointer -fstack-protector-all \
  -std=gnu11 -D__FAVOR_BSD -D_BSD_SOURCE"

CFLAGS="$FLAGS -std=gnu11"
CPPFLAGS="$FLAGS -std=c++14"

echo "int main() {}"|$CC -x c - -lrt 2>/dev/null
if [ $? -eq 0 ]; then
    LRT="-lrt"
fi

clang $CPPFLAGS -c dht.cpp -I ./libbtdht/src -I ./libbtdht/btutils/src 
clang $CFLAGS -o injector injector.c log.c icmp_handler.c network.c dht.o \
  -I ./libutp libutp/libutp.a \
  ./libbtdht/libbtdht.a ./libbtdht/btutils/libbtutils.a \
  `pkg-config --cflags libsodium` `pkg-config --libs libsodium` \
  -lc++ $LRT
