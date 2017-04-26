cmake_minimum_required (VERSION 2.8)
################################################################################
set(CMAKE_BUILD_TYPE Debug)
include(ExternalProject)
################################################################################

externalproject_add(libutp
    URL "${CMAKE_SOURCE_DIR}/libutp"
    BUILD_COMMAND ${MAKE}
    BUILD_IN_SOURCE 1
    UPDATE_COMMAND ""
    INSTALL_COMMAND ""
    CONFIGURE_COMMAND ""
    PREFIX "libutp")

externalproject_add(libbtdht
    URL "${CMAKE_SOURCE_DIR}/libbtdht"
    BUILD_COMMAND make -f makefile.gcc product
    BUILD_IN_SOURCE 1
    UPDATE_COMMAND ""
    INSTALL_COMMAND ""
    CONFIGURE_COMMAND ""
    PREFIX "libbtdht")

externalproject_add(libevent
    URL https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz
    #DOWNLOAD_COMMAND ""
    #SOURCE_DIR /home/peter/work/libevent-2.1.8-stable/
    BUILD_IN_SOURCE 1
    BUILD_COMMAND ${MAKE}
    UPDATE_COMMAND ""
    INSTALL_COMMAND ""
    CONFIGURE_COMMAND ./configure
    PREFIX "libevent")

################################################################################
set(UTP_DIR "${CMAKE_BINARY_DIR}/libutp/src/libutp")
set(DHT_DIR "${CMAKE_BINARY_DIR}/libbtdht/src/libbtdht")
set(UTIL_DIR "${DHT_DIR}/btutils")
set(EVT_DIR "${CMAKE_BINARY_DIR}/libevent/src/libevent")
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

set(C_FLAGS "${CMAKE_C_FLAGS} -Wall -fblocks -Werror")
set(CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fblocks -std=c++14 -Werror")

set(COMMON_INCLUDE
    "${UTP_DIR}"
    "${DHT_DIR}/src"
    "${UTIL_DIR}/src"
    "${EVT_DIR}/include"
    "${CMAKE_SOURCE_DIR}")

################################################################################
# dependencies:
#    libblocksruntime-dev
################################################################################
project (dcdn)

include_directories(${COMMON_INCLUDE})

file(GLOB sources
    "${CMAKE_SOURCE_DIR}/*.cpp"
    "${CMAKE_SOURCE_DIR}/*.c"
    )

# The file injector.c contains the `main` function and thus can't be included
# in the resulting library.
list(REMOVE_ITEM sources "${CMAKE_SOURCE_DIR}/injector.c")

set(CMAKE_C_FLAGS "${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CXX_FLAGS}")

add_library(dcdn STATIC ${sources})

add_dependencies(dcdn libutp libbtdht libevent)

################################################################################
project (proxy)

set(CMAKE_C_FLAGS "${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CXX_FLAGS}")

include_directories(${COMMON_INCLUDE})

file(GLOB sources "${CMAKE_SOURCE_DIR}/apps/proxy.c")

add_executable(proxy ${sources})

add_dependencies(proxy dcdn)

target_link_libraries(proxy
    dcdn
    ${UTP_DIR}/libutp.a
    ${DHT_DIR}/obj-unicode-debug-O0/libutdht.so
    ${EVT_DIR}/.libs/libevent.a
    ${EVT_DIR}/.libs/libevent_pthreads.a
    pthread
    BlocksRuntime
    sodium)

################################################################################
