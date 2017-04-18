cmake_minimum_required (VERSION 2.8)
################################################################################
set(CMAKE_BUILD_TYPE Debug)
include(ExternalProject)
################################################################################

if(NOT UTP_REPO)
    set(UTP_REPO "https://github.com/clostra/libutp")
endif()

if(NOT DHT_REPO)
    set(DHT_REPO "https://github.com/clostra/libbtdht")
endif()

externalproject_add(libutp
    GIT_REPOSITORY ${UTP_REPO}
    BUILD_COMMAND ${MAKE}
    BUILD_IN_SOURCE 1
    UPDATE_COMMAND ""
    INSTALL_COMMAND ""
    CONFIGURE_COMMAND ""
    PREFIX "libutp")

externalproject_add(libbtdht
    GIT_REPOSITORY ${DHT_REPO}
    BUILD_COMMAND make -f makefile.gcc product
    BUILD_IN_SOURCE 1
    UPDATE_COMMAND ""
    INSTALL_COMMAND ""
    CONFIGURE_COMMAND ""
    PREFIX "libbtdht")

externalproject_add(libevent
    URL https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz
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

################################################################################
# dependencies:
#    libblocksruntime-dev
################################################################################
project (dcdn)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fblocks")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -Wall -fblocks -std=c++14")

include_directories(
    "${UTP_DIR}"
    "${DHT_DIR}/src"
    "${UTIL_DIR}/src"
    "${EVT_DIR}/include"
    "${CMAKE_SOURCE_DIR}")

file(GLOB sources
    "${CMAKE_SOURCE_DIR}/*.cpp"
    "${CMAKE_SOURCE_DIR}/*.c"
    )

add_executable(dcdn ${sources})

add_dependencies(dcdn libutp libbtdht)

target_link_libraries(dcdn
    ${UTP_DIR}/libutp.a
    ${DHT_DIR}/obj-unicode-debug-O0/libutdht.so
    ${EVT_DIR}/.libs/libevent.a
    ${EVT_DIR}/.libs/libevent_pthreads.a
    pthread
    BlocksRuntime
    sodium)

################################################################################
