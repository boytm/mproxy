cmake_minimum_required (VERSION 2.8)
project(mproxy)

set(MPROXY_MAJOR_VERSION 0)
set(MPROXY_MINOR_VERSION 1)
set(MPROXY_PATCH_VERSION 11)

set(CMAKE_VERBOSE_MAKEFILE on)

#set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -g -O0")
#set(CMAKE_C_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall -O2")

# -DENABLE_SS:STRING=ON
OPTION(ENABLE_SS "Enable shadowsocks protocol" ON)
# -DUSE_CRYPTO_OPENSSL:STRING=ON
OPTION(USE_CRYPTO_OPENSSL "Use OpenSSL crypt library" ON)
#OPTION(USE_CRYPTO_MBEDTLS "Use mbed TLS/PolarSSL crypt library" OFF)

# add source files to DIR_SRCS
aux_source_directory(. DIR_SRCS)

# libevhtp subdir
set(EVHTP_DISABLE_SSL ON)
set(EVHTP_DISABLE_EVTHR ON)
set(EVHTP_DISABLE_REGEX ON)
add_subdirectory(libevhtp)

include_directories(libevhtp)

set(MPROXY_SOURCES connector.c evhtp_proxy.c  evhtp_sock_relay.c)
if (ENABLE_SS)
        add_definitions(-DENABLE_SS=1)
        set (MPROXY_SOURCES ${MPROXY_SOURCES} ss_connector.c encrypt.c )
endif(ENABLE_SS)
if (USE_CRYPTO_OPENSSL)
	find_package(OpenSSL)
        add_definitions(-DUSE_CRYPTO_OPENSSL=1)
        set (MPROXY_LIBS ${MPROXY_LIBS} crypto)
#elseif (USE_CRYPTO_MBEDTLS)
#	#find_package(PolarSSL)
#	find_path(LIBMBED_INCLUDE_DIR mbedtls/cipher.h REQUIRED)
#	include_directories(${LIBMBED_INCLUDE_DIR})
#	find_library(HAS_MBED mbedtls)
#        add_definitions(-DUSE_CRYPTO_MBEDTLS=1)
#        set (MPROXY_LIBS ${MPROXY_LIBS} mbedcrypto)
endif(USE_CRYPTO_OPENSSL)

add_executable(mproxy ${MPROXY_SOURCES} )
target_link_libraries(mproxy evhtp ${MPROXY_LIBS} rt )

message("")
message(STATUS "${Blue}CMAKE_BUILD_TYPE${ColourReset}         : " ${BoldRed}${CMAKE_BUILD_TYPE}${ColourReset})
