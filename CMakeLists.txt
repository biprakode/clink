cmake_minimum_required(VERSION 3.10)
project(clink C)

set(CMAKE_C_STANDARD 11)

# common source files — every target needs these
set(CLINK_COMMON_SRCS
        src/bignum.c
        src/dh.c
        src/aes.c
        src/sha256.c
        src/kdf.c
        src/net.c
        src/tunnel.c)

# --- the actual clink binaries ---
add_executable(clink_server src/main_server.c ${CLINK_COMMON_SRCS})
add_executable(clink_client src/main_client.c ${CLINK_COMMON_SRCS})

# --- tests ---
add_executable(bignum_test src/tests/bignum_test.c src/bignum.c)
add_executable(dh_test src/tests/dh_test.c src/bignum.c src/dh.c)
add_executable(aes_test src/tests/aes_test.c src/aes.c)
add_executable(sha256_test src/tests/sha256_test.c src/sha256.c)
add_executable(net_test src/tests/net_test.c src/net.c)
add_executable(tunnel_test src/tests/tunnel_test.c ${CLINK_COMMON_SRCS})
