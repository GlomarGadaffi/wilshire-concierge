# CMakeLists.txt for TinySSH component in ESP-IDF

# Dynamically generate empty stub headers for unsupported POSIX/system features
foreach(header
    hasmlock.h
    haslibutilh.h
    hasutilh.h
    hasopenpty.h
    haslogintty.h
    hasutmpx.h
    hasutmpxupdwtmpx.h
    hasutmpxsyslen.h
    hasutmp.h
    hasutmpname.h
    hasutmpuser.h
    hasutmphost.h
    hasutmptime.h
    hasutmptv.h
    hasutmppid.h
    hasutmptype.h
    hasutmplogwtmp.h
    hasutmploginlogout.h
)
    if(NOT EXISTS "${CMAKE_CURRENT_BINARY_DIR}/${header}")
        file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${header}" "")
    endif()
endforeach()

# Also generate the base crypto.h header including all tinyssh crypto primitives
set(crypto_h_content "
#ifndef _CRYPTO_H____
#define _CRYPTO_H____
#include \"crypto_stream_chacha20.h\"
#include \"crypto_onetimeauth_poly1305.h\"
#include \"crypto_hash_sha512.h\"
#include \"crypto_hash_sha256.h\"
#include \"crypto_verify_16.h\"
#include \"crypto_verify_32.h\"
#include \"crypto_scalarmult_curve25519.h\"
#include \"crypto_sign_ed25519.h\"
#include \"crypto_sort_uint32.h\"
#include \"crypto_kem_sntrup761.h\"
#include \"crypto_kem_sntrup761x25519.h\"
#endif
")
if(NOT EXISTS "${CMAKE_CURRENT_BINARY_DIR}/crypto.h")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/crypto.h" "${crypto_h_content}")
endif()

# Glob all tinyssh sources
file(GLOB TINYSSH_CORE_SRCS "tinyssh/tinyssh/*.c")
file(GLOB TINYSSH_CRYPTO_SRCS "tinyssh/crypto/*.c")

# Filter out main-bearing files and POSIX layers we are replacing
list(REMOVE_ITEM TINYSSH_CORE_SRCS
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/tinysshd.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/tinysshd-makekey.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/tinysshd-printkey.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/main_tinysshd_makekey.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/main_tinysshd_printkey.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/channel.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/channel_fork.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/channel_forkpty.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/dropuidgid.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/load.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/subprocess_auth.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/subprocess_sign.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/open.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/global.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/packet.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/main_tinysshd.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/tinyssh/sshcrypto_cipher_chachapoly.c"
)

list(REMOVE_ITEM TINYSSH_CRYPTO_SRCS
    "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh/crypto/randombytes.c"
)

# Custom ESP-IDF porting sources
set(PORT_SRCS
    "port_random.c"
    "port_load.c"
    "port_sign.c"
    "port_auth.c"
    "port_channel.c"
    "port_listener.c"
    "port_global.c"
    "port_packet.c"
    "port_main_tinysshd.c"
    "port_sshcrypto_cipher_chachapoly.c"
)

# Register component
idf_component_register(
    SRCS
        ${TINYSSH_CORE_SRCS}
        ${TINYSSH_CRYPTO_SRCS}
        ${PORT_SRCS}
    INCLUDE_DIRS
        "."
        "tinyssh/tinyssh"
        "tinyssh/crypto"
        "${CMAKE_CURRENT_BINARY_DIR}"
    REQUIRES
        nvs_flash
        lwip
        esp_hw_support
        esp_wifi
)

# Force-include tinyssh-config.h in all compilation units
target_compile_options(${COMPONENT_LIB} PRIVATE
    -include "${CMAKE_CURRENT_SOURCE_DIR}/tinyssh-config.h"
    -Wno-pointer-sign
    -Wno-unused-function
    -Wno-unused-variable
    -Wno-unused-parameter
    -Wno-unused-but-set-parameter
    -Wno-type-limits
)
