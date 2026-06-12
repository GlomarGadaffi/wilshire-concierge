# CMakeLists.txt for Dropbear component in ESP-IDF

# Get all tommath sources
file(GLOB TOMMATH_SRCS "dropbear/libtommath/*.c")

# Get all tomcrypt sources
file(GLOB_RECURSE TOMCRYPT_SRCS "dropbear/libtomcrypt/src/**/*.c")
list(REMOVE_ITEM TOMCRYPT_SRCS 
    "${CMAKE_CURRENT_SOURCE_DIR}/dropbear/libtomcrypt/src/math/gmp_desc.c" 
    "${CMAKE_CURRENT_SOURCE_DIR}/dropbear/libtomcrypt/src/math/tfm_desc.c"
)

set(DROPBEAR_SRCS
    "dbutil.c"
    "ssh.c"
    "aes_enc.c"
    "dropbear/atomicio.c"
    "dropbear/bignum.c"
    "dropbear/buffer.c"
    "dropbear/circbuffer.c"
    "dropbear/common-algo.c"
    "dropbear/common-channel.c"
    "dropbear/common-chansession.c"
    "dropbear/common-kex.c"
    "dropbear/common-runopts.c"
    "dropbear/common-session.c"
    "dropbear/crypto_desc.c"
    "dbrandom-esp.c"
    "dropbear/ecc.c"
    "dropbear/ecdsa.c"
    "dropbear/ed25519.c"
    "dropbear/curve25519.c"
    "dropbear/chachapoly.c"
    "dropbear/gcm.c"
    "dropbear/dh_groups.c"
    "dropbear/dss.c"
    "dropbear/rsa.c"
    "dropbear/list.c"
    "dropbear/listener.c"
    "dropbear/packet.c"
    "dropbear/process-packet.c"
    "dropbear/queue.c"
    "dropbear/signkey.c"
    "dropbear/keyimport.c"
    "dropbear/netio.c"
    # server files
    "dropbear/svr-agentfwd.c"
    "svr-auth-esp.c"
    "dropbear/svr-authpasswd.c"
    "dropbear/svr-authpubkey.c"
    "dropbear/svr-authpubkeyoptions.c"
    "dropbear/svr-kex.c"
    "dropbear/svr-runopts.c"
    "dropbear/svr-service.c"
    "dropbear/svr-session.c"
    "svr-chansession-esp.c"
    "dropbear/tcp-accept.c"
    "dropbear/termcodes.c"
)

idf_component_register(
    SRCS
        ${DROPBEAR_SRCS}
        ${TOMMATH_SRCS}
        ${TOMCRYPT_SRCS}
    INCLUDE_DIRS
        "."
        "dropbear"
        "dropbear/libtomcrypt/src/headers"
        "dropbear/libtommath"
    REQUIRES
        nvs_flash
        lwip
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    DROPBEAR_SERVER
    LOCALOPTIONS_H_EXISTS
)

target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wno-pointer-sign
    -Wno-unused-function
    -Wno-type-limits
    -Wno-unused-variable
    -Wno-unused-but-set-variable
    -Wno-deprecated-declarations
)
