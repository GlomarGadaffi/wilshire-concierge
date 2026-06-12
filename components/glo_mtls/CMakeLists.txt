# glo_mtls — GloSSH outbound mTLS client (scaffold)
#
# Roadmap component: a minimal, permissively-licensed TLS 1.3 client built on
# the public-domain crypto already vendored with Dropbear (LibTomCrypt /
# LibTomMath). No upstream TLS library, no Apache-2.0 / wolfSSL dependency.
#
# Currently header-only (API surface only, no implementation yet). Sources are
# added to SRCS as the record layer and handshake state machine land.

idf_component_register(
    SRCS
    INCLUDE_DIRS "include"
    REQUIRES dropbear        # for LibTomCrypt/LibTomMath primitives
)
