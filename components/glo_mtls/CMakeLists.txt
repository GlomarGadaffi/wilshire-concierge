# glo_mtls — GloSSH outbound mTLS 1.3 client
#
# Crypto backend is built on TinySSH's tinynacl primitives (X25519, Poly1305,
# SHA-256, Ed25519) plus a small IETF ChaCha20 (RFC 8439). No libtomcrypt, no
# dropbear, no X.509 — raw-public-key (RFC 7250) Ed25519 peer auth.
#
# Implemented: the TLS 1.3 crypto layer + self-test (KATs).
# Roadmap:     record layer + handshake state machine (glo_mtls_connect/...).

idf_component_register(
    SRCS
        "src/glo_chacha20.c"
        "src/glo_aead.c"
        "src/glo_hkdf.c"
        "src/glo_kex.c"
        "src/glo_ks.c"
        "src/glo_record.c"
        "src/glo_selftest.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src"
    REQUIRES tinyssh        # tinynacl crypto primitives
)
