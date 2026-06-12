/*
 * glo_mtls — GloSSH outbound mutual-TLS client (API scaffold)
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 GlomarGadaffi
 *
 * STATUS: scaffold / not yet implemented.
 *
 * Goal: a small, permissively-licensed TLS 1.3 *client* for ESP-IDF, built on
 * the public-domain primitives already vendored with Dropbear (LibTomCrypt:
 * X25519/ECDHE, AES-GCM, ChaCha20-Poly1305, SHA-2, RSA/ECDSA verify). It exists
 * to replace wolfSSL/mbedTLS for the one surface drawbridge needs: outbound-only
 * mutual TLS to an operator-owned media anchor.
 *
 * Deliberately NOT a general-purpose TLS library: client-only, version-pinned,
 * AEAD-only, with mandatory peer-certificate + SAN validation and client-cert
 * (mTLS) presentation. Server-side TLS is explicitly out of scope.
 */
#ifndef GLO_MTLS_H
#define GLO_MTLS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct glo_mtls_ctx glo_mtls_ctx;

typedef struct {
    const char   *server_name;        /* SNI + SAN verification target        */
    const uint8_t *ca_cert_pem;       /* trust anchor(s) for the peer chain    */
    size_t        ca_cert_pem_len;
    const uint8_t *client_cert_pem;   /* our identity for mTLS                  */
    size_t        client_cert_pem_len;
    const uint8_t *client_key_pem;    /* our private key (DER/PEM)             */
    size_t        client_key_pem_len;
} glo_mtls_config;

/* Establish an outbound mTLS 1.3 connection over an existing TCP socket fd.
 * Returns 0 on success. NOT YET IMPLEMENTED. */
int glo_mtls_connect(glo_mtls_ctx **out, int sockfd, const glo_mtls_config *cfg);

int  glo_mtls_write(glo_mtls_ctx *ctx, const void *buf, size_t len);
int  glo_mtls_read(glo_mtls_ctx *ctx, void *buf, size_t len);
void glo_mtls_close(glo_mtls_ctx *ctx);

/* Run the crypto backend self-test (RFC KATs + round-trips).
 * Returns the number of failures; 0 means the TLS 1.3 crypto is byte-correct. */
int glo_mtls_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* GLO_MTLS_H */
