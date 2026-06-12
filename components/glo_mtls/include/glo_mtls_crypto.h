/*
 * glo_mtls_crypto — TLS 1.3 crypto primitives for GloSSH
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 GlomarGadaffi
 *
 * The load-bearing crypto for a TLS 1.3 (RFC 8446) client, assembled from
 * TinySSH's tinynacl primitives (X25519, Poly1305, SHA-256, Ed25519) plus a
 * small IETF ChaCha20 (RFC 8439) — because tinynacl's ChaCha20 is the DJB
 * 64-bit-nonce variant, while TLS needs the IETF 96-bit-nonce / 32-bit-counter
 * construction.
 *
 * All functions are constant-time where it matters (X25519, Poly1305 verify).
 */
#ifndef GLO_MTLS_CRYPTO_H
#define GLO_MTLS_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- IETF ChaCha20 (RFC 8439 §2.4) -------------------------------------- *
 * XOR `len` bytes of `in` with the ChaCha20 keystream into `out`.
 * `in` may be NULL to produce raw keystream. `counter` is the initial block
 * counter (0 for keystream/Poly1305-key, 1 for AEAD payload). */
void glo_chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                      const uint8_t key[32], const uint8_t nonce[12],
                      uint32_t counter);

/* ---- AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8) ----------------------------- *
 * seal: encrypts pt -> ct (same length) and writes a 16-byte tag.
 * open: verifies tag (constant-time) then decrypts ct -> pt; returns 0 on
 *       success, -1 on auth failure (pt left untouched on failure).
 * ct and pt may alias. Returns 0 on success, <0 on error. */
int glo_aead_seal(uint8_t *ct, uint8_t tag[16],
                  const uint8_t *pt, size_t ptlen,
                  const uint8_t *aad, size_t aadlen,
                  const uint8_t key[32], const uint8_t nonce[12]);
int glo_aead_open(uint8_t *pt,
                  const uint8_t *ct, size_t ctlen, const uint8_t tag[16],
                  const uint8_t *aad, size_t aadlen,
                  const uint8_t key[32], const uint8_t nonce[12]);

/* ---- SHA-256 / HMAC / HKDF (RFC 5869) + HKDF-Expand-Label (RFC 8446) ----- */
#define GLO_SHA256_LEN 32
void glo_sha256(uint8_t out[32], const uint8_t *msg, size_t msglen);
void glo_hmac_sha256(uint8_t mac[32], const uint8_t *key, size_t keylen,
                     const uint8_t *msg, size_t msglen);
void glo_hkdf_extract(uint8_t prk[32], const uint8_t *salt, size_t saltlen,
                      const uint8_t *ikm, size_t ikmlen);
int  glo_hkdf_expand(uint8_t *okm, size_t okmlen, const uint8_t prk[32],
                     const uint8_t *info, size_t infolen);
/* TLS 1.3 HKDF-Expand-Label: label is the bare name; "tls13 " is prepended. */
int  glo_hkdf_expand_label(uint8_t *out, size_t outlen, const uint8_t secret[32],
                           const char *label, const uint8_t *ctx, size_t ctxlen);

/* ---- X25519 (RFC 7748) -------------------------------------------------- */
#define GLO_X25519_LEN 32
int glo_x25519_base(uint8_t pub[32], const uint8_t sk[32]);              /* pub = sk*B   */
int glo_x25519(uint8_t shared[32], const uint8_t sk[32], const uint8_t peer[32]); /* DH */

#ifdef __cplusplus
}
#endif

#endif /* GLO_MTLS_CRYPTO_H */
