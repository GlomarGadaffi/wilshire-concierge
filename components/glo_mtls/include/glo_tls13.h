/*
 * glo_tls13 — TLS 1.3 key schedule (RFC 8446 §7.1) and record layer (§5.2/5.3).
 * Built on glo_mtls_crypto (HKDF-SHA256 + ChaCha20-Poly1305).
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 GlomarGadaffi
 */
#ifndef GLO_TLS13_H
#define GLO_TLS13_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GLO_TLS13_SECRET_LEN 32   /* SHA-256 */
#define GLO_TLS13_KEY_LEN    32   /* ChaCha20 */
#define GLO_TLS13_IV_LEN     12

/* ---- Key schedule (RFC 8446 §7.1) --------------------------------------- *
 * All secrets are 32 bytes (Hash.length for SHA-256). Compose as:
 *   early  = early_secret(psk)              ; psk NULL => 0
 *   hs     = handshake_secret(early, ecdhe)
 *   chts   = derive_secret(hs, "c hs traffic", transcript_hash(CH..SH))
 *   ms     = master_secret(hs)
 *   cats   = derive_secret(ms, "c ap traffic", transcript_hash(CH..SF))
 * then per-secret: traffic_key_iv() and finished_key().
 */
void glo_ks_early_secret(uint8_t early[32], const uint8_t *psk, size_t psklen);
void glo_ks_derive_secret(uint8_t out[32], const uint8_t secret[32],
                          const char *label, const uint8_t transcript_hash[32]);
void glo_ks_handshake_secret(uint8_t hs[32], const uint8_t early[32],
                             const uint8_t ecdhe[32]);
void glo_ks_master_secret(uint8_t ms[32], const uint8_t hs[32]);
void glo_ks_traffic_key_iv(uint8_t key[32], uint8_t iv[12],
                           const uint8_t traffic_secret[32]);
void glo_ks_finished_key(uint8_t fk[32], const uint8_t traffic_secret[32]);

/* ---- Record layer (RFC 8446 §5.2/5.3) ----------------------------------- *
 * TLSCiphertext = opaque_type(0x17) || legacy_version(0x0303) || length(u16)
 *                 || AEAD(inner), inner = content || content_type || pad(0).
 * AAD is the 5-byte record header; nonce = iv XOR (0^4 || seq_be64).
 *
 * seal: `out` must hold contentlen + 1 (type) + 16 (tag) + 5 (header) bytes.
 * open: `content` must hold at least recordlen bytes; strips padding and
 *       returns the inner content_type. Returns 0 on success, <0 on error
 *       (incl. AEAD auth failure). `seq` is the record sequence number. */
#define GLO_RECORD_OVERHEAD 21   /* 5 header + 1 type + 15 max we never exceed (5+1+16=22 worst tag) */
int glo_record_seal(uint8_t *out, size_t *outlen,
                    const uint8_t *content, size_t contentlen, uint8_t content_type,
                    const uint8_t key[32], const uint8_t iv[12], uint64_t seq);
int glo_record_open(uint8_t *content, size_t *contentlen, uint8_t *content_type,
                    const uint8_t *record, size_t recordlen,
                    const uint8_t key[32], const uint8_t iv[12], uint64_t seq);

#ifdef __cplusplus
}
#endif

#endif /* GLO_TLS13_H */
