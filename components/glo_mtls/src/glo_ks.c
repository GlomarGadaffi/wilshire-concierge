/*
 * TLS 1.3 key schedule (RFC 8446 §7.1) on HKDF-SHA256.
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 GlomarGadaffi
 */
#include "glo_tls13.h"
#include "glo_mtls_crypto.h"
#include <string.h>

#define HLEN 32

static void empty_hash(uint8_t out[32]) {
    glo_sha256(out, (const uint8_t *)"", 0);
}

void glo_ks_early_secret(uint8_t early[32], const uint8_t *psk, size_t psklen) {
    uint8_t zeros[HLEN];
    memset(zeros, 0, HLEN);
    if (!psk || psklen == 0) { psk = zeros; psklen = HLEN; }
    /* Early Secret = HKDF-Extract(salt=0, IKM=PSK) */
    glo_hkdf_extract(early, NULL, 0, psk, psklen);
}

void glo_ks_derive_secret(uint8_t out[32], const uint8_t secret[32],
                          const char *label, const uint8_t transcript_hash[32]) {
    /* Derive-Secret = HKDF-Expand-Label(secret, label, Transcript-Hash, Hash.length) */
    glo_hkdf_expand_label(out, HLEN, secret, label, transcript_hash, HLEN);
}

void glo_ks_handshake_secret(uint8_t hs[32], const uint8_t early[32],
                             const uint8_t ecdhe[32]) {
    uint8_t eh[HLEN], derived[HLEN];
    empty_hash(eh);
    glo_hkdf_expand_label(derived, HLEN, early, "derived", eh, HLEN);
    /* Handshake Secret = HKDF-Extract(salt=Derive-Secret(.,"derived",""), IKM=ECDHE) */
    glo_hkdf_extract(hs, derived, HLEN, ecdhe, HLEN);
    memset(derived, 0, sizeof derived);
}

void glo_ks_master_secret(uint8_t ms[32], const uint8_t hs[32]) {
    uint8_t eh[HLEN], derived[HLEN], zeros[HLEN];
    memset(zeros, 0, HLEN);
    empty_hash(eh);
    glo_hkdf_expand_label(derived, HLEN, hs, "derived", eh, HLEN);
    /* Master Secret = HKDF-Extract(salt=derived, IKM=0) */
    glo_hkdf_extract(ms, derived, HLEN, zeros, HLEN);
    memset(derived, 0, sizeof derived);
}

void glo_ks_traffic_key_iv(uint8_t key[32], uint8_t iv[12],
                           const uint8_t traffic_secret[32]) {
    glo_hkdf_expand_label(key, GLO_TLS13_KEY_LEN, traffic_secret, "key", NULL, 0);
    glo_hkdf_expand_label(iv, GLO_TLS13_IV_LEN, traffic_secret, "iv", NULL, 0);
}

void glo_ks_finished_key(uint8_t fk[32], const uint8_t traffic_secret[32]) {
    glo_hkdf_expand_label(fk, HLEN, traffic_secret, "finished", NULL, 0);
}
