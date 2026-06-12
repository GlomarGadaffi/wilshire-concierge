/*
 * AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8) for TLS 1.3.
 * IETF ChaCha20 keystream (glo_chacha20) + tinynacl Poly1305 one-time MAC.
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 GlomarGadaffi
 */
#include "glo_mtls_crypto.h"
#include <stdlib.h>
#include <string.h>

#include "crypto_onetimeauth_poly1305.h"   /* tinynacl Poly1305 */
#include "crypto_verify_16.h"              /* constant-time 16-byte compare */

static void store64_le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) { p[i] = (uint8_t)v; v >>= 8; }
}

/* tag = Poly1305_otk( aad || pad16 || ct || pad16 || le64(aadlen) || le64(ctlen) ) */
static int poly_tag(uint8_t tag[16], const uint8_t otk[32],
                    const uint8_t *aad, size_t aadlen,
                    const uint8_t *ct, size_t ctlen) {
    size_t apad = (16 - (aadlen & 15)) & 15;
    size_t cpad = (16 - (ctlen & 15)) & 15;
    size_t mlen = aadlen + apad + ctlen + cpad + 16;
    uint8_t *m = calloc(1, mlen ? mlen : 1);
    size_t o = 0;
    if (!m) return -1;
    if (aadlen) { memcpy(m + o, aad, aadlen); }
    o += aadlen + apad;
    if (ctlen)  { memcpy(m + o, ct, ctlen); }
    o += ctlen + cpad;
    store64_le(m + o, (uint64_t)aadlen);
    store64_le(m + o + 8, (uint64_t)ctlen);
    crypto_onetimeauth_poly1305(tag, m, mlen, otk);
    memset(m, 0, mlen);
    free(m);
    return 0;
}

int glo_aead_seal(uint8_t *ct, uint8_t tag[16],
                  const uint8_t *pt, size_t ptlen,
                  const uint8_t *aad, size_t aadlen,
                  const uint8_t key[32], const uint8_t nonce[12]) {
    uint8_t otk[32];
    /* Poly1305 one-time key = first 32 bytes of ChaCha20 keystream, counter 0 */
    glo_chacha20_xor(otk, NULL, 32, key, nonce, 0);
    /* payload encrypted starting at counter 1 */
    glo_chacha20_xor(ct, pt, ptlen, key, nonce, 1);
    int rc = poly_tag(tag, otk, aad, aadlen, ct, ptlen);
    memset(otk, 0, sizeof otk);
    return rc;
}

int glo_aead_open(uint8_t *pt,
                  const uint8_t *ct, size_t ctlen, const uint8_t tag[16],
                  const uint8_t *aad, size_t aadlen,
                  const uint8_t key[32], const uint8_t nonce[12]) {
    uint8_t otk[32], expect[16];
    int rc;
    glo_chacha20_xor(otk, NULL, 32, key, nonce, 0);
    rc = poly_tag(expect, otk, aad, aadlen, ct, ctlen);
    memset(otk, 0, sizeof otk);
    if (rc != 0) return -1;
    /* crypto_verify_16 returns 0 iff equal — constant-time */
    if (crypto_verify_16(expect, tag) != 0) return -1;
    glo_chacha20_xor(pt, ct, ctlen, key, nonce, 1);
    return 0;
}
