/*
 * IETF ChaCha20 (RFC 8439 §2.4) — 96-bit nonce, 32-bit block counter.
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 GlomarGadaffi
 */
#include "glo_mtls_crypto.h"

static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

#define QR(a, b, c, d)              \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d, 8);  \
    c += d; b ^= c; b = rotl32(b, 7);

static void chacha20_block(uint8_t out[64], const uint32_t in[16]) {
    uint32_t x[16];
    int i;
    for (i = 0; i < 16; i++) x[i] = in[i];
    for (i = 0; i < 10; i++) {       /* 10 double-rounds = 20 rounds */
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }
    for (i = 0; i < 16; i++) store32_le(out + 4 * i, x[i] + in[i]);
}

void glo_chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                      const uint8_t key[32], const uint8_t nonce[12],
                      uint32_t counter) {
    uint32_t state[16];
    uint8_t ks[64];
    int i;

    state[0] = 0x61707865; state[1] = 0x3320646e;   /* "expand 32-byte k" */
    state[2] = 0x79622d32; state[3] = 0x6b206574;
    for (i = 0; i < 8; i++) state[4 + i] = load32_le(key + 4 * i);
    state[12] = counter;
    state[13] = load32_le(nonce + 0);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    while (len > 0) {
        size_t n = len < 64 ? len : 64;
        size_t j;
        chacha20_block(ks, state);
        for (j = 0; j < n; j++) out[j] = (uint8_t)((in ? in[j] : 0) ^ ks[j]);
        out += n;
        if (in) in += n;
        len -= n;
        state[12]++;                 /* next block */
    }
}
