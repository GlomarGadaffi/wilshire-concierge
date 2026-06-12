/*
 * glo_mtls crypto self-test: RFC known-answer vectors + round-trips.
 * Proves the TLS 1.3 crypto backend (on TinySSH primitives) is byte-correct
 * on-device. Run once at boot; returns the number of failures (0 = all good).
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 GlomarGadaffi
 */
#include "glo_mtls.h"
#include "glo_mtls_crypto.h"
#include "glo_kat_vectors.h"
#include "crypto_sign_ed25519.h"
#include <stdio.h>
#include <string.h>

static int check(const char *name, const uint8_t *got, const uint8_t *want, size_t n) {
    int ok = (memcmp(got, want, n) == 0);
    printf("[glo_mtls]  %-20s %s\n", name, ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

static int boolcheck(const char *name, int ok) {
    printf("[glo_mtls]  %-20s %s\n", name, ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

int glo_mtls_selftest(void) {
    int fails = 0;
    uint8_t buf[64];

    printf("[glo_mtls] crypto self-test (TinySSH primitives, RFC KATs)\n");

    /* SHA-256 KAT */
    glo_sha256(buf, (const uint8_t *)"abc", 3);
    fails += check("sha256(abc)", buf, KAT_SHA256_ABC, 32);

    /* HKDF RFC 5869 Test Case 1 */
    uint8_t prk[32], okm[42];
    glo_hkdf_extract(prk, KAT_HKDF_SALT, sizeof KAT_HKDF_SALT,
                     KAT_HKDF_IKM, sizeof KAT_HKDF_IKM);
    fails += check("hkdf-extract", prk, KAT_HKDF_PRK, 32);
    glo_hkdf_expand(okm, sizeof okm, prk, KAT_HKDF_INFO, sizeof KAT_HKDF_INFO);
    fails += check("hkdf-expand", okm, KAT_HKDF_OKM, sizeof okm);

    /* HKDF-Expand-Label smoke (TLS 1.3 key schedule path) */
    uint8_t klabel[16];
    fails += boolcheck("hkdf-expand-label",
                       glo_hkdf_expand_label(klabel, sizeof klabel, prk, "key", NULL, 0) == 0);

    /* X25519 RFC 7748 KAT */
    uint8_t sh[32];
    glo_x25519(sh, KAT_X25519_SCALAR, KAT_X25519_U);
    fails += check("x25519 kat", sh, KAT_X25519_OUT, 32);

    /* X25519 ECDH agreement round-trip */
    uint8_t ask[32], bsk[32], apk[32], bpk[32], ss1[32], ss2[32];
    for (int i = 0; i < 32; i++) { ask[i] = (uint8_t)(i + 1); bsk[i] = (uint8_t)(0x40 + i); }
    glo_x25519_base(apk, ask); glo_x25519_base(bpk, bsk);
    glo_x25519(ss1, ask, bpk); glo_x25519(ss2, bsk, apk);
    fails += check("x25519 ecdh agree", ss1, ss2, 32);

    /* AEAD ChaCha20-Poly1305 RFC 8439 §2.8.2 KAT */
    uint8_t ct[sizeof KAT_AEAD_PT], tag[16], pt2[sizeof KAT_AEAD_PT];
    glo_aead_seal(ct, tag, KAT_AEAD_PT, sizeof KAT_AEAD_PT,
                  KAT_AEAD_AAD, sizeof KAT_AEAD_AAD, KAT_AEAD_KEY, KAT_AEAD_NONCE);
    fails += check("aead seal ct", ct, KAT_AEAD_CT, sizeof KAT_AEAD_CT);
    fails += check("aead seal tag", tag, KAT_AEAD_TAG, 16);

    int op = glo_aead_open(pt2, ct, sizeof ct, tag,
                           KAT_AEAD_AAD, sizeof KAT_AEAD_AAD, KAT_AEAD_KEY, KAT_AEAD_NONCE);
    fails += boolcheck("aead open ok", op == 0);
    fails += check("aead open pt", pt2, KAT_AEAD_PT, sizeof KAT_AEAD_PT);

    tag[0] ^= 1; /* tamper */
    fails += boolcheck("aead tamper-reject",
                       glo_aead_open(pt2, ct, sizeof ct, tag, KAT_AEAD_AAD,
                                     sizeof KAT_AEAD_AAD, KAT_AEAD_KEY, KAT_AEAD_NONCE) != 0);

    /* Ed25519 raw-key auth: sign/open round-trip + tamper-reject */
    unsigned char edpk[32], edsk[64];
    crypto_sign_ed25519_keypair(edpk, edsk);
    const unsigned char msg[3] = { 'g', 'l', 'o' };
    unsigned char sm[64 + 3], om[64 + 3];
    unsigned long long smlen = 0, omlen = 0;
    crypto_sign_ed25519(sm, &smlen, msg, 3, edsk);
    int eo = crypto_sign_ed25519_open(om, &omlen, sm, smlen, edpk);
    fails += boolcheck("ed25519 sign/open", eo == 0 && omlen == 3 && memcmp(om, msg, 3) == 0);
    sm[0] ^= 1;
    fails += boolcheck("ed25519 tamper-rej",
                       crypto_sign_ed25519_open(om, &omlen, sm, smlen, edpk) != 0);

    printf("[glo_mtls] self-test complete: %d failure(s)\n", fails);
    return fails;
}
