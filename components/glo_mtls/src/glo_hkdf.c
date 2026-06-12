/*
 * HMAC-SHA256, HKDF (RFC 5869) and TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
 * SHA-256 backend = TinySSH tinynacl.
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 GlomarGadaffi
 */
#include "glo_mtls_crypto.h"
#include <stdlib.h>
#include <string.h>

#include "crypto_hash_sha256.h"   /* tinynacl SHA-256 (one-shot) */

#define SHA_BLK 64
#define SHA_LEN 32

void glo_sha256(uint8_t out[32], const uint8_t *msg, size_t msglen) {
    crypto_hash_sha256(out, msg, (unsigned long long)msglen);
}

void glo_hmac_sha256(uint8_t mac[32], const uint8_t *key, size_t keylen,
                     const uint8_t *msg, size_t msglen) {
    uint8_t k0[SHA_BLK], ipad[SHA_BLK], opad[SHA_BLK], ihash[SHA_LEN];
    uint8_t obuf[SHA_BLK + SHA_LEN];
    uint8_t *ibuf;
    size_t i;

    memset(k0, 0, SHA_BLK);
    if (keylen > SHA_BLK) glo_sha256(k0, key, keylen);
    else if (keylen)      memcpy(k0, key, keylen);
    for (i = 0; i < SHA_BLK; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }

    /* inner = H(ipad || msg) */
    ibuf = malloc(SHA_BLK + msglen);
    if (!ibuf) { memset(mac, 0, SHA_LEN); return; }   /* fail closed */
    memcpy(ibuf, ipad, SHA_BLK);
    if (msglen) memcpy(ibuf + SHA_BLK, msg, msglen);
    glo_sha256(ihash, ibuf, SHA_BLK + msglen);
    memset(ibuf, 0, SHA_BLK + msglen);
    free(ibuf);

    /* outer = H(opad || inner) */
    memcpy(obuf, opad, SHA_BLK);
    memcpy(obuf + SHA_BLK, ihash, SHA_LEN);
    glo_sha256(mac, obuf, SHA_BLK + SHA_LEN);

    memset(k0, 0, sizeof k0);
    memset(ipad, 0, sizeof ipad);
    memset(opad, 0, sizeof opad);
}

void glo_hkdf_extract(uint8_t prk[32], const uint8_t *salt, size_t saltlen,
                      const uint8_t *ikm, size_t ikmlen) {
    uint8_t zero[SHA_LEN];
    if (!salt || saltlen == 0) { memset(zero, 0, sizeof zero); salt = zero; saltlen = sizeof zero; }
    glo_hmac_sha256(prk, salt, saltlen, ikm, ikmlen);
}

int glo_hkdf_expand(uint8_t *okm, size_t okmlen, const uint8_t prk[32],
                    const uint8_t *info, size_t infolen) {
    uint8_t t[SHA_LEN];
    uint8_t *buf;
    size_t tlen = 0, done = 0;
    uint8_t counter = 1;

    if (okmlen > 255 * SHA_LEN) return -1;     /* RFC 5869 limit */
    buf = malloc(SHA_LEN + infolen + 1);
    if (!buf) return -1;

    while (done < okmlen) {
        size_t bl = 0, n;
        if (tlen) { memcpy(buf, t, tlen); bl += tlen; }
        if (infolen) { memcpy(buf + bl, info, infolen); bl += infolen; }
        buf[bl++] = counter;
        glo_hmac_sha256(t, prk, SHA_LEN, buf, bl);
        tlen = SHA_LEN;
        n = (okmlen - done < SHA_LEN) ? (okmlen - done) : SHA_LEN;
        memcpy(okm + done, t, n);
        done += n;
        counter++;
    }
    memset(t, 0, sizeof t);
    memset(buf, 0, SHA_LEN + infolen + 1);
    free(buf);
    return 0;
}

int glo_hkdf_expand_label(uint8_t *out, size_t outlen, const uint8_t secret[32],
                          const char *label, const uint8_t *ctx, size_t ctxlen) {
    /* HkdfLabel = uint16 length || u8 labellen || "tls13 "+label || u8 ctxlen || ctx */
    uint8_t info[2 + 1 + 255 + 1 + 255];
    size_t o = 0, labellen = strlen(label), fulllen = 6 + labellen;

    if (outlen > 0xffff) return -1;
    if (fulllen > 255) return -1;
    if (ctxlen > 255) return -1;

    info[o++] = (uint8_t)(outlen >> 8);
    info[o++] = (uint8_t)(outlen & 0xff);
    info[o++] = (uint8_t)fulllen;
    memcpy(info + o, "tls13 ", 6); o += 6;
    memcpy(info + o, label, labellen); o += labellen;
    info[o++] = (uint8_t)ctxlen;
    if (ctxlen) { memcpy(info + o, ctx, ctxlen); o += ctxlen; }

    return glo_hkdf_expand(out, outlen, secret, info, o);
}
