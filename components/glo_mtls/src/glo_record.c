/*
 * TLS 1.3 record layer (RFC 8446 §5.2/5.3) — AEAD-protected records.
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 GlomarGadaffi
 */
#include "glo_tls13.h"
#include "glo_mtls_crypto.h"
#include <stdlib.h>
#include <string.h>

#define TAG_LEN 16
#define HDR_LEN 5

/* per-record nonce = static_iv XOR (0^4 || seq_be64)  (RFC 8446 §5.3) */
static void build_nonce(uint8_t nonce[12], const uint8_t iv[12], uint64_t seq) {
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++)
        nonce[11 - i] ^= (uint8_t)(seq >> (8 * i));
}

int glo_record_seal(uint8_t *out, size_t *outlen,
                    const uint8_t *content, size_t contentlen, uint8_t content_type,
                    const uint8_t key[32], const uint8_t iv[12], uint64_t seq) {
    size_t innerlen = contentlen + 1;            /* content || content_type (no padding) */
    size_t length = innerlen + TAG_LEN;          /* encrypted_record length */
    uint8_t *inner, nonce[12];
    int rc;

    if (length > 0xffff) return -1;
    inner = malloc(innerlen);
    if (!inner) return -1;
    memcpy(inner, content, contentlen);
    inner[contentlen] = content_type;

    /* TLSCiphertext header (also the AEAD additional_data) */
    out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
    out[3] = (uint8_t)(length >> 8); out[4] = (uint8_t)(length & 0xff);

    build_nonce(nonce, iv, seq);
    /* ciphertext -> out+5, tag -> out+5+innerlen ; AAD = 5-byte header */
    rc = glo_aead_seal(out + HDR_LEN, out + HDR_LEN + innerlen,
                       inner, innerlen, out, HDR_LEN, key, nonce);
    memset(inner, 0, innerlen);
    free(inner);
    if (rc) return rc;

    *outlen = HDR_LEN + length;
    return 0;
}

int glo_record_open(uint8_t *content, size_t *contentlen, uint8_t *content_type,
                    const uint8_t *record, size_t recordlen,
                    const uint8_t key[32], const uint8_t iv[12], uint64_t seq) {
    size_t length, innerlen, n;
    const uint8_t *ct, *tag;
    uint8_t *inner, nonce[12];
    int rc;

    if (recordlen < HDR_LEN + TAG_LEN) return -1;
    if (record[0] != 0x17) return -1;            /* all TLS 1.3 records wrap as app_data */
    length = ((size_t)record[3] << 8) | record[4];
    if (length + HDR_LEN != recordlen) return -1;
    if (length < TAG_LEN) return -1;

    innerlen = length - TAG_LEN;
    ct = record + HDR_LEN;
    tag = record + HDR_LEN + innerlen;

    inner = malloc(innerlen ? innerlen : 1);
    if (!inner) return -1;
    build_nonce(nonce, iv, seq);
    rc = glo_aead_open(inner, ct, innerlen, tag, record, HDR_LEN, key, nonce);
    if (rc) { memset(inner, 0, innerlen); free(inner); return -1; }

    /* strip trailing zero padding; last non-zero byte is the real content_type */
    n = innerlen;
    while (n > 0 && inner[n - 1] == 0) n--;
    if (n == 0) { memset(inner, 0, innerlen); free(inner); return -1; }

    *content_type = inner[n - 1];
    *contentlen = n - 1;
    memcpy(content, inner, n - 1);
    memset(inner, 0, innerlen);
    free(inner);
    return 0;
}
