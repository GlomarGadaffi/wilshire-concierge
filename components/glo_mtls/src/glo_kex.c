/*
 * X25519 (RFC 7748) key exchange — thin wrapper over TinySSH tinynacl.
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 GlomarGadaffi
 */
#include "glo_mtls_crypto.h"
#include "crypto_scalarmult_curve25519.h"

int glo_x25519_base(uint8_t pub[32], const uint8_t sk[32]) {
    return crypto_scalarmult_curve25519_base(pub, sk);
}

int glo_x25519(uint8_t shared[32], const uint8_t sk[32], const uint8_t peer[32]) {
    return crypto_scalarmult_curve25519(shared, sk, peer);
}
