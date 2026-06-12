#include "subprocess.h"
#include "sshcrypto.h"
#include "load.h"
#include "purge.h"
#include "bug.h"

int subprocess_sign(unsigned char *y, long long ylen, const char *keydir, unsigned char *x, long long xlen) {
    unsigned char sk[sshcrypto_sign_SECRETKEYMAX];
    unsigned char sm[sshcrypto_sign_MAX + sshcrypto_hash_MAX];
    unsigned long long smlen;

    if (ylen != sshcrypto_sign_bytes) bug_inval();
    if (xlen != sshcrypto_hash_bytes) bug_inval();
    if (!y || !x) bug_inval();

    // Load secret key (which calls our port_load.c's NVS load)
    if (load(sshcrypto_sign_secretkeyfilename, sk, sshcrypto_sign_secretkeybytes) == -1) {
        purge(sk, sizeof sk);
        return -1;
    }

    // Sign using sshcrypto_sign (which wraps crypto_sign_ed25519)
    if (sshcrypto_sign(sm, &smlen, x, sshcrypto_hash_bytes, sk) != 0) {
        purge(sk, sizeof sk);
        return -1;
    }

    purge(sk, sizeof sk);

    // Copy the signature (first sshcrypto_sign_bytes of the signed message)
    for (long long i = 0; i < ylen; ++i) {
        y[i] = sm[i];
    }

    purge(sm, sizeof sm);
    return 0; // Success
}
