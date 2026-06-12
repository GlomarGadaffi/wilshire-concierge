#include "includes.h"
#include "dbrandom.h"
#include "dbutil.h"
#include "bignum.h"
#include "esp_random.h"

static int donerandinit = 0;

void seedrandom() {
    /* esp_fill_random is hardware-based. We assume the system is already 
     * seeded (e.g. WiFi is initialized before the SSH server is started). */
    donerandinit = 1;
}

void genrandom(unsigned char* buf, unsigned int len) {
    if (!donerandinit) {
        seedrandom();
    }
    esp_fill_random(buf, len);
}

void addrandom(const unsigned char * UNUSED(buf), unsigned int UNUSED(len)) {
    /* No-op since we use hardware RNG directly */
}

/* Generates a random mp_int. 
 * max is a *mp_int specifying an upper bound.
 * rand must be an initialised *mp_int for the result.
 * the result rand satisfies:  0 < rand < max 
 * */
void gen_random_mpint(mp_int *max, mp_int *rand) {
	unsigned char *randbuf = NULL;
	unsigned int len = 0;
	const unsigned char masks[] = {0xff, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f};

	const int size_bits = mp_count_bits(max);

	len = size_bits / 8;
	if ((size_bits % 8) != 0) {
		len += 1;
	}

	randbuf = (unsigned char*)m_malloc(len);
	do {
		genrandom(randbuf, len);
		/* Mask out the unrequired bits - mp_read_unsigned_bin expects
		 * MSB first.*/
		randbuf[0] &= masks[size_bits % 8];

		bytes_to_mp(rand, randbuf, len);

		/* keep regenerating until we get one satisfying
		 * 0 < rand < max    */
	} while (!(mp_cmp(rand, max) == MP_LT && mp_cmp_d(rand, 0) == MP_GT));
	m_burn(randbuf, len);
	m_free(randbuf);
}
