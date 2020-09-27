#ifndef __SHA512_H
#define __SHA512_H

#define SHA512_STATE_LEN 128
#define SHA512_DIGEST_LEN 64

#include <stdint.h>

struct sha512_state {
	uint64_t h[8];
	unsigned char buf[128];
	unsigned long long len;
};

void sha512_init(struct sha512_state *state);
#define sha512_wipe_state sha512_init

void sha512_update(struct sha512_state *state, const unsigned char *in,
		  unsigned int n);
void sha512_final(struct sha512_state *state, unsigned char *digest);

#endif /* __SHA512_H */
