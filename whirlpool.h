#ifndef __WHIRLPOOL_H
#define __WHIRLPOOL_H

#define WHIRLPOOL_STATE_LEN 64
#define WHIRLPOOL_DIGEST_LEN 64

struct whirlpool_state {
	unsigned char bitLength[32];	/* global number of hashed bits (256-bit counter) */
	unsigned char buffer[64];	/* buffer of data to hash */
	int bufferBits;			/* current number of bits on the buffer */
	int bufferPos;			/* current (possibly incomplete) byte slot on the buffer */
	unsigned long hash[64 / 8];	/* the hashing state */
};

void whirlpool_init(struct whirlpool_state *state);
#define whirlpool_wipe_state whirlpool_init

void whirlpool_update(struct whirlpool_state *state, const unsigned char *in,
		      unsigned int n);
void whirlpool_final(struct whirlpool_state *state, unsigned char *digest);

#endif /* __WHIRLPOOL_H */
