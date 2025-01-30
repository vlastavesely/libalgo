#include "blake2b.h"
#include "utils.h"
#include <string.h> /* memcpy, memset */

static const uint64_t iv[8] = {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
	0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const unsigned char sigma[12][16] = {
	{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
	{14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
	{11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
	{ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
	{ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
	{ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
	{12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
	{13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
	{ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
	{10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0},
	{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
	{14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3}
};

static inline void set_key(struct blake2b_state *state, const unsigned char *key,
			   unsigned int len)
{
	memset(state->k, '\0', sizeof(state->k));

	if (key == NULL) {
		return;
	}

	memcpy(state->k, key, len);

	/* prefill */
	memcpy(state->buf, key, len);
	state->len = 128;
}

void blake2b_init(struct blake2b_state *state, const unsigned char *key,
		  unsigned int keylen, unsigned int digestsize)
{
	unsigned int i;
	state->len = 0;

	memset(state, 0, sizeof(*state));

	for (i = 0; i < 8; i++) {
		state->h[i] = iv[i];
	}

	state->h[0] ^= 0x01010000 | keylen << 8 | digestsize;
	set_key(state, key, keylen);

	state->digestsize = digestsize;
}

#define G(r, i, a, b, c, d) {			\
	a = a + b + m[sigma[r][2 * i + 0]];	\
	d = ROTR64(d ^ a, 32);			\
	c = c + d;				\
	b = ROTR64(b ^ c, 24);			\
	a = a + b + m[sigma[r][2 * i + 1]];	\
	d = ROTR64(d ^ a, 16);			\
	c = c + d;				\
	b = ROTR64(b ^ c, 63);			\
}

#define ROUND(r) {				\
	G(r, 0, v[ 0], v[ 4], v[ 8], v[12]);	\
	G(r, 1, v[ 1], v[ 5], v[ 9], v[13]);	\
	G(r, 2, v[ 2], v[ 6], v[10], v[14]);	\
	G(r, 3, v[ 3], v[ 7], v[11], v[15]);	\
						\
	G(r, 4, v[ 0], v[ 5], v[10], v[15]);	\
	G(r, 5, v[ 1], v[ 6], v[11], v[12]);	\
	G(r, 6, v[ 2], v[ 7], v[ 8], v[13]);	\
	G(r, 7, v[ 3], v[ 4], v[ 9], v[14]);	\
}

static void blake2b_block(struct blake2b_state *state, const unsigned char *in)
{
	uint64_t m[16], v[16];
	unsigned int i;

	for (i = 0; i < 16; i++) {
		m[i] = GETU64_LE(in + (8 * i));
	}

	for (i = 0; i < 8; i++) {
		v[i] = state->h[i];
	}

	v[ 8] = iv[0];
	v[ 9] = iv[1];
	v[10] = iv[2];
	v[11] = iv[3];
	v[12] = iv[4] ^ state->t[0];
	v[13] = iv[5] ^ state->t[1];
	v[14] = iv[6] ^ state->f[0];
	v[15] = iv[7] ^ state->f[1];

	ROUND(0);
	ROUND(1);
	ROUND(2);
	ROUND(3);
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (i = 0; i < 8; ++i) {
		state->h[i] = state->h[i] ^ v[i] ^ v[i + 8];
	}
}

static void blake2b_increment_counter(struct blake2b_state *state,
				      const uint64_t inc)
{
	state->t[0] += inc;
	state->t[1] += (state->t[0] < inc);
}

void blake2b_update(struct blake2b_state *state, const unsigned char *in,
		    unsigned int len)
{
	unsigned int left = state->len;
	unsigned int fill = 128 - left;

	if (!len) {
		return;
	}

	if (len > fill) {
		state->len = 0;

		memcpy(state->buf + left, in, fill);
		blake2b_increment_counter(state, 128);
		blake2b_block(state, state->buf);

		in += fill;
		len -= fill;

		while (len > 128) {
			blake2b_increment_counter(state, 128);
			blake2b_block(state, in);
			in += 128;
			len -= 128;
		}
	}

	memcpy(state->buf + state->len, in, len);
	state->len += len;
}

void blake2b_final(struct blake2b_state *state, unsigned char *out)
{
	unsigned char blk[64];

	blake2b_increment_counter(state, state->len);
	state->f[0] = (uint64_t) -1;

	memset(state->buf + state->len, 0, 128 - state->len);
	blake2b_block(state, state->buf);

	PUTU64_LE(blk +  0, state->h[0]);
	PUTU64_LE(blk +  8, state->h[1]);
	PUTU64_LE(blk + 16, state->h[2]);
	PUTU64_LE(blk + 24, state->h[3]);
	PUTU64_LE(blk + 32, state->h[4]);
	PUTU64_LE(blk + 40, state->h[5]);
	PUTU64_LE(blk + 48, state->h[6]);
	PUTU64_LE(blk + 56, state->h[7]);

	memcpy(out, blk, state->digestsize);
}
