/*
 * Implemented according to the reference document:
 * https://tools.ietf.org/html/rfc7539
 */
#include "chacha20.h"
#include "config.h"
#include "utils.h"

#define GETU32_LE(a) ( \
	((unsigned int)(a)[3] << 24) | \
	((unsigned int)(a)[2] << 16) | \
	((unsigned int)(a)[1] <<  8) | \
	((unsigned int)(a)[0])         \
)

int chacha20_prepare_key(struct chacha20_subkeys *subkeys,
			 const unsigned char *key, const unsigned char *nonce,
			 unsigned int blockno)
{
	subkeys->key[0] = GETU32_LE(key +  0);
	subkeys->key[1] = GETU32_LE(key +  4);
	subkeys->key[2] = GETU32_LE(key +  8);
	subkeys->key[3] = GETU32_LE(key + 12);
	subkeys->key[4] = GETU32_LE(key + 16);
	subkeys->key[5] = GETU32_LE(key + 20);
	subkeys->key[6] = GETU32_LE(key + 24);
	subkeys->key[7] = GETU32_LE(key + 28);
	subkeys->nonce[0] = GETU32_LE(nonce + 0);
	subkeys->nonce[1] = GETU32_LE(nonce + 4);
	subkeys->nonce[2] = GETU32_LE(nonce + 8);
	subkeys->i = blockno;
	subkeys->avail = 0;
	return 0;
}

void chacha20_wipe_key(struct chacha20_subkeys *subkeys)
{
	unsigned int i;
	for (i = 0; i < 8; i++)
		subkeys->key[i] = 0;
	for (i = 0; i < 3; i++)
		subkeys->nonce[i] = 0;
	for (i = 0; i < 16; i++)
		subkeys->state[i] = 0;
	subkeys->i = 0;
}

#define QUARTERROUND(a, b, c, d)	\
	a += b; d = ROTL32(d ^ a, 16);	\
	c += d;	b = ROTL32(b ^ c, 12);	\
	a += b;	d = ROTL32(d ^ a, 8);	\
	c += d; b = ROTL32(b ^ c, 7);

#define DOUBLEROUND(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p)	\
	/* The ‘column’ round */	\
	QUARTERROUND(a, e, i, m);	\
	QUARTERROUND(b, f, j, n);	\
	QUARTERROUND(c, g, k, o);	\
	QUARTERROUND(d, h, l, p);	\
	/* The ‘diagonal’ round */	\
	QUARTERROUND(a, f, k, p);	\
	QUARTERROUND(b, g, l, m);	\
	QUARTERROUND(c, h, i, n);	\
	QUARTERROUND(d, e, j, o);

static void chacha20_init_state(struct chacha20_subkeys *subkeys)
{
	unsigned int *state = subkeys->state;

	state[ 0] = 0x61707865;
	state[ 1] = 0x3320646e;
	state[ 2] = 0x79622d32;
	state[ 3] = 0x6b206574;
	state[ 4] = subkeys->key[0];
	state[ 5] = subkeys->key[1];
	state[ 6] = subkeys->key[2];
	state[ 7] = subkeys->key[3];
	state[ 8] = subkeys->key[4];
	state[ 9] = subkeys->key[5];
	state[10] = subkeys->key[6];
	state[11] = subkeys->key[7];
	state[12] = subkeys->i;
	state[13] = subkeys->nonce[0];
	state[14] = subkeys->nonce[1];
	state[15] = subkeys->nonce[2];
}

#if WORDS_BIGENDIAN
#define CPU_TO_LE(i) BSWAP32(i)
#else
#define CPU_TO_LE(i) (i)
#endif

static void chacha20_process(struct chacha20_subkeys *subkeys)
{
	unsigned int a, b, c, d, e, f, g, h;
	unsigned int i, j, k, l, m, n, o, p;
	unsigned int *state = subkeys->state;

	chacha20_init_state(subkeys);

	a = state[ 0];
	b = state[ 1];
	c = state[ 2];
	d = state[ 3];
	e = state[ 4];
	f = state[ 5];
	g = state[ 6];
	h = state[ 7];
	i = state[ 8];
	j = state[ 9];
	k = state[10];
	l = state[11];
	m = state[12];
	n = state[13];
	o = state[14];
	p = state[15];

	DOUBLEROUND(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p); /*  1 */
	DOUBLEROUND(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p); /*  2 */
	DOUBLEROUND(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p); /*  3 */
	DOUBLEROUND(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p); /*  4 */
	DOUBLEROUND(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p); /*  5 */

	DOUBLEROUND(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p); /*  6 */
	DOUBLEROUND(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p); /*  7 */
	DOUBLEROUND(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p); /*  8 */
	DOUBLEROUND(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p); /*  9 */
	DOUBLEROUND(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p); /* 10 */

	state[ 0] = CPU_TO_LE(state[ 0] + a);
	state[ 1] = CPU_TO_LE(state[ 1] + b);
	state[ 2] = CPU_TO_LE(state[ 2] + c);
	state[ 3] = CPU_TO_LE(state[ 3] + d);
	state[ 4] = CPU_TO_LE(state[ 4] + e);
	state[ 5] = CPU_TO_LE(state[ 5] + f);
	state[ 6] = CPU_TO_LE(state[ 6] + g);
	state[ 7] = CPU_TO_LE(state[ 7] + h);
	state[ 8] = CPU_TO_LE(state[ 8] + i);
	state[ 9] = CPU_TO_LE(state[ 9] + j);
	state[10] = CPU_TO_LE(state[10] + k);
	state[11] = CPU_TO_LE(state[11] + l);
	state[12] = CPU_TO_LE(state[12] + m);
	state[13] = CPU_TO_LE(state[13] + n);
	state[14] = CPU_TO_LE(state[14] + o);
	state[15] = CPU_TO_LE(state[15] + p);

	subkeys->i++;
	subkeys->avail = 64;
}

void chacha20_crypt(struct chacha20_subkeys *subkeys, unsigned char *out,
		    const unsigned char *in, unsigned len)
{
	unsigned int i;
	unsigned char *state = (unsigned char *) subkeys->state;

	for (i = 0; i < len; i++) {
		if (!subkeys->avail)
			chacha20_process(subkeys);
		out[i] = in[i] ^ state[64 - subkeys->avail];
		subkeys->avail--;
	}
}
