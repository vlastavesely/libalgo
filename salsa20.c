#include "salsa20.h"
#include "config.h"
#include "utils.h"

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

int salsa20_prepare_key(struct salsa20_subkeys *subkeys,
			const unsigned char *k, unsigned int kbits,
			const unsigned char *nonce, unsigned int blockno)
{
	const char *constants;

	subkeys->input[1] = GETU32_LE(k + 0);
	subkeys->input[2] = GETU32_LE(k + 4);
	subkeys->input[3] = GETU32_LE(k + 8);
	subkeys->input[4] = GETU32_LE(k + 12);

	if (kbits == 256) {
		k += 16;
		constants = sigma;

 	} else if (kbits == 128) {
		constants = tau;

	} else {
		return -1;
	}

	subkeys->input[11] = GETU32_LE(k + 0);
	subkeys->input[12] = GETU32_LE(k + 4);
	subkeys->input[13] = GETU32_LE(k + 8);
	subkeys->input[14] = GETU32_LE(k + 12);
	subkeys->input[0]  = GETU32_LE(constants + 0);
	subkeys->input[5]  = GETU32_LE(constants + 4);
	subkeys->input[10] = GETU32_LE(constants + 8);
	subkeys->input[15] = GETU32_LE(constants + 12);
	subkeys->input[6]  = GETU32_LE(nonce + 0);
	subkeys->input[7]  = GETU32_LE(nonce + 4);
	subkeys->input[8]  = 0;
	subkeys->input[9]  = 0;
	subkeys->avail = 0;

	return 0;
}

void salsa20_wipe_key(struct salsa20_subkeys *subkeys)
{
	unsigned int i;

	for (i = 0; i < 16; i++)
		subkeys->input[i] = 0;
	for (i = 0; i < 16; i++)
		subkeys->state[i] = 0;
}

#define QUARTERROUND(a, b, c, d)	\
	b ^= ROTL32(a + d, 7);		\
	c ^= ROTL32(b + a, 9);		\
	d ^= ROTL32(c + b, 13);		\
	a ^= ROTL32(d + c, 18);

#define DOUBLEROUND(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p)	\
	QUARTERROUND(a, e, i, m);	\
	QUARTERROUND(f, j, n, b);	\
	QUARTERROUND(k, o, c, g);	\
	QUARTERROUND(p, d, h, l);	\
	QUARTERROUND(a, b, c, d);	\
	QUARTERROUND(f, g, h, e);	\
	QUARTERROUND(k, l, i, j);	\
	QUARTERROUND(p, m, n, o);	\

static void salsa20_init_state(struct salsa20_subkeys *subkeys)
{
	unsigned int i;

	for (i = 0; i < 16; i++)
		subkeys->state[i] = subkeys->input[i];
}

#if WORDS_BIGENDIAN
#define CPU_TO_LE(i) BSWAP32(i)
#else
#define CPU_TO_LE(i) (i)
#endif

static void salsa20_process(struct salsa20_subkeys *subkeys)
{

	unsigned int a, b, c, d, e, f, g, h;
	unsigned int i, j, k, l, m, n, o, p;
	unsigned int *state = subkeys->state;

	salsa20_init_state(subkeys);

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

	if (++subkeys->input[8] == 0)
		subkeys->input[9]++;

	subkeys->avail = 64;
}

void salsa20_crypt(struct salsa20_subkeys *subkeys, unsigned char *out,
		   const unsigned char *in, unsigned len)
{
	unsigned int i;
	unsigned char *state = (unsigned char *) subkeys->state;

	for (i = 0; i < len; i++) {
		if (!subkeys->avail)
			salsa20_process(subkeys);
		out[i] = in[i] ^ state[64 - subkeys->avail];
		subkeys->avail--;
	}
}
