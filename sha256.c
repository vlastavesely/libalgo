#include "sha256.h"
#include "utils.h"
#include <string.h> /* memcpy */

static const unsigned int k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_init(struct sha256_state *state)
{
	state->len = 0;
	state->h[0] = 0x6a09e667;
	state->h[1] = 0xbb67ae85;
	state->h[2] = 0x3c6ef372;
	state->h[3] = 0xa54ff53a;
	state->h[4] = 0x510e527f;
	state->h[5] = 0x9b05688c;
	state->h[6] = 0x1f83d9ab;
	state->h[7] = 0x5be0cd19;
}

/* Message expansion */
#define SUM0(x)	(ROTR32(x,  7) ^ ROTR32(x, 18) ^ (x >>  3))
#define SUM1(x)	(ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10))
#define I(i)	(w[i] = GETU32_BE(in + (i * 4)))
#define W(i)	(w[i & 15] = SUM1(w[(i - 2) & 15]) +	\
			     w[(i - 7) & 15] +		\
			     SUM0(w[(i - 15) & 15]) +	\
			     w[(i - 16) & 15])

/* Round transformations */
#define SIGMA0(a)	(ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22))
#define SIGMA1(a)	(ROTR32(a, 6) ^ ROTR32(a, 11) ^ ROTR32(a, 25))
#define CH(a, b, c)	((a & b) ^ ((~a) & c))
#define MAJ(a, b, c)	((a & b) ^ (a & c) ^ (b & c))

#define R(a, b, c, d, e, f, g, h, k, m) do {		\
	t1 = h + SIGMA1(e) + CH(e, f, g) + k + (m);	\
	t2 = SIGMA0(a) + MAJ(a, b, c);			\
	d += t1;					\
	h = t1 + t2;					\
} while (0);

static void sha256_block(struct sha256_state *state, const unsigned char *in)
{
	unsigned int a, b, c, d, e, f, g, h, t1, t2;
	unsigned int w[16];

	a = state->h[0];
	b = state->h[1];
	c = state->h[2];
	d = state->h[3];
	e = state->h[4];
	f = state->h[5];
	g = state->h[6];
	h = state->h[7];

	R(a, b, c, d, e, f, g, h, k[ 0], I( 0));
	R(h, a, b, c, d, e, f, g, k[ 1], I( 1));
	R(g, h, a, b, c, d, e, f, k[ 2], I( 2));
	R(f, g, h, a, b, c, d, e, k[ 3], I( 3));
	R(e, f, g, h, a, b, c, d, k[ 4], I( 4));
	R(d, e, f, g, h, a, b, c, k[ 5], I( 5));
	R(c, d, e, f, g, h, a, b, k[ 6], I( 6));
	R(b, c, d, e, f, g, h, a, k[ 7], I( 7));
	R(a, b, c, d, e, f, g, h, k[ 8], I( 8));
	R(h, a, b, c, d, e, f, g, k[ 9], I( 9));
	R(g, h, a, b, c, d, e, f, k[10], I(10));
	R(f, g, h, a, b, c, d, e, k[11], I(11));
	R(e, f, g, h, a, b, c, d, k[12], I(12));
	R(d, e, f, g, h, a, b, c, k[13], I(13));
	R(c, d, e, f, g, h, a, b, k[14], I(14));
	R(b, c, d, e, f, g, h, a, k[15], I(15));

	R(a, b, c, d, e, f, g, h, k[16], W(16));
	R(h, a, b, c, d, e, f, g, k[17], W(17));
	R(g, h, a, b, c, d, e, f, k[18], W(18));
	R(f, g, h, a, b, c, d, e, k[19], W(19));
	R(e, f, g, h, a, b, c, d, k[20], W(20));
	R(d, e, f, g, h, a, b, c, k[21], W(21));
	R(c, d, e, f, g, h, a, b, k[22], W(22));
	R(b, c, d, e, f, g, h, a, k[23], W(23));
	R(a, b, c, d, e, f, g, h, k[24], W(24));
	R(h, a, b, c, d, e, f, g, k[25], W(25));
	R(g, h, a, b, c, d, e, f, k[26], W(26));
	R(f, g, h, a, b, c, d, e, k[27], W(27));
	R(e, f, g, h, a, b, c, d, k[28], W(28));
	R(d, e, f, g, h, a, b, c, k[29], W(29));
	R(c, d, e, f, g, h, a, b, k[30], W(30));
	R(b, c, d, e, f, g, h, a, k[31], W(31));

	R(a, b, c, d, e, f, g, h, k[32], W(32));
	R(h, a, b, c, d, e, f, g, k[33], W(33));
	R(g, h, a, b, c, d, e, f, k[34], W(34));
	R(f, g, h, a, b, c, d, e, k[35], W(35));
	R(e, f, g, h, a, b, c, d, k[36], W(36));
	R(d, e, f, g, h, a, b, c, k[37], W(37));
	R(c, d, e, f, g, h, a, b, k[38], W(38));
	R(b, c, d, e, f, g, h, a, k[39], W(39));
	R(a, b, c, d, e, f, g, h, k[40], W(40));
	R(h, a, b, c, d, e, f, g, k[41], W(41));
	R(g, h, a, b, c, d, e, f, k[42], W(42));
	R(f, g, h, a, b, c, d, e, k[43], W(43));
	R(e, f, g, h, a, b, c, d, k[44], W(44));
	R(d, e, f, g, h, a, b, c, k[45], W(45));
	R(c, d, e, f, g, h, a, b, k[46], W(46));
	R(b, c, d, e, f, g, h, a, k[47], W(47));

	R(a, b, c, d, e, f, g, h, k[48], W(48));
	R(h, a, b, c, d, e, f, g, k[49], W(49));
	R(g, h, a, b, c, d, e, f, k[50], W(50));
	R(f, g, h, a, b, c, d, e, k[51], W(51));
	R(e, f, g, h, a, b, c, d, k[52], W(52));
	R(d, e, f, g, h, a, b, c, k[53], W(53));
	R(c, d, e, f, g, h, a, b, k[54], W(54));
	R(b, c, d, e, f, g, h, a, k[55], W(55));
	R(a, b, c, d, e, f, g, h, k[56], W(56));
	R(h, a, b, c, d, e, f, g, k[57], W(57));
	R(g, h, a, b, c, d, e, f, k[58], W(58));
	R(f, g, h, a, b, c, d, e, k[59], W(59));
	R(e, f, g, h, a, b, c, d, k[60], W(60));
	R(d, e, f, g, h, a, b, c, k[61], W(61));
	R(c, d, e, f, g, h, a, b, k[62], W(62));
	R(b, c, d, e, f, g, h, a, k[63], W(63));

	state->h[0] += a;
	state->h[1] += b;
	state->h[2] += c;
	state->h[3] += d;
	state->h[4] += e;
	state->h[5] += f;
	state->h[6] += g;
	state->h[7] += h;
}

void sha256_update(struct sha256_state *state, const unsigned char *in, unsigned int len)
{
	unsigned int buflen = state->len & 63;

	state->len += len;

	if (buflen) {
		unsigned int left = 64 - buflen;
		if (left > len)
			left = len;
		memcpy(state->buf + buflen, in, left);
		buflen = (buflen + left) & 63;
		len -= left;
		in += left;
		if (buflen)
			return;
		sha256_block(state, state->buf);
	}
	while (len >= 64) {
		sha256_block(state, in);
		in += 64;
		len -= 64;
	}
	if (len)
		memcpy(state->buf, in, len);
}

void sha256_final(struct sha256_state *state, unsigned char *out)
{
	const unsigned char pad[64] = {0x80};
	unsigned char len[8];
	unsigned int i = state->len & 63;

	PUTU64_BE(len, state->len << 3); /* length is in bits */

	sha256_update(state, pad, 1 + (63 & (55 - i)));
	sha256_update(state, len, 8);

	PUTU32_BE(out +  0, state->h[0]);
	PUTU32_BE(out +  4, state->h[1]);
	PUTU32_BE(out +  8, state->h[2]);
	PUTU32_BE(out + 12, state->h[3]);
	PUTU32_BE(out + 16, state->h[4]);
	PUTU32_BE(out + 20, state->h[5]);
	PUTU32_BE(out + 24, state->h[6]);
	PUTU32_BE(out + 28, state->h[7]);
}
