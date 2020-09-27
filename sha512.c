#include "sha512.h"
#include "utils.h"
#include <string.h> /* memcpy */

static const uint64_t k[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
	0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
	0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
	0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
	0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
	0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
	0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
	0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
	0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
	0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
	0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
	0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
	0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
	0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
	0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
	0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

void sha512_init(struct sha512_state *state)
{
	state->len = 0;
	state->h[0] = 0x6a09e667f3bcc908;
	state->h[1] = 0xbb67ae8584caa73b;
	state->h[2] = 0x3c6ef372fe94f82b;
	state->h[3] = 0xa54ff53a5f1d36f1;
	state->h[4] = 0x510e527fade682d1;
	state->h[5] = 0x9b05688c2b3e6c1f;
	state->h[6] = 0x1f83d9abfb41bd6b;
	state->h[7] = 0x5be0cd19137e2179;
}

/* Message expansion */
#define SUM0(x)	(ROTR64(x,  1) ^ ROTR64(x,  8) ^ (x >> 7))
#define SUM1(x)	(ROTR64(x, 19) ^ ROTR64(x, 61) ^ (x >> 6))
#define I(i)	(w[i] = GETU64_BE(in + (i * 8)))
#define W(i)	(w[i & 15] = SUM1(w[(i - 2) & 15]) +	\
			     w[(i - 7) & 15] +		\
			     SUM0(w[(i - 15) & 15]) +	\
			     w[(i - 16) & 15])

/* Round transformations */
#define SIGMA0(a)	(ROTR64(a, 28) ^ ROTR64(a, 34) ^ ROTR64(a, 39))
#define SIGMA1(a)	(ROTR64(a, 14) ^ ROTR64(a, 18) ^ ROTR64(a, 41))
#define CH(a, b, c)	((a & b) ^ ((~a) & c))
#define MAJ(a, b, c)	((a & b) ^ (a & c) ^ (b & c))

#define R(a, b, c, d, e, f, g, h, k, m) do {		\
	t1 = h + SIGMA1(e) + CH(e, f, g) + k + (m);	\
	t2 = SIGMA0(a) + MAJ(a, b, c);			\
	d += t1;					\
	h = t1 + t2;					\
} while (0);

static void sha512_block(struct sha512_state *state, const unsigned char *in)
{
	uint64_t a, b, c, d, e, f, g, h, t1, t2;
	uint64_t w[16];

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

	R(a, b, c, d, e, f, g, h, k[64], W(64));
	R(h, a, b, c, d, e, f, g, k[65], W(65));
	R(g, h, a, b, c, d, e, f, k[66], W(66));
	R(f, g, h, a, b, c, d, e, k[67], W(67));
	R(e, f, g, h, a, b, c, d, k[68], W(68));
	R(d, e, f, g, h, a, b, c, k[69], W(69));
	R(c, d, e, f, g, h, a, b, k[70], W(70));
	R(b, c, d, e, f, g, h, a, k[71], W(71));
	R(a, b, c, d, e, f, g, h, k[72], W(72));
	R(h, a, b, c, d, e, f, g, k[73], W(73));
	R(g, h, a, b, c, d, e, f, k[74], W(74));
	R(f, g, h, a, b, c, d, e, k[75], W(75));
	R(e, f, g, h, a, b, c, d, k[76], W(76));
	R(d, e, f, g, h, a, b, c, k[77], W(77));
	R(c, d, e, f, g, h, a, b, k[78], W(78));
	R(b, c, d, e, f, g, h, a, k[79], W(79));

	state->h[0] += a;
	state->h[1] += b;
	state->h[2] += c;
	state->h[3] += d;
	state->h[4] += e;
	state->h[5] += f;
	state->h[6] += g;
	state->h[7] += h;
}

void sha512_update(struct sha512_state *state, const unsigned char *in, unsigned int len)
{
	unsigned int buflen = state->len & 127;

	state->len += len;

	if (buflen) {
		unsigned int left = 128 - buflen;
		if (left > len)
			left = len;
		memcpy(state->buf + buflen, in, left);
		buflen = (buflen + left) & 127;
		len -= left;
		in += left;
		if (buflen)
			return;
		sha512_block(state, state->buf);
	}
	while (len >= 128) {
		sha512_block(state, in);
		in += 128;
		len -= 128;
	}
	if (len)
		memcpy(state->buf, in, len);
}

void sha512_final(struct sha512_state *state, unsigned char *out)
{
	const unsigned char pad[128] = {0x80};
	unsigned char len[16] = {};
	unsigned int i = state->len & 127;

	/* lengh is in bits */
	PUTU64_BE(len + 0, (state->len >> 61));
	PUTU64_BE(len + 8, (state->len << 3));

	sha512_update(state, pad, 1 + (127 & (111 - i)));
	sha512_update(state, len, 16);

	PUTU64_BE(out +  0, state->h[0]);
	PUTU64_BE(out +  8, state->h[1]);
	PUTU64_BE(out + 16, state->h[2]);
	PUTU64_BE(out + 24, state->h[3]);
	PUTU64_BE(out + 32, state->h[4]);
	PUTU64_BE(out + 40, state->h[5]);
	PUTU64_BE(out + 48, state->h[6]);
	PUTU64_BE(out + 56, state->h[7]);
}
