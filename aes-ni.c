#include "aes-ni.h"

static void generate_decryption_keys(struct aes_ni_subkeys *subkeys)
{
	__m128i *ek = subkeys->ek;
	__m128i *dk = subkeys->dk;
	unsigned int i, n = subkeys->nr;

	dk[0] = ek[n];
	for (i = 1; i < n; i++)
		dk[i] = _mm_aesimc_si128(ek[n - i]);
	dk[n] = ek[0];
}

#define AES_128_key_exp(k, rcon) \
	aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static inline __m128i aes_128_key_expansion(__m128i a, __m128i b)
{
	b = _mm_shuffle_epi32(b, _MM_SHUFFLE(3, 3, 3, 3));
	a = _mm_xor_si128(a, _mm_slli_si128(a, 4));
	a = _mm_xor_si128(a, _mm_slli_si128(a, 4));
	a = _mm_xor_si128(a, _mm_slli_si128(a, 4));

	return _mm_xor_si128(a, b);
}

static void aes_ni_prepare_128bit_key(struct aes_ni_subkeys *subkeys,
				      const unsigned char *key)
{
	__m128i *ek = subkeys->ek;

	subkeys->nr = 10;
	ek[ 0] = _mm_loadu_si128((__m128i *) (key + 0));
	ek[ 1] = AES_128_key_exp(ek[0], 0x01);
	ek[ 2] = AES_128_key_exp(ek[1], 0x02);
	ek[ 3] = AES_128_key_exp(ek[2], 0x04);
	ek[ 4] = AES_128_key_exp(ek[3], 0x08);
	ek[ 5] = AES_128_key_exp(ek[4], 0x10);
	ek[ 6] = AES_128_key_exp(ek[5], 0x20);
	ek[ 7] = AES_128_key_exp(ek[6], 0x40);
	ek[ 8] = AES_128_key_exp(ek[7], 0x80);
	ek[ 9] = AES_128_key_exp(ek[8], 0x1b);
	ek[10] = AES_128_key_exp(ek[9], 0x36);

	generate_decryption_keys(subkeys);
}

#define KEY_192_ASSIST(a, b, c) {		\
	__m128i d;				\
	b = _mm_shuffle_epi32(b, 0x55);		\
	d = _mm_slli_si128(a, 4);		\
	a = _mm_xor_si128(a, d);		\
	d = _mm_slli_si128(d, 4);		\
	a = _mm_xor_si128(a, d);		\
	d = _mm_slli_si128(d, 4);		\
	a = _mm_xor_si128(a, d);		\
	a = _mm_xor_si128(a, b);		\
	b = _mm_shuffle_epi32(a, 0xff);		\
	d = _mm_slli_si128(c, 4);		\
	c = _mm_xor_si128(c, d);		\
	c = _mm_xor_si128(c, b);		\
}

#define KEY192_ROUND1(o1, o2, r)					\
	b = _mm_aeskeygenassist_si128(c, r);				\
	KEY_192_ASSIST(a, b, c);					\
	o1 = (__m128i) _mm_shuffle_pd((__m128d) o1, (__m128d) a, 0);	\
	o2 = (__m128i) _mm_shuffle_pd((__m128d) a, (__m128d) c, 1);	\

#define KEY192_ROUND2(o1, o2, r)		\
	b = _mm_aeskeygenassist_si128(c, r);	\
	KEY_192_ASSIST(a, b, c);		\
	o1 = a;					\
	o2 = c;

static void aes_ni_prepare_192bit_key(struct aes_ni_subkeys *subkeys,
				      const unsigned char *key)
{
	__m128i *ek = subkeys->ek;
	__m128i a, b, c;

	subkeys->nr = 12;
	ek[0] = a = _mm_loadu_si128((__m128i *) (key + 0));
	ek[1] = c = _mm_loadu_si128((__m128i *) (key + 16));

	KEY192_ROUND1(ek[ 1], ek[ 2], 0x01);
	KEY192_ROUND2(ek[ 3], ek[ 4], 0x02);
	KEY192_ROUND1(ek[ 4], ek[ 5], 0x04);
	KEY192_ROUND2(ek[ 6], ek[ 7], 0x08);
	KEY192_ROUND1(ek[ 7], ek[ 8], 0x10);
	KEY192_ROUND2(ek[ 9], ek[10], 0x20);
	KEY192_ROUND1(ek[10], ek[11], 0x40);

	b = _mm_aeskeygenassist_si128(c, 0x80);
	KEY_192_ASSIST(a, b, c);
	ek[12] = a;

	generate_decryption_keys(subkeys);
}

#define KEY_256_ASSIST_1(a, b) {		\
	__m128i t;				\
	b = _mm_shuffle_epi32(b, 0xff);		\
	t = _mm_slli_si128(a, 4);		\
	a = _mm_xor_si128(a, t);		\
	t = _mm_slli_si128(t, 4);		\
	a = _mm_xor_si128(a, t);		\
	t = _mm_slli_si128(t, 4);		\
	a = _mm_xor_si128(a, t);		\
	a = _mm_xor_si128(a, b);		\
}

#define KEY_256_ASSIST_2(a, b) {		\
	__m128i c, d;				\
	d = _mm_aeskeygenassist_si128(a, 0x00);	\
	c = _mm_shuffle_epi32(d, 0xaa);		\
	d = _mm_slli_si128(b, 4);		\
	b = _mm_xor_si128(b, d);		\
	d = _mm_slli_si128(d, 4);		\
	b = _mm_xor_si128(b, d);		\
	d = _mm_slli_si128(d, 4);		\
	b = _mm_xor_si128(b, d);		\
	b = _mm_xor_si128(b, c);		\
}

#define KEY256_ROUND(o1, o2, r)			\
	KEY_256_ASSIST_1(t1, t2);		\
	o1 = t1;				\
	KEY_256_ASSIST_2(t1, t3);		\
	o2 = t3;				\
	t2 = _mm_aeskeygenassist_si128(t3, r);

static void aes_ni_prepare_256bit_key(struct aes_ni_subkeys *subkeys,
				      const unsigned char *key)
{
	__m128i *ek = subkeys->ek;
	__m128i t1, t2, t3;

	subkeys->nr = 14;
	t1 = ek[0] = _mm_loadu_si128((__m128i *) (key + 0));
	t3 = ek[1] = _mm_loadu_si128((__m128i *) (key + 16));
 	t2 = _mm_aeskeygenassist_si128(t3, 0x01);

	KEY256_ROUND(ek[ 2], ek[ 3], 0x02);
	KEY256_ROUND(ek[ 4], ek[ 5], 0x04);
	KEY256_ROUND(ek[ 6], ek[ 7], 0x08);
	KEY256_ROUND(ek[ 8], ek[ 9], 0x10);
	KEY256_ROUND(ek[10], ek[11], 0x20);
	KEY256_ROUND(ek[12], ek[13], 0x40);
	KEY_256_ASSIST_1(t1, t2);

	ek[14] = t1;

	generate_decryption_keys(subkeys);
}

int aes_ni_prepare_key(struct aes_ni_subkeys *subkeys, const unsigned char *key,
		       unsigned int bits)
{
	switch (bits) {
	case 128:
		aes_ni_prepare_128bit_key(subkeys, key);
		return 0;
	case 192:
		aes_ni_prepare_192bit_key(subkeys, key);
		return 0;
	case 256:
		aes_ni_prepare_256bit_key(subkeys, key);
		return 0;
	default:
		return -1;
	}
}

void aes_ni_encrypt(struct aes_ni_subkeys *subkeys, unsigned char *out,
		    const unsigned char *in)
{
	__m128i state = _mm_loadu_si128((__m128i *) in);
	__m128i *k = subkeys->ek;
	unsigned int nr = subkeys->nr;

	state = _mm_xor_si128(state, k[0]);
	state = _mm_aesenc_si128(state, k[1]);
	state = _mm_aesenc_si128(state, k[2]);
	state = _mm_aesenc_si128(state, k[3]);
	state = _mm_aesenc_si128(state, k[4]);
	state = _mm_aesenc_si128(state, k[5]);
	state = _mm_aesenc_si128(state, k[6]);
	state = _mm_aesenc_si128(state, k[7]);
	state = _mm_aesenc_si128(state, k[8]);
	state = _mm_aesenc_si128(state, k[9]);

	switch (nr) {
	case 10:
		state = _mm_aesenclast_si128(state, k[10]);
		break;
	case 12:
		state = _mm_aesenc_si128(state, k[10]);
		state = _mm_aesenc_si128(state, k[11]);
		state = _mm_aesenclast_si128(state, k[12]);
		break;
	case 14:
		state = _mm_aesenc_si128(state, k[10]);
		state = _mm_aesenc_si128(state, k[11]);
		state = _mm_aesenc_si128(state, k[12]);
		state = _mm_aesenc_si128(state, k[13]);
		state = _mm_aesenclast_si128(state, k[14]);
		break;
	}

	_mm_storeu_si128((__m128i *) out, state);

}

void aes_ni_decrypt(struct aes_ni_subkeys *subkeys, unsigned char *out,
		    const unsigned char *in)
{
	__m128i state = _mm_loadu_si128((__m128i *) in);
	__m128i *k = subkeys->dk;
	unsigned int nr = subkeys->nr;

	state = _mm_xor_si128(state, k[0]);
	state = _mm_aesdec_si128(state, k[1]);
	state = _mm_aesdec_si128(state, k[2]);
	state = _mm_aesdec_si128(state, k[3]);
	state = _mm_aesdec_si128(state, k[4]);
	state = _mm_aesdec_si128(state, k[5]);
	state = _mm_aesdec_si128(state, k[6]);
	state = _mm_aesdec_si128(state, k[7]);
	state = _mm_aesdec_si128(state, k[8]);
	state = _mm_aesdec_si128(state, k[9]);

	switch (nr) {
	case 10:
		state = _mm_aesdeclast_si128(state, k[10]);
		break;
	case 12:
		state = _mm_aesdec_si128(state, k[10]);
		state = _mm_aesdec_si128(state, k[11]);
		state = _mm_aesdeclast_si128(state, k[12]);
		break;
	case 14:
		state = _mm_aesdec_si128(state, k[10]);
		state = _mm_aesdec_si128(state, k[11]);
		state = _mm_aesdec_si128(state, k[12]);
		state = _mm_aesdec_si128(state, k[13]);
		state = _mm_aesdeclast_si128(state, k[14]);
		break;
	}

	_mm_storeu_si128((__m128i *) out, state);
}

void aes_ni_wipe_key(struct aes_ni_subkeys *subkeys)
{
	unsigned int i;

	subkeys->nr = 0;
	for (i = 0; i < 15; i++) {
		subkeys->ek[i] = _mm_setzero_si128();
		subkeys->dk[i] = _mm_setzero_si128();
	}
}
