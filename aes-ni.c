#include "aes-ni.h"

static void aes_ni_prepare_128bit_key(struct aes_ni_subkeys *subkeys,
				      const unsigned char *key)
{
}

static void aes_ni_prepare_192bit_key(struct aes_ni_subkeys *subkeys,
				      const unsigned char *key)
{
}

static void aes_ni_prepare_256bit_key(struct aes_ni_subkeys *subkeys,
				      const unsigned char *key)
{
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
}

void aes_ni_decrypt(struct aes_ni_subkeys *subkeys, unsigned char *out,
		    const unsigned char *in)
{
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
