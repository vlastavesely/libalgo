#include "arcfour.h"

int arcfour_prepare_key(struct arcfour_subkeys *subkeys,
			const unsigned char *key, unsigned int keylen)
{
	unsigned int i, j = 0;
	unsigned char t, *s = subkeys->s;

	subkeys->i = 0;
	subkeys->j = 0;

	for (i = 0; i < 256; i++)
		s[i] = i;

	for (i = 0; i < 256; i++) {
		j = (j + s[i] + key[i % keylen]) % 256;
		t = s[i];
		s[i] = s[j];
		s[j] = t;
	}

	return 0;
}

void arcfour_crypt(struct arcfour_subkeys *subkeys, unsigned char *out,
		   const unsigned char *in, unsigned len)
{
	unsigned char i = subkeys->i, j = subkeys->j;
	unsigned char t, k, *s = subkeys->s;

	while (len--) {
		i++;
		j = j + s[i];
		t = s[i];
		s[i] = s[j];
		s[j] = t;
		k = s[(s[i] + s[j]) % 256];
		*out++ = *in++ ^ k;
	}

	subkeys->i = i;
	subkeys->j = j;
}

void arcfour_wipe_key(struct arcfour_subkeys *subkeys)
{
	unsigned int i;

	for (i = 0; i < 256; i++)
		subkeys->s[i] = 0;
	subkeys->i = 0;
	subkeys->j= 0;
}
