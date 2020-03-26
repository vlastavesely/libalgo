#ifndef __RIJNDAEL_ALG_FST_H
#define __RIJNDAEL_ALG_FST_H

#if defined (__cplusplus)
extern "C" {
#endif

struct rijndael_subkeys {
	unsigned int nr;
	unsigned int ek[60]; /* 60 == 4 * (MAXNR + 1) */
	unsigned int dk[60];
};

int rijndael_prepare_key(struct rijndael_subkeys *subkeys,
			 const unsigned char *key, unsigned int bits);

void rijndael_encrypt(struct rijndael_subkeys *subkeys, unsigned char *out,
		      const unsigned char *in);
void rijndael_decrypt(struct rijndael_subkeys *subkeys, unsigned char *out,
		      const unsigned char *in);
void rijndael_wipe(struct rijndael_subkeys *subkeys);

#if defined (__cplusplus)
}
#endif

#endif /* __RIJNDAEL_ALG_FST_H */
