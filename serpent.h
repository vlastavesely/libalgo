#ifndef __SERPENT_H
#define __SERPENT_H

#if defined (__cplusplus)
extern "C" {
#endif

struct serpent_subkeys {
	unsigned int l_key[140];
};

int serpent_prepare_key(struct serpent_subkeys *subkeys,
			const unsigned char *key, unsigned int bits);

void serpent_encrypt(struct serpent_subkeys *subkeys, unsigned char *out,
		     const unsigned char *in);
void serpent_decrypt(struct serpent_subkeys *subkeys, unsigned char *out,
		     const unsigned char *in);
void serpent_wipe_key(struct serpent_subkeys *subkeys);

#if defined (__cplusplus)
}
#endif

#endif /* __SERPENT_H */
