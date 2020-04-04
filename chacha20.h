#ifndef __CHACHA20_H
#define __CHACHA20_H

#if defined (__cplusplus)
extern "C" {
#endif

struct chacha20_subkeys {
        unsigned int key[8];
        unsigned int nonce[3];
        unsigned int state[16];
        unsigned int i;
        unsigned int avail;
};

int chacha20_prepare_key(struct chacha20_subkeys *subkeys,
			 const unsigned char *key, const unsigned char *nonce,
			 unsigned int blockno);

void chacha20_crypt(struct chacha20_subkeys *subkeys, unsigned char *out,
		    const unsigned char *in, unsigned len);
void chacha20_wipe_key(struct chacha20_subkeys *subkeys);

#if defined (__cplusplus)
}
#endif

#endif /* __CHACHA20_H */
