#ifndef __SHA1_H
#define __SHA1_H

#define SHA1_STATE_LEN 64
#define SHA1_DIGEST_LEN 20

struct sha1_state {
	unsigned long long size;
	unsigned int H[5];
	unsigned int W[16];
};

void sha1_init(struct sha1_state *state);
#define sha1_wipe_state sha1_init

void sha1_update(struct sha1_state *state, const unsigned char *in,
		  unsigned int n);
void sha1_final(struct sha1_state *state, unsigned char *digest);

#endif /* __SHA1_H */
