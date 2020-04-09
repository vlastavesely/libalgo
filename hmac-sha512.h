#ifndef __HMAC_SHA512_H
#define __HMAC_SHA512_H

#include "sha512.h"

struct hmac_sha512_state {
	struct sha512_state state;
	unsigned char ipad[SHA512_STATE_LEN];
	unsigned char opad[SHA512_STATE_LEN];
};

void hmac_sha512_init(struct hmac_sha512_state *state,
		      const unsigned char *key, unsigned int keylen);
void hmac_sha512_update(struct hmac_sha512_state *state,
			const unsigned char *data, unsigned int len);
void hmac_sha512_final(struct hmac_sha512_state *state,
		       unsigned char *digest);
void hmac_sha512_wipe_state(struct hmac_sha512_state *state);

#endif /* __HMAC_SHA512_H */
