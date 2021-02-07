/*
 * This file is part of Libalgo.
 *
 * Copyright (c) 2021 by Vlasta Vesely.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted under the terms of the GPL-2 license.
 * The full text of the license is included with the source code
 * of Kuzcrypt.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */
#ifndef __HMAC_SHA256_H
#define __HMAC_SHA256_H

#include "sha256.h"

struct hmac_sha256_state {
	struct sha256_state state;
	unsigned char ipad[SHA256_STATE_LEN];
	unsigned char opad[SHA256_STATE_LEN];
};

void hmac_sha256_init(struct hmac_sha256_state *state,
		      const unsigned char *key, unsigned int keylen);
void hmac_sha256_update(struct hmac_sha256_state *state,
			const unsigned char *data, unsigned int len);
void hmac_sha256_final(struct hmac_sha256_state *state,
		       unsigned char *digest);
void hmac_sha256_wipe_state(struct hmac_sha256_state *state);

#endif /* __HMAC_SHA256_H */
