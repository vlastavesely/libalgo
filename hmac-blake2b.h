/*
 * This file is part of Libalgo.
 *
 * Copyright (c) 2025 by Vlasta Vesely.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted under the terms of the GPL-2 license.
 * The full text of the license is included with the source code
 * of Kuzcrypt.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */
#ifndef __HMAC_BLAKE2B_H
#define __HMAC_BLAKE2B_H

#include "blake2b.h"

struct hmac_blake2b_state {
	struct blake2b_state state;
	unsigned char ipad[BLAKE2B_STATE_LEN];
	unsigned char opad[BLAKE2B_STATE_LEN];
};

void hmac_blake2b_init(struct hmac_blake2b_state *state,
		       const unsigned char *key, unsigned int keylen);
void hmac_blake2b_update(struct hmac_blake2b_state *state,
			 const unsigned char *data, unsigned int len);
void hmac_blake2b_final(struct hmac_blake2b_state *state,
			unsigned char *digest);
void hmac_blake2b_wipe_state(struct hmac_blake2b_state *state);

#endif /* __HMAC_BLAKE2B_H */
