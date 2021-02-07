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
#ifndef __HMAC_WHIRLPOOL_H
#define __HMAC_WHIRLPOOL_H

#include "whirlpool.h"

struct hmac_whirlpool_state {
	struct whirlpool_state state;
	unsigned char ipad[WHIRLPOOL_STATE_LEN];
	unsigned char opad[WHIRLPOOL_STATE_LEN];
};

void hmac_whirlpool_init(struct hmac_whirlpool_state *state,
			 const unsigned char *key, unsigned int keylen);
void hmac_whirlpool_update(struct hmac_whirlpool_state *state,
			   const unsigned char *data, unsigned int len);
void hmac_whirlpool_final(struct hmac_whirlpool_state *state,
			  unsigned char *digest);
void hmac_whirlpool_wipe_state(struct hmac_whirlpool_state *state);

#endif /* __HMAC_WHIRLPOOL_H */
