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
#ifndef __BLAKE2B_H
#define __BLAKE2B_H

#define BLAKE2B_STATE_LEN 128
#define BLAKE2B_DIGEST_LEN 64

#include <stdint.h>

struct blake2b_state {
	uint64_t h[8];
	uint64_t k[8];
	uint64_t t[2];
	uint64_t f[2];
	unsigned char buf[128];
	unsigned long long len;
};

void blake2b_init(struct blake2b_state *state, const unsigned char *key,
		 unsigned int keylen);
#define blake2b_wipe_state(s) blake2b_init(s, NULL, 0)

void blake2b_update(struct blake2b_state *state, const unsigned char *in,
		    unsigned int n);
void blake2b_final(struct blake2b_state *state, unsigned char *digest);

#endif /* __BLAKE2BB_H */
