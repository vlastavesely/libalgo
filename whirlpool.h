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
#ifndef __WHIRLPOOL_H
#define __WHIRLPOOL_H

#define WHIRLPOOL_STATE_LEN 64
#define WHIRLPOOL_DIGEST_LEN 64

struct whirlpool_state {
	unsigned char bitLength[32];	/* global number of hashed bits (256-bit counter) */
	unsigned char buffer[64];	/* buffer of data to hash */
	int bufferBits;			/* current number of bits on the buffer */
	int bufferPos;			/* current (possibly incomplete) byte slot on the buffer */
	unsigned long long hash[8];	/* the hashing state */
};

void whirlpool_init(struct whirlpool_state *state);
#define whirlpool_wipe_state whirlpool_init

void whirlpool_update(struct whirlpool_state *state, const unsigned char *in,
		      unsigned int n);
void whirlpool_final(struct whirlpool_state *state, unsigned char *digest);

#endif /* __WHIRLPOOL_H */
