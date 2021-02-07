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
#ifndef __SHA512_H
#define __SHA512_H

#define SHA512_STATE_LEN 128
#define SHA512_DIGEST_LEN 64

#include <stdint.h>

struct sha512_state {
	uint64_t h[8];
	unsigned char buf[128];
	unsigned long long len;
};

void sha512_init(struct sha512_state *state);
#define sha512_wipe_state sha512_init

void sha512_update(struct sha512_state *state, const unsigned char *in,
		  unsigned int n);
void sha512_final(struct sha512_state *state, unsigned char *digest);

#endif /* __SHA512_H */
