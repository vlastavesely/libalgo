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
#ifndef __SHA256_H
#define __SHA256_H

#define SHA256_STATE_LEN 64
#define SHA256_DIGEST_LEN 32

struct sha256_state {
	unsigned int h[8];
	unsigned char buf[64];
	unsigned long long len;
};

void sha256_init(struct sha256_state *state);
#define sha256_wipe_state sha256_init

void sha256_update(struct sha256_state *state, const unsigned char *in,
		  unsigned int n);
void sha256_final(struct sha256_state *state, unsigned char *digest);

#endif /* __SHA256_H */
