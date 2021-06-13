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
#ifndef __SALSA20_H
#define __SALSA20_H

#if defined (__cplusplus)
extern "C" {
#endif

struct salsa20_subkeys {
        unsigned int input[16];
        unsigned int state[16];
        unsigned int avail;
};

int salsa20_prepare_key(struct salsa20_subkeys *subkeys,
			const unsigned char *k, unsigned int kbits,
			const unsigned char *nonce, unsigned int blockno);

void salsa20_crypt(struct salsa20_subkeys *subkeys, unsigned char *out,
		   const unsigned char *in, unsigned len);
void salsa20_wipe_key(struct salsa20_subkeys *subkeys);

#if defined (__cplusplus)
}
#endif

#endif /* __SALSA20_H */
