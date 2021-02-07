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
#ifndef __TWOFISH_FERGUSON_H
#define __TWOFISH_FERGUSON_H

#if defined (__cplusplus)
extern "C" {
#endif

struct twofish_subkeys {
        unsigned int s[4][256];   /* pre-computed S-boxes */
        unsigned int K[40];       /* round keys */
};

int twofish_prepare_key(struct twofish_subkeys *subkeys,
			const unsigned char *key, unsigned int bits);

void twofish_encrypt(struct twofish_subkeys *subkeys, unsigned char *out,
		     const unsigned char *in);
void twofish_decrypt(struct twofish_subkeys *subkeys, unsigned char *out,
		     const unsigned char *in);
void twofish_wipe_key(struct twofish_subkeys *subkeys);

#if defined (__cplusplus)
}
#endif

#endif /* __TWOFISH_FERGUSON_H */
