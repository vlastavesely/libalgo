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
#ifndef __BLOWFISH_H
#define __BLOWFISH_H

#if defined (__cplusplus)
extern "C" {
#endif

struct blowfish_subkeys {
	unsigned int p[18];
	unsigned int s[1024];
};

int blowfish_prepare_key(struct blowfish_subkeys *subkeys,
			 const unsigned char *key, unsigned int keybits);

void blowfish_encrypt(struct blowfish_subkeys *subkeys, unsigned char *out,
		      const unsigned char *in);
void blowfish_decrypt(struct blowfish_subkeys *subkeys, unsigned char *out,
		      const unsigned char *in);
void blowfish_wipe_key(struct blowfish_subkeys *subkeys);

#if defined (__cplusplus)
}
#endif

#endif /* __BLOWFISH_H */
