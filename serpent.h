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
#ifndef __SERPENT_H
#define __SERPENT_H

#if defined (__cplusplus)
extern "C" {
#endif

struct serpent_subkeys {
	unsigned int l_key[140];
};

int serpent_prepare_key(struct serpent_subkeys *subkeys,
			const unsigned char *key, unsigned int bits);

void serpent_encrypt(struct serpent_subkeys *subkeys, unsigned char *out,
		     const unsigned char *in);
void serpent_decrypt(struct serpent_subkeys *subkeys, unsigned char *out,
		     const unsigned char *in);
void serpent_wipe_key(struct serpent_subkeys *subkeys);

#if defined (__cplusplus)
}
#endif

#endif /* __SERPENT_H */
