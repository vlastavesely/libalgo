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
#ifndef __ARCFOUR_H
#define __ARCFOUR_H

#if defined (__cplusplus)
extern "C" {
#endif

struct arcfour_subkeys {
	unsigned char s[256];
	unsigned char i;
	unsigned char j;
};

int arcfour_prepare_key(struct arcfour_subkeys *subkeys,
			const unsigned char *key, unsigned int keylen);
void arcfour_crypt(struct arcfour_subkeys *subkeys, unsigned char *out,
		   const unsigned char *in, unsigned len);
void arcfour_wipe_key(struct arcfour_subkeys *subkeys);

#if defined (__cplusplus)
}
#endif

#endif /* __ARCFOUR_H */
