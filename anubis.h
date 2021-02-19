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
#ifndef __ANUBIS_H
#define __ANUBIS_H

#if defined (__cplusplus)
extern "C" {
#endif

struct anubis_subkeys {
	int keyBits;
	int R;
	unsigned int roundKeyEnc[19][4];
	unsigned int roundKeyDec[19][4];
};

int anubis_prepare_key(struct anubis_subkeys *subkeys,
		       const unsigned char *key, unsigned int keylen);
void anubis_encrypt(struct anubis_subkeys *subkeys, unsigned char *out,
		    const unsigned char *in);
void anubis_decrypt(struct anubis_subkeys *subkeys, unsigned char *out,
		    const unsigned char *in);
void anubis_wipe_key(struct anubis_subkeys *subkeys);

#if defined (__cplusplus)
}
#endif

#endif /* __ANUBIS_H */
