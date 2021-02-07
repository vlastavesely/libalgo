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
#ifndef __AES_NI_H
#define __AES_NI_H

#if defined (__cplusplus)
extern "C" {
#endif

#include <wmmintrin.h>

struct aes_ni_subkeys {
	__m128i ek[15];
	__m128i dk[15];
	unsigned int nr;
};

int aes_ni_prepare_key(struct aes_ni_subkeys *subkeys, const unsigned char *key,
		       unsigned int bits);
void aes_ni_encrypt(struct aes_ni_subkeys *subkeys, unsigned char *out,
		    const unsigned char *in);
void aes_ni_decrypt(struct aes_ni_subkeys *subkeys, unsigned char *out,
		    const unsigned char *in);
void aes_ni_wipe_key(struct aes_ni_subkeys *subkeys);

#if defined (__cplusplus)
}
#endif

#endif /* __AES_NI_H */
