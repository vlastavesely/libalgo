/*
 * This file is part of Libalgo.
 *
 * Copyright (c) 2025 by Vlasta Vesely.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted under the terms of the GPL-2 license.
 * The full text of the license is included with the source code
 * of Kuzcrypt.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */
#ifndef __ARGON2_H
#define __ARGON2_H

#include <stdint.h>

#if defined (__cplusplus)
extern "C" {
#endif

#define ARGON2_INIT {}

enum argon2_type {
	ARGON2D,
	ARGON2I,
	ARGON2ID
};

enum argon2_version {
	ARGON2_VERSION_10 = 0x10,
	ARGON2_VERSION_13 = 0x13
};

enum argon2_code {
	ARGON2_OK = 0,
	ARGON2_M_TOO_LITTLE,
	ARGON2_M_NOT_DIVISIBLE_BY_P,
	ARGON2_ITER_TOO_LITTLE,
	ARGON2_P_TOO_LITTLE,
	ARGON2_SALT_TOO_SHORT,
	ARGON2_BAD_VERSION,
	ARGON2_BAD_TYPE,
	ARGON2_THREAD_FAIL,
};

struct argon2_state {
	const unsigned char *password;
	unsigned int passwordlen;

	const unsigned char *salt;
	unsigned int saltlen;

	const unsigned char *key;
	unsigned int keylen;

	const unsigned char *assoc;
	unsigned int assoclen;

	unsigned int p; /* paralelism/lanes */
	unsigned int t; /* tag length */
	unsigned int m; /* memory size in KB */
	unsigned int i; /* iterations */
	unsigned int version;
	unsigned int type;

	/* private */
	uint64_t *memory;
	unsigned int segment_len;
	unsigned int lane_len;
};

int argon2(struct argon2_state *state, unsigned char *digest);

#if defined (__cplusplus)
}
#endif

#endif /* __ARGON2_H */
