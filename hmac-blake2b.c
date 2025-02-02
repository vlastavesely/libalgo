#include "hmac-blake2b.h"

/*
 * Predefine the init function because it takes more arguments that other
 * hash functions.
 */
#define HMAC_INIT_FUNC(ALGO, state) blake2b_init(state, NULL, 0, 64)

#include "hmac.h"
#include <string.h> /* memcpy() */

DEFINE_HMAC_ALGO(blake2b, BLAKE2B_STATE_LEN, BLAKE2B_DIGEST_LEN);

#undef HMAC_INIT_FUNC
