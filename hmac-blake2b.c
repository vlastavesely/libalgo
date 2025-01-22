#include "hmac-blake2b.h"

#define KEYED_HASH 1

#include "hmac.h"
#include <string.h> /* memcpy() */

DEFINE_HMAC_ALGO(blake2b, BLAKE2B_STATE_LEN, BLAKE2B_DIGEST_LEN);

#undef KEYED_HASH
