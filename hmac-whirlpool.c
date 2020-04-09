#include "hmac-whirlpool.h"
#include "hmac.h"
#include <string.h> /* memcpy() */

DEFINE_HMAC_ALGO(whirlpool, WHIRLPOOL_STATE_LEN, WHIRLPOOL_DIGEST_LEN);
