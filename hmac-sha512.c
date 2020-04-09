#include "hmac-sha512.h"
#include "hmac.h"
#include <string.h> /* memcpy() */

DEFINE_HMAC_ALGO(sha512, SHA512_STATE_LEN, SHA512_DIGEST_LEN);
