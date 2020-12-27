#include "hmac-sha1.h"
#include "hmac.h"
#include <string.h> /* memcpy() */

DEFINE_HMAC_ALGO(sha1, SHA1_STATE_LEN, SHA1_DIGEST_LEN);
