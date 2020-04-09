#include "hmac-sha256.h"
#include "hmac.h"
#include <string.h> /* memcpy() */

DEFINE_HMAC_ALGO(sha256, SHA256_STATE_LEN, SHA256_DIGEST_LEN);
