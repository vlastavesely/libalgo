#include "test.h"
#include "hmac-sha1.h"
#include "../hmac-sha1.h"

/*
 * https://tools.ietf.org/html/rfc2202
 */
START_TEST(test_hmac_sha1_rfc_2202)
{
	struct hmac_sha1_state state;
	unsigned char buf[20];
	unsigned char key[20];
	char hex[129] = {};
	unsigned int i;

	memset(key, 0x0b, 20);

	hmac_sha1_init(&state, key, 20);
	hmac_sha1_update(&state, (const unsigned char *) "Hi There", 8);
	hmac_sha1_final(&state, buf);

	for (i = 0; i < 20; i++)
		sprintf(hex + (i * 2), "%02x", buf[i]);

	ck_assert_str_eq("b617318655057264e28bc0b6fb378c8ef146be00", hex);

	hmac_sha1_wipe_state(&state);
}
END_TEST

void register_hmac_sha1_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_hmac_sha1_rfc_2202);
}
