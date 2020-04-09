#include "test.h"
#include "hmac-sha256.h"
#include "../hmac-sha256.h"

void test_hmac_sha256(const char *expected, const char *key, const char *data)
{
	struct hmac_sha256_state state;
	unsigned char buf[64];
	char hex[129] = {};
	unsigned int i;

	hmac_sha256_init(&state, (const unsigned char *) key, strlen(key));
	hmac_sha256_update(&state, (const unsigned char *) data, strlen(data));
	hmac_sha256_final(&state, buf);

	for (i = 0; i < 32; i++)
		sprintf(hex + (i * 2), "%02x", buf[i]);

	ck_assert_str_eq(expected, hex);

	hmac_sha256_wipe_state(&state);
}

#define SIXTYFOUR "0123456701234567012345670123456701234567012345670123456701234567"
#define LAZY_DOG "The quick brown fox jumps over the lazy dog"

START_TEST(test_hmac_sha256_short_key)
{
	test_hmac_sha256(
		"79748ca9a8e943f8fc39b264ec64655d082c2031c39cd48e3462083cfa7cb24b",
		"01234567", LAZY_DOG);
}
END_TEST

START_TEST(test_hmac_sha256_long_key)
{
	test_hmac_sha256(
		"9564cde63e5ce16cbefebdf345d932855b8588a2fc1cd239538e400972fc23ba",
		SIXTYFOUR SIXTYFOUR SIXTYFOUR, LAZY_DOG);
}
END_TEST

void register_hmac_sha256_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_hmac_sha256_short_key);
	tcase_add_test(test_case, test_hmac_sha256_long_key);
}
