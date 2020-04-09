#include "test.h"
#include "hmac-whirlpool.h"
#include "../hmac-whirlpool.h"

void test_hmac_whirlpool(const char *expected, const char *key, const char *data)
{
	struct hmac_whirlpool_state state;
	unsigned char buf[64];
	char hex[129] = {};
	unsigned int i;

	hmac_whirlpool_init(&state, (const unsigned char *) key, strlen(key));
	hmac_whirlpool_update(&state, (const unsigned char *) data, strlen(data));
	hmac_whirlpool_final(&state, buf);

	for (i = 0; i < 64; i++)
		sprintf(hex + (i * 2), "%02x", buf[i]);

	ck_assert_str_eq(expected, hex);

	hmac_whirlpool_wipe_state(&state);
}

#define SIXTYFOUR "0123456701234567012345670123456701234567012345670123456701234567"
#define LAZY_DOG "The quick brown fox jumps over the lazy dog"

START_TEST(test_hmac_whirlpool_short_key)
{
	test_hmac_whirlpool(
		"51e01894fdc63459bbd84578af75584f932d47e1bab6e5f5f27f4fe4a6f8bcce"
		"ca5ef60c9df6bcee780bb51c780b3354b0e22c92e0f2894ef6238fd5008f590d",
		"01234567", LAZY_DOG);
}
END_TEST

START_TEST(test_hmac_whirlpool_long_key)
{
	test_hmac_whirlpool(
		"29e4e3b0291e6ce9d7dedb0d7705db88c092b579c7d3034f384cdb3a5e3e5c71"
		"53d34fa1360495275454a865902959aaea89b521dad734c501f1bdbb89c478b1",
		SIXTYFOUR SIXTYFOUR SIXTYFOUR, LAZY_DOG);
}
END_TEST

void register_hmac_whirlpool_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_hmac_whirlpool_short_key);
	tcase_add_test(test_case, test_hmac_whirlpool_long_key);
}
