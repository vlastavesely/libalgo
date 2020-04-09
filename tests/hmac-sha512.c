#include "test.h"
#include "hmac-sha512.h"
#include "../hmac-sha512.h"

void test_hmac_sha512(const char *expected, const char *key, const char *data)
{
	struct hmac_sha512_state state;
	unsigned char buf[64];
	char hex[129] = {};
	unsigned int i;

	hmac_sha512_init(&state, (const unsigned char *) key, strlen(key));
	hmac_sha512_update(&state, (const unsigned char *) data, strlen(data));
	hmac_sha512_final(&state, buf);

	for (i = 0; i < 64; i++)
		sprintf(hex + (i * 2), "%02x", buf[i]);

	ck_assert_str_eq(expected, hex);

	hmac_sha512_wipe_state(&state);
}

#define SIXTYFOUR "0123456701234567012345670123456701234567012345670123456701234567"
#define LAZY_DOG "The quick brown fox jumps over the lazy dog"

START_TEST(test_hmac_sha512_short_key)
{
	test_hmac_sha512(
		"2487cf17cffb87487997e152dc798e30594bc93b1725e42d0e23228cff22be36"
		"b8a39c3026081a11c47e7dd4f184b530179d8566d53ca7e649988e22ff9a600a",
		"01234567", LAZY_DOG);
}
END_TEST

START_TEST(test_hmac_sha512_long_key)
{
	test_hmac_sha512(
		"bdf82f827c07fcc240885897be96661b8f3251be2bcb21f0364bcb6eb267b168"
		"3c7af0425c5b3c38b5a2684a1bc85b62f826feca4a5674dbb4cbf518241f4c2a",
		SIXTYFOUR SIXTYFOUR SIXTYFOUR, LAZY_DOG);
}
END_TEST

void register_hmac_sha512_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_hmac_sha512_short_key);
	tcase_add_test(test_case, test_hmac_sha512_long_key);
}
