#include "test.h"
#include "aes-ni.h"
#include "../aes-ni.h"

#include "aes-test-vectors.h"

static void test_aes_ni(const unsigned char *key, const unsigned char *ct,
			unsigned int bits)
{
	struct aes_ni_subkeys subkeys;
	unsigned char buf[16];

	aes_ni_prepare_key(&subkeys, key, bits);
	aes_ni_encrypt(&subkeys, buf, plaintext);
	ck_assert_byte_array_eq(ct, buf, 16);

	aes_ni_decrypt(&subkeys, buf, buf);
	ck_assert_byte_array_eq(plaintext, buf, 16);

	aes_ni_wipe_key(&subkeys);
}

START_TEST(test_aes_ni_128)
{
	test_aes_ni(key_128, ciphertext_128, 128);
}
END_TEST

START_TEST(test_aes_ni_192)
{
	test_aes_ni(key_192, ciphertext_192, 192);
}
END_TEST

START_TEST(test_aes_ni_256)
{
	test_aes_ni(key_256, ciphertext_256, 256);
}
END_TEST
void register_aes_ni_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_aes_ni_128);
	tcase_add_test(test_case, test_aes_ni_192);
	tcase_add_test(test_case, test_aes_ni_256);
}
