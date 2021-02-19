#include "test.h"
#include "rijndael-alg-fst.h"
#include "../rijndael-alg-fst.h"

#include "aes-test-vectors.h"

static void test_rijndael(const unsigned char *key, const unsigned char *ct,
			  unsigned int bits)
{
	struct rijndael_subkeys subkeys;
	unsigned char buf[16];

	rijndael_prepare_key(&subkeys, key, bits);
	rijndael_encrypt(&subkeys, buf, plaintext);
	ck_assert_byte_array_eq(ct, buf, 16);

	rijndael_decrypt(&subkeys, buf, buf);
	ck_assert_byte_array_eq(plaintext, buf, 16);

	rijndael_wipe_key(&subkeys);
}

START_TEST(test_rijndael_128)
{
	test_rijndael(key_128, ciphertext_128, 128);
}
END_TEST

START_TEST(test_rijndael_192)
{
	test_rijndael(key_192, ciphertext_192, 192);
}
END_TEST

START_TEST(test_rijndael_256)
{
	test_rijndael(key_256, ciphertext_256, 256);
}
END_TEST

void register_rijndael_alg_fst_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_rijndael_128);
	tcase_add_test(test_case, test_rijndael_192);
	tcase_add_test(test_case, test_rijndael_256);
}
