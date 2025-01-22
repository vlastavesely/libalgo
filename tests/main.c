#include "test.h"
#include "rijndael-alg-fst.h"
#include "twofish-ferguson.h"
#include "serpent.h"
#include "anubis.h"
#include "blowfish.h"
#include "whirlpool.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "blake2b.h"
#include "chacha20.h"
#include "salsa20.h"
#include "arcfour.h"
#include "hmac-whirlpool.h"
#include "hmac-sha1.h"
#include "hmac-sha256.h"
#include "hmac-sha512.h"
#include "hmac-blake2b.h"
#include "utils.h"

#ifdef HAVE_AES_INSTRUCTIONS
#include "aes-ni.h"
#endif

static struct Suite *create_test_suite()
{
	Suite *suite;
	TCase *test_case;

	suite = suite_create(NULL);
	test_case = tcase_create(NULL);
	suite_add_tcase(suite, test_case);

	register_rijndael_alg_fst_tests(test_case);
	register_twofish_ferguson_tests(test_case);
	register_serpent_tests(test_case);
	register_anubis_tests(test_case);
	register_blowfish_tests(test_case);
	register_whirlpool_tests(test_case);
	register_sha1_tests(test_case);
	register_sha256_tests(test_case);
	register_sha512_tests(test_case);
	register_blake2b_tests(test_case);
	register_chacha20_tests(test_case);
	register_salsa20_tests(test_case);
	register_arcfour_tests(test_case);
	register_hmac_whirlpool_tests(test_case);
	register_hmac_sha1_tests(test_case);
	register_hmac_sha256_tests(test_case);
	register_hmac_sha512_tests(test_case);
	register_hmac_blake2b_tests(test_case);
	register_utils_tests(test_case);

	#ifdef HAVE_AES_INSTRUCTIONS
	register_aes_ni_tests(test_case);
	#endif

	return suite;
}

static int run_test_suites(struct SRunner *runner)
{
	int retval;

	puts("-----------------------------------------");
	srunner_run_all(runner, CK_NORMAL);
	retval = srunner_ntests_failed(runner);
	puts("-----------------------------------------");

	puts(retval == 0 ? "\033[32mpassed\033[0m\n"
			 : "\033[31mfailed\033[0m\n");

	return retval;
}

int main(int argc, const char **argv)
{
	struct SRunner *runner;
	int retval;

	runner = srunner_create(NULL);
	srunner_add_suite(runner, create_test_suite());
	retval = run_test_suites(runner);
	srunner_free(runner);

	return retval;
}
