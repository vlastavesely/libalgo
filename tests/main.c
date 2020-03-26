#include "test.h"
#include "rijndael-alg-fst.h"
#include "twofish-ferguson.h"

static struct Suite *create_test_suite()
{
	Suite *suite;
	TCase *test_case;

	suite = suite_create(NULL);
	test_case = tcase_create(NULL);
	suite_add_tcase(suite, test_case);

	register_rijndael_alg_fst_tests(test_case);
	register_twofish_ferguson_tests(test_case);

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
