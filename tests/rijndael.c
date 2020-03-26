#include "test.h"
#include "rijndael.h"
//#include "../rijndael.h"

START_TEST(test_rijndael)
{

}
END_TEST

void register_rijndael_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_rijndael);
}
