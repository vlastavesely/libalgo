#include "test.h"
#include "utils.h"
#include "../utils.h"

START_TEST(test_rotation)
{
	unsigned int i32 = 0x11223344;
	unsigned long long i64 = 0x1122334455667788;

	i32 = ROTR32(i32, 8);
	ck_assert_int_eq(0x44112233, i32);
	i64 = ROTR64(i64, 8);
	ck_assert_int_eq(0x8811223344556677, i64);
}
END_TEST

START_TEST(test_get)
{
	unsigned char a[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
	unsigned int i32 = GETU32_BE(a);
	unsigned long long i64 = GETU64_BE(a);

	ck_assert_int_eq(0x11223344, i32);
	ck_assert_int_eq(0x1122334455667788, i64);
}
END_TEST

START_TEST(test_put)
{
	unsigned char a[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
	unsigned char b[8] = {};

	PUTU32_BE(b, 0x11223344);
	ck_assert_byte_array_eq(a, b, 4);

	PUTU64_BE(b, 0x1122334455667788);
	ck_assert_byte_array_eq(a, b, 8);
}
END_TEST

void register_utils_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_rotation);
	tcase_add_test(test_case, test_get);
	tcase_add_test(test_case, test_put);
}
