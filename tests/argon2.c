#include "test.h"
#include "argon2.h"
#include "../argon2.h"

static void test_argon2_hash(const char *password, const char *salt,
			     unsigned int m, unsigned int t, unsigned int p,
			     unsigned int hlen, enum argon2_type type,
			     const char *expected)
{
	struct argon2_state a2 = ARGON2_INIT;
	unsigned char buf[hlen], hex[(hlen * 2) + 1];
	unsigned int i;
	int ret;

	a2.password = password;
	a2.passwordlen = strlen(password);
	a2.salt = salt;
	a2.saltlen = strlen(salt);
	a2.m = m;
	a2.i = t;
	a2.p = p;
	a2.t = hlen;
	a2.type = type;
	a2.version = 0x13;

	ret = argon2(&a2, buf);
	ck_assert_int_eq(0, ret);

	for (i = 0; i < hlen; i++) {
		sprintf(hex + (i * 2), "%02x", buf[i]);
	}

	ck_assert_str_eq(expected, hex);
}

/*
 * The test vectors were generated with the argon2 package in python3.
 */
START_TEST(test_argon2)
{
	/* types */
	test_argon2_hash("password", "saltsalt", 32, 1, 4, 32, ARGON2ID,
			 "3ab46f9cb6360e680cfc63ce00474a655f2e4fab29649a1ed3078f8ce94260e1");
	test_argon2_hash("password", "saltsalt", 32, 1, 4, 32, ARGON2D,
			 "cc804ce57f7aafefe41e992a9afb8e618ced986fe1588a185a8e343aaa109725");
	test_argon2_hash("password", "saltsalt", 32, 1, 4, 32, ARGON2I,
			 "d5c499875a3bc4130cf8b86244059f235c2e1a54054bed923ba964098b68a70f");

	/* different tag lengths */
	test_argon2_hash("password", "saltsalt", 32, 1, 4, 32, ARGON2ID,
			 "3ab46f9cb6360e680cfc63ce00474a655f2e4fab29649a1ed3078f8ce94260e1");
	test_argon2_hash("password", "saltsalt", 32, 1, 4, 64, ARGON2ID,
			 "2fb42e7d09d728b5c51c1bfcd0f873fdf92bfe383eb465ee36f4e884eafe9a96"
			 "4b2b5cd43c5bd76e91187d38b54e815454ff195d199fdf182627b0b8ed7875ce");
	test_argon2_hash("password", "saltsalt", 32, 1, 4, 128, ARGON2ID,
			 "5038cd48cfb50357157759aa6c07dff7e755894a74d0b223ea663a5c4362cafb"
			 "c04650d06667e1f4f8dea33f9ab2f55743a108d49898c069ce6fc4e220fb0099"
			 "9451f00a74bcc23f037d2a21f05d9b35c9ba9c14b7c7f4a549bb1df8d9d1b1a9"
			 "0928ecd89132c34604fb1f98c8ec9ac7f8fb3eb368510e95e1b48747d1688e7d");

	/* memory size */
	test_argon2_hash("password", "saltsalt", 64, 3, 4, 32, ARGON2ID,
			 "15beda7396b7a899bbee94cf67d5d6c7b2673f74257e6cf44edb424275876786");
	test_argon2_hash("password", "saltsalt", 128, 6, 8, 32, ARGON2ID,
			 "a6caf8308820335dee7b40e8b9b5900030dcffa17f10a34a72e678c0732f23b2");

	/* password and salt */
	test_argon2_hash("lacinia venetatis", "saltsalt", 128, 11, 8, 8, ARGON2ID,
			 "22afee99e49a1fef");
	test_argon2_hash("password", "magna et, convallis eros", 128, 11, 8, 8, ARGON2ID,
			 "860c215c846b21e1");
}
END_TEST

static int argon2_hash(const char *password, const char *salt,
		       unsigned int m, unsigned int t, unsigned int p,
		       unsigned int hlen, enum argon2_type type)
{
	struct argon2_state a2 = ARGON2_INIT;
	unsigned char buf[hlen], hex[(hlen * 2) + 1];
	unsigned int i;

	a2.password = password;
	a2.passwordlen = strlen(password);
	a2.salt = salt;
	a2.saltlen = strlen(salt);
	a2.m = m;
	a2.i = t;
	a2.p = p;
	a2.t = hlen;
	a2.type = type;
	a2.version = 0x13;

	return argon2(&a2, buf);
}

START_TEST(test_argon2_errors)
{
	int ret;

	ret = argon2_hash("", "", 256, 1, 2, 32, ARGON2ID);
	ck_assert_int_eq(ARGON2_SALT_TOO_SHORT, ret);

	ret = argon2_hash("", "saltsalt", 8, 1, 2, 32, ARGON2ID);
	ck_assert_int_eq(ARGON2_M_TOO_LITTLE, ret);

	ret = argon2_hash("", "saltsalt", 256, 1, 13, 32, ARGON2ID);
	ck_assert_int_eq(ARGON2_M_NOT_DIVISIBLE_BY_P, ret);

	ret = argon2_hash("", "saltsalt", 256, 1, 2, 32, 11);
	ck_assert_int_eq(ARGON2_BAD_TYPE, ret);
}
END_TEST

void register_argon2_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_argon2);
	tcase_add_test(test_case, test_argon2_errors);
}
