#include "test.h"
#include "sha256.h"
#include "../sha256.h"

/*
 * The test vectors were generated by a Ruby script using the ‘Digest::SHA256.hexdigest’ function.
 */

static const char digest_empty[] = {
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
};

static const char digest_56chars[] = {
	"6f2f0a498c0efe37829466bec79fdde57380e1fe4c0ebd79b9e8987b9c0859c9"
};

static const char digest_64chars[] = {
	"06bcbf53e05cd44da1c9dc7a0737f08eceef318eeab6f4c6743dea34038b62ce"
};

static const char digest_70zeroes[] = {
	"82fcfd5215175da9e65ca7c4fb927a1fb0e61f09d54987c368e8e16ebd9c2969"
};

static void dump_hex(char *out, const unsigned char *in, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		sprintf(out, "%02x", in[i]);
		out += 2;
	}
	*out = '\0';
}

void sha256_test(const char *str, const char *expected)
{
	struct sha256_state state;
	unsigned char buf[32];
	char hex[65];

	sha256_init(&state);
	sha256_update(&state, (const unsigned char *) str, strlen(str));
	sha256_final(&state, buf);

	dump_hex(hex, buf, 32);
	ck_assert_str_eq(expected, hex);

	sha256_wipe_state(&state);
}

START_TEST(test_sha256_empty)
{
	sha256_test("", digest_empty);
}
END_TEST

#define SIXTEEN "1234567812345678"

START_TEST(test_sha256_56chars)
{
	sha256_test(SIXTEEN SIXTEEN SIXTEEN "12345678", digest_56chars);
}
END_TEST

START_TEST(test_sha256_64chars)
{
	struct sha256_state state;
	unsigned char buf[32];
	char hex[65];

	sha256_test(SIXTEEN SIXTEEN SIXTEEN SIXTEEN, digest_64chars);

	sha256_init(&state);
	sha256_update(&state, (const unsigned char *) SIXTEEN, 16);
	sha256_update(&state, (const unsigned char *) SIXTEEN, 16);
	sha256_update(&state, (const unsigned char *) SIXTEEN, 16);
	sha256_update(&state, (const unsigned char *) SIXTEEN, 16);
	sha256_final(&state, buf);

	dump_hex(hex, buf, 32);
	ck_assert_str_eq(digest_64chars, hex);

	sha256_wipe_state(&state);
}
END_TEST

START_TEST(test_sha256_70zeroes)
{
	struct sha256_state state;
	unsigned char buf[70] = {};
	char hex[65];

	sha256_init(&state);
	sha256_update(&state, buf, 70);
	sha256_final(&state, buf);

	dump_hex(hex, buf, 32);
	ck_assert_str_eq(digest_70zeroes, hex);

	memset(buf, '\0', 70);
	sha256_init(&state);
	sha256_update(&state, buf, 10);
	sha256_update(&state, buf, 50);
	sha256_update(&state, buf, 10);
	sha256_final(&state, buf);

	dump_hex(hex, buf, 32);
	ck_assert_str_eq(digest_70zeroes, hex);

	sha256_wipe_state(&state);
}
END_TEST

void register_sha256_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_sha256_empty);
	tcase_add_test(test_case, test_sha256_56chars);
	tcase_add_test(test_case, test_sha256_64chars);
	tcase_add_test(test_case, test_sha256_70zeroes);
}
