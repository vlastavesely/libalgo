#include "test.h"
#include "sha1.h"
#include "../sha1.h"

/*
 * The test vectors are from Wikipedia.
 */
static const char digest_empty[] = {
	"da39a3ee5e6b4b0d3255bfef95601890afd80709"
};

static const char digest_lazy_dog[] = {
	"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
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

void sha1_test(const char *str, const char *expected)
{
	struct sha1_state state;
	unsigned char buf[20];
	char hex[41];

	sha1_init(&state);
	sha1_update(&state, (const unsigned char *) str, strlen(str));
	sha1_final(&state, buf);

	dump_hex(hex, buf, 20);
	ck_assert_str_eq(expected, hex);

	sha1_wipe_state(&state);
}

START_TEST(test_sha1_empty)
{
	sha1_test("", digest_empty);
}
END_TEST

START_TEST(test_sha1_lazy_dog)
{
	sha1_test("The quick brown fox jumps over the lazy dog", digest_lazy_dog);
}
END_TEST

void register_sha1_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_sha1_empty);
	tcase_add_test(test_case, test_sha1_lazy_dog);
}
