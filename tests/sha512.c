#include "test.h"
#include "sha512.h"
#include "../sha512.h"

/*
 * The test vectors were generated by a Ruby script using the ‘Digest::SHA512.hexdigest’ function. 
 */

static const char digest_empty[] = {
	"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
};

static const char digest_56chars[] = {
	"7f2f7d496d626b701725068d630cbfb9cecabe92aaf8bc92199fc38dcd73aa4efdae336b6bac552977c0bafc516995249c0134e592cc2d468cad46f58ca4aea7"
};

static const char digest_64chars[] = {
	"6cbce8f347e8d1b3d3517b27fdc4ee1c71d8406ab54e2335f3a39732fa0009d22193c41677d18504e90b4c1138c32e7cc1aa7500597ba99cacd525ef2c44e9dc"
};

static const char digest_70zeroes[] = {
	"3a4ac70aeaa4c39fa67d80018ef7eb6509df394b801a2b4b7421420dfa75cda9746786391dec6a9e7741394f65e400d92860e4195d8a6fa940f30ab962b75bdf"
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

void sha512_test(const char *str, const char *expected)
{
	struct sha512_state state;
	unsigned char buf[64];
	char hex[129];

	sha512_init(&state);
	sha512_update(&state, (const unsigned char *) str, strlen(str));
	sha512_final(&state, buf);

	dump_hex(hex, buf, 64);
	ck_assert_str_eq(expected, hex);

	sha512_wipe_state(&state);
}

START_TEST(test_sha512_empty)
{
	sha512_test("", digest_empty);
}
END_TEST

#define SIXTEEN "1234567812345678"

START_TEST(test_sha512_56chars)
{
	sha512_test(SIXTEEN SIXTEEN SIXTEEN "12345678", digest_56chars);
}
END_TEST

START_TEST(test_sha512_64chars)
{
	struct sha512_state state;
	unsigned char buf[64];
	char hex[129];

	sha512_test(SIXTEEN SIXTEEN SIXTEEN SIXTEEN, digest_64chars);

	sha512_init(&state);
	sha512_update(&state, (const unsigned char *) SIXTEEN, 16);
	sha512_update(&state, (const unsigned char *) SIXTEEN, 16);
	sha512_update(&state, (const unsigned char *) SIXTEEN, 16);
	sha512_update(&state, (const unsigned char *) SIXTEEN, 16);
	sha512_final(&state, buf);

	dump_hex(hex, buf, 64);
	ck_assert_str_eq(digest_64chars, hex);

	sha512_wipe_state(&state);
}
END_TEST

START_TEST(test_sha512_70zeroes)
{
	struct sha512_state state;
	unsigned char buf[70] = {};
	char hex[129];

	sha512_init(&state);
	sha512_update(&state, buf, 70);
	sha512_final(&state, buf);

	dump_hex(hex, buf, 64);
	ck_assert_str_eq(digest_70zeroes, hex);

	memset(buf, '\0', 70);
	sha512_init(&state);
	sha512_update(&state, buf, 10);
	sha512_update(&state, buf, 50);
	sha512_update(&state, buf, 10);
	sha512_final(&state, buf);

	dump_hex(hex, buf, 64);
	ck_assert_str_eq(digest_70zeroes, hex);

	sha512_wipe_state(&state);
}
END_TEST

void register_sha512_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_sha512_empty);
	tcase_add_test(test_case, test_sha512_56chars);
	tcase_add_test(test_case, test_sha512_64chars);
	tcase_add_test(test_case, test_sha512_70zeroes);
}
