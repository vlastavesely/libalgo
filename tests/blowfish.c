#include "test.h"
#include "blowfish.h"
#include "../blowfish.h"

/* https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt */
static const unsigned char k1[8] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const unsigned char p1[8] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const unsigned char c1[8] = {
	0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78
};

static const unsigned char k2[8] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const unsigned char p2[8] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const unsigned char c2[8] = {
	0x51, 0x86, 0x6f, 0xd5, 0xb8, 0x5e, 0xcb, 0x8a
};

static void test_blowfish(const char *key, const unsigned char *pt,
			  const unsigned char *ct, unsigned int bits)
{
 	struct blowfish_subkeys subkeys;
	unsigned char buf[8];

	blowfish_prepare_key(&subkeys, key, bits);
	blowfish_encrypt(&subkeys, buf, pt);
	ck_assert_byte_array_eq(ct, buf, 8);

	blowfish_decrypt(&subkeys, buf, buf);
	ck_assert_byte_array_eq(pt, buf, 8);

	blowfish_wipe_key(&subkeys);
}

START_TEST(test_blowfish_64)
{
	test_blowfish(k1, p1, c1, 64);
	test_blowfish(k2, p2, c2, 64);
}
END_TEST

void register_blowfish_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_blowfish_64);
}
