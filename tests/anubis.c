#include "test.h"
#include "anubis.h"
#include "../anubis.h"

/* https://web.archive.org/web/20161013081838/http://www.larc.usp.br/%7Epbarreto/anubis-tweak-test-vectors.zip */

/* 128-bit - #0 */
static const unsigned char k1[16] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const unsigned char p1[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const unsigned char c1[16] = {
	0xb8, 0x35, 0xbd, 0xc3, 0x34, 0x82, 0x9d, 0x83,
	0x71, 0xbf, 0xa3, 0x71, 0xe4, 0xb3, 0xc4, 0xfd
};

/* 128-bit - #247 */
static const unsigned char k2[16] = {
	0xf7, 0xf7, 0xf7, 0xf7, 0xf7, 0xf7, 0xf7, 0xf7,
	0xf7, 0xf7, 0xf7, 0xf7, 0xf7, 0xf7, 0xf7, 0xf7
};

static const unsigned char p2[16] = {
	0xf7, 0xf7, 0xf7, 0xf7, 0xf7, 0xf7, 0xf7, 0xf7,
	0xf7, 0xf7, 0xf7, 0xf7, 0xf7, 0xf7, 0xf7, 0xf7
};

static const unsigned char c2[16] = {
	0x2d, 0xae, 0xed, 0x82, 0xa8, 0xd7, 0xa3, 0x8c,
	0xad, 0x24, 0xb1, 0x86, 0xfc, 0xae, 0x5a, 0x2d
};

/* 256-bit - #2 */
static const unsigned char k3[32] = {
	0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const unsigned char p3[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const unsigned char c3[16] = {
	0x7e, 0x1d, 0xe6, 0xbb, 0xc0, 0x6b, 0xb5, 0xbe,
	0x2f, 0x6d, 0x6a, 0x71, 0x9f, 0xe5, 0xb8, 0x07
};

/* 320-bit - #75 */
static const unsigned char k4[40] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const unsigned char p4[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const unsigned char c4[16] = {
	0xfa, 0x4d, 0x7c, 0x32, 0x66, 0x28, 0x55, 0x5c,
	0x41, 0x57, 0xd6, 0xd0, 0x95, 0x97, 0x96, 0x36
};


static void test_anubis(const char *key, const unsigned char *pt,
			const unsigned char *ct, unsigned int bits)
{
 	struct anubis_subkeys subkeys;
	unsigned char buf[16];

	anubis_prepare_key(&subkeys, key, bits >> 3);
	anubis_encrypt(&subkeys, buf, pt);
	ck_assert_byte_array_eq(ct, buf, 16);

	anubis_decrypt(&subkeys, buf, buf);
	ck_assert_byte_array_eq(pt, buf, 16);

	anubis_wipe_key(&subkeys);
}

START_TEST(test_anubis_128)
{
	test_anubis(k1, p1, c1, 128);
	test_anubis(k2, p2, c2, 128);
}
END_TEST

START_TEST(test_anubis_256)
{
	test_anubis(k3, p3, c3, 256);
}
END_TEST

START_TEST(test_anubis_320)
{
	test_anubis(k4, p4, c4, 320);
}
END_TEST

void register_anubis_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_anubis_128);
	tcase_add_test(test_case, test_anubis_256);
	tcase_add_test(test_case, test_anubis_320);
}
