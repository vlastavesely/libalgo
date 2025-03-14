#include "test.h"
#include "serpent.h"
#include "../serpent.h"

/* http://www.cs.technion.ac.il/~biham/Reports/Serpent/ */

static const unsigned char pt[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-128-128.verified.test-vectors */
static const unsigned char k128[] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const unsigned char c128[] = {
	0x26, 0x4e, 0x54, 0x81, 0xef, 0xf4, 0x2a, 0x46,
	0x06, 0xab, 0xda, 0x06, 0xc0, 0xbf, 0xda, 0x3d
};

/* http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-192-128.verified.test-vectors */
static const unsigned char k192[] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const unsigned char c192[] = {
	0x9e, 0x27, 0x4e, 0xad, 0x9b, 0x73, 0x7b, 0xb2,
	0x1e, 0xfc, 0xfc, 0xa5, 0x48, 0x60, 0x26, 0x89
};

/* http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-256-128.verified.test-vectors */
static const unsigned char k256[] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const unsigned char c256[] = {
	0xa2, 0x23, 0xaa, 0x12, 0x88, 0x46, 0x3c, 0x0e,
	0x2b, 0xe3, 0x8e, 0xbd, 0x82, 0x56, 0x16, 0xc0
};

static void test_serpent(const unsigned char *key, const unsigned char *pt,
			 const unsigned char *ct, unsigned int bits)
{
	struct serpent_subkeys subkeys;
	unsigned char buf[16];

	serpent_prepare_key(&subkeys, key, bits);
	serpent_encrypt(&subkeys, buf, pt);
	ck_assert_byte_array_eq(ct, buf, 16);

	serpent_decrypt(&subkeys, buf, buf);
	ck_assert_byte_array_eq(pt, buf, 16);

	serpent_wipe_key(&subkeys);
}

START_TEST(test_serpent_128)
{
	test_serpent(k128, pt, c128, 128);
}
END_TEST

START_TEST(test_serpent_192)
{
	test_serpent(k192, pt, c192, 192);
}
END_TEST

START_TEST(test_serpent_256)
{
	test_serpent(k256, pt, c256, 256);
}
END_TEST
void register_serpent_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_serpent_128);
	tcase_add_test(test_case, test_serpent_192);
	tcase_add_test(test_case, test_serpent_256);
}
