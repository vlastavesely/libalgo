#include "test.h"
#include "../blake2b.h"
#include "blake2b.h"

/*
 * https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2b-kat.txt
 */
static const char *hash0 =
	"10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786"
	"b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568";

static const char *hash1 =
	"961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4"
	"187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd";

static void fill_buffer(unsigned char *buf, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		buf[i] = i;
}

static void dump_hex(char *out, const unsigned char *in, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		sprintf(out, "%02x", in[i]);
		out += 2;
	}
	*out = '\0';
}

START_TEST(test_blake2b)
{
	struct blake2b_state state;
	unsigned char buf[70] = {};
	unsigned char key[64] = {};
	char hex[129];

	fill_buffer(key, sizeof(key));

	blake2b_init(&state, key, sizeof(key));
	blake2b_update(&state, buf, 0);
	blake2b_final(&state, buf);
	dump_hex(hex, buf, 64);
	ck_assert_str_eq(hash0, hex);

	memset(buf, '\0', 70);
	blake2b_init(&state, key, sizeof(key));
	blake2b_update(&state, buf, 1);
	blake2b_final(&state, buf);
	dump_hex(hex, buf, 64);
	ck_assert_str_eq(hash1, hex);

	blake2b_wipe_state(&state);
}
END_TEST

void register_blake2b_tests(struct TCase *test_case)
{
	tcase_add_test(test_case, test_blake2b);
}
