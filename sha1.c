/*
 * Source: https://github.com/git/git/blob/master/block-sha1/sha1.c
 */
#include "sha1.h"
#include "utils.h"
#include <string.h> /* memcpy */
#include <arpa/inet.h>

#define SHA_ROL(x, n) ROTL32(x, n)
#define SHA_ROR(x, n) ROTR32(x, n)

/*
 * If you have 32 registers or more, the compiler can (and should)
 * try to change the array[] accesses into registers. However, on
 * machines with less than ~25 registers, that won't really work,
 * and at least gcc will make an unholy mess of it.
 *
 * So to avoid that mess which just slows things down, we force
 * the stores to memory to actually happen (we might be better off
 * with a 'W(t)=(val);asm("":"+m" (W(t))' there instead, as
 * suggested by Artur Skawina - that will also make gcc unable to
 * try to do the silly "optimize away loads" part because it won't
 * see what the value will be).
 *
 * Ben Herrenschmidt reports that on PPC, the C version comes close
 * to the optimized asm with this (ie on PPC you don't want that
 * 'volatile', since there are lots of registers).
 *
 * On ARM we get the best code generation by forcing a full memory barrier
 * between each SHA_ROUND, otherwise gcc happily get wild with spilling and
 * the stack frame size simply explode and performance goes down the drain.
 */

#if defined(__i386__) || defined(__x86_64__)
  #define setW(x, val) (*(volatile unsigned int *)&W(x) = (val))
#elif defined(__GNUC__) && defined(__arm__)
  #define setW(x, val) do { W(x) = (val); __asm__("":::"memory"); } while (0)
#else
  #define setW(x, val) (W(x) = (val))
#endif

/* This "rolls" over the 512-bit array */
#define W(x) (array[(x) & 15])

/*
 * Where do we get the source from? The first 16 iterations get it from
 * the input data, the next mix it from the 512-bit array.
 */
#define SHA_SRC(t) GETU32_BE((unsigned char *) block + (t)*4)
#define SHA_MIX(t) SHA_ROL(W((t)+13) ^ W((t)+8) ^ W((t)+2) ^ W(t), 1);

#define SHA_ROUND(t, input, fn, constant, A, B, C, D, E) do { \
	unsigned int TEMP = input(t); setW(t, TEMP); \
	E += TEMP + SHA_ROL(A,5) + (fn) + (constant); \
	B = SHA_ROR(B, 2); } while (0)

#define T_00_15(t, A, B, C, D, E) SHA_ROUND(t, SHA_SRC, (((C^D)&B)^D) , 0x5a827999, A, B, C, D, E )
#define T_16_19(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, (((C^D)&B)^D) , 0x5a827999, A, B, C, D, E )
#define T_20_39(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, (B^C^D) , 0x6ed9eba1, A, B, C, D, E )
#define T_40_59(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, ((B&C)+(D&(B^C))) , 0x8f1bbcdc, A, B, C, D, E )
#define T_60_79(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, (B^C^D) ,  0xca62c1d6, A, B, C, D, E )

static void blk_sha1_block(struct sha1_state *ctx, const unsigned char *block)
{
	unsigned int A,B,C,D,E;
	unsigned int array[16];

	A = ctx->H[0];
	B = ctx->H[1];
	C = ctx->H[2];
	D = ctx->H[3];
	E = ctx->H[4];

	/* Round 1 - iterations 0-16 take their input from 'block' */
	T_00_15( 0, A, B, C, D, E);
	T_00_15( 1, E, A, B, C, D);
	T_00_15( 2, D, E, A, B, C);
	T_00_15( 3, C, D, E, A, B);
	T_00_15( 4, B, C, D, E, A);
	T_00_15( 5, A, B, C, D, E);
	T_00_15( 6, E, A, B, C, D);
	T_00_15( 7, D, E, A, B, C);
	T_00_15( 8, C, D, E, A, B);
	T_00_15( 9, B, C, D, E, A);
	T_00_15(10, A, B, C, D, E);
	T_00_15(11, E, A, B, C, D);
	T_00_15(12, D, E, A, B, C);
	T_00_15(13, C, D, E, A, B);
	T_00_15(14, B, C, D, E, A);
	T_00_15(15, A, B, C, D, E);

	/* Round 1 - tail. Input from 512-bit mixing array */
	T_16_19(16, E, A, B, C, D);
	T_16_19(17, D, E, A, B, C);
	T_16_19(18, C, D, E, A, B);
	T_16_19(19, B, C, D, E, A);

	/* Round 2 */
	T_20_39(20, A, B, C, D, E);
	T_20_39(21, E, A, B, C, D);
	T_20_39(22, D, E, A, B, C);
	T_20_39(23, C, D, E, A, B);
	T_20_39(24, B, C, D, E, A);
	T_20_39(25, A, B, C, D, E);
	T_20_39(26, E, A, B, C, D);
	T_20_39(27, D, E, A, B, C);
	T_20_39(28, C, D, E, A, B);
	T_20_39(29, B, C, D, E, A);
	T_20_39(30, A, B, C, D, E);
	T_20_39(31, E, A, B, C, D);
	T_20_39(32, D, E, A, B, C);
	T_20_39(33, C, D, E, A, B);
	T_20_39(34, B, C, D, E, A);
	T_20_39(35, A, B, C, D, E);
	T_20_39(36, E, A, B, C, D);
	T_20_39(37, D, E, A, B, C);
	T_20_39(38, C, D, E, A, B);
	T_20_39(39, B, C, D, E, A);

	/* Round 3 */
	T_40_59(40, A, B, C, D, E);
	T_40_59(41, E, A, B, C, D);
	T_40_59(42, D, E, A, B, C);
	T_40_59(43, C, D, E, A, B);
	T_40_59(44, B, C, D, E, A);
	T_40_59(45, A, B, C, D, E);
	T_40_59(46, E, A, B, C, D);
	T_40_59(47, D, E, A, B, C);
	T_40_59(48, C, D, E, A, B);
	T_40_59(49, B, C, D, E, A);
	T_40_59(50, A, B, C, D, E);
	T_40_59(51, E, A, B, C, D);
	T_40_59(52, D, E, A, B, C);
	T_40_59(53, C, D, E, A, B);
	T_40_59(54, B, C, D, E, A);
	T_40_59(55, A, B, C, D, E);
	T_40_59(56, E, A, B, C, D);
	T_40_59(57, D, E, A, B, C);
	T_40_59(58, C, D, E, A, B);
	T_40_59(59, B, C, D, E, A);

	/* Round 4 */
	T_60_79(60, A, B, C, D, E);
	T_60_79(61, E, A, B, C, D);
	T_60_79(62, D, E, A, B, C);
	T_60_79(63, C, D, E, A, B);
	T_60_79(64, B, C, D, E, A);
	T_60_79(65, A, B, C, D, E);
	T_60_79(66, E, A, B, C, D);
	T_60_79(67, D, E, A, B, C);
	T_60_79(68, C, D, E, A, B);
	T_60_79(69, B, C, D, E, A);
	T_60_79(70, A, B, C, D, E);
	T_60_79(71, E, A, B, C, D);
	T_60_79(72, D, E, A, B, C);
	T_60_79(73, C, D, E, A, B);
	T_60_79(74, B, C, D, E, A);
	T_60_79(75, A, B, C, D, E);
	T_60_79(76, E, A, B, C, D);
	T_60_79(77, D, E, A, B, C);
	T_60_79(78, C, D, E, A, B);
	T_60_79(79, B, C, D, E, A);

	ctx->H[0] += A;
	ctx->H[1] += B;
	ctx->H[2] += C;
	ctx->H[3] += D;
	ctx->H[4] += E;
}

void sha1_init(struct sha1_state *ctx)
{
	ctx->size = 0;

	/* Initialize H with the magic constants (see FIPS180 for constants) */
	ctx->H[0] = 0x67452301;
	ctx->H[1] = 0xefcdab89;
	ctx->H[2] = 0x98badcfe;
	ctx->H[3] = 0x10325476;
	ctx->H[4] = 0xc3d2e1f0;
}

void sha1_update(struct sha1_state *ctx, const unsigned char *data, unsigned int len)
{
	unsigned int lenW = ctx->size & 63;

	ctx->size += len;

	/* Read the data into W and process blocks as they get full */
	if (lenW) {
		unsigned int left = 64 - lenW;
		if (len < left)
			left = len;
		memcpy(lenW + (unsigned char *) ctx->W, data, left);
		lenW = (lenW + left) & 63;
		len -= left;
		data = (data + left);
		if (lenW)
			return;
		blk_sha1_block(ctx, (const unsigned char *) ctx->W);
	}
	while (len >= 64) {
		blk_sha1_block(ctx, data);
		data = (data + 64);
		len -= 64;
	}
	if (len)
		memcpy(ctx->W, data, len);
}

void sha1_final(struct sha1_state *ctx, unsigned char *out)
{
	static const unsigned char pad[64] = { 0x80 };
	unsigned int padlen[2];
	int i;

	/* Pad with a binary 1 (ie 0x80), then zeroes, then length */
	padlen[0] = htonl((uint32_t) (ctx->size >> 29));
	padlen[1] = htonl((uint32_t) (ctx->size << 3));

	i = ctx->size & 63;
	sha1_update(ctx, pad, 1 + (63 & (55 - i)));
	sha1_update(ctx, (const unsigned char *) padlen, 8);

	/* Output hash */
	for (i = 0; i < 5; i++)
		PUTU32_BE(out + i * 4, ctx->H[i]);
}
