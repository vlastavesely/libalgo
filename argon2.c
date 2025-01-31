#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include "argon2.h"
#include "blake2b.h"
#include "utils.h"

#define ARGON2_SLICES 4

static void hash(unsigned char *out, unsigned int outlen, const unsigned char *in,
		 unsigned int len)
{
	struct blake2b_state b2;
	unsigned char buf[64], val[4];
	unsigned int r, i;

	PUTU32_LE(val, outlen);

	if (outlen <= 64) {
		blake2b_init(&b2, NULL, 0, outlen);
		blake2b_update(&b2, val, 4);
		blake2b_update(&b2, in, len);
		blake2b_final(&b2, out);

		return;
	}

	blake2b_init(&b2, NULL, 0, 64);
	blake2b_update(&b2, val, 4);
	blake2b_update(&b2, in, len);
	blake2b_final(&b2, buf);
	memcpy(out, buf, 32);
	out += 32;

	r = ceil(outlen / 32) - 1;

	for (i = 2; i <= r; i++) {
		blake2b_init(&b2, NULL, 0, 64);
		blake2b_update(&b2, buf, 64);
		blake2b_final(&b2, buf);
		memcpy(out, buf, 32);
		out += 32;
	}

	memcpy(out, buf + 32, 32);
}

/* ────────────────────────────────────────────────────────────────────────── */

static inline void block_copy(uint64_t *dst, const uint64_t *src)
{
	unsigned int i;

	for (i = 0; i < 128; i++) {
		dst[i] = src[i];
	}
}

static inline void block_xor(uint64_t *dst, const uint64_t *a, const uint64_t *b)
{
	unsigned int i;

	for (i = 0; i < 128; i++) {
		dst[i] = a[i] ^ b[i];
	}
}

/* ────────────────────────────────────────────────────────────────────────── */

/* designed by the Lyra PHC team */
static inline uint64_t fBlaMka(uint64_t x, uint64_t y)
{
	const uint64_t m = 0xffffffffLL;
	const uint64_t xy = (x & m) * (y & m);
	return x + y + 2 * xy;
}

#define G(a, b, c, d) do {	\
	a = fBlaMka(a, b);	\
	d = ROTR64(d ^ a, 32);	\
	c = fBlaMka(c, d);	\
	b = ROTR64(b ^ c, 24);	\
	a = fBlaMka(a, b);	\
	d = ROTR64(d ^ a, 16);	\
	c = fBlaMka(c, d);	\
	b = ROTR64(b ^ c, 63);	\
} while(0);

#define BLAKE2_ROUND_NOMSG(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) \
do { 				\
	G(a, e, i, m);		\
	G(b, f, j, n);		\
	G(c, g, k, o);		\
	G(d, h, l, p);		\
	G(a, f, k, p);		\
	G(b, g, l, m);		\
	G(c, h, i, n);		\
	G(d, e, j, o);		\
} while(0);

/*
 * Compression function: compresses blocks X and Y
 */
static void g(uint64_t *dst, const uint64_t *x, const uint64_t *y, bool xor)
{
	uint64_t r[128], tmp[128];
	unsigned int i;

	block_xor(r, x, y);
	block_copy(tmp, r);

	if (xor == true) {
		block_xor(tmp, tmp, dst);
	}

	for (i = 0; i < 8; ++i) {
		BLAKE2_ROUND_NOMSG(
			r[16 * i],      r[16 * i + 1],  r[16 * i + 2],
			r[16 * i + 3],  r[16 * i + 4],  r[16 * i + 5],
			r[16 * i + 6],  r[16 * i + 7],  r[16 * i + 8],
			r[16 * i + 9],  r[16 * i + 10], r[16 * i + 11],
			r[16 * i + 12], r[16 * i + 13], r[16 * i + 14],
			r[16 * i + 15]);
	}

	for (i = 0; i < 8; i++) {
		BLAKE2_ROUND_NOMSG(
			r[2 * i],      r[2 * i + 1],  r[2 * i + 16],
			r[2 * i + 17], r[2 * i + 32], r[2 * i + 33],
			r[2 * i + 48], r[2 * i + 49], r[2 * i + 64],
			r[2 * i + 65], r[2 * i + 80], r[2 * i + 81],
			r[2 * i + 96], r[2 * i + 97], r[2 * i + 112],
			r[2 * i + 113]);
	}

	block_xor(dst, tmp, r);
}

/* ────────────────────────────────────────────────────────────────────────── */

static uint32_t index_alpha(struct argon2_state *state, unsigned int p,
			    unsigned int s, unsigned i, uint32_t pseudo_rand,
			    int same_lane)
{
	unsigned int area_size;
	uint64_t pos_rel;
	unsigned int pos_start = 0, pos_abs;
	unsigned int lane_len = state->lane_len;
	unsigned int segment_len = state->segment_len;

	if (p == 0) {
		if (s == 0) {
			area_size = i - 1;
		} else {
			if (same_lane) {
				area_size = s * segment_len + i - 1;
			} else {
				area_size = s * segment_len + ((i == 0) ? (-1) : 0);
			}
		}
	} else {
		if (same_lane) {
			area_size = lane_len - segment_len + i - 1;
		} else {
			area_size = lane_len - segment_len + ((i == 0) ? (-1) : 0);
		}
	}

	pos_rel = pseudo_rand;
	pos_rel = pos_rel * pos_rel >> 32;
	pos_rel = area_size - 1 - (area_size * pos_rel >> 32);

	if (p != 0) {
		pos_start = (s == 4 - 1) ? 0 : (s + 1) * segment_len;
	}

	pos_abs = (pos_start + pos_rel) % lane_len;

	return pos_abs;
}

static void next_addr(uint64_t *dst, uint64_t *a, uint64_t *b)
{
	a[6]++;
	g(dst, b, a, false);
	g(dst, b, dst, false);
}

static void fill_segment(struct argon2_state *state, unsigned int r,
			 unsigned int l, unsigned int s)
{
	uint64_t input[128] = {}, zero[128] = {}, addr[128];
	unsigned int segment_len = state->segment_len;
	unsigned int lane_len = state->lane_len;
	unsigned int curr_off, prev_off;
	unsigned int ref_lane, ref_index, ref_block;
	unsigned int start = 0, i;
	uint64_t pseudo_rand;
	bool indep;

	indep = (state->type == ARGON2I) || (state->type == ARGON2ID && r == 0 && s < 2);

	if (indep == true) {
		input[0] = r;
		input[1] = l;
		input[2] = s;
		input[3] = state->m;
		input[4] = state->i;
		input[5] = state->type;
	}

	if (r == 0 && s == 0) {
		start = 2; /* skip the initial blocks */
		if (indep) {
			next_addr(addr, input, zero);
		}
	}

	curr_off = (l * lane_len) + (s * segment_len) + start;
	prev_off = curr_off - 1;

	if (curr_off % lane_len == 0) {
		prev_off += lane_len;
	}

	for (i = start; i < segment_len; i++, curr_off++, prev_off++) {
		if (curr_off % lane_len == 1) {
			prev_off = curr_off - 1;
		}

		if (indep) {
			if (i % 128 == 0) {
				next_addr(addr, input, zero);
			}
			pseudo_rand = addr[i % 128];
		} else {
			pseudo_rand = state->memory[prev_off * 128];
		}

		ref_lane = (pseudo_rand >> 32) % state->p;
		if (r == 0 && s == 0) {
			ref_lane = l;
		}

		ref_index = index_alpha(state, r, s, i, pseudo_rand & 0xffffffff, ref_lane == l);
		ref_block = state->lane_len * ref_lane + ref_index;

		g(state->memory + (curr_off * 128), state->memory + (prev_off * 128),
		  state->memory + (ref_block * 128), r != 0);
	}
}

/* ────────────────────────────────────────────────────────────────────────── */

static void initialise_memory(struct argon2_state *state, unsigned char *h0)
{
	unsigned int segment_len = state->m / (state->p * ARGON2_SLICES);
	unsigned int lane_len = segment_len * ARGON2_SLICES;
	unsigned int i;
	unsigned char *ptr;

	for (i = 0; i < state->p; i++) {
		/* block 0 */
		PUTU32_LE(h0 + 64, 0);
		PUTU32_LE(h0 + 68, i);
		ptr = ((unsigned char *) state->memory) + (i * lane_len * 1024);
		hash(ptr, 1024, h0, 72);

		/* block 1 */
		PUTU32_LE(h0 + 64, 1);
		PUTU32_LE(h0 + 68, i);
		ptr += 1024;
		hash(ptr, 1024, h0, 72);
	}

	state->segment_len = segment_len;
	state->lane_len = lane_len;
}


#define HASH_UINT32(s, i) {		\
	unsigned char val[4];		\
	PUTU32_LE(val, i);		\
	blake2b_update(s, val, 4);	\
}

#define HASH_DATA(s, d, len) {			\
	HASH_UINT32(s, len);			\
	if (len > 0) {				\
		blake2b_update(s, d, len);	\
	}					\
}

static void initialise(struct argon2_state *state)
{
	struct blake2b_state b2;
	unsigned char h0[72];

	blake2b_init(&b2, NULL, 0, 64);

	HASH_UINT32(&b2, state->p);
	HASH_UINT32(&b2, state->t);
	HASH_UINT32(&b2, state->m);
	HASH_UINT32(&b2, state->i);
	HASH_UINT32(&b2, state->version);
	HASH_UINT32(&b2, state->type);

	HASH_DATA(&b2, state->password, state->passwordlen);
	HASH_DATA(&b2, state->salt, state->saltlen);
	HASH_DATA(&b2, state->key, state->keylen);
	HASH_DATA(&b2, state->assoc, state->assoclen);

	blake2b_final(&b2, h0);

	/* m × 1024 bytes */
	state->memory = calloc(state->m * 128, sizeof(uint64_t));
	initialise_memory(state, h0);
}

static void fill_memory_blocks(struct argon2_state *state)
{
	unsigned int r, s, l;

	/* round/iterations */
	for (r = 0; r < state->i; r++) {
		/* slices */
		for (s = 0; s < ARGON2_SLICES; s++) {
			/* lanes */
			for (l = 0; l < state->p; l++) {
				fill_segment(state, r, l, s);
			}
		}
	}
}

static void finalise(struct argon2_state *state, unsigned char *digest)
{
	struct blake2b_state b2;
	uint64_t block[128] = {};
	unsigned int i, last, lane_len;

	lane_len = state->lane_len * 128; /* of uint64_t */

	for (i = 0; i < state->p; i++) {
		last = (i * lane_len) + (lane_len - 128);
		block_xor(block, block, state->memory + last);
	}

	hash(digest, state->t, (unsigned char *) block, 1024);

	memset(state->memory, '\0', state->m * 1024);
	free(state->memory);
}

static int validate_params(struct argon2_state *state)
{
	if (state->m < 8 * state->p) {
		return ARGON2_M_TOO_LITTLE;
	}

	if (state->i < 1) {
		return ARGON2_ITER_TOO_LITTLE;
	}

	if (state->p < 1) {
		return ARGON2_P_TOO_LITTLE;
	}

	if (state->type != ARGON2D && state->type != ARGON2I && state->type != ARGON2ID) {
		return ARGON2_BAD_TYPE;
	}

	if (state->version != ARGON2_VERSION_10 && state->version != ARGON2_VERSION_13) {
		return ARGON2_BAD_VERSION;
	}

	return ARGON2_OK;
}

int argon2(struct argon2_state *state, unsigned char *digest)
{
	int ret;

	ret = validate_params(state);
	if (ret != ARGON2_OK) {
		return ret;
	}

	initialise(state);
	fill_memory_blocks(state);
	finalise(state, digest);

	return 0;
}
