#ifndef __HMAC_H
#define __HMAC_H

#ifdef KEYED_HASH
  /*
   * some functions, like Blake2B use optional key which is, nevertheless,
   * not used with HMAC.
   */
  #define HMAC_INIT_FUNC(ALGO, state) ALGO##_init(state, NULL, 0)
#else
  #define HMAC_INIT_FUNC(ALGO, state) ALGO##_init(state)
#endif

#define HMAC_INIT(ALGO, STATELEN)					\
	void hmac_##ALGO##_init(struct hmac_##ALGO##_state *s, 		\
			const unsigned char *k, unsigned int keylen) {	\
		unsigned char buf[STATELEN] = {};			\
		unsigned int i;						\
									\
		if (keylen > STATELEN) {				\
			HMAC_INIT_FUNC(ALGO, &(s->state));		\
			ALGO##_update(&(s->state), k, keylen);		\
			ALGO##_final(&(s->state), buf);			\
		} else {						\
			memcpy(buf, k, keylen);				\
		}							\
									\
		for (i = 0; i < STATELEN; i++) {			\
			s->ipad[i] = buf[i] ^ 0x36;			\
			s->opad[i] = buf[i] ^ 0x5c;			\
		}							\
									\
		HMAC_INIT_FUNC(ALGO, &(s->state));			\
		ALGO##_update(&(s->state), s->ipad, STATELEN);		\
	}

#define HMAC_UPDATE(ALGO)						\
	void hmac_##ALGO##_update(struct hmac_##ALGO##_state *s,	\
			const unsigned char *d, unsigned int n) {	\
		ALGO##_update(&(s->state), d, n);			\
	}

#define HMAC_FINAL(ALGO, STATELEN, DIGESTLEN)			\
	void hmac_##ALGO##_final(struct hmac_##ALGO##_state *s,	\
			unsigned char *d) {			\
		unsigned char buf[DIGESTLEN];			\
		ALGO##_final(&(s->state), buf);			\
		HMAC_INIT_FUNC(ALGO, &(s->state));		\
		ALGO##_update(&(s->state), s->opad, STATELEN);	\
		ALGO##_update(&(s->state), buf, DIGESTLEN);	\
		ALGO##_final(&(s->state), d);			\
	}

#define HMAC_WIPE(ALGO, STATELEN)					\
	void hmac_##ALGO##_wipe_state(struct hmac_##ALGO##_state *s) {	\
		unsigned int i;						\
		HMAC_INIT_FUNC(ALGO, &(s->state));			\
		for (i = 0; i < STATELEN; i++) {			\
			s->ipad[i] = 0x00;				\
			s->opad[i] = 0x00;				\
		}							\
	}

#define DEFINE_HMAC_ALGO(ALGO, STATELEN, DIGESTLEN)	\
	HMAC_INIT(ALGO, STATELEN)			\
	HMAC_UPDATE(ALGO)				\
	HMAC_FINAL(ALGO, STATELEN, DIGESTLEN)		\
	HMAC_WIPE(ALGO, STATELEN)

#endif /* __HMAC_H */
