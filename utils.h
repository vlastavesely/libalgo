#ifndef __UTILS_H
#define __UTILS_H

#include <stdint.h>

#define GETU32_BE(a) ( \
	((unsigned int) (a)[0] << 24) | \
	((unsigned int) (a)[1] << 16) | \
	((unsigned int) (a)[2] <<  8) | \
	((unsigned int) (a)[3])         \
)

#define GETU32_LE(a) ( \
	((unsigned int) (a)[0]      ) | \
	((unsigned int) (a)[1] <<  8) | \
	((unsigned int) (a)[2] << 16) | \
	((unsigned int) (a)[3] << 24)   \
)

#define PUTU32_BE(a, i) {			\
	(a)[0] = (unsigned char) ((i) >> 24);	\
	(a)[1] = (unsigned char) ((i) >> 16);	\
	(a)[2] = (unsigned char) ((i) >>  8);	\
	(a)[3] = (unsigned char) ((i)); 	\
}

#define PUTU32_LE(a, i) {			\
	(a)[0] = (unsigned char) ((i)      );	\
	(a)[1] = (unsigned char) ((i) >>  8);	\
	(a)[2] = (unsigned char) ((i) >> 16);	\
	(a)[3] = (unsigned char) ((i) >> 24); 	\
}

#define GETU64_BE(a) ( \
	((uint64_t) (a)[0] << 56) | \
	((uint64_t) (a)[1] << 48) | \
	((uint64_t) (a)[2] << 40) | \
	((uint64_t) (a)[3] << 32) | \
	((uint64_t) (a)[4] << 24) | \
	((uint64_t) (a)[5] << 16) | \
	((uint64_t) (a)[6] <<  8) | \
	((uint64_t) (a)[7])         \
)

#define GETU64_LE(a) ( \
	((uint64_t) (a)[7] << 56) | \
	((uint64_t) (a)[6] << 48) | \
	((uint64_t) (a)[5] << 40) | \
	((uint64_t) (a)[4] << 32) | \
	((uint64_t) (a)[3] << 24) | \
	((uint64_t) (a)[2] << 16) | \
	((uint64_t) (a)[1] <<  8) | \
	((uint64_t) (a)[0])         \
)

#define PUTU64_BE(a, i) { \
	(a)[0] = (unsigned char) ((i) >> 56); \
	(a)[1] = (unsigned char) ((i) >> 48); \
	(a)[2] = (unsigned char) ((i) >> 40); \
	(a)[3] = (unsigned char) ((i) >> 32); \
	(a)[4] = (unsigned char) ((i) >> 24); \
	(a)[5] = (unsigned char) ((i) >> 16); \
	(a)[6] = (unsigned char) ((i) >>  8); \
	(a)[7] = (unsigned char) ((i));       \
}

#define PUTU64_LE(a, i) { \
	(a)[7] = (unsigned char) ((i) >> 56); \
	(a)[6] = (unsigned char) ((i) >> 48); \
	(a)[5] = (unsigned char) ((i) >> 40); \
	(a)[4] = (unsigned char) ((i) >> 32); \
	(a)[3] = (unsigned char) ((i) >> 24); \
	(a)[2] = (unsigned char) ((i) >> 16); \
	(a)[1] = (unsigned char) ((i) >>  8); \
	(a)[0] = (unsigned char) ((i));       \
}

#define ROTR32(v, n)	(((v) >> n) | ((v) << (32 - n)))
#define ROTL32(v, n)	(((v) << n) | ((v) >> (32 - n)))
#define ROTR64(v, n)	(((v) >> n) | ((v) << (64 - n)))

/*
 * Byte-order swap functions for conversion from big-endian to little-endian
 * and vice versa.
 */
/* gcc 4.3 and higher */
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 2)

	/*
	 * These functions check whether CPU supports Intel's instruction BSWAP.
	 * If so, this instruction will be used, portable code otherwise.
	 */
	#ifndef BSWAP32
	#define BSWAP32(n) __builtin_bswap32(n)
	#endif

	#ifndef BSWAP64
	#define BSWAP64(n) __builtin_bswap64(n)
	#endif

	#ifndef BSWAP16 /* This one does not have built-in function. */
	#define BSWAP16(n) ((n) << 8 | ((n) >> 8 & 0x00FF))
	#endif

#else

	/*
	 * In Visual C++ should be possible call BSWAP instruction in this way:
	 *
	 *	#include <intrin.h>
	 *
	 *	unsigned short _byteswap_ushort(unsigned short value);
	 *	unsigned long _byteswap_ulong(unsigned long value);
	 *	unsigned __int64 _byteswap_uint64(unsigned __int64 value);
	 *
	 * but it is not tested since I do not use Windows...
	 */

	#ifndef BSWAP16
	#define BSWAP16(n) \
		((n) << 8 | \
		((n) >> 8 & 0x00FF))
	#endif

	#ifndef BSWAP32
	#define BSWAP32(n) \
		((n) >> 24) | \
		(((n) << 8) & 0x00FF0000L) | \
		(((n) >> 8) & 0x0000FF00L) | \
		((n) << 24)
	#endif

	#ifndef BSWAP64
	#define BSWAP64(n) \
		((n) >> 56) | \
		(((n) << 40) & 0x00FF000000000000LL) | \
		(((n) << 24) & 0x0000FF0000000000LL) | \
		(((n) << 8)  & 0x000000FF00000000LL) | \
		(((n) >> 8)  & 0x00000000FF000000LL) | \
		(((n) >> 24) & 0x0000000000FF0000LL) | \
		(((n) >> 40) & 0x000000000000FF00LL) | \
		((n) << 56)
	#endif

#endif

#endif /* __UTILS_H */
