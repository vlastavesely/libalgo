#ifndef __UTILS_H
#define __UTILS_H

#include <stdint.h>

#define GETU32_BE(a) ( \
	((unsigned int) (a)[0] << 24) | \
	((unsigned int) (a)[1] << 16) | \
	((unsigned int) (a)[2] <<  8) | \
	((unsigned int) (a)[3])         \
)

#define PUTU32_BE(a, i) {			\
	(a)[0] = (unsigned char) ((i) >> 24);	\
	(a)[1] = (unsigned char) ((i) >> 16);	\
	(a)[2] = (unsigned char) ((i) >>  8);	\
	(a)[3] = (unsigned char) ((i)); 	\
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

#define ROTR32(v, n)	((v >> n) | (v << (32 - n)))
#define ROTR64(v, n)	((v >> n) | (v << (64 - n)))

#endif /* __UTILS_H */
