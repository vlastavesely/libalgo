#ifndef __TEST_TEST_H
#define __TEST_TEST_H

#include <stdio.h>
#include <check.h>

#define ck_assert_byte_array_eq(a, b, n)	{	\
	const unsigned char *aa = a;			\
	const unsigned char *bb = b;			\
	for (int ii = 0; ii < n; ii++) {		\
		ck_assert_int_eq(aa[ii], bb[ii]);	\
	}						\
}

#endif /* __TEST_TEST_H */
