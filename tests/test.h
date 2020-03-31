#ifndef __TEST_TEST_H
#define __TEST_TEST_H

#include <stdio.h>
#include <check.h>

#define ck_assert_byte_array_eq(a, b, n)	{	\
	for (int ii = 0; ii < n; ii++) {		\
		ck_assert_int_eq(a[ii], b[ii]);		\
	}						\
}

#endif /* __TEST_TEST_H */
