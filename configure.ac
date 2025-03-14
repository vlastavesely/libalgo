#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([algo], [1.0], [vlastavesely(at)protonmail.ch])
AC_CONFIG_SRCDIR([.])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_LN_S

PKG_PROG_PKG_CONFIG
PKG_INSTALLDIR

# Checks for header files.
AC_CHECK_HEADERS([limits.h stdint.h stdlib.h string.h])

# Checks for libraries.
PKG_CHECK_MODULES(CHECK, check)

# Checks for header files.
AC_CHECK_HEADERS([limits.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset])

# Check for CPU features
AC_C_BIGENDIAN

# Enable hardware optimised AES
USE_AES_NI=no
AC_MSG_CHECKING([whether AES-NI support should be enabled])
AC_ARG_ENABLE(aes-ni,
	AS_HELP_STRING([--enable-aes-ni], [enable AES-NI optimisations]), [
		AC_MSG_RESULT(yes)
		USE_AES_NI=yes
		CFLAGS="$CFLAGS -maes"
], [AC_MSG_RESULT(no)])

AC_SUBST([USE_AES_NI])
if test "x$USE_AES_NI" = xyes; then
	AX_GCC_X86_CPU_SUPPORTS([aes])
fi

AC_CONFIG_FILES([Makefile libalgo.pc])

AC_OUTPUT
