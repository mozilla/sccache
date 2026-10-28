AC_INIT([basedirs-test], [1.0])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_SRCDIR([main.cpp])
AC_CONFIG_HEADERS([config.h])
AC_PROG_RANLIB

AC_PROG_CXX

# Get absolute source and build directories for use in Makefile
AC_SUBST([abs_srcdir], [`cd $srcdir && pwd`])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
