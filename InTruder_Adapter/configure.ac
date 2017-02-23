#                                               -*- Autoconf -*-
#  @configure_input@
#
#  Configuration scipt for eCAP Library
#
# Process this file with autoconf to produce a configure script.

AC_INIT(eCAP ClamAV Adapter, 2.0.0, [http://www.e-cap.org/], ecap_clamav_adapter)
AC_CONFIG_AUX_DIR(cfgaux)
AC_CONFIG_MACRO_DIR(cfgaux)
AC_CONFIG_SRCDIR([src/ClamAv.cc])
AC_CONFIG_HEADERS(src/autoconf.h)

AM_INIT_AUTOMAKE([nostdinc])
AM_MAINTAINER_MODE

AM_PROG_AR
LT_INIT

m4_include(cfgaux/xstd_common.ac)
m4_include(cfgaux/xstd_cpp_checks.ac)

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET


# Checks for libraries.

dnl check for libecap v1.0.x
PKG_CHECK_MODULES(LIBECAP, [libecap >= 1.0 libecap < 1.1])

ACX_PTHREAD_PREFER

# Checks for header files.
AC_CHECK_HEADERS([libecap/adapter/service.h])
AC_CHECK_HEADERS(clamav.h)


# Checks for typedefs, structures, and compiler characteristics.
# AC_HEADER_STDBOOL
# AC_C_CONST

# Checks for library functions.

AC_CONFIG_FILES([\
        Makefile \
        src/Makefile \
])
AC_OUTPUT
