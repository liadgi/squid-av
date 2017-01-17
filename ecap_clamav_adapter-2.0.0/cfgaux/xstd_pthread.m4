# Provides macros to enables POSIX threads (pthreads) support when appropriate.
# Requires ACX_PTHREAD from the Autoconf Macros Archive.
#
# Three pthreads support checks are supported: require, avoid, and prefer.
# All #define HAVE_PTHREAD when pthreads support is available and enabled.

# Enable required pthreads support if available.
# Fail otherwise.
AC_DEFUN([ACX_PTHREAD_REQUIRE],[dnl
    AC_MSG_NOTICE([trying to enable required pthreads support])dnl
    ACX_PTHREAD_CHECK([required pthreads support unavailable])dnl
])

# Enable optional pthreads support if available.
# Fail if requested but unavailable.
# Disable otherwise.
AC_DEFUN([ACX_PTHREAD_PREFER],[dnl
    AC_ARG_ENABLE([pthread],
        [AS_HELP_STRING([--disable-pthread],
            [disable pthreads support (default is to enable if possible)])],
        [pthread_required="$enableval"],
        [pthread_required=check]dnl
    )dnl
    AS_IF(dnl
        [test "x$pthread_required" = xyes],
            [AC_MSG_NOTICE([trying to enable requested pthreads support])dnl
            ACX_PTHREAD_CHECK([requested pthreads support unavailable])],
        [test "x$pthread_required" = xcheck],
            [AC_MSG_NOTICE([trying to enable optional pthreads support])dnl
            ACX_PTHREAD_CHECK([])],
        [AC_MSG_NOTICE([not enabling optional pthreads support])]dnl
    )dnl
])

# Enable optional pthreads support if requested.
# Fail if requested but unavailable.
# Disable otherwise.
AC_DEFUN([ACX_PTHREAD_AVOID],[
    AC_ARG_ENABLE([pthread],
        [AS_HELP_STRING([--enable-pthread],
            [enable pthreads support (default is no)])],
        [pthread_required="$enableval"],
        [pthread_required=avoid]
    )
    AS_IF(
        [test "x$pthread_required" = xyes],
            [AC_MSG_NOTICE([trying to enable requested pthreads support])
            ACX_PTHREAD_CHECK([requested pthreads support unavailable])],
        [test "x$pthread_required" = xavoid],
            [AC_MSG_NOTICE([avoiding optional pthreads support])],
        [AC_MSG_NOTICE([not enabling rejected pthreads support])]
    )
])

# ACX_PTHREAD_CHECK([error message to fail with])
# Used internally to implement the three ACX_PTHREAD_* macros above.
# Checks whether pthreads support is available.
# If it is available, enables pthreads support.
# Otherwise, either fails with a given error message or,
# if no message was given, just warns that pthreads support is not available.
AC_DEFUN([ACX_PTHREAD_CHECK],[
    ACX_PTHREAD([
        AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.])
        LIBS="$PTHREAD_LIBS $LIBS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
        CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS"
        CC="$PTHREAD_CC"
        AC_MSG_NOTICE([enabled pthreads support])
    ],[
        AS_IF([test "x$1" = x],
            [AC_MSG_NOTICE([disabled pthreads support])],
            [AC_MSG_ERROR([$1])]
        )
    ])
])
