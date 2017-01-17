SUBDIRS	= \
	common \
	adapter \
	host

# this library contains all convenience noinst_ libraries
lib_LTLIBRARIES = \
	libecap.la

libecap_la_SOURCES =
# Dummy C++ source to cause C++ linking.
nodist_EXTRA_libecap_la_SOURCES = dummy4lib.cc

libecap_la_LDFLAGS = -version-info $(LIBECAP_LIBRARY_VERSION)

# include all libraries
libecap_la_LIBADD = \
	common/libcommon.la \
	adapter/libadapter.la \
	host/libhost.la

include $(top_srcdir)/src/libecap/common/common.am
