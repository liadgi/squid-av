
noinst_LTLIBRARIES = \
	libcommon.la

libcommon_la_SOURCES = \
	area.cc \
	body_size.cc \
	memory.cc \
	message.cc \
	name.cc \
	names.cc \
	registry.cc \
	errors.cc

include_common_pkgdir = ${pkgincludedir}/common

include_common_pkg_HEADERS = \
	libecap.h \
	registry.h \
	forward.h \
	errors.h \
	log.h \
	memory.h \
	area.h \
	name.h \
	names.h \
	header.h \
	body.h \
	body_size.h \
	message.h \
	version.h \
	delay.h \
	named_values.h \
	options.h \
	\
	autoconf.h

DISTCLEANFILES = \
	ac-autoconf.h \
	autoconf.h

include $(top_srcdir)/src/libecap/common/common.am
