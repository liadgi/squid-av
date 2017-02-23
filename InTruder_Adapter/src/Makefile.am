lib_LTLIBRARIES = \
	ecap_clamav_adapter.la

noinst_HEADERS = \
	Time.h \
	Adapter.h \
	Answer.h \
	Pointers.h \
	Timeout.h \
	TricklingConfig.h \
	Answers.h \
	Service.h \
	Xaction.h \
	Debugger.h \
	Antivirus.h \
	ClamAv.h \
	FileBuffer.h \
	Gadgets.h \
	Async.h \
	\
	autoconf.h

ecap_clamav_adapter_la_SOURCES = \
	Time.cc \
	Adapter.cc \
	Answers.cc \
	Antivirus.cc \
	Service.cc \
	TricklingConfig.cc \
	Xaction.cc \
	Debugger.cc \
	FileBuffer.cc \
	Gadgets.cc \
	ClamAv.cc

ecap_clamav_adapter_la_LDFLAGS = -module -avoid-version
ecap_clamav_adapter_la_LIBADD = $(LIBECAP_LIBS)
ecap_clamav_adapter_la_CPPFLAGS = $(LIBECAP_CFLAGS) \
	-I$(top_srcdir)/src -I$(top_builddir)/src

DISTCLEANFILES = \
        autoconf.h
