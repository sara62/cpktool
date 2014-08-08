AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

lib_LTLIBRARIES = libcpktool.la
libcpktool_la_SOURCES = src/cpktool.h \
	src/cpktool_stub.h src/cpktool.c

libcpktool_includedir = $(includedir)/cpk
libcpktool_include_HEADERS = src/cpktool.h
libcpktool_libincludedir = $(libdir)/

bin_PROGRAMS = cpk
cpk_SOURCES = src/cpk.c
cpk_LDADD = libcpktool.la -lcpk -lcrypto

noinst_PROGRAMS = cpktool_test
cpktool_test_SOURCES = src/cpktool_test.c
cpktool_test_LDADD = libcpktool.la -lcpk -lcrypto
