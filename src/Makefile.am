# Build the shared library and keep private headers out of installations.
lib_LTLIBRARIES			= libmpq.la
noinst_HEADERS			= compression.h crypt_buf.h crypto.h endian.h huffman.h mpq-internal.h pack_begin.h pack_end.h pkware.h platform.h reader.h wave.h writer.h

AM_CPPFLAGS			= -I$(top_builddir) -I$(top_srcdir)/include

libmpq_la_SOURCES		= $(GENERAL_SRCS)
libmpq_la_LDFLAGS		= -version-info @LIBMPQ_ABI@

# Library source files.
GENERAL_SRCS = \
	compression.c \
	crypto.c \
	endian.c \
	huffman.c \
	mpq.c \
	pkware.c \
	reader.c \
	wave.c \
	writer.c
