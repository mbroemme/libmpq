# Build the shared library and keep private headers out of installations.
lib_LTLIBRARIES			= libmpq.la
noinst_HEADERS			= mpq-compression.h mpq-crypt-buf.h mpq-crypto.h mpq-endian.h mpq-huffman.h mpq-internal.h mpq-pack-begin.h mpq-pack-end.h mpq-pkware.h mpq-platform.h mpq-reader.h mpq-wave.h mpq-writer.h

AM_CPPFLAGS			= -I$(top_builddir) -I$(top_srcdir)/include

libmpq_la_SOURCES		= $(GENERAL_SRCS)
libmpq_la_LDFLAGS		= -version-info @LIBMPQ_ABI@

# Library source files.
GENERAL_SRCS = \
	mpq-compression.c \
	mpq-crypto.c \
	mpq-endian.c \
	mpq-huffman.c \
	mpq-api.c \
	mpq-pkware.c \
	mpq-reader.c \
	mpq-wave.c \
	mpq-writer.c
