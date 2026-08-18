# Build the shared library and keep private headers out of installations.
lib_LTLIBRARIES			= libmpq.la
noinst_HEADERS			= common.h crypt_buf.h endian.h explode.h extract.h huffman.h mpq-internal.h pack_begin.h pack_end.h platform.h wave.h

AM_CPPFLAGS			= -I$(top_builddir) -I$(top_srcdir)/include

libmpq_la_SOURCES		= $(GENERAL_SRCS)
libmpq_la_LDFLAGS		= -version-info @LIBMPQ_ABI@

# Library source files.
GENERAL_SRCS =			\
	common.c		\
	huffman.c		\
	extract.c		\
	explode.c		\
		mpq.c			\
		wave.c			\
		writer.c
