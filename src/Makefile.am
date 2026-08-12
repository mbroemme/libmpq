# Build the shared library and keep private headers out of installations.
lib_LTLIBRARIES			= libmpq.la
noinst_HEADERS			= common.h crypt_buf.h explode.h extract.h huffman.h mpq-internal.h pack_begin.h pack_end.h platform.h wave.h

# Install public headers under the libmpq-specific include directory.
libmpq_includedir		= $(includedir)/libmpq

# Public headers to install.
libmpq_include_HEADERS		= mpq.h

libmpq_la_SOURCES		= $(GENERAL_SRCS)
libmpq_la_LDFLAGS		= -version-info @LIBMPQ_ABI@

# Library source files.
GENERAL_SRCS =			\
	common.c		\
	huffman.c		\
	extract.c		\
	explode.c		\
	mpq.c			\
	wave.c
