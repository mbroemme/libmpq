# Build the shared library and keep private headers out of installations.
lib_LTLIBRARIES			= libmpq.la
# Keep private implementation headers available to in-tree readers and fuzzers.
noinst_HEADERS			= mpq-compression.h mpq-crypt-buf.h mpq-crypto.h mpq-endian.h mpq-huffman.h mpq-internal.h mpq-pack-begin.h mpq-pack-end.h mpq-pkware.h mpq-platform.h mpq-reader.h mpq-stream.h mpq-wave.h mpq-writer.h

# Use generated configuration and installed public headers when compiling.
AM_CPPFLAGS			= -I$(top_builddir) -I$(top_srcdir)/include

# Link the public library from the complete native implementation.
libmpq_la_SOURCES		= $(GENERAL_SRCS)
libmpq_la_LDFLAGS		= -version-info @LIBMPQ_ABI@

# Fuzzers need private codec entry points without widening the installed ABI.
# This convenience library is built only for --enable-fuzzing configurations.
if ENABLE_FUZZING
noinst_LTLIBRARIES		= libmpq-fuzz-internal.la
libmpq_fuzz_internal_la_SOURCES	= $(GENERAL_SRCS)
endif

# Library source files.
GENERAL_SRCS = \
	mpq-compression.c \
	mpq-crypto.c \
	mpq-endian.c \
	mpq-huffman.c \
	mpq-api.c \
	mpq-pkware.c \
	mpq-reader.c \
	mpq-stream.c \
	mpq-wave.c \
	mpq-writer.c
