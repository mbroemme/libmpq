# Build the shared library and keep private headers out of installations.
lib_LTLIBRARIES = libmpq.la

# Keep private implementation headers available to in-tree readers and fuzzers.
noinst_HEADERS = \
	mpq-attributes.h \
	mpq-block.h \
	mpq-compression.h \
	mpq-crypt-buf.h \
	mpq-crypto.h \
	mpq-endian.h \
	mpq-entry.h \
	mpq-file.h \
	mpq-hash.h \
	mpq-header.h \
	mpq-huffman.h \
	mpq-internal.h \
	mpq-md5.h \
	mpq-mpqe.h \
	mpq-patch-reader.h \
	mpq-patch-writer.h \
	mpq-pkware.h \
	mpq-reader.h \
	mpq-rsa.h \
	mpq-sha1.h \
	mpq-signature.h \
	mpq-source.h \
	mpq-sparse.h \
	mpq-stream.h \
	mpq-update.h \
	mpq-verify.h \
	mpq-wave.h \
	mpq-writer.h

# Use generated configuration and installed public headers when compiling.
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir)/include

# Link the public library from the complete native implementation.
libmpq_la_SOURCES = $(GENERAL_SRCS)
libmpq_la_LDFLAGS = -no-undefined -version-info @LIBMPQ_ABI@

# Fuzzers need private codec entry points without widening the installed ABI.
# This convenience library is built only for --enable-fuzzing configurations.
if ENABLE_FUZZING
noinst_LTLIBRARIES = libmpq-fuzz-internal.la
libmpq_fuzz_internal_la_SOURCES = $(GENERAL_SRCS)
endif

# Library source files.
GENERAL_SRCS = \
	mpq-api.c \
	mpq-attributes.c \
	mpq-block.c \
	mpq-compression.c \
	mpq-crypto.c \
	mpq-endian.c \
	mpq-file.c \
	mpq-hash.c \
	mpq-header.c \
	mpq-huffman.c \
	mpq-md5.c \
	mpq-mpqe.c \
	mpq-patch-reader.c \
	mpq-patch-writer.c \
	mpq-pkware.c \
	mpq-reader.c \
	mpq-rsa.c \
	mpq-sha1.c \
	mpq-signature.c \
	mpq-source.c \
	mpq-sparse.c \
	mpq-stream.c \
	mpq-update.c \
	mpq-verify.c \
	mpq-wave.c \
	mpq-writer.c
