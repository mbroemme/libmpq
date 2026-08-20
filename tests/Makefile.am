# Keep object names local to this directory when building the test programs.
AUTOMAKE_OPTIONS = subdir-objects

# Link every regression program against the library built from this tree.
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src
AM_LDFLAGS = -no-install
LDADD = $(top_builddir)/src/libmpq.la

# Each executable mirrors one implementation module in src/.
check_PROGRAMS = \
	test-compression \
	test-crypto \
	test-huffman \
	test-endian \
	test-mpq \
	test-pkware \
	test-reader \
	test-wave \
	test-writer
TESTS = $(check_PROGRAMS)

# Compile shared assertions and deterministic-data helpers into every test.
COMMON_SOURCES = helper.c helper.h
test_compression_SOURCES = test-compression.c $(COMMON_SOURCES)
test_crypto_SOURCES = test-crypto.c $(COMMON_SOURCES)
test_huffman_SOURCES = test-huffman.c $(COMMON_SOURCES)
test_endian_SOURCES = test-endian.c ../src/endian.c $(COMMON_SOURCES)
test_mpq_SOURCES = test-mpq.c $(COMMON_SOURCES)
test_pkware_SOURCES = test-pkware.c $(COMMON_SOURCES)
test_reader_SOURCES = test-reader.c $(COMMON_SOURCES)
test_wave_SOURCES = test-wave.c $(COMMON_SOURCES)
test_writer_SOURCES = test-writer.c $(COMMON_SOURCES)

# Fixture-dependent tests resolve archives from the source tree, including
# when Automake runs them from a separate VPATH or distcheck build directory.
test_huffman_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_pkware_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_reader_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'

# Ship the deterministic fixture corpus and all module-mapped test sources.
EXTRA_DIST = \
	helper.h \
	helper.c \
	test-compression.c \
	test-crypto.c \
	test-huffman.c \
	test-endian.c \
	test-mpq.c \
	test-pkware.c \
	test-reader.c \
	test-wave.c \
	test-writer.c \
	fixtures/README.md \
	fixtures/mpq-v1-features.mpq \
	fixtures/mpq-v2-features.mpq
