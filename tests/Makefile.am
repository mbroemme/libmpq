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
	test-malformed \
	test-endian \
	test-fixtures \
	test-mpq \
	test-pkware \
	test-reader \
	test-wave \
	test-writer
TESTS = $(check_PROGRAMS)

# Verify the generated build-tree helper honors configured installation paths.
check-local:
	test "$$($(top_builddir)/libmpq-config --cflags)" = "-I$(includedir)"
	test "$$($(top_builddir)/libmpq-config --libs)" = "-L$(libdir) -lmpq -lbz2 -lz"

# Compile shared assertions and deterministic-data helpers into every test.
COMMON_SOURCES = test-mpq-helper.c test-mpq-helper.h
test_compression_SOURCES = test-mpq-compression.c $(COMMON_SOURCES)
test_crypto_SOURCES = test-mpq-crypto.c ../src/mpq-crypto.c ../src/mpq-endian.c $(COMMON_SOURCES)
test_huffman_SOURCES = test-mpq-huffman.c ../src/mpq-huffman.c $(COMMON_SOURCES)
test_malformed_SOURCES = test-mpq-malformed.c $(COMMON_SOURCES)
test_endian_SOURCES = test-mpq-endian.c ../src/mpq-endian.c $(COMMON_SOURCES)
test_fixtures_SOURCES = test-mpq-fixtures.c $(COMMON_SOURCES)
test_mpq_SOURCES = test-mpq-api.c $(COMMON_SOURCES)
test_pkware_SOURCES = test-mpq-pkware.c \
	../src/mpq-compression.c \
	../src/mpq-pkware.c \
	../src/mpq-huffman.c \
	../src/mpq-wave.c \
	../src/mpq-endian.c \
	$(COMMON_SOURCES)
test_reader_SOURCES = test-mpq-reader.c $(COMMON_SOURCES)
test_wave_SOURCES = test-mpq-wave.c ../src/mpq-wave.c ../src/mpq-endian.c $(COMMON_SOURCES)
test_writer_SOURCES = test-mpq-writer.c $(COMMON_SOURCES)

# Fixture-dependent tests resolve archives from the source tree, including
# when Automake runs them from a separate VPATH or distcheck build directory.
test_huffman_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_fixtures_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_pkware_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_reader_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'

# Ship the deterministic fixture corpus and all module-mapped test sources.
EXTRA_DIST = \
	test-mpq-helper.h \
	test-mpq-helper.c \
	test-mpq-compression.c \
	test-mpq-crypto.c \
	test-mpq-huffman.c \
	test-mpq-malformed.c \
	test-mpq-endian.c \
	test-mpq-api.c \
	test-mpq-pkware.c \
	test-mpq-reader.c \
	test-mpq-wave.c \
	test-mpq-writer.c \
	test-mpq-fixtures.c \
	fixtures/README.md \
	fixtures/mpq-v1-features.mpq \
	fixtures/mpq-v2-features.mpq
