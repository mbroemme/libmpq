# Keep object names local to this directory when building the test programs.
AUTOMAKE_OPTIONS		= subdir-objects

# Link every regression program against the library built from this tree.
AM_CPPFLAGS			= -I$(top_srcdir)/include -I$(top_srcdir)/src
AM_LDFLAGS			= -no-install
LDADD				= $(top_builddir)/src/libmpq.la

# Test executables are built for `make check` but are not installed.
check_PROGRAMS = \
	test-errors \
	test-archive \
	test-files \
	test-blocks \
	test-fixtures \
	test-create \
	test-codecs \
	test-payloads \
	test-clone \
	test-endian
TESTS				= $(check_PROGRAMS)

# Keep helper declarations generic while separately compiling their
# implementation into each independent end-to-end test executable.
COMMON_SOURCES			= test-common.c test.h
test_errors_SOURCES		= test-errors.c $(COMMON_SOURCES)
test_archive_SOURCES		= test-archive.c $(COMMON_SOURCES)
test_files_SOURCES		= test-files.c $(COMMON_SOURCES)
test_blocks_SOURCES		= test-blocks.c $(COMMON_SOURCES)
test_fixtures_SOURCES		= test-fixtures.c $(COMMON_SOURCES)
test_create_SOURCES		= test-create.c $(COMMON_SOURCES)
test_codecs_SOURCES		= test-codecs.c $(COMMON_SOURCES)
test_payloads_SOURCES		= test-payloads.c $(COMMON_SOURCES)
test_clone_SOURCES		= test-clone.c $(COMMON_SOURCES)
test_endian_SOURCES		= test-endian.c $(COMMON_SOURCES)

# Fixture-dependent tests resolve archives from the source tree, including
# when Automake runs them from a separate VPATH or distcheck build directory.
test_fixtures_CPPFLAGS		= $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_clone_CPPFLAGS		= $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_blocks_CPPFLAGS		= $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'

# Ship the deterministic fixture corpus with source distributions.
EXTRA_DIST = \
	test.h \
	test-common.c \
	fixtures/README.md \
	fixtures/mpq-v1-features.mpq \
	fixtures/mpq-v2-features.mpq
