# Build opt-in libFuzzer targets. They are not installed or part of make check.
noinst_PROGRAMS = fuzz-archive-open fuzz-sector-decode

# Compile fuzz targets against generated configuration, public, and private headers.
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir)/include -I$(top_srcdir)/src

# Keep fuzz targets as ordinary local executables rather than installed programs.
AM_LDFLAGS = -no-install

# Link the public archive-opening API target with the normal shared library.
fuzz_archive_open_SOURCES = fuzz-archive-open.c
fuzz_archive_open_LDADD = $(top_builddir)/src/libmpq.la
fuzz_archive_open_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer,address,undefined

# Link the sector target with private codec internals without changing the public ABI.
fuzz_sector_decode_SOURCES = fuzz-sector-decode.c
fuzz_sector_decode_LDADD = $(top_builddir)/src/libmpq-fuzz-internal.la $(LIBS)
fuzz_sector_decode_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer,address,undefined

# Include the harness sources and usage notes in source distributions.
EXTRA_DIST = \
	README.md \
	fuzz-archive-open.c \
	fuzz-sector-decode.c
