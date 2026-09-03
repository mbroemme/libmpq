# Build opt-in libFuzzer targets. They are not installed or part of make check.
noinst_PROGRAMS = \
	fuzz-archive-open \
	fuzz-mpqe-open \
	fuzz-file-read \
	fuzz-writer-roundtrip \
	fuzz-encrypted-archive \
	fuzz-sector-decode \
	fuzz-pkware-decode \
	fuzz-huffman-decode \
	fuzz-zlib-decode \
	fuzz-bzip2-decode \
	fuzz-wave-decode

# Compile fuzz targets against generated configuration, public, and private headers.
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir)/include -I$(top_srcdir)/src

# Keep fuzz targets as ordinary local executables rather than installed programs.
AM_LDFLAGS = -no-install

# Link the public archive-opening API target with the normal shared library.
fuzz_archive_open_SOURCES = fuzz-archive-open.c
fuzz_archive_open_LDADD = $(top_builddir)/src/libmpq.la
fuzz_archive_open_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer,address,undefined

# Link the caller-authenticated MPQE stream target with the normal shared library.
fuzz_mpqe_open_SOURCES = fuzz-mpqe-open.c fuzz-common.h
fuzz_mpqe_open_LDADD = $(top_builddir)/src/libmpq.la
fuzz_mpqe_open_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer,address,undefined

# Link reader and writer API targets with the normal shared library.
fuzz_file_read_SOURCES = fuzz-file-read.c fuzz-common.h
fuzz_file_read_LDADD = $(top_builddir)/src/libmpq.la
fuzz_file_read_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer,address,undefined
fuzz_writer_roundtrip_SOURCES = fuzz-writer-roundtrip.c
fuzz_writer_roundtrip_LDADD = $(top_builddir)/src/libmpq.la
fuzz_writer_roundtrip_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer,address,undefined
fuzz_encrypted_archive_SOURCES = fuzz-encrypted-archive.c fuzz-common.h
fuzz_encrypted_archive_LDADD = $(top_builddir)/src/libmpq.la
fuzz_encrypted_archive_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer,address,undefined

# Link the sector target with private codec internals without changing the public ABI.
fuzz_sector_decode_SOURCES = fuzz-sector-decode.c
fuzz_sector_decode_LDADD = $(top_builddir)/src/libmpq-fuzz-internal.la $(LIBS)
fuzz_sector_decode_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer,address,undefined

# Build focused codec targets from one bounded decoder harness.
fuzz_pkware_decode_SOURCES = fuzz-codec-decode.c
fuzz_pkware_decode_CPPFLAGS = $(AM_CPPFLAGS) -DLIBMPQ_FUZZ_CODEC=LIBMPQ_COMPRESSION_PKZIP
fuzz_pkware_decode_LDADD = $(top_builddir)/src/libmpq-fuzz-internal.la $(LIBS)
fuzz_pkware_decode_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer,address,undefined
fuzz_huffman_decode_SOURCES = fuzz-codec-decode.c
fuzz_huffman_decode_CPPFLAGS = $(AM_CPPFLAGS) -DLIBMPQ_FUZZ_CODEC=LIBMPQ_COMPRESSION_HUFFMAN
fuzz_huffman_decode_LDADD = $(top_builddir)/src/libmpq-fuzz-internal.la $(LIBS)
fuzz_huffman_decode_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer,address,undefined
fuzz_zlib_decode_SOURCES = fuzz-codec-decode.c
fuzz_zlib_decode_CPPFLAGS = $(AM_CPPFLAGS) -DLIBMPQ_FUZZ_CODEC=LIBMPQ_COMPRESSION_ZLIB
fuzz_zlib_decode_LDADD = $(top_builddir)/src/libmpq-fuzz-internal.la $(LIBS)
fuzz_zlib_decode_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer,address,undefined
fuzz_bzip2_decode_SOURCES = fuzz-codec-decode.c
fuzz_bzip2_decode_CPPFLAGS = $(AM_CPPFLAGS) -DLIBMPQ_FUZZ_CODEC=LIBMPQ_COMPRESSION_BZIP2
fuzz_bzip2_decode_LDADD = $(top_builddir)/src/libmpq-fuzz-internal.la $(LIBS)
fuzz_bzip2_decode_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer,address,undefined
fuzz_wave_decode_SOURCES = fuzz-wave-decode.c
fuzz_wave_decode_LDADD = $(top_builddir)/src/libmpq-fuzz-internal.la $(LIBS)
fuzz_wave_decode_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer,address,undefined

# Include the harness sources and usage notes in source distributions.
EXTRA_DIST = \
	README.md \
	corpus/README.md \
	corpus/writer-roundtrip/pkware-short-runs.txt \
	fuzz-archive-open.c \
	fuzz-codec-decode.c \
	fuzz-common.h \
	fuzz-encrypted-archive.c \
	fuzz-file-read.c \
	fuzz-mpqe-open.c \
	fuzz-sector-decode.c \
	fuzz-wave-decode.c \
	fuzz-writer-roundtrip.c
