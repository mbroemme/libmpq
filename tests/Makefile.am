# Keep object names local to this directory when building the test programs.
AUTOMAKE_OPTIONS = subdir-objects

# Link every regression program against the library built from this tree.
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src
AM_LDFLAGS = -no-install
LDADD = $(top_builddir)/src/mpq-file.lo $(top_builddir)/src/libmpq.la

# Each executable mirrors one implementation module in src/.
check_PROGRAMS = \
	test-bit \
	test-ext-table \
	test-het \
	test-bet \
	test-file \
	test-block \
	test-verify \
	test-attributes \
	test-md5 \
	test-signature \
	test-compression \
	test-lzma \
	test-sparse \
	test-crypto \
	test-huffman \
	test-malformed \
	test-mpqe \
	test-endian \
	test-hash \
	test-header \
	test-fixtures \
	test-mpq \
	test-pkware \
	test-reader \
	test-source \
	test-stream \
	test-patch-reader \
	test-patch-writer \
	test-update \
	test-wave \
	test-writer
TESTS = $(check_PROGRAMS)

# The update regression creates working archives in the build directory.
# Remove them during clean so source-release distcheck leaves no artifacts.
CLEANFILES = \
	update-abort-reference.mpq \
	update-abort.mpq \
	update-close.bin \
	update-collision.mpq \
	update-container.bin \
	update-edit.mpq \
	update-embedded-abort.w3x \
	update-embedded-before.bin \
	update-embedded-data.w3x \
	update-embedded-input.bin \
	update-embedded-path.w3m \
	update-embedded-reference.bin \
	update-embedded-remove.bin \
	update-embedded-rename.bin \
	update-embedded-source.mpq \
	update-embedded.bin \
	update-embedded.w3x \
	update-fixture.w3x \
	update-flush.bin \
	update-identity.bin \
	update-mpqe-data.mpqe \
	update-mpqe-input.bin \
	update-mpqe-multiple.mpqe \
	update-mpqe-path.mpqe \
	update-mpqe-remove.mpqe \
	update-mpqe-rename.mpqe \
	update-mpqe-rollback-before.bin \
	update-mpqe-rollback.mpqe \
	update-mpqe-signed.mpqe \
	update-mpqe.mpqe \
	update-noop.mpq \
	update-normal-rename.mpq \
	update-not-mpqe.mpq \
	update-options-data.mpq \
	update-options-path.mpq \
	update-options.bin \
	update-permissions.bin \
	update-public.mpq \
	update-publish.bin \
	update-reference.mpq \
	update-shared-attributes.mpq \
	update-shared-encrypted.mpq \
	update-shared-list.mpq \
	update-shared-metadata-before.mpq \
	update-shared-remove.mpq \
	update-shared-rename.mpq \
	update-shared-replace.mpq \
	update-shared-signature.mpq \
	update-shared-staged.mpq \
	update-signatures.mpq \
	update-trailing.mpq \
	update-unknown.mpq \
	update-v2.mpq \
	update.mpq \
	update.mpqe \
	update.mpqe.reference

# Build explicitly for repeatable, non-installed module profiling.
EXTRA_PROGRAMS = \
	bench-compression \
	bench-patch-reader \
	bench-patch-writer \
	bench-verify \
	bench-signature \
	bench-mpqe \
	bench-reader \
	bench-source \
	bench-stream \
	bench-writer \
	bench-update
bench_compression_SOURCES = bench-mpq-compression.c
bench_compression_LDADD = $(test_lzma_LDADD)
bench_patch_reader_SOURCES = bench-mpq-patch-reader.c
bench_patch_reader_LDADD = $(test_patch_writer_LDADD)
bench_patch_writer_SOURCES = bench-mpq-patch-writer.c
bench_patch_writer_LDADD = $(test_patch_writer_LDADD)
bench_verify_SOURCES = bench-mpq-verify.c
bench_signature_SOURCES = bench-mpq-signature.c $(COMMON_SOURCES)
bench_signature_LDADD = $(test_signature_LDADD)
bench_mpqe_SOURCES = bench-mpq-mpqe.c
bench_mpqe_LDADD = $(test_attributes_LDADD)
bench_reader_SOURCES = bench-mpq-reader.c
bench_reader_LDADD = $(test_attributes_LDADD)
bench_source_SOURCES = bench-mpq-source.c $(COMMON_SOURCES)
bench_source_LDADD = $(test_attributes_LDADD)
bench_stream_SOURCES = bench-mpq-stream.c
bench_stream_LDADD = $(test_attributes_LDADD)
bench_writer_SOURCES = bench-mpq-writer.c
bench_writer_LDADD = $(test_attributes_LDADD)
bench_update_SOURCES = bench-mpq-update.c
bench_update_LDADD = $(test_update_LDADD)

.PHONY: benchmarks run-benchmarks
benchmarks: $(EXTRA_PROGRAMS)
run-benchmarks: benchmarks
	./bench-compression$(EXEEXT)
	./bench-patch-reader$(EXEEXT)
	./bench-patch-writer$(EXEEXT)
	./bench-verify$(EXEEXT)
	./bench-signature$(EXEEXT)
	./bench-mpqe$(EXEEXT)
	./bench-reader$(EXEEXT)
	./bench-source$(EXEEXT)
	./bench-stream$(EXEEXT)
	./bench-writer$(EXEEXT)
	./bench-update$(EXEEXT)

# Verify the generated build-tree helper honors configured installation paths.
check-local:
	test "$$($(top_builddir)/libmpq-config --cflags)" = "-I$(includedir)"
	test "$$($(top_builddir)/libmpq-config --libs)" = "-L$(libdir) -lmpq @LIBS@"

# Compile shared assertions and deterministic-data helpers into every test.
COMMON_SOURCES = test-mpq-helper.c test-mpq-helper.h
test_bit_SOURCES = test-mpq-bit.c $(COMMON_SOURCES)
test_bit_LDADD = $(top_builddir)/src/mpq-bit.lo $(LDADD)
test_ext_table_SOURCES = test-mpq-ext-table.c $(COMMON_SOURCES)
test_ext_table_LDADD = $(top_builddir)/src/mpq-ext-table.lo $(top_builddir)/src/mpq-endian.lo $(LDADD)
test_het_SOURCES = test-mpq-het.c $(COMMON_SOURCES)
test_het_LDADD = $(top_builddir)/src/mpq-het.lo $(top_builddir)/src/mpq-bit.lo $(test_ext_table_LDADD)
test_bet_SOURCES = test-mpq-bet.c $(COMMON_SOURCES)
test_bet_LDADD = $(top_builddir)/src/mpq-bet.lo $(test_het_LDADD)
test_block_SOURCES = test-mpq-block.c $(COMMON_SOURCES)
test_block_LDADD = $(top_builddir)/src/mpq-block.lo $(top_builddir)/src/mpq-endian.lo $(LDADD)
test_file_SOURCES = test-mpq-file.c $(COMMON_SOURCES)
test_file_LDADD = $(top_builddir)/src/mpq-source.lo $(PRIVATE_MPQE_LDADD) $(LDADD)
test_source_SOURCES = test-mpq-source.c $(COMMON_SOURCES)
test_source_LDADD = $(test_file_LDADD)
test_verify_SOURCES = test-mpq-verify.c $(COMMON_SOURCES)
test_verify_LDADD = $(top_builddir)/src/mpq-md5.lo $(top_builddir)/src/mpq-attributes.lo $(top_builddir)/src/mpq-reader.lo $(top_builddir)/src/mpq-block.lo $(top_builddir)/src/mpq-hash.lo $(top_builddir)/src/mpq-header.lo $(top_builddir)/src/mpq-source.lo $(top_builddir)/src/mpq-mpqe.lo $(top_builddir)/src/mpq-crypto.lo $(PRIVATE_EXT_TABLE_LDADD) $(PRIVATE_COMPRESSION_LDADD) $(LDADD)
test_attributes_SOURCES = test-mpq-attributes.c $(COMMON_SOURCES)
test_attributes_LDADD = $(top_builddir)/src/mpq-attributes.lo $(top_builddir)/src/mpq-md5.lo $(top_builddir)/src/mpq-reader.lo $(top_builddir)/src/mpq-block.lo $(top_builddir)/src/mpq-hash.lo $(top_builddir)/src/mpq-header.lo $(top_builddir)/src/mpq-source.lo $(top_builddir)/src/mpq-mpqe.lo $(top_builddir)/src/mpq-crypto.lo $(PRIVATE_EXT_TABLE_LDADD) $(PRIVATE_COMPRESSION_LDADD) $(LDADD)
PRIVATE_EXT_TABLE_LDADD = $(top_builddir)/src/mpq-het.lo $(top_builddir)/src/mpq-bet.lo $(top_builddir)/src/mpq-bit.lo $(top_builddir)/src/mpq-ext-table.lo
test_md5_SOURCES = test-mpq-md5.c $(COMMON_SOURCES)
test_signature_SOURCES = test-mpq-signature.c $(COMMON_SOURCES)
test_signature_LDADD = $(top_builddir)/src/mpq-rsa.lo $(top_builddir)/src/mpq-sha1.lo $(test_attributes_LDADD)
test_md5_LDADD = $(top_builddir)/src/mpq-md5.lo $(top_builddir)/src/mpq-endian.lo $(LDADD)
test_compression_SOURCES = test-mpq-compression.c $(COMMON_SOURCES)
test_lzma_SOURCES = test-mpq-lzma.c $(COMMON_SOURCES)
test_sparse_SOURCES = test-mpq-sparse.c $(COMMON_SOURCES)
test_crypto_SOURCES = test-mpq-crypto.c ../src/mpq-crypto.c ../src/mpq-endian.c $(COMMON_SOURCES)
test_huffman_SOURCES = test-mpq-huffman.c ../src/mpq-huffman.c $(COMMON_SOURCES)
test_malformed_SOURCES = test-mpq-malformed.c $(COMMON_SOURCES)
test_mpqe_SOURCES = test-mpq-mpqe.c $(COMMON_SOURCES)
test_endian_SOURCES = test-mpq-endian.c ../src/mpq-endian.c $(COMMON_SOURCES)
test_hash_SOURCES = test-mpq-hash.c $(COMMON_SOURCES)
test_hash_LDADD = $(top_builddir)/src/mpq-hash.lo $(top_builddir)/src/mpq-endian.lo $(LDADD)
test_header_SOURCES = test-mpq-header.c $(COMMON_SOURCES)
test_header_LDADD = \
	$(top_builddir)/src/mpq-block.lo \
	$(top_builddir)/src/mpq-crypto.lo \
	$(top_builddir)/src/mpq-endian.lo \
	$(top_builddir)/src/mpq-hash.lo \
	$(top_builddir)/src/mpq-header.lo \
	$(LDADD)
test_fixtures_SOURCES = test-mpq-fixtures.c $(COMMON_SOURCES)
test_fixtures_LDADD = $(top_builddir)/src/mpq-rsa.lo $(test_attributes_LDADD)
test_mpq_SOURCES = test-mpq-api.c $(COMMON_SOURCES)
test_pkware_SOURCES = test-mpq-pkware.c \
	../src/mpq-compression.c \
	../src/mpq-pkware.c \
	../src/mpq-huffman.c \
	../src/mpq-wave.c \
	../src/mpq-endian.c \
	$(COMMON_SOURCES)
test_reader_SOURCES = test-mpq-reader.c $(COMMON_SOURCES)
test_reader_LDADD = $(test_attributes_LDADD)
test_stream_SOURCES = test-mpq-stream.c $(COMMON_SOURCES)
test_patch_reader_SOURCES = test-mpq-patch-reader.c $(COMMON_SOURCES)
test_patch_reader_LDADD = $(top_builddir)/src/mpq-patch-reader.lo $(test_attributes_LDADD)
test_patch_writer_SOURCES = test-mpq-patch-writer.c $(COMMON_SOURCES)
test_patch_writer_LDADD = \
	$(top_builddir)/src/mpq-patch-writer.lo \
	$(top_builddir)/src/mpq-patch-reader.lo \
	$(top_builddir)/src/mpq-writer.lo \
	$(top_builddir)/src/mpq-stream.lo \
	$(top_builddir)/src/mpq-signature.lo \
	$(top_builddir)/src/mpq-rsa.lo \
	$(top_builddir)/src/mpq-sha1.lo \
	$(test_attributes_LDADD)
test_update_SOURCES = test-mpq-update.c $(COMMON_SOURCES)
test_update_LDADD = \
	$(top_builddir)/src/mpq-update.lo \
	$(top_builddir)/src/mpq-writer.lo \
	$(top_builddir)/src/mpq-stream.lo \
	$(top_builddir)/src/mpq-signature.lo \
	$(top_builddir)/src/mpq-rsa.lo \
	$(top_builddir)/src/mpq-sha1.lo \
	$(test_attributes_LDADD)
test_wave_SOURCES = test-mpq-wave.c ../src/mpq-wave.c ../src/mpq-endian.c $(COMMON_SOURCES)
test_writer_SOURCES = test-mpq-writer.c $(COMMON_SOURCES)

# Reuse the library's already-built hidden MPQE helper objects for private checks.
PRIVATE_MPQE_LDADD = $(top_builddir)/src/mpq-mpqe.lo $(top_builddir)/src/mpq-endian.lo
test_mpqe_LDADD = $(top_builddir)/src/mpq-source.lo $(PRIVATE_MPQE_LDADD) $(LDADD)

# Reuse production codec objects for direct malformed-codec regressions.
PRIVATE_COMPRESSION_LDADD = \
	$(top_builddir)/src/mpq-compression.lo \
	$(top_builddir)/src/mpq-pkware.lo \
	$(top_builddir)/src/mpq-huffman.lo \
	$(top_builddir)/src/mpq-wave.lo \
	$(top_builddir)/src/mpq-sparse.lo \
	$(top_builddir)/src/mpq-endian.lo
test_lzma_LDADD = $(PRIVATE_COMPRESSION_LDADD) $(LDADD)
test_sparse_LDADD = $(PRIVATE_COMPRESSION_LDADD) $(LDADD)

# The legacy PKWARE dispatcher test also calls the production SPARSE codec.
test_pkware_LDADD = $(top_builddir)/src/mpq-sparse.lo $(LDADD)

test_writer_LDADD = $(PRIVATE_MPQE_LDADD) $(LDADD)

# Fixture-dependent tests resolve archives from the source tree, including
# when Automake runs them from a separate VPATH or distcheck build directory.
test_huffman_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_lzma_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_fixtures_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_mpqe_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_pkware_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_reader_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_patch_reader_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_patch_writer_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_signature_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_update_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'
test_wave_CPPFLAGS = $(AM_CPPFLAGS) -DFIXTURE_DIR='"$(top_srcdir)/tests/fixtures"'

# Ship the deterministic fixture corpus and all module-mapped test sources.
EXTRA_DIST = \
	test-mpq-block.c \
	test-mpq-consumer.c \
	test-mpq-helper.h \
	test-mpq-helper.c \
	test-mpq-compression.c \
	test-mpq-lzma.c \
	test-mpq-sparse.c \
	test-mpq-crypto.c \
	test-mpq-huffman.c \
	test-mpq-malformed.c \
	test-mpq-mpqe.c \
	test-mpq-endian.c \
	test-mpq-hash.c \
	test-mpq-header.c \
	test-mpq-api.c \
	test-mpq-pkware.c \
	test-mpq-reader.c \
	test-mpq-stream.c \
	test-mpq-patch-reader.c \
	test-mpq-patch-writer.c \
	test-mpq-update.c \
	test-mpq-wave.c \
	test-mpq-writer.c \
	test-mpq-fixtures.c \
	fixtures/README.md \
	fixtures/mpq-v1-features.mpq \
	fixtures/mpq-v1-features-patch.mpq \
	fixtures/mpq-v1-features-patch.w3x \
	fixtures/mpq-v1-features.mpqe \
	fixtures/mpq-v1-features.w3x \
	fixtures/mpq-v2-features.mpq \
	fixtures/mpq-v2-features-patch.mpq \
	fixtures/mpq-v2-features.mpqe

EXTRA_DIST += fixtures/mpq-v3-features.mpq fixtures/mpq-v3-features.mpqe
