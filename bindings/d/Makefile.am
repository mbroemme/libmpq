# Install the D modules in the same public namespace as the C header.
libmpq_includedir = $(includedir)/libmpq
libmpq_include_HEADERS = \
	source/libmpq/archive.d \
	source/libmpq/errors.d \
	source/libmpq/mpq.d \
	source/libmpq/native.d \
	source/libmpq/options.d

# Keep DUB metadata, documentation, and integration tests in distributions.
EXTRA_DIST = \
	README.md \
	../../dub.sdl \
	tests/main.d
