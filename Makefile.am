# Subdirectories that are built and installed.
SUBDIRS				= include/libmpq src bindings docs/man1 docs/man3 tests

# Subdirectories included in source distributions.
DIST_SUBDIRS			= $(SUBDIRS) tools

# Install the libmpq runtime configuration script.
bin_SCRIPTS			= libmpq-config

# Install the pkg-config metadata in the standard directory.
pkgconfigdir			= $(libdir)/pkgconfig
pkgconfig_DATA			= libmpq.pc

# Additional files included in source distributions.
EXTRA_DIST = \
	COPYING \
	COPYING.LESSER \
	README.md \
	RELICENSING.md \
	dub.sdl
