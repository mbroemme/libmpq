# Subdirectories that are built and installed.
SUBDIRS = d

# The Java binding has its own Maven build and is included in distributions
# without becoming part of the native Autotools build.
DIST_SUBDIRS = d java python

if HAVE_PYTHON
SUBDIRS += python
endif
