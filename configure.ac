# Initialize the Autoconf package metadata.
AC_INIT([libmpq],[0.7.0],[mbroemme@libmpq.org],[libmpq])
AC_SUBST(LIBMPQ_ABI, [3:0:2])

# Detect the canonical host and target build environments.
AC_CANONICAL_TARGET

# Initialize Autoconf and Automake.
AM_INIT_AUTOMAKE([no-dependencies])
AC_CONFIG_HEADERS([config.h:config.h.in])

# Keep libFuzzer targets opt-in so normal developer and release builds do not
# require a compiler with the libFuzzer runtime.
AC_ARG_ENABLE(
	[fuzzing],
	[AS_HELP_STRING([--enable-fuzzing], [build libFuzzer harnesses])],
	[enable_fuzzing=$enableval],
	[enable_fuzzing=no]
)
AS_CASE(
	[$enable_fuzzing],
	[yes|no], [],
	[AC_MSG_ERROR([--enable-fuzzing accepts only yes or no])]
)
AM_CONDITIONAL([ENABLE_FUZZING], [test "x$enable_fuzzing" = xyes])

# Check for the required build tools.
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC

# Use C99 by default while allowing callers to select a newer C dialect.
case "$CFLAGS" in
	*-std=*|*-ansi*) ;;
	*) CFLAGS="$CFLAGS -std=c99" ;;
esac

# Initialize Libtool and disable static-library builds.
LT_INIT([disable-static])

# Require a C99-capable compiler for project checks and builds.
AC_MSG_CHECKING([whether $CC supports C99])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([[#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
#error "C99 support is required"
#endif]])],
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])
	 AC_MSG_ERROR([*** a C99 capable compiler is required])]
)

# Enable hidden symbol visibility when the compiler supports it.
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([[__attribute__((visibility("hidden"))) int hidden_symbol;]], [[]])],
	[CFLAGS="$CFLAGS -fvisibility=hidden"],
	[]
)

# Check for the zlib compression library.
AC_CHECK_HEADER([zlib.h], [], [AC_MSG_ERROR([*** zlib.h is required, install zlib header files])])
AC_CHECK_LIB([z], [inflateEnd], [], [AC_MSG_ERROR([*** inflateEnd is required, install zlib library files])])

# Check for the bzip2 compression library.
AC_CHECK_HEADER([bzlib.h], [], [AC_MSG_ERROR([*** bzlib.h is required, install bzip2 header files])])
AC_CHECK_LIB([bz2], [BZ2_bzDecompressInit], [], [AC_MSG_ERROR([*** BZ2_bzDecompressInit is required, install bzip2 library files])])

# Generate package metadata and the runtime configuration script.
AC_CONFIG_FILES([libmpq.pc])
AC_CONFIG_FILES([libmpq-config],[chmod +x libmpq-config])

# Generate the remaining package build files.
AC_CONFIG_FILES([
Makefile
include/libmpq/Makefile
src/Makefile
bindings/Makefile
bindings/d/Makefile
bindings/java/Makefile
bindings/python/Makefile
docs/man1/Makefile
docs/man3/Makefile
tests/Makefile
fuzz/Makefile
tools/Makefile
])

# Complete the configuration process.
AC_OUTPUT
