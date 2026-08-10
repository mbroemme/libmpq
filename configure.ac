# the autoconf initilization.
AC_INIT([libmpq],[0.5.0],[mbroemme@libmpq.org],[libmpq])
AC_SUBST(LIBMPQ_ABI, [1:0:0])

# detect the canonical host and target build environment.
AC_CANONICAL_TARGET

# initialize autoconf and automake system.
AM_INIT_AUTOMAKE([no-dependencies])
AC_CONFIG_HEADERS([config.h:config.h.in])

# detect platform feature declarations.
AC_USE_SYSTEM_EXTENSIONS

# checking for programs.
LT_INIT
AC_PROG_MAKE_SET
AC_PROG_CC

# require C99 capable compiler and use it for all project checks/builds.
AC_MSG_CHECKING([whether $CC supports C99])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([[#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
#error "C99 support is required"
#endif]])],
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])
	 AC_MSG_ERROR([*** a C99 capable compiler is required])]
)

# compile with hidden visibility when the compiler supports it.
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([[__attribute__((visibility("hidden"))) int hidden_symbol;]], [[]])],
	[CFLAGS="$CFLAGS -fvisibility=hidden"],
	[]
)

# check for zlib library.
AC_CHECK_HEADER([zlib.h], [], [AC_MSG_ERROR([*** zlib.h is required, install zlib header files])])
AC_CHECK_LIB([z], [inflateEnd], [], [AC_MSG_ERROR([*** inflateEnd is required, install zlib library files])])

# check for bzlib2 library.
AC_CHECK_HEADER([bzlib.h], [], [AC_MSG_ERROR([*** bzlib.h is required, install bzip2 header files])])
AC_CHECK_LIB([bz2], [BZ2_bzDecompressInit], [], [AC_MSG_ERROR([*** BZ2_bzDecompressInit is required, install bzip2 library files])])

# find python for binding
AM_PATH_PYTHON([2.4],,[:])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != :])

# configuration files.
AC_CONFIG_FILES([libmpq.pc])
AC_CONFIG_FILES([libmpq-config],[chmod +x libmpq-config])

# creating files.
AC_CONFIG_FILES([
Makefile
src/Makefile
bindings/Makefile
bindings/d/Makefile
bindings/python/Makefile
docs/Makefile
docs/man1/Makefile
docs/man3/Makefile
tools/Makefile
])

# perform configuration actions.
AC_OUTPUT
