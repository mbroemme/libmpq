# Require CMake 3.21 or newer and initialize a C-only libmpq project.
# Keep the release version synchronized with AC_INIT in configure.ac;
# it is independent of the Libtool ABI version.
cmake_minimum_required(VERSION 3.21)
project(libmpq VERSION 0.8.0 LANGUAGES C)

# Native MSVC frontend; Autotools remains the canonical Unix/cross build.
option(BUILD_SHARED_LIBS "Build the shared library" ON)

# Reuse GENERAL_SRCS rather than maintaining a second core source list.
# Match the entire continued assignment, including its final noncontinued line,
# so an unexpected Makefile format fails instead of silently omitting sources.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/Makefile.am" source_text)
string(REPLACE "\r\n" "\n" source_text "${source_text}")

# Assignment header, zero or more continued sources, then the final source.
string(CONCAT source_pattern
    "(^|\n)GENERAL_SRCS[ \t]*=[ \t]*\\\\\n"
    "([ \t]+mpq-[a-z0-9-]+\\.c[ \t]*\\\\\n)*"
    "[ \t]+mpq-[a-z0-9-]+\\.c[ \t]*(\n|$)"
)
string(REGEX MATCH "${source_pattern}" source_block "${source_text}")
if(NOT source_block)
    message(FATAL_ERROR "Cannot parse GENERAL_SRCS in src/Makefile.am")
endif()
string(REGEX MATCHALL "mpq-[a-z0-9-]+\\.c" sources "${source_block}")
if(NOT sources OR NOT "mpq-api.c" IN_LIST sources)
    message(FATAL_ERROR "Missing or incomplete GENERAL_SRCS in src/Makefile.am")
endif()
list(TRANSFORM sources PREPEND "src/")

# Public wrappers belong only to the library target, not the private objects.
list(REMOVE_ITEM sources src/mpq-api.c)

# Imported targets carry codec include paths and platform-specific libraries.
find_package(ZLIB REQUIRED)
find_package(BZip2 REQUIRED)
find_package(LibLZMA REQUIRED)
set(codec_libraries
    ZLIB::ZLIB
    BZip2::BZip2
    LibLZMA::LibLZMA
)

# Compiler settings shared by the library and native regression tests.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
if(MSVC)
    add_compile_options(/utf-8)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_definitions(_FILE_OFFSET_BITS=64 _POSIX_C_SOURCE=200809L)
endif()

# Tests reuse these production objects to reach hidden helpers without exporting
# private APIs or compiling a second implementation with test-only definitions.
add_library(mpq-core OBJECT ${sources})
set_target_properties(mpq-core PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_VISIBILITY_PRESET hidden
)
target_include_directories(mpq-core PUBLIC include PRIVATE src)
target_link_libraries(mpq-core PUBLIC ${codec_libraries})

# VERSION supplies libmpq__version(), as config.h does in the Autotools build.
add_library(mpq src/mpq-api.c $<TARGET_OBJECTS:mpq-core>)
target_include_directories(mpq PUBLIC include PRIVATE src)
target_compile_definitions(mpq PRIVATE VERSION="${PROJECT_VERSION}")

# CMake defines DLL_EXPORT only when compiling the shared target. Public wrappers
# use it privately; neither static builds nor consumers need linkage macros.
set_target_properties(mpq PROPERTIES
    DEFINE_SYMBOL DLL_EXPORT
    C_VISIBILITY_PRESET hidden
)
target_link_libraries(mpq PRIVATE ${codec_libraries})
if(WIN32)

    # Secure random filenames and owner-only temporary-file security descriptors.
    target_link_libraries(mpq-core PUBLIC bcrypt advapi32)
    target_link_libraries(mpq PRIVATE bcrypt advapi32)

    # Native Windows outputs are libmpq.dll and its toolchain's import library.
    set_target_properties(mpq PROPERTIES OUTPUT_NAME libmpq PREFIX "")
endif()

# Install only the public header; private filesystem/codec headers stay internal.
include(GNUInstallDirs)
install(TARGETS mpq
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(FILES include/libmpq/mpq.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libmpq
)

# Keep CMake installs aligned with the section-3 API manuals shipped by Autotools.
file(GLOB man3_pages CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/docs/man3/*.3")
install(FILES ${man3_pages}
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man3
)

# Release builds may provide debugging symbols without requiring them to exist.
if(MSVC AND BUILD_SHARED_LIBS)
    install(FILES "$<TARGET_PDB_FILE:mpq>"
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        OPTIONAL
    )
endif()

# Each test has its own writable working directory, separate from the immutable
# source fixtures and other tests, allowing independent/parallel execution.
include(CTest)
if(BUILD_TESTING)
    set(test_modules
        file
        verify
        attributes
        md5
        signature
        compression
        lzma
        sparse
        crypto
        huffman
        malformed
        mpqe
        endian
        fixtures
        api
        pkware
        reader
        update
        wave
        writer
    )

    foreach(module IN LISTS test_modules)
        add_executable(test-${module}
            tests/test-mpq-${module}.c
            tests/test-mpq-helper.c
        )
        target_include_directories(test-${module} PRIVATE src tests)
        target_compile_definitions(test-${module} PRIVATE
            FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures"
        )
        target_link_libraries(test-${module} PRIVATE mpq mpq-core)

        set(test_work_dir "${CMAKE_CURRENT_BINARY_DIR}/test-work/${module}")
        file(MAKE_DIRECTORY "${test_work_dir}")
        add_test(NAME ${module} COMMAND test-${module})
        set_tests_properties(${module} PROPERTIES
            WORKING_DIRECTORY "${test_work_dir}"
        )
    endforeach()
endif()
