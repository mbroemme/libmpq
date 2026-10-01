# libmpq developer guide

This guide covers native API usage, SDK integration, and binding development.
See [README.md](README.md) for requirements, building, and limitations,
[MPQ.md](MPQ.md) for the archive-format reference, and
[RELEASING.md](RELEASING.md) for release packaging, validation, and publication.

## Native API usage

### Native API example

The public header is installed as `libmpq/mpq.h`. The following example opens
an archive, reads the first file into memory, and reports library errors:

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <libmpq/mpq.h>

int
main(int argc, char **argv)
{
    mpq_archive_s *archive = NULL;
    libmpq__off_t file_size = 0;
    uint8_t *file_data = NULL;
    int32_t result;

    if (argc != 2) {
        fprintf(stderr, "usage: %s ARCHIVE\n", argv[0]);
        return EXIT_FAILURE;
    }

    result = libmpq__archive_open(&archive, argv[1], -1);
    if (result < 0) {
        fprintf(stderr, "archive_open: %s\n", libmpq__strerror(result));
        return EXIT_FAILURE;
    }

    result = libmpq__file_size_unpacked(archive, 0, &file_size);
    if (result < 0) {
        fprintf(stderr, "file_size_unpacked: %s\n", libmpq__strerror(result));
        libmpq__archive_close(archive);
        return EXIT_FAILURE;
    }

    file_data = malloc((size_t)file_size);
    if (file_data == NULL && file_size != 0) {
        libmpq__archive_close(archive);
        return EXIT_FAILURE;
    }

    result = libmpq__file_read(archive, 0, file_data, file_size, NULL);
    if (result < 0) {
        fprintf(stderr, "file_read: %s\n", libmpq__strerror(result));
        free(file_data);
        libmpq__archive_close(archive);
        return EXIT_FAILURE;
    }

    free(file_data);
    libmpq__archive_close(archive);
    return EXIT_SUCCESS;
}
```

If `pkg-config` is available, compile the example with the installed header
and shared library:

```sh
cc -std=c99 -Wall -Wextra mpq-example.c -o mpq-example \
  $(pkg-config --cflags --libs libmpq)
```

The legacy `libmpq-config` helper is also available:

```sh
cc -std=c99 -Wall -Wextra mpq-example.c -o mpq-example \
  $(libmpq-config --cflags) $(libmpq-config --libs)
```

### Custom random-access I/O

`libmpq__archive_open_io()` accepts an exact random-access callback instead
of a path. The callback receives absolute source offsets and must synchronously
fill the complete requested buffer before returning zero. libmpq range-checks
every request and normalizes positive callback results to `LIBMPQ_ERROR_READ`.

The callback context is borrowed and may be NULL for a stateless callback.
Keep a non-NULL context, its storage, and the callback valid until the opened
archive and every clone are closed. libmpq never frees or closes caller-owned
context. Clones allocate independent parser state and adapter wrappers but
share the borrowed context, so callers provide any needed synchronization.
`source_name` is optional. When supplied, libmpq copies it as the logical
archive name and uses its basename for legacy strong-signature verification.
Without a source name, basename-dependent strong signatures are skipped while
plain and `ARCHIVE` variants remain available. Clones preserve that name or
anonymous state. `libmpq__archive_open_mpqe_io()` applies the same rules below
the existing MPQE transform.

```c
typedef struct
{
    const uint8_t *data;
    size_t size;
} memory_source_s;

static int32_t
memory_read_at(void *context, libmpq__off_t offset, uint8_t *buffer, size_t size)
{
    const memory_source_s *source = context;

    if (offset < 0 || (uint64_t)offset > source->size ||
        size > source->size - (size_t)offset)
        return LIBMPQ_ERROR_READ;
    memcpy(buffer, source->data + (size_t)offset, size);
    return 0;
}
```

### Logical member streams

`libmpq__stream_open()` and `libmpq__stream_open_name()` provide
incremental logical-member reads and seeks without a complete file buffer.
An archive source is the backing MPQ or MPQE byte source; a logical member
stream is a decoded logical archive member.
The handle owns a private archive clone, so the source archive may close after
opening the stream. For custom I/O, the caller must retain its callback context
until every derived logical member stream is closed. Ordinary sectorized
members retain one decoded sector; a single-unit member can require its
complete logical unit.

```c
mpq_stream_s *stream = NULL;
uint8_t buffer[4096];
libmpq__off_t transferred;

if (libmpq__stream_open_name(archive, "data/file.bin", &stream) == 0) {
    while (libmpq__stream_read(stream, buffer, sizeof(buffer), &transferred) == 0 &&
           transferred != 0) {
        /* Consume buffer[0..transferred). */
    }
    (void)libmpq__stream_close(stream);
}
```

Reads at EOF succeed with zero transferred bytes. Seek accepts
`LIBMPQ_SEEK_SET`, `LIBMPQ_SEEK_CUR`, and `LIBMPQ_SEEK_END` only. Incremental
reads verify usable sector Adler-32 values when their sectors load, but do not
implicitly verify whole-file CRC32/MD5 attributes; use `libmpq__file_verify()`
when that verification is required.

### Streaming and one-shot writers

`libmpq__writer_begin()` starts an archive member and returns `mpq_writer_s`.
Use `libmpq__writer_write()`, `libmpq__writer_timestamp()`, and
`libmpq__writer_finish()` on that handle. Finishing consumes it, even on error.
Use `libmpq__archive_add_data()` to add an in-memory source in one call, or
`libmpq__archive_add_path()` to add a filesystem-path source.

### Writer compression policy

For MPQ v2+ creation, `LIBMPQ_COMPRESSION_LZMA` is an exclusive API selector,
not a chainable multi-compression bit. It maps to serialized method `0x12`;
that byte retains its legacy bzip2-plus-zlib meaning in MPQ v1.

Writer compression defaults to `LIBMPQ_COMPRESSION_POLICY_STANDARD`, favoring
interoperability. For MPQ v2+, this permits zlib, PKWARE, bzip2, LZMA, SPARSE
alone or paired with zlib/bzip2, and Huffman paired with mono or stereo WAVE
ADPCM. The fixed SPARSE forms are `0x20`, `0x22`, and `0x30`. MPQ v1 retains
normal compression-mask semantics under either policy, allowing other valid
combinations such as SPARSE with Huffman (`0x21`) or PKWARE (`0x28`). Add
`LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED` to the archive creation flags to
permit broader valid lossless SPARSE combinations and other implemented forms,
including standalone Huffman, in MPQ v2+. `EXTENDED` output may be less
interoperable with StormLib and other MPQ implementations; it is not
classified as invalid MPQ. Readers stay permissive.

Use `libmpq__archive_compression_allowed(version, mask, policy)` to query
whether a compression selection is allowed by the writer policy. Version uses
the zero-based `LIBMPQ_ARCHIVE_VERSION_*` selectors. Both policies reject
unknown bits, conflicting ADPCM channels, and v2 chains containing both zlib
and bzip2, whose surviving stages could collide with LZMA's `0x12`. Both
policies reject SPARSE combined with WAVE ADPCM: lossy ADPCM cannot preserve
SPARSE control bytes. If skipped stages leave a method disallowed by the
selected policy, the original sector is stored raw. The first WAVE sector
stays lossless (zlib for STANDARD v2).

### Optional attributes

Select optional metadata separately from archive creation flags:

```c
mpq_archive_create_options_s options = {0};
options.flags = LIBMPQ_ARCHIVE_CREATE_LISTFILE |
                LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED;
options.attributes = LIBMPQ_ATTRIBUTE_CRC32 | LIBMPQ_ATTRIBUTE_FILETIME |
                     LIBMPQ_ATTRIBUTE_MD5;
```

Zero `options.attributes` disables generation. Any nonzero combination
creates one `(attributes)` file and consumes one reserved file slot.
Use `libmpq__archive_attributes()` to query available arrays and
`libmpq__file_attributes()` to read a file's stored values. FILETIME is
explicit/default-zero; set it through `libmpq__writer_timestamp()` using Windows
FILETIME, not Unix time.

### Explicit checksum verification and block metadata

Explicitly compare available stored checksums after opening an archive:

```c
uint32_t mismatches = 0;
int32_t status = libmpq__file_verify(archive, file_number,
                                    LIBMPQ_VERIFY_ALL, &mismatches);
/* status < 0: operation failed; otherwise inspect the requested VERIFY_* bits. */
```

`LIBMPQ_VERIFY_ALL` requests sector Adler-32 and file CRC32/MD5 checks.
The returned mismatch mask uses those same bits and is a subset of the request.
A set bit means an available checksum mismatched; a clear bit means it matched
or was unavailable/skipped. Operational errors leave the mask zero.
Sector checks cover decrypted packed bytes before decompression; absent tables
and unavailable entries are skipped. Use `LIBMPQ_VERIFY_SECTOR_CRC` alone to
verify sectors without requiring `(attributes)`.

Use `libmpq__block_verify(archive, file_number, block_number, &checksum,
&mismatches)` to verify one sector and retrieve its stored Adler-32.
It returns `LIBMPQ_ERROR_EXIST` for unavailable checksums; success returns
zero or `LIBMPQ_VERIFY_SECTOR_CRC` in `mismatches`. Both outputs stay zero
on errors. No calculated checksum is exposed.

Use `libmpq__block_compression()` to inspect the stored method without
decoding. Use `libmpq__file_flags()` to retrieve a member's complete stored
block-table flags and inspect the `LIBMPQ_FILE_FLAG_*` bits for file-level
storage properties. Zero means raw storage/fallback; LZMA is returned as
on-disk `0x12`, not the writer selector. In MPQ v1, `0x12` retains its legacy
bzip2/zlib meaning.

`libmpq__block_size_packed()` reports a block's stored data bytes, excluding
offset and checksum tables. `libmpq__block_size_unpacked()` reports the
decoded size needed for a `libmpq__block_read()` output buffer.

To generate sector checksums, add `LIBMPQ_FILE_FLAG_SECTOR_CRC` to the file
options alongside `LIBMPQ_FILE_FLAG_COMPRESS` or `LIBMPQ_FILE_FLAG_IMPLODE`.
This is opt-in for sectorized files, including encrypted files. Empty, raw,
and single-unit files do not generate checksum tables. Tables are stored
unencrypted and compressed with zlib only when smaller.

File checksum requests without `(attributes)` return `LIBMPQ_ERROR_EXIST`.
Missing individual CRC32/MD5 values are skipped, so zero mismatch bits do not
prove that hashes were present. Complete file reads automatically verify usable
sector Adler-32 values and, for lossless data, available CRC32/MD5 attributes.
`libmpq__file_verify()` remains available when callers need selected checks and
mismatch bits. `libmpq__block_read()` is partial and does not implicitly verify
its stored sector checksum. Lossy ADPCM decoding cannot reproduce the writer's
source bytes byte-for-byte, so automatic file-level CRC32/MD5 comparison is
intentionally skipped. Explicit `libmpq__file_verify()` requests still compare
the decoded output and may report a mismatch; sector checks are unaffected.

### Archive signatures

Use `libmpq__archive_signatures` to detect weak and strong signatures. Use
`libmpq__archive_verify(archive, LIBMPQ_SIGNATURE_WEAK, key, 128, &mismatches)`
for weak verification and `LIBMPQ_SIGNATURE_STRONG` with a 512-byte public key
for strong verification. A mismatch is a result bit, not an operational error;
a missing signature returns `LIBMPQ_ERROR_EXIST`. Strong signatures use external
`NGIS` trailers, SHA-1 and RSA-2048. Writer creation emits only the plain
SHA-1 archive-range variant. Basename and `ARCHIVE` variants are accepted
during verification only.

To sign, call `libmpq__archive_sign` on a v1 or v2 writer with the
corresponding private key before close. Weak signing reserves one file
slot for `(signature)`; strong signing appends an external `NGIS` trailer
after finalization.

The weak 128-byte raw key is two 64-byte unsigned big-endian integers: a modulus
followed by a zero-padded exponent value. Use a public key to verify a signature and a private key to
create one. There are no built-in keys. See [MPQ.md](MPQ.md) for storage,
hashing, error, and key-format details. Weak signatures use
obsolete MD5/RSA-512 and must not be used for modern trust decisions.
Strong public and private keys contain a 256-byte unsigned big-endian modulus
and a 256-byte zero-padded unsigned big-endian exponent (512 bytes total).
The writer accepts the private exponent and emits only the plain SHA-1 range variant.
External strong trailers are not defined for MPQE, so strong signing is rejected there.

For files beginning with `HM3W`, weak and strong hashing
starts at physical offset zero; weak hashing still excludes `(signature)`.

### Transactional modification

Use a separate `mpq_update_s` handle to stage changes to an existing,
filesystem-backed MPQ. Each operation rebuilds the private working copy; the
original path changes only on commit. For example:

```c
mpq_update_s *update = NULL;
const uint8_t replacement[] = "new contents";

if (libmpq__update_begin(&update, "data.mpq") == LIBMPQ_SUCCESS) {
    if (libmpq__update_replace_data(update, "data/file.bin", replacement,
                                    sizeof(replacement) - 1, NULL) == LIBMPQ_SUCCESS)
        (void)libmpq__update_commit(update);
    else
        (void)libmpq__update_abort(update);
}
```

Embedded HM3W-style containers use the same scanner and update operations,
regardless of `.w3x` or `.w3m` extension. Rebuilding retains the prefix and
unrelated trailing bytes; stale weak and external strong signatures are
removed. For an MPQE archive, use `libmpq__update_begin_mpqe()` with an explicit
authentication code. It decodes into a private same-directory working MPQ;
ordinary update operations apply unchanged. Commit re-encrypts and validates
an encrypted sibling before atomic publication. No-op commit leaves the MPQE
container byte-identical. Only the first 32 authentication bytes needed for
the existing MPQE key derivation are copied into private state, then cleared
on every consuming path. A crash may leave owner-only plaintext staging data.

`libmpq__update_replace_path()` reads replacement data from a filesystem
path. `libmpq__update_remove()` and `libmpq__update_rename()` affect
existing named entries only; rename rejects an existing destination name.
Replacement accepts the same optional `mpq_file_options_s` as
`libmpq__archive_add_data()` and `libmpq__archive_add_path()`, including
separate `compression_first` and `compression_next` masks. A NULL options
pointer uses default storage options. When options are supplied, their
`locale` and `platform` must match the existing member; replacement cannot
move a member to a different hash identity.
When multiple names share one physical block, removing or renaming an
unencrypted name leaves the other names intact. Replacing that block, or
renaming it when encrypted, returns `LIBMPQ_ERROR_FORMAT` until block splitting
is supported. Modification also rejects shared `(listfile)`, `(attributes)`, or
`(signature)` blocks when those internal entries must be rewritten or removed.
Commit and abort both consume the update handle, including on error. Commit
rechecks the destination's filesystem identity immediately before atomic
replacement, but this is best effort and does not lock out a concurrent change
between check and publication.

Unchanged physical entries, including entries absent from `(listfile)`, retain
their packed representation. Encrypted rename decodes using the old plaintext
name and re-encodes using the new name. Existing `(listfile)` and valid
`(attributes)` metadata are updated. Replacement resets FILETIME to the normal
writer default of zero; rename retains the existing FILETIME. Weak
`(signature)` entries and external
`NGIS` trailers are removed after mutation because this API takes no signing
key. A no-op transaction preserves all original bytes. Embedded MPQs use the
ordinary update entry point; MPQE uses the authenticated entry point described
above. Ordinary updates do not write PATCH_BIT=true; the separate patch writer
sets it for patch-file entries. The current rebuild rejects an archive extent
that cannot fit the 32-bit MPQ archive-size field.

### Patch archive creation

The public patch handle creates a new MPQ v1/v2 patch artifact without modifying
the base archive:

```c
mpq_patch_s *patch = NULL;

libmpq__patch_begin(&patch, "base.mpq", "changes.mpq");
libmpq__patch_replace_data(patch, "file.txt", data, data_size, NULL);
libmpq__patch_remove(patch, "obsolete.txt");
libmpq__patch_sign(patch, LIBMPQ_SIGNATURE_WEAK, private_key, key_size);
libmpq__patch_finish(patch);
```

`libmpq__patch_begin()` creates an ordinary MPQ patch. To create an
MPQE-wrapped patch instead, call `libmpq__patch_begin_mpqe()` with a
caller-supplied authentication code; replacement, removal, finish, and abort
then follow the same lifecycle. Authenticated patch readers can consume the
result using that patch layer's own code. Signing is optional and configured
with `libmpq__patch_sign()` before finish. It delegates to the existing archive
writer: ordinary patches may use weak, strong, or both signatures; MPQE patches
support weak signatures only. A finished patch is inspected and verified with
`libmpq__archive_signatures()` and `libmpq__archive_verify()`.

Replacement options control storage of the patch member inside the patch
archive, not storage of the resulting file in the patched view.

The private `mpq-patch-writer` module stages a same-directory temporary archive.
It writes named replacements as PTCH BSD0
members when a deterministic binary delta is smaller than PTCH COPY, and uses
COPY otherwise. Deletions are delete markers. It publishes only on finish;
abort discards the temporary output. Finish and abort consume the handle even
when they report an error; the pointer must not be reused. Patch creation
does not add or rename members. Public patch creation currently requires an
ordinary filesystem MPQ base; this restriction does not apply to private patch
view composition, which accepts authenticated MPQE sources.
The BSD0 splice candidate uses the existing libmpq decoder's control tuples:
literal extra-block copies for unchanged prefix and suffix bytes, and base-byte
differences plus optional inserted literals for the changed middle. Every BSD0
candidate is decoded and compared with the target before size-based selection.
This guarantees compatibility with libmpq's reader, not generic bsdiff or
external StormLib compatibility. Testing against independently generated
StormLib patches remains a private validation step.
Existing base members are read with their plaintext names, so encrypted
members can supply their filename-derived keys.

The patch writer emits a generated `(listfile)` and `(attributes)` with
PATCH_BIT=true only for patch-file replacements, not delete markers. It does
not emit a Blizzard `(patch_metadata)` marker; the private patch reader
identifies these archives from patch-file and delete-marker flags.
Game-specific Blizzard patch-prefix autodetection heuristics are deliberately
outside the game-neutral core.
Patch-file block sizes describe the resulting logical file, while the patch
prefix describes the PTCH data size. The reader validates the fixed patch
prefix against the stored member extent before using its declared body size;
optional prefix extensions do not require a separate allocation. The
attributes MD5 records the resulting file; CRC32 covers the plaintext patch
prefix and decoded PTCH body. FILETIME is
omitted, allowing the patched view to retain the base member's timestamp.
PATCH_BIT marks stored patch entries; materialized ordinary members retain
their lower-layer bit instead of inheriting the patch artifact's marker.
Ordinary archive creation still rejects true PATCH_BIT values. The
patch-writer tests generate temporary archives and apply them through the
private patch view; no repository fixture needs to change. Patch creation can
use the existing archive signer but does not write embedded patch containers.
The public patch API supports replacement and removal, but not addition or
rename.

### Private patch views

The private `mpq-patch-reader` layer composes filesystem-backed ordinary MPQ
and authenticated MPQE sources for both base and ordered patch layers. Each
MPQE source requires its own explicit authentication code. It materializes a
temporary read-only archive view; later layers override earlier ones, delete
markers hide lower-layer names, and `PTCH` COPY or BSD0 payloads are checked
against their before/after MD5 values. Existing archive and logical stream
read APIs operate on the resulting private view.
No public patch-composition API is exposed yet.

Patch matching primarily uses each entry's MPQ hash identity, including locale
and platform. `(listfile)` is optional metadata that enriches entries with
plaintext names. An unnamed patch entry can replace an existing hash identity
when its payload can be decoded without a name-derived key. A new patch-only
member requires a recoverable plaintext name so its hash-table probe position
can be computed. Otherwise that entry is rejected rather than
silently omitted. Unnamed base members and their packed data remain intact.
MPQE inputs use the existing source decoder before patch composition; their
credentials are independent and are not retained by the view. A `.w3x` input is treated only as an MPQ
container; its prefix and unrelated trailing bytes are retained while a
stale external strong-signature trailer is removed after a content change.
This layer does not perform HM3W map-header hashing.
Each patch layer may supply an independent namespace prefix. Physical names
such as `Base\\Foo` are read from the patch using their original names, while
the prefix-stripped logical name `Foo` identifies the lower-layer member and
the materialized result. A single `(patch_metadata)` path in `(listfile)`
deterministically discovers the prefix; conflicting paths are rejected.
An explicit private prefix takes precedence, but must agree with discovered
metadata. Unnamed entries requiring prefix removal are rejected because their
logical identity cannot be recovered. Game-specific prefix discovery
heuristics are deliberately outside the game-neutral core.
The view retains usable `(listfile)` names, merges known patch-only names, and
maps available `(attributes)` rows to resulting file entries by MPQ hash
identity. Existing PATCH_BIT values, including true values from input
metadata, remain readable; the patch view does not create new true values.
A content change invalidates the base archive's signatures, so the temporary
view omits stale weak and strong signatures. Patch-view composition remains
private.

### Game-neutral authentication and namespace policy

libmpq does not embed product-specific Blizzard MPQE keys. Callers provide
authentication material explicitly for each MPQE source or output; the existing
decoder and writer derive the working key without retaining caller-owned data.
The library also avoids StormLib-specific known-key or key-selection modes and
WoW/SC2/game-installation-specific patch-prefix heuristics. It uses
deterministic format-derived names, such as a recoverable `(patch_metadata)`
path, or an explicit private per-layer prefix instead of game-specific
assumptions. This keeps the core game-neutral, avoids embedding proprietary or
product-specific secrets and semantics, and reduces legal/distribution risk.

libmpq does not embed or distribute Blizzard- or product-specific signature
key material, including public verification keys or private signing keys. All
signature keys are supplied explicitly by the caller. This leaves trust
decisions with applications, avoids maintaining a product-specific key database,
and reduces legal/distribution risk from bundling product-specific material.

### Developer benchmarks

The ten module-specific benchmarks are non-installed developer tools:

- `bench-reader` measures single-file and many-file archive open, name lookup,
  and full-file extraction for stored, zlib, and encrypted workloads.
- `bench-source` compares file-backed and custom-memory-I/O open, extraction,
  focused stream reads, callback granularity, and authenticated MPQE access.
- `bench-stream` measures stream open, sequential and incremental reads, and
  forward, backward, and random seeks on stored, compressed, and encrypted
  members.
- `bench-writer` measures ordinary archive creation, one-shot and streaming
  member writes, many-small-file insertion, and archive finalization.
- `bench-mpqe` measures MPQE encoding, authenticated open, and transport reads
  alongside equivalent ordinary-MPQ diagnostic cases.
- `bench-verify` measures sector Adler-32, CRC32/MD5 `(attributes)`, automatic
  extraction checks, and explicit file verification.
- `bench-signature` measures weak, strong, and combined archive signature
  verification.
- `bench-patch-reader` measures patch-view materialization for COPY, BSD0, and
  mixed chains.
- `bench-patch-writer` measures patch staging and COPY/BSD0 transform selection.
- `bench-update` measures transactional update begin, operation, and commit for
  ordinary MPQ, embedded HM3W-style, and authenticated MPQE archives.

In a disposable build tree, build them together with `make -C tests benchmarks`
and run their default cases with `make -C tests run-benchmarks`. Individual
build targets are `make -C tests bench-reader`, `make -C tests bench-source`,
`make -C tests bench-stream`,
`make -C tests bench-writer`, `make -C tests bench-mpqe`,
`make -C tests bench-verify`, `make -C tests bench-signature`,
`make -C tests bench-patch-reader`, `make -C tests bench-patch-writer`, and
`make -C tests bench-update`. Run an individual tool from `tests` as
`./bench-reader [runs]`, `./bench-source [runs]`, `./bench-stream [runs]`,
`./bench-writer [runs]`,
`./bench-mpqe [runs]`, `./bench-verify [runs]`,
`./bench-signature [runs]`,
`./bench-patch-reader [runs]`,
`./bench-patch-writer [runs]`, or `./bench-update [runs]`.

The optional `runs` argument defaults to three; each tool reports the best
monotonic elapsed time for deterministic 64 KiB, 1 MiB, and 16 MiB cases.
Fixture creation and result verification are outside timed regions where
practical. These benchmarks are not part of `make check`. Compare before and
after results on the same machine and build configuration; the timings are not
portable performance guarantees.

## SDK integration and binding development

### Native C SDK packages

Prebuilt SDKs provide public headers, a shared library, development metadata,
licenses, and documentation. Choose the package matching your platform and
compiler; see the [release package summary](RELEASING.md#release-package-summary) for the
complete download list.

#### Linux

Linux SDKs are available as individual relocatable x86_64 and aarch64 release
archives, built and tested on native runners:

* `libmpq-X.Y.Z-linux-glibc-x86_64.tar.gz` for glibc 2.17 and later.
* `libmpq-X.Y.Z-linux-glibc-aarch64.tar.gz` for glibc 2.17 and later.
* `libmpq-X.Y.Z-linux-musl-x86_64.tar.gz` for musl 1.2 and later.
* `libmpq-X.Y.Z-linux-musl-aarch64.tar.gz` for musl 1.2 and later.

The SDKs use the host's zlib, bzip2, and liblzma shared libraries; those
runtime and development dependencies are not bundled. The glibc baseline
applies to libmpq itself. Each archive extracts a single package directory
containing the executable helper, public headers, shared library, pkg-config
metadata, manual pages, licenses, README, and BUILDINFO.

For example, after extracting the glibc SDK, set:

```sh
export LIBMPQ_ROOT="$PWD/libmpq-X.Y.Z-linux-glibc-x86_64"
export PATH="${LIBMPQ_ROOT}/bin:${PATH}"
export PKG_CONFIG_PATH="${LIBMPQ_ROOT}/lib/pkgconfig"
export LD_LIBRARY_PATH="${LIBMPQ_ROOT}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export MANPATH="${LIBMPQ_ROOT}/share/man${MANPATH:+:${MANPATH}}"

pkg-config --cflags --libs libmpq
libmpq-config --prefix="${LIBMPQ_ROOT}" --cflags
libmpq-config --prefix="${LIBMPQ_ROOT}" --libs
man 1 libmpq-config
man 3 libmpq
```

For the musl SDK, use `libmpq-X.Y.Z-linux-musl-x86_64` as
`LIBMPQ_ROOT` instead. On aarch64, select the corresponding directory ending
in `-aarch64` for either libc.

#### macOS

macOS SDKs are available as individual relocatable archives for Apple silicon
and Intel systems:

* `libmpq-X.Y.Z-macos-arm64.tar.gz`
* `libmpq-X.Y.Z-macos-x86_64.tar.gz`

Each package contains `bin/libmpq-config`, `include/libmpq/mpq.h`, a versioned
`lib/libmpq.*.dylib` with a `libmpq.dylib` symlink, `lib/pkgconfig/libmpq.pc`,
manual pages, licenses, and project documentation. The dylib uses an `@rpath`
install name and the package metadata derives paths relative to the extracted
SDK. Select the archive that matches the native architecture; packages are not
Universal 2 binaries.

Set `LIBMPQ_ROOT` to the extracted `libmpq-X.Y.Z-macos-arm64` or
`libmpq-X.Y.Z-macos-x86_64` directory, matching the selected package.

The SDK depends on macOS-provided zlib, bzip2, and liblzma. Add its `bin/`
directory to `PATH` to locate `libmpq-config`, then pass the extracted SDK
root explicitly: `libmpq-config --prefix="${LIBMPQ_ROOT}" --cflags` and
`libmpq-config --prefix="${LIBMPQ_ROOT}" --libs`. Add `lib/pkgconfig/` to
`PKG_CONFIG_PATH` for compiler and linker flags. Consumers should add an
application-appropriate runtime rpath for the SDK's `lib/` directory when
linking, for example `-Wl,-rpath,"${LIBMPQ_ROOT}/lib"`.

#### Windows MSVC

Extract `libmpq-X.Y.Z-windows-msvc-x64.zip` for x64 or
`libmpq-X.Y.Z-windows-msvc-arm64.zip` for ARM64. Both are built and tested
on native Windows runners. The SDK contains
`bin/libmpq.dll`, the `lib/libmpq.lib` import library, and the public header
`include/libmpq/mpq.h`. Required non-system runtime DLLs are bundled under
`bin/`, together with `libmpq.pdb` when available.

Add the SDK's `include/` directory to your compiler's include search path and
link against `lib/libmpq.lib`. Put the SDK's `bin/` directory on `PATH` when
running applications. No libmpq-specific consumer preprocessor define is
required.

#### Windows MinGW-w64

Extract `libmpq-X.Y.Z-windows-mingw-x86_64.zip` for MINGW64 x86_64 or
`libmpq-X.Y.Z-windows-mingw-aarch64.zip` for native Windows ARM64 using
MSYS2 CLANGARM64. The SDK contains
`bin/libmpq*.dll`, the `lib/libmpq.dll.a` import library, and the public header
`include/libmpq/mpq.h`. Required non-system runtime DLLs are bundled under
`bin/`. No libmpq-specific consumer preprocessor define is required.

Add `lib/pkgconfig/` to `PKG_CONFIG_PATH` and use
`pkg-config --cflags --libs libmpq` for compiler and linker flags. The SDK also
provides `bin/libmpq-config` for use from a shell such as MSYS2 Bash. Put the
SDK's `bin/` directory on `PATH` when running applications.

### Binding development

The source tree contains bindings for the public C API. Each binding has its
own package metadata and tests. Release packaging and registry publication are
covered in [RELEASING.md](RELEASING.md).

Python exposes `Writer.sign(private_key, signature_type=SIGNATURE_WEAK)`, `Archive.signatures()`, and
`Archive.verify(public_key)`. D and Java expose equivalent `Archive.sign`,
`signatures`, and `verify` methods taking raw key byte arrays. All wrappers
preserve mismatch bits and raise their normal exceptions for native errors.

#### Python

The Python binding is a Python 3.11+ `ctypes` package. Its implementation is
in `bindings/python/mpq.py`, package metadata is in
`bindings/python/pyproject.toml`, and tests are in `bindings/python/tests`.
Autotools does not detect or install the Python package; use the PEP 517
backend and pip/PyPI instead.

For development from a source checkout, build the native library and run the
tests with an explicit native-library override:

```sh
sh autogen.sh
./configure
make
LIBMPQ_LIBRARY="$PWD/src/.libs/libmpq.so" \
    python -m pytest bindings/python/tests
```

See [`bindings/python/README.md`](bindings/python/README.md) for API examples,
package installation, native-library behavior, and test instructions.

#### D

The D binding is a DUB package named `libmpq`. The manifest is
[`dub.sdl`](dub.sdl), and the modules are under `bindings/d/source/libmpq`.
Import the high-level API with:

```d
import libmpq.mpq;
```

Autotools includes the D sources in source distributions but does not install
them. DUB/code.dlang.org owns D package installation. From a checkout, build
the native library and run the tests with DMD or LDC:

```sh
sh autogen.sh
./configure
make
LIBRARY_PATH="$PWD/src/.libs" LD_LIBRARY_PATH="$PWD/src/.libs" \
    dub run --config=tests --compiler=dmd
LIBRARY_PATH="$PWD/src/.libs" LD_LIBRARY_PATH="$PWD/src/.libs" \
    dub run --config=tests --compiler=ldc2
```

See [`bindings/d/README.md`](bindings/d/README.md) for DUB usage, compiler
requirements, binary package details, and examples.

#### Java

The Java binding is a Maven project under `bindings/java` and requires JDK 22
or newer. It uses the Java Foreign Function and Memory API and exposes both
the low-level `org.libmpq.ffi.LibmpqNative` mapping and higher-level
`AutoCloseable` classes such as `Archive` and `MpqFileWriter`.

The Java JAR is platform-independent and does not contain `libmpq.so`. Supply
the native library explicitly:

```sh
mvn -B -f bindings/java/pom.xml test \
    -Dorg.libmpq.library="$PWD/src/.libs/libmpq.so" \
    -Dlibmpq.sourceDir="$PWD"
```

The binding also supports the normal system loader path:

```sh
LD_LIBRARY_PATH="$PWD/src/.libs" \
    mvn -B -f bindings/java/pom.xml test \
    -Dorg.libmpq.test.loaderPath=true \
    -Dlibmpq.sourceDir="$PWD"
```

See [`bindings/java/README.md`](bindings/java/README.md) and
[`bindings/java/pom.xml`](bindings/java/pom.xml) for Maven configuration,
project metadata, and API information.
