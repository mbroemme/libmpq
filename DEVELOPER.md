# libmpq developer guide

This guide covers native API usage, SDK integration, and binding development.
See [README.md](README.md) for requirements, building, and limitations,
[MPQ.md](MPQ.md) for the archive-format reference, and
[RELEASING.md](RELEASING.md) for release packaging, validation, and
publication.

## Getting started

### Native API example

The public header is installed as `libmpq/mpq.h`. The following example opens
an archive, reads file number zero into memory, and reports library errors.
Empty archives have no file zero. Encrypted members requiring a
filename-derived key should instead be opened by name; see the
[streaming example](#logical-member-streams) below.

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
    libmpq__off_t transferred = 0;
    uint8_t *file_data = NULL;
    int32_t result;
    int32_t close_result;

    if (argc != 2) {
        fprintf(stderr, "usage: %s ARCHIVE\n", argv[0]);
        return EXIT_FAILURE;
    }

    result = libmpq__archive_open(&archive, argv[1], -1);
    if (result < 0)
        goto done;
    result = libmpq__file_size_unpacked(archive, 0, &file_size);
    if (result < 0)
        goto done;
    if (file_size < 0 || (uint64_t)file_size > SIZE_MAX) {
        result = LIBMPQ_ERROR_SIZE;
        goto done;
    }

    /* Keep a valid buffer even for an empty member. */
    file_data = malloc(file_size == 0 ? 1 : (size_t)file_size);
    if (file_data == NULL) {
        result = LIBMPQ_ERROR_MALLOC;
        goto done;
    }
    result = libmpq__file_read(archive, 0, file_data, file_size, &transferred);
    if (result == 0 && transferred != file_size)
        result = LIBMPQ_ERROR_READ;

done:
    free(file_data);
    if (archive != NULL) {
        close_result = libmpq__archive_close(archive);
        if (result == 0)
            result = close_result;
    }
    if (result < 0)
        fprintf(stderr, "libmpq: %s\n", libmpq__strerror(result));
    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
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

## Reading and writing archives

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

Include `<string.h>` for `memcpy()`; this callback requires a valid
`memory_source_s` context and backing storage for nonempty reads.

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

    if (source == NULL || (buffer == NULL && size != 0) ||
        (source->data == NULL && size != 0) ||
        offset < 0 || (uint64_t)offset > source->size ||
        size > source->size - (size_t)offset)
        return LIBMPQ_ERROR_READ;
    if (size != 0)
        memcpy(buffer, source->data + (size_t)offset, size);
    return 0;
}
```

### Logical member streams

`libmpq__stream_open()` and `libmpq__stream_open_name()` provide incremental
logical-member reads and seeks without a complete file buffer. An archive
source is the backing MPQ or MPQE byte source; a logical member stream is a
decoded logical archive member. The handle owns a private archive clone, so
the source archive may close after opening the stream. For custom I/O, the
caller must retain its callback context until every derived logical member
stream is closed. Ordinary sectorized members retain one decoded sector; a
single-unit member can require its complete logical unit.

```c
mpq_stream_s *stream = NULL;
uint8_t buffer[4096];
libmpq__off_t transferred;
int32_t status;

if (libmpq__stream_open_name(archive, "data/file.bin", &stream) == 0) {
    while ((status = libmpq__stream_read(stream, buffer, sizeof(buffer),
                                        &transferred)) == 0 &&
           transferred != 0) {
        /* Consume buffer[0..transferred). */
    }
    if (status < 0)
        fprintf(stderr, "stream_read: %s\n", libmpq__strerror(status));
    status = libmpq__stream_close(stream);
    if (status < 0)
        fprintf(stderr, "stream_close: %s\n", libmpq__strerror(status));
}
```

Reads at EOF succeed with zero transferred bytes. Seek accepts
`LIBMPQ_SEEK_SET`, `LIBMPQ_SEEK_CUR`, and `LIBMPQ_SEEK_END` only. Incremental
reads verify usable sector Adler-32 values when their sectors load, but do not
implicitly verify whole-file CRC32/MD5 attributes; use `libmpq__file_verify()`
when that verification is required.

### Streaming and one-shot writers

The existing public creation APIs accept `LIBMPQ_ARCHIVE_VERSION_THREE` (2).
The default remains v1, 1024 entries, and 4096-byte sectors; explicit capacity,
sector size, compression policy, listfile, attributes, timestamps, and signing
options retain their meanings. MPQE creation uses the same v3 writer and
unchanged authentication/wrapping. MPQ v4 remains unsupported.

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

## Advanced API workflows

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

These are host-endian API structures, not disk layouts. Creation options occupy
20 bytes: `version`, `max_files`, `sector_size`, `flags` and `attributes` begin
at offsets 0, 4, 8, 12 and 16. The 40-byte per-file attributes result places
`flags`, `crc32`, `filetime`, `md5` and `patch_bit` at offsets 0, 4, 8, 16 and 32;
the four reserved bytes at offset 36 are always zero.

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

Use `libmpq__block_verify()` to verify one sector and retrieve its stored Adler-32:
`libmpq__block_verify(archive, file_number, block_number, &checksum, &mismatches)`.
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

To sign, call `libmpq__archive_sign` on a v1, v2 or v3 writer with the
corresponding private key before close. Weak signing reserves one file
slot for `(signature)`; strong signing appends an external `NGIS` trailer
after finalization.

The weak 128-byte raw key is two 64-byte unsigned big-endian integers: a
modulus followed by a zero-padded exponent value. Use a public key to verify a
signature and a private key to create one. There are no built-in keys. See
[MPQ.md](MPQ.md) for storage, hashing, error, and key-format details. Weak
signatures use obsolete MD5/RSA-512 and must not be used for modern trust
decisions. Strong public and private keys contain a 256-byte unsigned
big-endian modulus and a 256-byte zero-padded unsigned big-endian exponent
(512 bytes total). The writer accepts the private exponent and emits only the
plain SHA-1 range variant. External strong trailers are not defined for MPQE,
so strong signing is rejected there.

For files beginning with `HM3W`, weak and strong hashing
starts at physical offset zero; weak hashing still excludes `(signature)`.

### Transactional modification

Use a separate `mpq_update_s` handle to stage changes to an existing,
filesystem-backed MPQ. Each operation rebuilds the private working copy; the
original path changes only on commit. For example:

`libmpq__update_add_data()` and `libmpq__update_add_path()`
require an absent staged filename. They support remove-then-add;
replacement remains strictly replacement-only. MPQ v3 filename
and metadata requirements are described in [MPQ.md](MPQ.md).

```c
mpq_update_s *update = NULL;
const uint8_t replacement[] = "new contents";

int32_t status = libmpq__update_begin(&update, "data.mpq");

if (status == 0) {
    status = libmpq__update_replace_data(update, "data/file.bin", replacement,
                                        sizeof(replacement) - 1, NULL);
    if (status == 0)
        status = libmpq__update_commit(update);
    else
        (void)libmpq__update_abort(update);
    update = NULL; /* Commit and abort consume the handle, including on error. */
}
/* Report status using libmpq__strerror() when negative. */
```

Legacy embedded HM3W-style containers use the same scanner and update operations,
regardless of `.w3x` or `.w3m` extension. Rebuilding retains the prefix and
unrelated trailing bytes; stale weak and external strong signatures are
removed. For an MPQE archive, use `libmpq__update_begin_mpqe()` with an explicit
authentication code. It decodes into a private same-directory working MPQ;
ordinary update operations apply unchanged. Commit re-encrypts and validates
an encrypted sibling before atomic publication. No-op commit leaves the MPQE
container byte-identical. Only the first 32 authentication bytes needed for
the existing MPQE key derivation are copied into private state, then cleared
on every consuming path. A crash may leave owner-only plaintext staging data.

`libmpq__update_replace_path()` reads replacement data from a filesystem path.
`libmpq__update_remove()` and `libmpq__update_rename()` affect existing named
entries only; rename rejects an existing destination name. Replacement accepts
the same optional `mpq_file_options_s` as `libmpq__archive_add_data()` and
`libmpq__archive_add_path()`, including separate `compression_first` and
`compression_next` masks. A NULL options pointer uses default storage options.
When options are supplied, their `locale` and `platform` must match the
existing member; replacement cannot move a member to a different hash
identity. When multiple names share one physical block, removing or renaming
an unencrypted name leaves the other names intact. Replacing that block, or
renaming it when encrypted, returns `LIBMPQ_ERROR_FORMAT` until block
splitting is supported. Modification also rejects shared `(listfile)`,
`(attributes)`, or `(signature)` blocks when those internal entries must be
rewritten or removed. Commit and abort both consume the update handle,
including on error. Commit rechecks the destination's filesystem identity
immediately before atomic replacement, but this is best effort and does not
lock out a concurrent change between check and publication.

Legacy v1/v2 updates retain unchanged packed entries even without `(listfile)`
names, and preserve embedded prefixes and unrelated trailing bytes. Their
rebuilt archive extent must fit the legacy 32-bit size field. V3 uses a named
rebuild instead, with the requirements below.

V3 operations resolve every live public file number to an actual filename from
`(listfile)`, the operation's source name, internal-file names, or names learned
by earlier successful operations in the same transaction. Hash values are not
filenames. Incomplete coverage returns FORMAT without changing the previous
staged archive. Begin/abort and unchanged commits do not require reconstruction.
Repeated identical names and ASCII case or slash/backslash variants are one
normalized name. Distinct complete names resolving to the same logical entry
(including names indistinguishable after HET's hash-prefix limit) are ambiguous
and return FORMAT. Empty CRLF/LF lines are ignored; embedded null bytes,
unresolvable listed names and incomplete coverage reject reconstruction.
Known source/listfile spellings take precedence over equivalent caller spellings;
replacement retains that name so classic hashes do not change merely because
the caller uses a different slash direction or ASCII case.
Complete mixed and HET/BET-only sources are supported. A BET-only row with
classic attributes, unresolved classic aliases/locale variants, embedded v3
wrappers, unrelated trailing data, and patch/delete members are rejected.
Extra header extensions, nonzero reserved BET record values and retained
payload positions that overlap the new full header are also unsupported.
Legacy embedded updates and patch handling remain unchanged. Public file
numbers may change after a rebuild.

Untouched packed members retain their original positions, exact codec bytes,
flags and encryption keys, including FIX_KEY. Tables are regenerated by the
normal writer from the final rows: classic row N and BET row N agree. Encrypted
rename decodes and rewrites with the new name/key at the final position,
preserving FIX_KEY and timestamps. As with legacy updates, rewritten
multi-compression rename data uses zlib; replacement uses caller options or
native defaults. Untouched CRC32/MD5/FILETIME metadata uses explicit classic
provenance, not canonical indices; new/replaced attributes are regenerated.
Replacement resets FILETIME to the writer default of zero; rename retains it.

Legacy per-member staging encodes FIX_KEY at the final archive-relative copy
position: the plaintext rebuild stream position minus the source archive start.
The standalone staging archive starts at zero. For compact inputs, its reserved
classic tables are moved after the payload so finalization cannot overwrite it.
MPQE transactions use the same plaintext coordinates and re-encrypt the container
only at publication; the MPQE cipher position is not a member-key input.
When reading a patch payload past its plaintext prefix, FIX_KEY still uses the
original member start and reconstructed size, not the shifted payload view.

Modified weak signatures and strong trailers are removed, following existing
update policy. They are never presented as valid after a rebuild. MPQE uses
the existing authenticated staging and atomic rewrapping path. Rebuild or
publication failure preserves the original destination. Failures before staged
ownership transfer preserve the previous stage. If closing the previous staged
stream fails after validation, the stream is consumed and cleared: further
mutations/commit cannot publish it, and abort safely removes tracked temporary
files. Flush failures leave the previous stage available. Close callbacks follow
`fclose` ownership semantics even on failure. No in-place modification or
separate v3 transaction engine is used.

A no-op transaction preserves original bytes and signatures. Ordinary updates
do not create true PATCH_BIT values; the dedicated patch writer does.

### Patch archive creation

The public patch handle creates a new MPQ v1/v2/v3 patch artifact without modifying
the base archive:

```c
mpq_patch_s *patch = NULL;

int32_t status = libmpq__patch_begin(&patch, "base.mpq", "changes.mpq");

if (status == 0) {
    status = libmpq__patch_replace_data(patch, "file.txt", data, data_size, NULL);
    if (status == 0)
        status = libmpq__patch_remove(patch, "obsolete.txt");
    if (status == 0)
        status = libmpq__patch_sign(patch, LIBMPQ_SIGNATURE_WEAK, private_key, key_size);
    if (status == 0)
        status = libmpq__patch_finish(patch);
    else
        (void)libmpq__patch_abort(patch);
    patch = NULL; /* Finish and abort consume the handle, including on error. */
}
/* Report status using libmpq__strerror() when negative. */
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

The private `mpq-patch-writer` module stages a same-directory temporary
archive. It writes named replacements as PTCH BSD0 members when a
deterministic binary delta is smaller than PTCH COPY, and uses COPY otherwise.
Deletions are delete markers. It publishes only on finish; abort discards the
temporary output. Finish and abort consume the handle even when they report an
error; the pointer must not be reused. Patch creation does not add or rename
members. Public patch creation currently requires an ordinary filesystem MPQ
base; this restriction does not apply to private patch view composition, which
accepts authenticated MPQE sources. PTCH COPY/BSD0 encoding and validation are
described in [MPQ.md](MPQ.md#patch-archives-and-ptchbsd0). Existing base
members are read with their plaintext names, so encrypted members can supply
their filename-derived keys.

The patch writer emits a generated `(listfile)` and `(attributes)` with
PATCH_BIT=true only for patch-file replacements, not delete markers. It does
not emit a Blizzard `(patch_metadata)` marker; the private patch reader
identifies these archives from patch-file and delete-marker flags.
Game-specific Blizzard patch-prefix autodetection heuristics are deliberately
outside the game-neutral core. Patch artifacts record target MD5 and plaintext
patch CRC32; FILETIME is omitted so materialization can retain base
timestamps. PATCH_BIT marks patch entries, not delete markers. Materialized
members keep lower-layer PATCH_BIT metadata rather than inheriting the
artifact's marker. Ordinary creation rejects true PATCH_BIT values. The
patch-writer tests generate temporary archives and apply them through the
private patch view. Checked-in synthetic patch fixtures provide complementary
regression coverage; their inventory and regeneration recipes are documented
in [tests/fixtures/README.md](tests/fixtures/README.md). Patch creation can
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
read APIs operate on the resulting private view. No public patch-composition
API is exposed yet.

Patch matching primarily uses each entry's MPQ hash identity, including locale
and platform. `(listfile)` is optional metadata that enriches entries with
plaintext names. For legacy v1/v2 materialization, an unnamed patch entry can
replace an existing hash identity when its payload can be decoded without a
name-derived key. A new patch-only member requires a recoverable plaintext
name so its hash-table probe position can be computed. Otherwise that entry is
rejected rather than silently omitted. Unnamed legacy base members and their
packed data remain intact. V3 materialization requires complete, unambiguous
names for every retained member and rejects missing coverage, aliases/locales
or reserved metadata it cannot represent. Its intermediates remain v3 and
regenerate HET/BET plus classic tables through the existing writer; modified
encrypted members use their final output offsets. MPQE inputs use the existing
source decoder before patch composition; their credentials are independent and
are not retained by the view. A `.w3x` input is treated only as an MPQ
container; legacy materialization retains its prefix and unrelated trailing
bytes while a stale external strong-signature trailer is removed after a
content change. Rebuilt v3 views are standalone and do not retain container
prefixes/suffixes. This layer does not perform HM3W map-header hashing. Each
patch layer may supply an independent namespace prefix. Physical names such as
`Base\\Foo` are read from the patch using their original names, while the
prefix-stripped logical name `Foo` identifies the lower-layer member and the
materialized result. A single `(patch_metadata)` path in `(listfile)`
deterministically discovers the prefix; conflicting paths are rejected. An
explicit private prefix takes precedence, but must agree with discovered
metadata. Unnamed entries requiring prefix removal are rejected because their
logical identity cannot be recovered. Game-specific prefix discovery
heuristics are deliberately outside the game-neutral core. The view retains
usable `(listfile)` names, merges known patch-only names, and maps available
`(attributes)` rows to resulting file entries by MPQ hash identity. Existing
PATCH_BIT values, including true values from input metadata, remain readable;
the patch view does not create new true values. A content change invalidates
the base archive's signatures, so the temporary view omits stale weak and
strong signatures. Patch-view composition remains private. Opening failure is
terminal and returns no partially usable view; consumed handles are never
closed twice. Temporary-file deletion is best effort when the filesystem
refuses removal. Source archives remain unchanged.

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

## Development, testing and benchmarks

Build and test in a disposable checkout or build environment. See
[README.md](README.md) for native build requirements and
[tests/fixtures/README.md](tests/fixtures/README.md) for synthetic fixture
inventory and regeneration. Fuzzing instructions and input contracts are in
[fuzz/README.md](fuzz/README.md).

### Transaction failure coverage

Private fault hooks cover staged flush/close and final publication, including
the handoff after rebuild validation. Writer/source I/O still uses the existing
error paths, not per-write transaction callbacks. Tests cover malformed
reconstruction, failed path input and the injectable handoff/publication
boundaries; they do not simulate every filesystem failure. Temporary cleanup
is attempted on handled failures and is not a crash-recovery guarantee.

### Manual interoperability checks

For manual/local testing only, use a legally obtained real v3 archive, such as
a historical World of Warcraft Cataclysm Beta MPQ. Keep it and all extracted
data outside the repository and CI. Inspect its header with a hex viewer using
the [header layouts in MPQ.md](MPQ.md#header-versions), accounting for any
embedded archive prefix. Use separate applications or locally maintained
callers of each library's public API to inspect the same archive and member
names. For manual extraction, use separate temporary output directories
outside the repository and compare lengths and `sha256sum` results. Include
both flat and directory member names, especially encrypted and FIX_KEY
members. Check missing-member errors, wrong MPQE authentication and truncated
local copies without modifying the original archive. These checks remain
manual; no real Blizzard archive validation is implied by the synthetic suite.
Patch members require a matching base to compare the applied result; decoded
PTCH payload access is not patch application. Do not copy Blizzard archive
bytes, trimmed archives, extracted payloads, or derived binary fixtures into
the repository. Repository and CI fixtures must be synthetic only. Successful
synthetic tests are not a claim that every historical protected/defragmented
archive is supported.

### Developer benchmarks

The eleven module-specific benchmarks are non-installed developer tools:

- `bench-compression` times production compression/decompression dispatch for
  representative codecs and compressible, structured, and incompressible data.
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

From a disposable build tree, build and run all benchmarks with:

```sh
make -C tests benchmarks
make -C tests run-benchmarks
```

To build and run one benchmark, use any name from the list above. For example:

```sh
make -C tests bench-compression
./tests/bench-compression 3
```

The optional `runs` argument defaults to three; each tool reports the best
monotonic elapsed time for deterministic cases. Compression cases use 64 KiB,
1 MiB, and 16 MiB where practical; slower legacy codecs stay at 64 KiB.
Fixture creation and result verification are outside timed regions where
practical. These benchmarks are not part of `make check`. Compare before and
after results on the same machine and build configuration; the timings are not
portable performance guarantees.

## SDK integration and language bindings

### Native C SDK packages

Prebuilt SDKs provide public headers, a shared library, development metadata,
licenses, and documentation. Choose the package matching your platform and
compiler; see the
[release package summary](RELEASING.md#release-package-summary) for the
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
`libmpq-X.Y.Z-windows-msvc-arm64.zip` for ARM64. Both are built and tested on
native Windows runners. The SDK contains `bin/libmpq.dll`, the
`lib/libmpq.lib` import library, and the public header `include/libmpq/mpq.h`.
Required non-system runtime DLLs are bundled under `bin/`, together with
`libmpq.pdb` when available.

Add the SDK's `include/` directory to your compiler's include search path and
link against `lib/libmpq.lib`. Put the SDK's `bin/` directory on `PATH` when
running applications. No libmpq-specific consumer preprocessor define is
required.

#### Windows MinGW-w64

Extract `libmpq-X.Y.Z-windows-mingw-x86_64.zip` for MINGW64 x86_64 or
`libmpq-X.Y.Z-windows-mingw-aarch64.zip` for native Windows ARM64 using MSYS2
CLANGARM64. The SDK contains `bin/libmpq*.dll`, the `lib/libmpq.dll.a` import
library, and the public header `include/libmpq/mpq.h`. Required non-system
runtime DLLs are bundled under `bin/`. No libmpq-specific consumer
preprocessor define is required.

Add `lib/pkgconfig/` to `PKG_CONFIG_PATH` and use
`pkg-config --cflags --libs libmpq` for compiler and linker flags. The SDK
also provides `bin/libmpq-config` for use from a shell such as MSYS2 Bash. Put
the SDK's `bin/` directory on `PATH` when running applications.

### Binding development

The in-tree Python, Java and D bindings are maintained and released alongside
the corresponding libmpq version. Each binding has its own package metadata,
tests and API documentation. Release packaging and registry publication are
covered in [RELEASING.md](RELEASING.md).

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

See [bindings/python/README.md](bindings/python/README.md) for API examples,
package installation, native-library behavior, and test instructions.

#### D

The D binding is a DUB package named `libmpq`. The manifest is
[dub.sdl](dub.sdl), and the modules are under `bindings/d/source/libmpq`.
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

See [bindings/d/README.md](bindings/d/README.md) for DUB usage, compiler
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

See [bindings/java/README.md](bindings/java/README.md) and
[bindings/java/pom.xml](bindings/java/pom.xml) for Maven configuration,
project metadata, and API information.
