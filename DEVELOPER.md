# libmpq developer guide

This guide covers native API usage, SDK integration, and binding development.
See [README.md](README.md) for requirements, building, and limitations,
[MPQ.md](MPQ.md) for the archive-format reference, and
[RELEASING.md](RELEASING.md) for release packaging, validation, and
publication.

The C API provides separate ordinary filename operations and explicit
`_identity` operations. Ordinary signatures retain their published argument
lists; exact operations take locale/platform values directly, including
neutral `(0,0)`, without fallback. Storage options remain independent and
must match the selected identity on replacement.

Autotools uses Libtool `6:0:2` and retains the published v0.8.1 function ABI
and public layouts. A Linux CMake development build produces an unversioned
`libmpq.so`. See the [build policy](README.md#building) for the versioned
Linux release configuration.

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

libmpq borrows the callback and context, which may be NULL for a stateless
callback. The caller owns the context and backing storage and is responsible
for closing or freeing them. Keep the callback, context and storage valid
until every dependent archive, clone and ordinary member stream has closed.
Independently owned clones and ordinary streams can still use the callback
after the original archive closes. Keep the underlying source bytes stable
and synchronize concurrent use of shared callback contexts.

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

`libmpq__file_identity(archive, name, identity_index, &identity)` retrieves
one live filename identity by zero-based index, returning an operational
status. Repeated calls enumerate identities in ascending original classic
hash-slot order. Probing crosses deleted slots and stops at the first
never-used slot or full wrap. Aliases may share a canonical file number;
locale/platform identities are retained separately. `mpq_file_identity_s` has
a 16-byte natural layout, with a zero reserved field.
`LIBMPQ_IDENTITY_CLASSIC` and `LIBMPQ_IDENTITY_BET` describe stored provenance,
not file-storage flags.
Mixed entries carry both flags when canonically reconciled. HET/BET-only
entries expose one unqualified `(0, 0)` identity with BET provenance.

Use `libmpq__file_number_from_identity()` or
`libmpq__stream_open_name_identity()` for exact selection with explicit
`uint16_t` locale/platform values; `(0,0)` selects the neutral identity.
Ordinary functions retain HET-first/classic first-hit resolution. Exact
selection never falls back.
Variant end and
exact misses return `LIBMPQ_ERROR_EXIST`; contradictory duplicate identities,
inconsistent canonical mappings, reduced extended hashes and HET names beyond
264 bytes return `LIBMPQ_ERROR_FORMAT`. Exact HET-only access requires complete
64-bit normalized HET/56-bit BET hashes and a unique mapping. A name found
only through HET/BET remains unqualified even if its canonical payload has
classic aliases under other names. Exact lookup outputs are cleared on failure.

Exact named streams resolve on their own archive clone and retain the supplied
filename for basename-derived encryption and KEY. Indexed metadata access
alone does not supply an encryption key. Exact named streams follow the
same source lifetime rules as other ordinary streams. These operations are
read-only and do not configure global locale state or mutate identity
locale/platform values.

`libmpq__stream_open()` and `libmpq__stream_open_name()` provide incremental
logical-member reads and seeks without a complete file buffer. An archive
source is the backing MPQ or MPQE byte source; a logical member stream is a
decoded logical archive member. The handle owns a private archive clone, so
the source archive may close after opening the stream. With custom I/O,
that clone still uses the caller-owned callback, context and backing storage.
Ordinary sectorized members retain one decoded sector. A single-unit member
can require its complete logical unit.

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

The public creation APIs accept versions through `LIBMPQ_ARCHIVE_VERSION_FOUR`
(3), including `LIBMPQ_ARCHIVE_VERSION_THREE` (2). The default remains v1,
1024 entries, and 4096-byte sectors; explicit capacity, sector size,
compression policy, listfile, attributes, timestamps, and signing options
retain their meanings. MPQE creation uses the same writer and unchanged
transport encryption. Public v4 creation defaults to 16 KiB (`0x4000`) raw
chunks and generates structural and raw-chunk MD5 digests automatically.
Transactions preserve the source raw-chunk size, including zero.

Use `libmpq__archive_raw_chunk_size_set(archive, size)` or
`libmpq__patch_raw_chunk_size_set(patch, size)` before any member begins,
signing succeeds or finalization starts. Every `uint32_t` value is supported,
including zero, 1, 17 and `UINT32_MAX`; powers of two are not required. Zero
disables member and HET/BET trailing raw arrays, while structural MD5 remains
enabled. Processing uses bounded buffers, not an allocation of chunk size.
Repeated setters before locking are allowed. Failed pre-write validation or
signing does not freeze policy; an accepted member begin does, even if later
aborted or failed. Invalid lifecycle returns `LIBMPQ_ERROR_NOT_INITIALIZED`,
older writable generations return `LIBMPQ_ERROR_FORMAT`, and terminal writer
errors take precedence. Rejected calls preserve the prior size.

`libmpq__archive_raw_chunk_size_get(archive, &size)` queries the configured
or loaded policy on writers/readers. V1/v2/v3 return zero; use archive version to
separate that case from v4 with disabled raw arrays. It neither changes policy
nor verifies checksums. Raw MD5 covers physical stored bytes, not logical
content, and configuration does not provide an update/conversion option. Use
`libmpq__patch_raw_chunk_size_get(patch, &size)` to query a live patch writer,
including after configuration locks. This does not mutate its state. A failed
patch query clears the output and preserves any terminal writer error.

`libmpq__writer_begin()` starts an archive member and returns `mpq_writer_s`.
Use `libmpq__writer_write()`, `libmpq__writer_timestamp()`, and
`libmpq__writer_finish()` on that handle. A failed write leaves the writer
active. Input rejected before encoding can be corrected if the archive has
no latched error. Sector encoding and output failures latch for callback-backed
writers and v4 path-backed writers. Finish consumes the writer even on error.
Archive close consumes both the archive and any remaining writer, returning
the latched error first or SIZE for an unfinished member. Otherwise it
finalizes the archive and can report serialization, output or cleanup errors.
Use `libmpq__archive_add_data()` to add an in-memory source in one call, or
`libmpq__archive_add_path()` to add a filesystem-path source.

SINGLE storage is independent of the archive sector size. A newly oversized
unit buffers its complete declared input, is encoded/encrypted once, and remains
one logical block without a sector-offset or sector-CRC table. The new path is
limited to min(INT32_MAX, UINT32_MAX, SIZE_MAX) by current representation and
one-block reader transfer types, with additional codec and output-extent checks.
Existing inputs fitting a configured sector retain their prior behavior.
Encoding may require several times the input size in memory. There is no fixed
MiB cap or library-managed memory budget. Applications handling untrusted sizes
should apply their own resource limits. Normal allocation failures are reported
where the runtime returns control; this does not guarantee survival of OOM
termination. Existing codec/version restrictions and ADPCM SINGLE rejection,
KEY adjustments, generated listfile defaults and physical patch defaults remain.

The ordinary `test-writer` regression exercises the production library and its
normal private objects. A separate focused `test-writer-alloc` executable runs
portable deterministic allocation faults without repeating the full writer
matrix. Only four private replacement modules (writer, filename, compression
and PKWARE) receive a test-owned forced header through compiler options;
production sources and installed artifacts have no test dependencies or runtime
allocation dispatch. The focused executable uses its own plain API wrapper and
a private static archive of already-built production objects, with ordinary
archive extraction selecting only the unaffected modules. No full core is
recompiled and no linker interception is required.

The same 33 native executables are registered on every platform. C-standard
compile-only checks build all of them; sanitizer and coverage runs execute the
focused fault scenarios too. Output identifies reached allocation sites, and
huge-input tests veto allocations before allocating. Caller ownership, realloc
failure and recovery assertions are retained in the focused driver. Test-only
archives, headers and replacement objects are never installed.

Archive creation accepts only `LIBMPQ_ARCHIVE_CREATE_LISTFILE` and
`LIBMPQ_ARCHIVE_CREATE_COMPRESSION_EXTENDED`. Ordinary member writes accept
`IMPLODE`, `COMPRESS`, `ENCRYPTED`, `KEY`, `SINGLE` and `SECTOR_CRC` from
the public file flag set. An unsupported bit returns `LIBMPQ_ERROR_FORMAT`.
The existing codec and combination rules still apply. `KEY` alone has no
encryption effect, and the writer ignores sector CRC requests for empty,
single-unit or uncompressed storage. Dedicated physical patch APIs handle
patch members and delete markers separately.

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

These are host-endian API structures, not disk layouts. Creation options
occupy 20 bytes: `version`, `max_files`, `sector_size`, `flags` and
`attributes` begin at offsets 0, 4, 8, 12 and 16. The 40-byte per-file
attributes result places `flags`, `crc32`, `filetime`, `md5` and `patch_bit`
at offsets 0, 4, 8, 16 and 32; the four reserved bytes at offset 36 are always
zero.

### Explicit checksum verification and block metadata

Explicitly compare available stored checksums after opening an archive:

```c
uint32_t mismatches = 0;
int32_t status = libmpq__file_verify(archive, file_number,
                                    LIBMPQ_VERIFY_ALL, &mismatches);
/* status < 0: operation failed; otherwise inspect the requested VERIFY_* bits. */
```

`LIBMPQ_VERIFY_ALL` requests sector Adler-32, file CRC32/MD5 and v4 raw-chunk
MD5. The returned mismatch mask uses those same bits and is a subset of the
request. A set bit means an available checksum mismatched; a clear bit means
it matched or was unavailable/skipped. Operational errors leave the mask zero.
Sector checks cover decrypted packed bytes before decompression; absent tables
and unavailable entries are skipped. Use `LIBMPQ_VERIFY_SECTOR_CRC` alone to
verify sectors without requiring `(attributes)`.

Use `LIBMPQ_VERIFY_RAW_MD5` alone to check v4 stored member chunks without
attributes or a filename encryption key. It hashes compressed/encrypted MPQ
bytes after MPQE transport decoding. Older versions, disabled raw chunks and
empty stored members are skipped; zero mismatch bits do not prove
availability. For patch archives this checks the physical member, not a
materialized result. File CRC32/MD5 requests, including `LIBMPQ_VERIFY_ALL`,
still require attributes.

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

To sign, call `libmpq__archive_sign` on a writer with the corresponding
private key before close. Weak-signature creation is unsupported for MPQ v4
output with raw-chunk MD5 enabled. Set raw size to zero before signing to
allow weak signatures on plain or MPQE v4 output. Plain v4 also supports
strong signing; MPQE strong signing remains unsupported. Weak signing reserves one file slot for
`(signature)`; strong signing appends an external `NGIS` trailer after
finalization.

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

`libmpq__update_add_data()` and `libmpq__update_add_path()` require an absent
staged filename. They support remove-then-add; replacement remains strictly
replacement-only. MPQ v3/v4 filename and metadata requirements are described
in [MPQ.md](MPQ.md).

```c
mpq_update_s *update = NULL;
const uint8_t replacement[] = "new contents";

int32_t status = libmpq__update_begin(&update, "data.mpq");

if (status == 0) {
    status = libmpq__update_replace_data(
        update, "data/file.bin", replacement, sizeof(replacement) - 1, NULL
    );
    if (status == 0)
        status = libmpq__update_commit(update);
    else
        (void)libmpq__update_abort(update);
    update = NULL; /* Commit and abort consume the handle, including on error. */
}
/* Report status using libmpq__strerror() when negative. */
```

Legacy embedded HM3W-style containers use the same scanner and update
operations, regardless of `.w3x` or `.w3m` extension. Rebuilding retains the
prefix and unrelated trailing bytes on the ordinary legacy route. Named
reconstruction preserves supported prefixes but rejects unrelated trailers;
stale weak and external strong signatures are removed. For an MPQE archive,
use `libmpq__update_begin_mpqe()` with an explicit authentication code. It
decodes into a private same-directory working MPQ; ordinary update operations
apply unchanged. Commit re-encrypts and validates an encrypted sibling before
atomic publication. No-op commit leaves the MPQE container byte-identical.
Only the first 32 authentication bytes needed for the existing MPQE key
derivation are copied into private state, then cleared on every consuming
path. A crash may leave owner-only plaintext staging data.

MPQ v2 combines a 32-bit block offset with a 16-bit hi-block word. Member
positions are relative to the MPQ header, so an embedded prefix can also
place a low relative offset above 4 GiB in the backing file. The reader
checks v2 payloads against physical source bounds. Creation supports sparse
high member placement on suitable storage and writes the low 32 bits of
the archive extent into the legacy size field. Update begin copies the source
in bounded buffers and can expand sparse holes. Eligibility is checked by
each mutation after staging:

- Ordinary legacy table rewrites return SIZE when the candidate MPQ extent,
  excluding the prefix and suffix, exceeds UINT32_MAX. Named reconstruction
  checks the declared extent against the stage and rejects inconsistent
  geometry or unrelated trailers with FORMAT.
- Both range-replacement functions return SIZE when the required v2 extent
  of the source or candidate exceeds UINT32_MAX. This extent comes from the
  header, tables and stored nonempty payloads. A validated empty batch skips
  candidate reconstruction and its extent checks.
- Both compaction functions use the declared legacy extent for v2 source
  layout and trailer validation. Stored ranges outside that extent can
  return FORMAT even when the reader can access them. Candidate planning
  and writing have independent size and offset checks. Filename hints in
  `libmpq__update_compact_ex()` supply key provenance under the same rules.

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
renaming it when encrypted, returns `LIBMPQ_ERROR_FORMAT` for these
name-based operations. Modification also rejects shared `(listfile)`,
`(attributes)`, or `(signature)` blocks when those internal entries must be
rewritten or removed. Commit and abort both consume the update handle,
including on error. Commit rechecks the destination's filesystem identity
immediately before atomic replacement, but this is best effort and does not
lock out a concurrent change between check and publication.

Add operations take no selector: `mpq_file_options_s.locale` and `.platform`
define the identity to create for an absent filename. Replacement uses the
ordinary or exact lookup to find an existing identity and keeps its tuple;
replacement options must match it and cannot redirect selection. Use
`libmpq__update_change_identity()` to change an existing tuple explicitly.

`libmpq__update_sign(update, type, private_key, size)` signs the current
private stage immediately. Commit remains the only publication step. Supply
raw big-endian `n || d`: 128 bytes for RSA-512/MD5 weak signing or 512 bytes
for RSA-2048/SHA-1 strong signing. The key is borrowed synchronously and is
not retained for commit. Success validates generation and archive structure;
independent verification requires `libmpq__archive_verify()` with a matching
public key, returning both status zero and zero mismatches. Caller-generated
signatures do not establish external trust.

Strong signing copies the complete archive core and replaces its recognized
`NGIS` trailer, preserving any weak signature. Weak signing adds or replaces
`(signature)` and removes a stale strong trailer. Missing weak members use
existing identity-preserving reconstruction; `(listfile)` changes only when
its signature entry is absent, retaining unrelated formatting and supported
storage policy. Existing mapping and metadata restrictions apply. Embedded
prefixes and origins are preserved; HM3W hashes include the prefix. Weak
signing requires v4 raw chunks disabled; MPQE supports eligible weak signing
only. Sign after other mutations, including compaction. Later actual changes
invalidate signatures, while validated no-ops preserve them. Private candidates
need temporary disk space; errors before adoption preserve the valid stage.

`libmpq__update_compact(update)` immediately stages physical compaction through
identity-preserving packed reconstruction. Commit alone publishes it. Call it
last when final layout matters: subsequent mutations can introduce gaps. Live
payloads are placed densely without retaining source holes; shared aliases
still reference one payload. Hash capacity and required metadata/raw storage
remain, so neither a minimum archive size nor a size reduction is promised.

`libmpq__update_compact_ex(update, filenames, filename_count)` uses the same
engine, adding borrowed filename context to transaction-known names and the
internal listfile. NULL/zero and non-NULL/zero input are exactly ordinary
compaction; the array is not dereferenced for zero count. Nonzero input is one
atomic batch: every nonempty spelling must pass strict current-stage identity
resolution. Missing entries fail with EXIST; ambiguous/reduced provenance or
incompatible encrypted aliases fail with FORMAT. Counts, pointer allocations
and merged name capacities are checked before narrowing. Valid names do not
make unsupported layouts eligible or establish plaintext correctness.

All matching locale/platform identities and compatible aliases remain intact.
Hints never add listfile entries or normalize classic slash spellings. After
actual candidate adoption, n.1 provenance retains owned copies of every valid
supplied alias, not merely the canonical row representative. Preparation and
candidate validation precede previous-stage consumption. Semantic/pre-adoption
failure installs no new names; existing abort-only adoption boundaries remain.
A true no-op still validates input but changes no bytes, path, signatures, dirty
state or knowledge. Callers may need to supply the same names again. This is not
a separate registration lifecycle and does not change ordinary clean commits
or the ordinary named-update collector's distinct-alias restrictions.

When removing a weak signature, compaction edits `(listfile)` only if it lists
that signature. Other lines and separators remain unchanged. Changed listfiles
retain supported storage flags and recoverable compression policy; unsupported
policies are rejected. Unchanged listfiles use packed copying, with KEY
ciphertext adjusted only when relocation requires it.

A proven already-compact stage remains byte-identical, including signatures.
Actual reconstruction invalidates signatures, regenerates applicable integrity
metadata and retains the generation, raw-chunk policy and supported attributes.
Opaque non-KEY ciphertext can move unchanged without a filename, which
establishes stored-byte preservation rather than plaintext verification. Moving
KEY data requires a usable basename key when its effective key changes.
Shared encrypted rows require known, key-compatible spellings for every alias.
Discoverable embedded prefixes retain every byte and the original absolute
MPQ-header position. Discovery uses 512-byte probes or one validated user-data
header; its pointer can target an unaligned MPQ. User-data headers, payloads
and padding are retained without interpreting incidental payload signatures.
KEY adjustments remain MPQ-relative and exclude the prefix. Prefix bytes
and supported MPQ relationships are preserved, not arbitrary container validity.
Unsupported identities, shared encryption provenance, contradictory prefix
metadata, unrelated trailers and physical patch/delete members are rejected.
Unaligned MPQs without a discoverable user-data pointer remain unsupported.

Compaction uses the current stage, including earlier identity and timestamp
changes. Semantic rejection preserves that stage; existing operational adoption
failures can leave it abort-only. Budget space for the original, working stage
and full candidate. Embedded assembly also retains a completed zero-origin
MPQ temporary until the prefixed candidate is closed. MPQE publication may
need an encrypted candidate; prefix bytes refer to the decoded logical source.
Existing cleanup, decoding checks and source-preservation guarantees apply.
Named transactional updates also preserve discoverable embedded prefixes and
the original MPQ origin across v1-v4, within their existing format restrictions.
They allow gaps; invoke compaction last when dense placement matters.

`libmpq__update_timestamp(update, name, filetime)` changes existing FILETIME
metadata using ordinary lookup. Use `libmpq__update_timestamp_identity(update,
name, filetime, locale, platform)` for exact selection without fallback.
FILETIME is unsigned 100-nanosecond ticks since 1601-01-01 UTC; zero and
`UINT64_MAX` are valid values. Valid, available classic-backed FILETIME is
required. Missing arrays are not created and timestamps cannot be unset.

A validated same-value request is a no-op, including shared rows, and keeps
staged bytes and signatures intact. Actual changes to rows shared by multiple
identities, including unknown aliases, return FORMAT. Eligible changes retain
packed payloads and offsets, regenerate attributes and physical integrity,
preserve raw-chunk policy, and invalidate signatures under the normal update
policy. Existing mixed-table and unsupported metadata restrictions remain.
Semantic rejection retains the preceding stage; operational adoption failures
can leave it abort-only. Set timestamps after ordinary replacement; exact
replacement retains the selected timestamp.

Exact identity operations use `libmpq__update_replace_data_identity()`,
`libmpq__update_replace_path_identity()`, `libmpq__update_remove_identity()`
and `libmpq__update_rename_identity()` with explicit locale/platform values. Each resolves
the filename, locale and platform against the current stage without neutral
fallback. For example:

```c
status = libmpq__update_replace_data_identity(
    update, "data/file.bin", 0x0409, 0, replacement, replacement_size, NULL
);
```

In classic-only v1-v4 archives, replacement detaches one selected alias into a
new payload; remove and rename preserve all other aliases and their original
packed contents. NULL replacement options keep the selected locale/platform
with default storage; explicit options must match. Mixed classic/HET/BET
mutations require a consistent one-to-one target with complete hashes.
Unique HET/BET-only targets accept `(0, 0)` only. Ambiguous aliases or metadata
are rejected, without discarding extended tables. Retained attributes and
timestamps, v4 raw policy, and final-offset encryption are preserved.

Exact operations use the reconstruction path for every generation. Supported
embedded prefixes and user-data relationships are retained byte-for-byte;
unsupported metadata and unrelated trailers are rejected. A rejected stage
leaves earlier valid changes available; the original remains
unchanged until commit. Existing name-based operations retain their behavior.

`libmpq__update_change_identity(update, name, old_locale, old_platform,
new_locale, new_platform)` selects the old tuple exactly and changes only its locale and
platform to the new tuple, preserving the filename and payload. Identical
tuples validate the source and succeed without rebuilding; missing sources or
occupied destinations return EXIST. Classic-only v1-v4 support shared aliases.
Mixed targets require consistent one-to-one classic/BET mappings with complete
hashes; HET/BET-only entries cannot acquire qualifiers. Ambiguous metadata and
special-member mutations return FORMAT. Existing reconstruction limits apply.

Ordinary payload offsets, packed bytes, flags, attributes and timestamps are
retained. If no internal `(signature)` member is present, listfiles also keep
their original storage. Payloads keep their stored representation, and KEY
remains valid because neither the basename nor the physical offset changes.
Canonical member numbers may remap during reconstruction; their payload
associations and probe slots are preserved. V4 raw policy and transaction
publication guarantees remain unchanged. Rejected calls preserve the preceding
valid stage.

Legacy v1/v2 updates retain unchanged packed entries even without `(listfile)`
names, and preserve embedded prefixes and unrelated trailing bytes. Their
rebuilt archive extent must fit the legacy 32-bit size field. V3/v4 use a
named rebuild instead, with the requirements below.

V3/v4 operations learn filenames from `(listfile)`, the operation's source
name, internal-file names, and earlier successful operations in the same
transaction. Repeated identical names and ASCII case or slash/backslash
variants are one normalized name. Distinct complete names resolving to the
same logical entry are ambiguous and return FORMAT. Empty CRLF/LF lines are
ignored; embedded null bytes and unresolvable listed names reject
reconstruction. Known source/listfile spellings take precedence over
equivalent caller spellings, so replacement preserves the original hashes.

Unrelated unnamed entries can be retained in classic-only, HET/BET-only and
mixed sources. Classic probe slots and locale/platform identities are kept;
the existing hash capacity cannot grow without the missing probe hashes.
Extended identities must contain the complete normalized 64-bit name hash,
with one HET reference per live BET row. Mixed sources require consistent
classic/BET provenance for every live entry. Add and rename reject conflicting
stored identities rather than assigning guessed names. Unnamed packed members
retain their exact bytes and original offsets, including encrypted/KEY
members; no filename-derived key is needed. V4 raw digests are checked and
regenerated with the source chunk size. A partial listfile remains partial.

Reduced or ambiguous extended hashes, incompatible provenance, BET-only rows
with classic attributes, ambiguous named aliases, unrelated trailing data, and
patch/delete members remain rejected. Extra header extensions, nonzero
reserved BET record values and retained payloads that overlap the full header
are also unsupported. Begin/abort and unchanged commits do not require
reconstruction. Failed operations leave the previous staged archive unchanged.
Legacy embedded updates and patch handling remain unchanged. Public file
numbers may change after a rebuild.

In v3 and raw-disabled v4 rebuilds, untouched packed members retain their
original positions, exact codec bytes, flags and encryption keys, including
KEY. Tables are regenerated by the normal writer from the final rows:
classic row N and BET row N agree. Encrypted rename decodes and rewrites with
the new name/key at the final position, preserving KEY and timestamps. As
with legacy updates, rewritten v3 multi-compression rename data uses zlib;
replacement uses caller options or native defaults. Untouched
CRC32/MD5/FILETIME metadata uses explicit classic provenance, not canonical
indices; new/replaced attributes are regenerated. Ordinary replacement resets
FILETIME to the writer default of zero; exact replacement and rename retain it.

Legacy per-member staging encodes KEY at the final archive-relative copy
position: the plaintext rebuild stream position minus the source archive
start. The standalone staging archive starts at zero. For compact inputs, its
reserved classic tables are moved after the payload so finalization cannot
overwrite it. MPQE transactions use the same plaintext coordinates and
re-encrypt the container only at publication; the MPQE cipher position is not
a member-key input. When reading a patch payload past its plaintext prefix,
KEY still uses the original member start and reconstructed size, not the
shifted payload view.

Modified weak signatures and strong trailers are removed, following existing
update policy. They are never presented as valid after a rebuild. MPQE uses
the existing plaintext staging and atomic MPQE rewrapping path. Rebuild or
publication failure preserves the original destination. Failures before staged
ownership transfer preserve the previous stage. If closing the previous staged
stream fails after validation, the stream is consumed and cleared: further
mutations/commit cannot publish it, and abort safely removes tracked temporary
files. Flush failures leave the previous stage available. Close callbacks follow
`fclose` ownership semantics even on failure. No in-place modification or
separate transaction engine is used.

A no-op transaction preserves original bytes and signatures. Ordinary updates
do not create true PATCH_BIT values; the dedicated patch writer does.

V4 reconstruction retains the source raw-chunk size and regenerates header,
table and member digests. Raw-enabled retained members keep their packed bytes,
including ADPCM and mixed sector methods. Relocation transforms encryption when
needed and regenerates raw MD5 without recompression. Unsupported metadata
remains rejected. MPQE updates use the same plaintext reconstruction before
encrypted publication.

### Patch archive creation

The public patch handle creates a new MPQ v1/v2/v3/v4 patch artifact without
modifying the base archive:

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
caller-supplied authentication code; addition, replacement, removal, finish,
and abort then follow the same lifecycle. Authenticated patch readers can
consume the result using that patch layer's own code. Signing is optional
and configured with `libmpq__patch_sign()` before finish. It delegates to the
existing archive writer: v1/v2/v3 plain patches may use weak, strong, or both
signatures; their MPQE variants support weak signatures only. V4 patches
default to enabled raw-chunk MD5, preventing weak signing. Set their raw size
to zero before signing to allow weak signatures, including on MPQE output.
Plain v4 supports strong signing at any raw size; MPQE excludes strong signing.
A finished patch is inspected and verified with
`libmpq__archive_signatures()` and `libmpq__archive_verify()`.

Replacement options control storage of the patch member inside the patch
archive, not storage of the resulting file in the patched view.

The private `mpq-patch-writer` module stages a same-directory temporary
archive. It writes named replacements as PTCH BSD0 members when a
deterministic binary delta is smaller than PTCH COPY, and uses COPY otherwise.
Deletions are delete markers. It publishes only on finish; abort discards the
temporary output. Finish and abort consume the handle even when they report an
error; the pointer must not be reused. Patch creation does not rename
members. Public patch creation currently requires an ordinary filesystem MPQ
base; this restriction does not apply to public patch composition, which
accepts MPQE sources decoded with the supplied code. PTCH COPY/BSD0 encoding and validation are
described in [MPQ.md](MPQ.md#patch-archives-and-ptchbsd0). Existing base
members are read with their plaintext names, so encrypted members can supply
their filename-derived keys.

The patch writer emits a generated `(listfile)` and `(attributes)` with
PATCH_BIT=true only for patch-file replacements, not additions or delete
markers. It does not emit a Blizzard `(patch_metadata)` marker; the private
patch reader identifies these archives from patch-file and delete-marker flags.
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
Use `libmpq__patch_add_data()` or `libmpq__patch_add_path()` for a genuinely
base-absent ordinary member. These calls do not generate PTCH or delete-marker
payloads; NULL options use ordinary writer defaults. They support existing
compression, encryption/KEY, sector CRC and representable locale/platform
options. Path input is read in bounded chunks without importing timestamps.
Additions have PATCH_BIT=false and use the common v4 raw/structural checksum
finalizer. Addition-only artifacts need no metadata marker when explicitly
supplied to `libmpq__archive_open_patch()`.

Existing base or staged identities return `LIBMPQ_ERROR_EXIST`; ambiguous
classic/extended hashes or locale/platform identities return
`LIBMPQ_ERROR_FORMAT`. A remove-then-add of a base member is rejected; use
replacement instead. A newly added name cannot be replaced or removed within
the same patch handle. Empty data is valid, including NULL at size zero.
PATCH_FILE, DELETE_MARKER and unsupported flags are rejected. Validation before
output leaves prior stages usable; partial output failures latch a terminal
error, so finish cannot publish an incomplete patch. Abort discards unpublished
output; finish and abort retain their consuming semantics.

### Patch composition

Use `libmpq__stream_open_patch()` to reconstruct one member using ordinary
final-view lookup, or `libmpq__stream_open_patch_identity()` for an exact
filename/locale/platform tuple. The wrappers use the shared selection
plan and executor, and borrow the ordered archives, callback contexts,
and prefix strings during open. NULL prefixes request inference and
empty strings select root. Open reports selected transform and integrity
errors before returning a verified seekable spool-backed result.
The stream owns its spool and retains no input handles or callback resources.
The caller may close the input archives after success. Release their callback
resources only after all dependent archives, clones and ordinary streams have
closed. Unrelated payloads may be unread. Scratch use depends on the selected
results and BSD0 transform, and SINGLE decoding can require whole-unit memory.
Close consumes the stream and reports backing cleanup errors.

`libmpq__archive_open_patch()` composes already-open ordinary MPQ and
MPQE-wrapped archives, including custom read-at sources, as the base
and ordered patch layers. Open each MPQE input with its own explicit
authentication code. The private `mpq-patch-reader` layer materializes a
temporary read-only archive view; later layers override earlier ones, delete
markers hide lower-layer names, and `PTCH` COPY or BSD0 payloads are checked
against their before/after MD5 values. Existing archive and logical stream
read APIs operate on the resulting owned archive. Use
`libmpq__archive_open_patch(&result, base, patches, prefixes, patch_count)`
with already-open, borrowed inputs in application order. A NULL prefix array
or entry requests inference; an empty string selects the root namespace.
Zero layers create an independent byte snapshot. The read-only result
retains no input handles, callback resources or MPQE credentials. Close the
inputs after success under the same callback lifetime rules as for selected
patched streams. Close the result with `libmpq__archive_close()`. Its clones and
streams independently retain temporary storage after parent closure. Verify
physical signatures and raw checksums on the original inputs, not as trust
in reconstructed output.

The private `libmpq__patch_reader_open_archives()` bridge borrows already-open
inputs during composition and returns an independently owned reader. Zero
layers produce a byte-preserving snapshot of the logical backing source,
including its source name; custom callback contexts are not retained.
Explicitly supplied layers can contain ordinary additions without a metadata
marker; automatic recognition for path-based private callers is unchanged. A
shared source owner retains temporary backing storage until the last archive
clone or stream closes. Cleanup closes backing handles before removing the
file; last-owner cleanup errors propagate through archive or stream close.
Cleanup is best effort and does not guarantee secure erasure or crash
recovery. These lifetime operations require external serialization, not
concurrent close/read.

Patch matching primarily uses each entry's MPQ hash identity, including locale
and platform. `(listfile)` is optional metadata that enriches entries with
plaintext names. For legacy v1/v2 materialization, an unnamed patch entry can
replace an existing hash identity when its payload can be decoded without a
name-derived key. A new patch-only member requires a recoverable plaintext
name so its hash-table probe position can be computed. Otherwise that entry is
rejected rather than silently omitted. Unnamed legacy base members and their
packed data remain intact. V3/v4 named materialization requires complete,
unambiguous names for every retained member and rejects missing coverage,
aliases/locales or reserved metadata it cannot represent. V4 bases and patch
layers are read-only inputs, including MPQE and mixed-version
chains. Changed intermediates are v3 and regenerate HET/BET plus classic tables
through the existing writer; modified encrypted members use their final output
offsets. Raw MD5 verifies a physical source member; it is unavailable on
reconstructed v3 output. MPQE inputs use the existing source decoder before
patch composition; their credentials are independent and are not retained by
the view. A `.w3x` input is treated only as an MPQ container; legacy
materialization retains its prefix and unrelated trailing bytes while a stale
external strong-signature trailer is removed after a content change. Rebuilt
v3 views are standalone and do not retain container prefixes/suffixes. This
layer does not perform HM3W map-header hashing. Each patch layer may supply an
independent namespace prefix. Physical names such as
`Base\\Foo` are read from the patch using their original names, while the
prefix-stripped logical name `Foo` identifies the lower-layer member and the
materialized result. A single `(patch_metadata)` path in `(listfile)`
deterministically discovers the prefix; conflicting paths are rejected. An
explicit prefix takes precedence, but must agree with discovered metadata.
Unnamed entries requiring prefix removal are rejected because their
logical identity cannot be recovered. Game-specific prefix discovery
heuristics are deliberately outside the game-neutral core. The view retains
usable `(listfile)` names, merges known patch-only names, and maps available
`(attributes)` rows to resulting file entries by MPQ hash identity. Existing
PATCH_BIT values, including true values from input metadata, remain readable;
the patch view does not create new true values. A content change invalidates
the base archive's signatures, so the temporary view omits stale weak and
strong signatures. Opening failure is terminal and returns no partially usable
view; consumed handles are never closed twice. Temporary-file deletion is
best effort when the filesystem refuses removal. Source archives remain
unchanged.

### Game-neutral MPQE and namespace policy

libmpq does not embed product-specific Blizzard MPQE keys. Callers provide
authentication material explicitly for each MPQE source or output; the existing
decoder and writer derive the working key without retaining caller-owned data.
MPQE carries no independent authentication tag. Opening a decoded archive
checks its MPQ structure. Member verification and digital signatures provide
separate checks, and a plausible wrong-code decode can pass structural checks.
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

Run `scripts/check` for source formatting and lint checks. Run
`scripts/check-c-standards` separately for strict GCC and Clang compilation
across C99, C11, C17, C23 and GNU23, or select one combination with
`scripts/check-c-standards gcc c99`. Each optimized build treats warnings as
errors and compiles and links every native regression program. Automake's
`make check TESTS=` builds all `check_PROGRAMS` without executing `TESTS`;
these checks establish compilation compatibility, not runtime test success.
Lint uses the same build-only mechanism to collect test compile commands for
clang-tidy.

CI retains full native runtime suites for the ordinary optimized Linux GCC
build, Clang ASan/UBSan/LSan, GCC coverage, big-endian s390x, Windows MSVC and
MinGW on both architectures/linkages, and the glibc, musl and macOS SDK
configurations. The ordinary Linux Clang build compiles regression programs
without repeating the full suite. Instrumented coverage still executes all
native tests before collecting gcovr reports. Packaging and release workflows
keep their independent platform runtime checks and installed-consumer tests.
No large-file assertions are skipped or changed; runtime validation with
multi-gigabyte files should use disk-backed working directories rather than
memory-backed temporary storage.

GCC coverage retains `-O0 -g --coverage` to preserve source line and branch
visibility. Its complete native suite runs with two Automake workers to overlap
independent regression programs without unbounded concurrent memory or I/O.
The 35-minute job budget includes the CPU-heavy transaction/signature tests,
setup, compilation, report generation and uploads; parallelism does not shorten
the longest individual test.

The coverage job uses `debian:trixie-slim` and its packaged gcovr 7.2.
Direct gcovr invocations process the actual large RSA execution counters without
extra counter-limit options. Source selection and coverage requirements remain
unchanged. XML, JSON, HTML, badges and PR/Pages consumers retain their existing
interfaces.

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
both flat and directory member names, especially encrypted and KEY
members. Check missing-member errors, incorrect MPQE codes and truncated
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
  focused stream reads, callback granularity, and MPQE decoding and reads.
- `bench-stream` measures stream open, sequential and incremental reads, and
  forward, backward, and random seeks on stored, compressed, and encrypted
  members.
- `bench-writer` measures ordinary archive creation, one-shot and streaming
  member writes, many-small-file insertion, and archive finalization.
- `bench-mpqe` measures MPQE encoding, MPQE open, and transport reads
  alongside equivalent ordinary-MPQ diagnostic cases.
- `bench-verify` measures sector Adler-32, CRC32/MD5 `(attributes)`, automatic
  extraction checks, and explicit file verification.
- `bench-signature` measures weak, strong, and combined archive signature
  verification.
- `bench-patch-reader` measures patch-view materialization for COPY, BSD0, and
  mixed chains.
- `bench-patch-writer` measures patch staging and COPY/BSD0 transform selection.
- `bench-update` measures transactional update begin, operation, and commit for
  ordinary MPQ, embedded HM3W-style, and MPQE-wrapped archives.

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

Availability-aware member verification uses `libmpq__file_verify_ex()` with
separate checked, unavailable and mismatch masks. On success their coverage
union equals the request; partial sector coverage can set both coverage
masks. Complete matching coverage requires checked equal to the request and
both unavailable and mismatches zero. Operational errors clear all outputs.
The legacy verifier retains its mismatch-only contract and skipped checks.

The optional filename is borrowed decryption-key context for the selected
canonical number, with no lookup fallback or parent key-cache changes. Exact
selection remains a separate identity lookup. Missing logical attributes and
inapplicable checks are unavailable; malformed metadata, read and decode errors
remain errors. Nonzero v4 raw chunk size declares expected trailing RAW MD5
arrays for eligible nonempty members. Missing, truncated or overlapping required
arrays are errors, regardless of table order or adjacent storage. A matching
unkeyed digest establishes neither provenance nor cryptographic authenticity.
Circular zero CRC placeholders and logical ADPCM checks lacking proven
decoded-byte provenance are unavailable. Ordinary CRC32 zero remains
valid. Raw checks do not need plaintext keys. Member checks establish neither
signature trust nor complete archive integrity. Archive metadata verification
remains a separate phase.

Extended RAW verification lazily copies live payload and metadata ranges into
an immutable private index with sorted starts and prefix maximum ends. It costs
O(N log N) preprocessing, O(N) memory and O(log N) per overlap query. Clones
share completed indexes using the existing externally serialized lifetime
contract; the last close frees them. Clones created before preprocessing can
build their own index once. Named verification prepares the parent index
before opening its key-isolated clone. Failed construction remains retryable.
Index construction does not certify overlapping storage: queries still reject
conflicts. The legacy verifier neither constructs nor queries this index.

### Archive metadata verification

Archive metadata verification uses `libmpq__archive_verify_ex()` and the eight
`LIBMPQ_VERIFY_METADATA_*` bits, combined by `LIBMPQ_VERIFY_METADATA_ALL`.
It performs fresh bounded reads of stored header/table representations against
opened descriptors, checking both object digests and stored reference fields.
Present empty tables with supplied digests compare MD5(empty). Missing optional
metadata is unavailable; required nonzero-v4 HET/BET RAW arrays that are missing,
truncated or overlapping are errors. Changed reference fields mismatch rather
than becoming unavailable. No newly changed geometry is adopted.

The result masks partition requested checks into checked and unavailable, with
mismatches a subset of checked. Complete matching coverage requires successful
status, checked equal to the request, no unavailable checks and no mismatches.
Errors clear all outputs. Zero flags perform no comparisons. Existing member
`VERIFY_ALL` remains unchanged and is rejected by archive metadata verification.

The source must remain stable; source reads do not promise uncached filesystem
access or an atomic snapshot of concurrent writes. Embedded offsets and MPQE
logical reads use existing source handling. Unkeyed MD5 establishes neither
provenance nor authenticity, MPQE transport authenticity or whole-archive
integrity. `archive_verify()` remains public-key signature verification;
`file_verify_ex()` remains member verification.

`LIBMPQ_FILE_FLAG_KEY` (`0x00020000`) selects offset- and size-adjusted
encryption-key derivation. It modifies `ENCRYPTED`; it does not enable encryption
on its own. The effective key is `(basename_key + uint32(MPQ-relative offset))
XOR uint32(uncompressed size)`, with modulo-2^32 arithmetic. Embedded prefixes
are excluded from this offset. The flag provides no integrity guarantee.

Transaction filename knowledge consists of owned spellings, not cached file
numbers. Before adopting a reconstruction, live spellings are resolved against
the candidate and copied into replacement provenance. Failed preparation leaves
the preceding stage and provenance intact. Removed spellings are discarded;
compatible live aliases remain subject to the existing encryption-provenance
checks. Validated no-ops neither learn names nor rebuild a stage.

### Caller-owned archive output

`libmpq__archive_create_io()` shares the archive and member encoders with
path output. An optional descriptor tracks the output cursor and maximum
successful write end. Read-back for v4 RAW MD5 and signing observes the
sink directly. V4 requires a read callback at creation. Older generations
may omit it for unsigned writing. The optional flush runs after metadata
and signatures. Callbacks transfer exact ranges and supply zero-filled
gaps without requiring the writer to pad sparse storage.

The caller retains the initially empty sink and callback context through
consuming close. A terminal error prevents further output callbacks.
The library leaves disposal, persistence and publication to the caller.
Sectorized writes retain existing bounded input buffers. Oversized SINGLE
still buffers the complete input unit and any codec workspace.

`libmpq__archive_create_mpqe_io()` uses an owner-only plaintext stage in the
system temporary directory. The existing MPQE transform streams its encrypted
bytes to the caller's sink during consuming close in batches of up to 16 KiB.
The transform still uses 64-byte cipher blocks and writes only the actual
transport bytes. RAW MD5 and permitted signing read from the private stage. The final
sink needs only positioned writes and can optionally flush after successful
stage cleanup. This output has the same non-atomic publication contract as
`libmpq__archive_create_io()`.
