# libmpq Java bindings

These bindings use the Java Foreign Function and Memory API and require JDK
22 or newer. They provide a complete mapping of libmpq's stable public C API
through `org.libmpq.ffi.LibmpqNative` and safer `AutoCloseable` wrappers in
`org.libmpq`.

Creation defaults to `Mpq.COMPRESSION_POLICY_STANDARD`. Set
`Mpq.ARCHIVE_CREATE_COMPRESSION_EXTENDED` in `ArchiveCreateOptions.flags`
for additional, potentially less interoperable compression forms. Use
`Mpq.archiveCompressionAllowed(version, mask, policy)` to query whether a
compression selection is allowed by the writer policy, using zero-based
`Mpq.ARCHIVE_VERSION_*` selectors. Readers remain permissive.

`Mpq.COMPRESSION_SPARSE` selects lossless zero-run compression. In MPQ v2+,
STANDARD allows the fixed SPARSE forms: alone (`0x20`), with zlib (`0x22`),
or with bzip2 (`0x30`). MPQ v1 retains normal compression-mask semantics
under either policy, allowing other valid combinations such as SPARSE
with Huffman (`0x21`) or PKWARE (`0x28`). In MPQ v2+, EXTENDED permits the
broader valid lossless SPARSE combinations. Neither policy allows SPARSE
with WAVE ADPCM. The shared `sparse*.txt` fixtures use UTF-32LE with a BOM;
extraction returns those bytes without transcoding.

The JAR does not contain a native library. Autotools does not install the
Java binding; Maven builds the platform-independent runtime, sources, and
Javadoc JARs. Build and install libmpq separately, then either set
`org.libmpq.library` to the absolute native-library path or make `mpq`
available through the platform library search path.

The canonical release installation path is Maven Central:

```xml
<dependency>
  <groupId>org.libmpq</groupId>
  <artifactId>libmpq-java</artifactId>
  <version>0.7.0</version>
</dependency>
```

For example:

```sh
mvn test -Dorg.libmpq.library=/path/to/libmpq/src/.libs/libmpq.so
```

To exercise the loader-path fallback explicitly, provide the native library
directory through the platform loader and enable the integration test mode:

```sh
LD_LIBRARY_PATH=/path/to/libmpq/src/.libs \
    mvn test -Dorg.libmpq.test.loaderPath=true
```

The GitHub Release Java ZIP is a supplementary download containing the
runtime, sources, and Javadoc JARs together with `COPYING`, `COPYING.LESSER`,
and this README. Release validation also builds an external consumer using
only the packaged runtime JAR and tests both native-library loading modes.

The high-level API uses `Archive.open`, `Archive.openMpqe`, `Archive.create`,
`Archive.createMpqe`, and `MpqFileWriter`. MPQE creation uses a private
plaintext temporary file before atomically replacing the destination; it
cannot modify an existing MPQE archive and crash cleanup is best effort. All
negative libmpq return codes are reported as
`LibmpqException` values containing the original code and diagnostic text.
