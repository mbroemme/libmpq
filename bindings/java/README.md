# libmpq Java bindings

These bindings use the Java Foreign Function and Memory API and require JDK
22 or newer. They provide a complete mapping of libmpq's stable public C API
through `org.libmpq.ffi.LibmpqNative` and safer `AutoCloseable` wrappers in
`org.libmpq`.

The JAR does not contain a native library. Build and install libmpq separately,
then either set `org.libmpq.library` to the absolute native-library path or
make `mpq` available through the platform library search path.

For example:

```sh
mvn test -Dorg.libmpq.library=/path/to/libmpq/src/.libs/libmpq.so
```

The high-level API uses `Archive.open`, `Archive.create`, and
`MpqFileWriter`. All negative libmpq return codes are reported as
`LibmpqException` values containing the original code and diagnostic text.
