# libmpq Java bindings

These bindings use the Java Foreign Function and Memory API and require JDK
22 or newer. They provide a complete mapping of libmpq's stable public C API
through `org.libmpq.ffi.LibmpqNative` and safer `AutoCloseable` wrappers in
`org.libmpq`.

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

The high-level API uses `Archive.open`, `Archive.create`, and
`MpqFileWriter`. All negative libmpq return codes are reported as
`LibmpqException` values containing the original code and diagnostic text.
