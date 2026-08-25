#!/usr/bin/env bash

set -euo pipefail

if (($# < 3 || $# > 4)); then
	printf 'Usage: %s JAVA_RELEASE_ZIP VERSION NATIVE_LIBRARY_DIR [FIXTURE]\n' \
		"${BASH_SOURCE[0]}" >&2
	exit 2
fi

readonly release_zip=$1
readonly expected_version=$2
readonly native_directory=$3
readonly project_root="$(
	cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd
)"
readonly fixture=${4:-"${project_root}/tests/fixtures/mpq-v1-features.mpq"}

for path in "${release_zip}" "${native_directory}" "${fixture}"; do
	if [[ ! -e "${path}" ]]; then
		printf 'Required path does not exist: %s\n' "${path}" >&2
		exit 1
	fi
done

readonly temporary_directory="$(mktemp -d)"
trap 'rm -rf -- "${temporary_directory}"' EXIT

readonly package_directory="${temporary_directory}/package"
readonly consumer_directory="${temporary_directory}/consumer"
mkdir -p "${package_directory}" "${consumer_directory}"
unzip -q "${release_zip}" -d "${package_directory}"

readonly runtime_jar="${package_directory}/libmpq-java-${expected_version}.jar"
readonly sources_jar="${package_directory}/libmpq-java-${expected_version}-sources.jar"
readonly javadoc_jar="${package_directory}/libmpq-java-${expected_version}-javadoc.jar"
for package_file in \
	"${runtime_jar}" \
	"${sources_jar}" \
	"${javadoc_jar}" \
	"${package_directory}/COPYING" \
	"${package_directory}/COPYING.LESSER" \
	"${package_directory}/README.md"; do
	test -s "${package_file}"
done

readonly native_library="${native_directory}/libmpq.so"
if [[ ! -e "${native_library}" ]]; then
	printf 'Packaged consumer native library does not exist: %s\n' \
		"${native_library}" >&2
	exit 1
fi

cat > "${consumer_directory}/Consumer.java" <<'EOF'
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import org.libmpq.Archive;
import org.libmpq.Mpq;

public final class Consumer {
    private Consumer() { }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 3) {
            throw new IllegalArgumentException("expected version, fixture, and entry name");
        }

        String expectedVersion = arguments[0];
        Path fixture = Path.of(arguments[1]);
        String entryName = arguments[2];
        if (!expectedVersion.equals(Mpq.version())) {
            throw new AssertionError("native version mismatch: expected "
                                     + expectedVersion + ", got " + Mpq.version());
        }

        try (Archive archive = Archive.open(fixture)) {
            int number = archive.fileNumber(entryName);
            byte[] data = archive.readFile(number);
            if (!new String(data, StandardCharsets.UTF_8).contains("libmpq")) {
                throw new AssertionError("fixture payload was not read correctly");
            }
            if (archive.readBlock(number, 0).length == 0) {
                throw new AssertionError("fixture block was unexpectedly empty");
            }
        }
    }
}
EOF

javac -cp "${runtime_jar}" -d "${consumer_directory}" \
	"${consumer_directory}/Consumer.java"

run_consumer() {
	local mode=$1
	shift
	printf 'Testing packaged Java consumer (%s loading)...\n' "${mode}"
	"$@" --enable-native-access=ALL-UNNAMED \
		-cp "${consumer_directory}:${runtime_jar}" \
		Consumer "${expected_version}" "${fixture}" overview.txt
}

run_consumer explicit \
	java "-Dorg.libmpq.library=${native_library}"

run_consumer loader \
	env -u JAVA_TOOL_OPTIONS "LD_LIBRARY_PATH=${native_directory}" java
