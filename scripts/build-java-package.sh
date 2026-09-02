#!/usr/bin/env bash

# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.

set -euo pipefail

readonly project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly output_dir="${project_root}/bindings/java/target"
cd "${project_root}"

if command -v nproc >/dev/null 2>&1; then
	jobs="$(nproc)"
else
	jobs="$(getconf _NPROCESSORS_ONLN)"
fi

sh autogen.sh
./configure --prefix=/usr
make -j"${jobs}" V=1

readonly native_directory="${project_root}/src/.libs"
readonly native_library="${native_directory}/libmpq.so"
test -e "${native_library}"

mvn -B -f bindings/java/pom.xml clean package \
	-Dorg.libmpq.library="${native_library}" \
	-Dlibmpq.sourceDir="${project_root}"
LD_LIBRARY_PATH="${native_directory}" \
	mvn -B -f bindings/java/pom.xml test \
		-Dorg.libmpq.test.loaderPath=true \
		-Dlibmpq.sourceDir="${project_root}"

version="$(mvn -q -f bindings/java/pom.xml \
	help:evaluate -Dexpression=project.version -DforceStdout)"
test -n "${version}"
if [[ -n "${LIBMPQ_JAVA_EXPECTED_VERSION:-}" ]]; then
	test "${version}" = "${LIBMPQ_JAVA_EXPECTED_VERSION}" || {
		printf 'Maven version %s does not match expected version %s.\n' \
			"${version}" "${LIBMPQ_JAVA_EXPECTED_VERSION}" >&2
		exit 1
	}
fi

readonly runtime_jar="${output_dir}/libmpq-java-${version}.jar"
readonly sources_jar="${output_dir}/libmpq-java-${version}-sources.jar"
readonly javadoc_jar="${output_dir}/libmpq-java-${version}-javadoc.jar"
for artifact in "${runtime_jar}" "${sources_jar}" "${javadoc_jar}"; do
	test -s "${artifact}"
done

readonly package_dir="$(mktemp -d)"
trap 'rm -rf -- "${package_dir}"' EXIT
cp "${runtime_jar}" "${sources_jar}" "${javadoc_jar}" \
	COPYING COPYING.LESSER bindings/java/README.md "${package_dir}/"
readonly release_zip="${output_dir}/libmpq-java-${version}.zip"
(
	cd "${package_dir}"
	zip -q "${release_zip}" ./*
)
unzip -t "${release_zip}"
scripts/test-java-package.sh "${release_zip}" "${version}" "${native_directory}"
