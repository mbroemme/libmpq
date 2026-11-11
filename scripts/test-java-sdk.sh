#!/usr/bin/env bash

# Copyright (c) 2026-2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this file; if not, see <https://www.gnu.org/licenses/>.

set -euo pipefail

fail()
{
	printf '%s\n' "$*" >&2
	exit 1
}

if [[ $# -ne 3 ]]; then
	printf 'Usage: %s SDK VERSION {x86_64|aarch64}\n' "${BASH_SOURCE[0]}" >&2
	exit 2
fi

sdk=$1
version=$2
architecture=$3
[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Expected an X.Y.Z SDK version"
case "${architecture}" in
	x86_64|aarch64) ;;
	*) fail "Unsupported SDK architecture: ${architecture}" ;;
esac

platform="$(uname -s)"
case "${platform}" in
	Linux) relative_library=lib/libmpq.so ;;
	Darwin) relative_library=lib/libmpq.dylib ;;
	MINGW*|MSYS*)
		relative_library=bin/mpq.dll
		sdk="$(cygpath -au "${sdk}")"
		;;
	*) fail "Unsupported SDK platform: ${platform}" ;;
esac

[[ -d "${sdk}" ]] || fail "Missing SDK directory: ${sdk}"
sdk="$(cd -- "${sdk}" && pwd -P)"
library="${sdk}/${relative_library}"
[[ -f "${library}" ]] || fail "Missing SDK library: ${library}"
if ! java="$(type -P java)" || ! javac="$(type -P javac)"; then
	fail "java and javac from a JDK 22 or newer are required"
fi
java="$(cd -- "${java%/*}" && pwd -P)/${java##*/}"
javac="$(cd -- "${javac%/*}" && pwd -P)/${javac##*/}"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
temporary="$(mktemp -d)"
trap 'rm -rf -- "${temporary}"' EXIT

native_path()
{
	case "${platform}" in
		MINGW*|MSYS*) cygpath -am "$1" ;;
		*) printf '%s\n' "$1" ;;
	esac
}

unset JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS
unset LD_LIBRARY_PATH DYLD_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH
runtime_path=${PATH}
case "${platform}" in
	MINGW*|MSYS*)
		export MSYS2_ARG_CONV_EXCL='*' MSYS_NO_PATHCONV=1
		system="$(cygpath -au "${SystemRoot:-${SYSTEMROOT:?Missing Windows system directory}}")"
		# Git Bash converts PATH itself when launching the native JVM.
		runtime_path="${library%/*}:${system}/System32:${system}"
		;;
esac

find "${root}/bindings/java/src/main/java" -name '*.java' -type f -print0 >"${temporary}/sources"
sources=()
while IFS= read -r -d '' source; do
	sources+=("$(native_path "${source}")")
done <"${temporary}/sources"
sources+=("$(native_path "${root}/bindings/java/src/test/java/org/libmpq/JavaSdkSmoke.java")")
classes="$(native_path "${temporary}")"
"${javac}" --release 22 -d "${classes}" "${sources[@]}"

run_smoke()
{
	local directory=$1
	shift
	PATH="${runtime_path}" \
		"${java}" --enable-native-access=ALL-UNNAMED \
		"-Djava.library.path=${directory}" "$@" -cp "${classes}" \
		org.libmpq.JavaSdkSmoke "${version}" "${architecture}"
}

(
	cd -- "${temporary}"
	mkdir override-test
	touch "override-test/${library##*/}"
	decoy="$(native_path "${temporary}/override-test")"
	printf 'Testing default loading of %s\n' "${library}"
	run_smoke "$(native_path "${library%/*}")"
	printf 'Checking that default lookup rejects the decoy\n'
	if run_smoke "${decoy}" >decoy.log 2>&1; then
		fail "Default lookup unexpectedly accepted the decoy"
	fi
	if ! grep -q 'UnsatisfiedLinkError' decoy.log; then
		cat decoy.log >&2
		fail "Default lookup failed without a native library load error"
	fi
	printf 'Testing explicit loading of %s with a decoy on the default path\n' "${library}"
	run_smoke "${decoy}" "-Dorg.libmpq.library=$(native_path "${library}")"
)
