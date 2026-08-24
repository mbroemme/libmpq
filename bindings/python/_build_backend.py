# Copyright (c) 2026 Maik Broemme <mbroemme@libmpq.org>
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

"""PEP 517 backend that builds and bundles libmpq for platform wheels."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import tomllib
import zipfile

from setuptools import build_meta as _backend


_ROOT = Path(__file__).resolve().parent
with (_ROOT / "pyproject.toml").open("rb") as _stream:
    _VERSION = tomllib.load(_stream)["project"]["version"]

_LICENSE_FILES = ("COPYING", "COPYING.LESSER")


def _stage_license_files():
    """Stage project licenses beside pyproject.toml for build metadata."""
    license_root = _ROOT.parents[1]
    if not (license_root / _LICENSE_FILES[0]).exists():
        license_root = _ROOT
    created = []
    for license_name in _LICENSE_FILES:
        license_path = _ROOT / license_name
        if not license_path.exists():
            shutil.copy2(license_root / license_name, license_path)
            created.append(license_path)
    return created


def _native_sources(destination):
    """Copy only canonical C sources into an sdist staging directory."""
    source_root = _ROOT / "native"
    if not source_root.exists():
        source_root = _ROOT.parents[1]
    destination = Path(destination)
    for relative, patterns in (
        ("src", ("*.c", "*.h")),
        ("include", ("*.h",)),
    ):
        source_directory = source_root / relative
        for pattern in patterns:
            for source_path in source_directory.rglob(pattern):
                if not source_path.is_file():
                    continue
                relative_path = source_path.relative_to(source_directory)
                if {".libs", ".deps"}.intersection(relative_path.parts):
                    continue
                target = destination / relative / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_path, target)


def _build_native():
    """Compile the native library into a temporary platform-specific file."""
    override = os.environ.get("LIBMPQ_LIBRARY")
    suffix = ".dylib" if sys.platform == "darwin" else ".so"
    output_dir = Path(tempfile.mkdtemp(prefix="libmpq-python-native-"))
    output = output_dir / ("libmpq" + suffix)
    if override:
        shutil.copy2(override, output)
        return output, output_dir

    source_root = _ROOT / "native"
    if not source_root.exists():
        source_root = _ROOT.parents[1]
    sources = sorted((source_root / "src").glob("*.c"))
    # Do not add src/ as an angle-bracket include directory: its endian.h
    # would shadow the system <endian.h> included by glibc headers.
    includes = ["-I", str(source_root / "include")]
    compiler = os.environ.get("CC", "cc")
    command = [
        compiler,
        "-std=c99",
        "-D_GNU_SOURCE",
        f'-DVERSION="{_VERSION}"',
        "-fPIC",
    ]
    command += includes + [str(path) for path in sources]
    if sys.platform == "darwin":
        command += ["-dynamiclib", "-o", str(output)]
    else:
        command += ["-shared", "-o", str(output)]
    command += ["-lbz2", "-lz"]
    subprocess.run(command, check=True, cwd=source_root)
    return output, output_dir


def _record_hash(data):
    """Return the URL-safe wheel RECORD digest for one file."""
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _bundle_wheel(wheel_path, native_path, wheel_directory):
    """Add the native library and convert a pure wheel into a platform wheel."""
    wheel_path = Path(wheel_path)
    platform_tag = os.environ.get("LIBMPQ_WHEEL_PLATFORM")
    if platform_tag is None:
        platform_tag = sysconfig.get_platform().replace("-", "_") \
            .replace(".", "_")
    # The ctypes wrapper contains no CPython extension module, so it is
    # compatible with every supported Python 3 ABI. Keep only the platform
    # tag supplied by the local build or by the release repair step.
    output_name = "-".join(wheel_path.name[:-4].split("-")[:-1] + [platform_tag]) + ".whl"
    output_path = Path(wheel_directory) / output_name
    native_name = "libmpq" + native_path.suffix
    native_member = "mpq_libs/" + native_name

    files = {}
    with zipfile.ZipFile(wheel_path, "r") as source:
        for info in source.infolist():
            files[info.filename] = source.read(info.filename)
    wheel_name = next(name for name in files if name.endswith(".dist-info/WHEEL"))
    wheel_text = files[wheel_name].decode("utf-8")
    wheel_text = wheel_text.replace("Root-Is-Purelib: true", "Root-Is-Purelib: false")
    wheel_text = "\n".join(line for line in wheel_text.splitlines()
                             if not line.startswith("Tag: "))
    wheel_text += "\nTag: py3-none-{}\n".format(platform_tag)
    files[wheel_name] = wheel_text.encode("utf-8")
    files[native_member] = native_path.read_bytes()
    record_name = next(name for name in files if name.endswith(".dist-info/RECORD"))

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as destination:
        for name, data in files.items():
            if name != record_name:
                destination.writestr(name, data)
        rows = []
        for name, data in files.items():
            if name == record_name:
                rows.append([name, "", ""])
            else:
                rows.append([name, "sha256=" + _record_hash(data), str(len(data))])
        record = io.StringIO(newline="")
        csv.writer(record, lineterminator="\n").writerows(rows)
        destination.writestr(record_name, record.getvalue())
    wheel_path.unlink()
    return output_path.name


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    """Build a setuptools wheel and add the locally compiled native library."""
    created_licenses = _stage_license_files()
    try:
        wheel = _backend.build_wheel(
            wheel_directory, config_settings, metadata_directory
        )
        native, temporary = _build_native()
        try:
            return _bundle_wheel(
                Path(wheel_directory) / wheel, native, wheel_directory
            )
        finally:
            shutil.rmtree(temporary)
    finally:
        for license_path in created_licenses:
            license_path.unlink()


def build_sdist(sdist_directory, config_settings=None):
    """Build an sdist containing canonical C sources but no binaries."""
    native = _ROOT / "native"
    created = not native.exists()
    if created:
        _native_sources(native)
    created_licenses = _stage_license_files()
    try:
        return _backend.build_sdist(sdist_directory, config_settings)
    finally:
        if created:
            shutil.rmtree(native)
        for license_path in created_licenses:
            license_path.unlink()


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    """Prepare wheel metadata with the staged project license files."""
    created_licenses = _stage_license_files()
    try:
        return _backend.prepare_metadata_for_build_wheel(
            metadata_directory,
            config_settings,
        )
    finally:
        for license_path in created_licenses:
            license_path.unlink()


def prepare_metadata_for_build_editable(metadata_directory, config_settings=None):
    """Prepare editable metadata with the staged project license files."""
    created_licenses = _stage_license_files()
    try:
        return _backend.prepare_metadata_for_build_editable(
            metadata_directory,
            config_settings,
        )
    finally:
        for license_path in created_licenses:
            license_path.unlink()


def build_editable(
        wheel_directory, config_settings=None, metadata_directory=None):
    """Build an editable wheel with the staged project license files."""
    created_licenses = _stage_license_files()
    try:
        return _backend.build_editable(
            wheel_directory,
            config_settings,
            metadata_directory,
        )
    finally:
        for license_path in created_licenses:
            license_path.unlink()


get_requires_for_build_wheel = _backend.get_requires_for_build_wheel
get_requires_for_build_sdist = _backend.get_requires_for_build_sdist
get_requires_for_build_editable = _backend.get_requires_for_build_editable
