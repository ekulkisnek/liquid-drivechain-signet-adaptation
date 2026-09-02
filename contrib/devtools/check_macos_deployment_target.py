#!/usr/bin/env python3
"""Audit deployment targets and, optionally, final dynamic dependencies.

Rust static archives can contain C objects produced by build scripts.  Those
objects do not necessarily inherit rustc's target unless
``MACOSX_DEPLOYMENT_TARGET`` is exported.  Checking only the final executable
therefore misses the exact mismatch that Apple's linker merely warns about.
Conversely, checking only load-command targets misses a final executable that
links a Homebrew dylib built for a newer macOS release.  Release daemon checks
can therefore require system-only dylib dependencies as well.
"""

from __future__ import annotations

import argparse
import collections
import re
import subprocess
import sys
from pathlib import Path


_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
_DYLIB_RE = re.compile(r"^\s+(.+?) \(compatibility version [^)]+\)$")
_SYSTEM_DYLIB_PREFIXES = ("/usr/lib/", "/System/Library/")


def normalized_version(value: str) -> tuple[int, ...]:
    if not _VERSION_RE.fullmatch(value):
        raise ValueError(f"invalid macOS deployment target: {value!r}")
    components = [int(component) for component in value.split(".")]
    while len(components) > 1 and components[-1] == 0:
        components.pop()
    return tuple(components)


def parse_otool_deployment_targets(output: str) -> list[tuple[str, str]]:
    """Return ``(Mach-O label, minimum-version)`` records from ``otool -l``."""
    label = "<unlabelled Mach-O>"
    command: str | None = None
    targets: list[tuple[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if raw_line and not raw_line[0].isspace() and raw_line.endswith(":"):
            if not raw_line.startswith("Archive :"):
                label = raw_line[:-1]
            continue
        if line == "cmd LC_BUILD_VERSION":
            command = "build"
            continue
        if line == "cmd LC_VERSION_MIN_MACOSX":
            command = "legacy"
            continue
        if command == "build" and line.startswith("minos "):
            targets.append((label, line.split(None, 1)[1]))
            command = None
        elif command == "legacy" and line.startswith("version "):
            targets.append((label, line.split(None, 1)[1]))
            command = None
    return targets


def parse_otool_macho_labels(output: str) -> list[str]:
    return [
        raw_line[:-1]
        for raw_line in output.splitlines()
        if raw_line
        and not raw_line[0].isspace()
        and raw_line.endswith(":")
        and not raw_line.startswith("Archive :")
    ]


def parse_otool_dependencies(output: str) -> list[tuple[str, str]]:
    """Return ``(Mach-O label, install-name)`` records from ``otool -L``."""
    label = "<unlabelled Mach-O>"
    dependencies: list[tuple[str, str]] = []
    for raw_line in output.splitlines():
        if raw_line and not raw_line[0].isspace() and raw_line.endswith(":"):
            if not raw_line.startswith("Archive :"):
                label = raw_line[:-1]
            continue
        match = _DYLIB_RE.match(raw_line)
        if match:
            dependencies.append((label, match.group(1)))
    return dependencies


def inspect_dependencies(path: Path) -> list[tuple[str, str]]:
    completed = subprocess.run(
        ["otool", "-L", str(path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"otool -L failed for {path}")
    return parse_otool_dependencies(completed.stdout)


def is_system_dependency(install_name: str) -> bool:
    return install_name.startswith(_SYSTEM_DYLIB_PREFIXES)


def inspect(path: Path) -> list[tuple[str, str]]:
    completed = subprocess.run(
        ["otool", "-l", str(path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"otool failed for {path}")
    labels = parse_otool_macho_labels(completed.stdout)
    targets = parse_otool_deployment_targets(completed.stdout)
    if not labels or not targets:
        raise RuntimeError(f"no macOS deployment-target load command found in {path}")
    target_counts = collections.Counter(label for label, _ in targets)
    malformed = [label for label in labels if target_counts[label] != 1]
    if malformed:
        raise RuntimeError(
            f"expected exactly one deployment-target load command in every Mach-O from "
            f"{path}; malformed labels: {', '.join(malformed)}"
        )
    return targets


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="required target, for example 11.0")
    parser.add_argument(
        "--system-dylibs-only",
        action="store_true",
        help="also reject non-system dynamic-library install names",
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Mach-O files or static archives")
    args = parser.parse_args()

    try:
        expected = normalized_version(args.target)
        failures: list[tuple[str, str]] = []
        dependency_failures: list[tuple[str, str]] = []
        checked = 0
        for path in args.paths:
            for label, actual_text in inspect(path):
                checked += 1
                if normalized_version(actual_text) != expected:
                    failures.append((label, actual_text))
            if args.system_dylibs_only:
                dependency_failures.extend(
                    (label, dependency)
                    for label, dependency in inspect_dependencies(path)
                    if not is_system_dependency(dependency)
                )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"deployment-target check failed: {error}", file=sys.stderr)
        return 2

    if failures:
        print(
            f"deployment-target check failed: {len(failures)} of {checked} Mach-O "
            f"objects do not target macOS {args.target}",
            file=sys.stderr,
        )
        for label, actual in failures:
            print(f"  {label}: macOS {actual}", file=sys.stderr)
        return 1

    if dependency_failures:
        print(
            "deployment-target check failed: non-system dynamic dependencies are "
            "not permitted for this release artifact",
            file=sys.stderr,
        )
        for label, dependency in dependency_failures:
            print(f"  {label}: {dependency}", file=sys.stderr)
        return 1

    suffix = " with system-only dylib dependencies" if args.system_dylibs_only else ""
    print(
        f"deployment-target check passed: {checked} Mach-O objects target macOS "
        f"{args.target}{suffix}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
