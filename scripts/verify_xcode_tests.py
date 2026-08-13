#!/usr/bin/env python3
"""Fail-closed validation for PortableFSKit Xcode test enumeration/results."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections import Counter
from typing import Any


TEST_URL_PREFIX = "test://com.apple.xcode/PortableFSKit/"
EXPECTED_TEST_MODULES = frozenset({"PortableFSAppCoreTests", "PortableFSKitTests"})
MAX_JSON_BYTES = 16 * 1024 * 1024
SUITE_COMPONENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
TEST_COMPONENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\(\)\Z")


class VerificationError(ValueError):
    """The generated Xcode evidence does not prove the complete test run."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: pathlib.Path) -> Any:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise VerificationError(f"cannot stat {path}: {exc}") from exc
    if size <= 0 or size > MAX_JSON_BYTES:
        raise VerificationError(f"invalid JSON evidence size for {path}: {size}")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot decode {path}: {exc}") from exc


def parse_test_identifier(identifier: Any, *, source: str) -> tuple[str, ...]:
    if not isinstance(identifier, str):
        raise VerificationError(f"invalid {source} test identifier: {identifier!r}")
    components = tuple(identifier.split("/"))
    if len(components) < 2:
        raise VerificationError(f"invalid {source} test identifier: {identifier!r}")
    module, *suites, test = components
    if module not in EXPECTED_TEST_MODULES:
        raise VerificationError(f"unexpected {source} test module: {module!r}")
    if any(SUITE_COMPONENT.fullmatch(suite) is None for suite in suites):
        raise VerificationError(f"invalid {source} test suite path: {identifier!r}")
    if TEST_COMPONENT.fullmatch(test) is None:
        raise VerificationError(f"invalid {source} test case: {identifier!r}")
    return components


def parse_enumeration(document: Any) -> tuple[str, ...]:
    if not isinstance(document, dict):
        raise VerificationError("Xcode enumeration root is not a dictionary")
    if document.get("errors") != []:
        raise VerificationError(f"Xcode enumeration reported errors: {document.get('errors')!r}")
    values = document.get("values")
    if not isinstance(values, list) or not values:
        raise VerificationError("Xcode enumeration has no values")

    identifiers: list[str] = []
    for index, value in enumerate(values):
        if not isinstance(value, dict):
            raise VerificationError(f"Xcode enumeration value {index} is not a dictionary")
        if value.get("disabledTests") != []:
            raise VerificationError(f"Xcode enumeration contains disabled tests in value {index}")
        enabled = value.get("enabledTests")
        if not isinstance(enabled, list):
            raise VerificationError(f"Xcode enumeration value {index} has no enabledTests list")
        for test in enabled:
            if not isinstance(test, dict):
                raise VerificationError("Xcode enumeration contains a non-dictionary test")
            identifier = test.get("identifier")
            parse_test_identifier(identifier, source="enumerated")
            identifiers.append(identifier)

    if not identifiers:
        raise VerificationError("Xcode enumerated zero tests")
    duplicates = sorted(name for name, count in Counter(identifiers).items() if count != 1)
    if duplicates:
        raise VerificationError(f"Xcode enumeration contains duplicate tests: {duplicates[:5]}")
    modules = {identifier.split("/", 1)[0] for identifier in identifiers}
    if modules != EXPECTED_TEST_MODULES:
        raise VerificationError(
            f"Xcode enumeration module set mismatch: expected {sorted(EXPECTED_TEST_MODULES)}, "
            f"got {sorted(modules)}"
        )
    return tuple(sorted(identifiers))


def _walk_test_cases(value: Any, cases: list[tuple[str, str]]) -> None:
    if isinstance(value, dict):
        if value.get("nodeType") == "Test Case":
            url = value.get("nodeIdentifierURL")
            result = value.get("result")
            if not isinstance(url, str) or not url.startswith(TEST_URL_PREFIX):
                raise VerificationError(f"unexpected Xcode test URL: {url!r}")
            if not isinstance(result, str):
                raise VerificationError(f"test {url} has no string result")
            identifier = url.removeprefix(TEST_URL_PREFIX)
            parse_test_identifier(identifier, source="result")
            cases.append((identifier, result))
        for child in value.values():
            _walk_test_cases(child, cases)
    elif isinstance(value, list):
        for child in value:
            _walk_test_cases(child, cases)


def parse_results(document: Any, architecture: str) -> tuple[tuple[str, str], ...]:
    if architecture not in {"arm64", "x86_64"}:
        raise VerificationError(f"unsupported expected architecture: {architecture}")
    if not isinstance(document, dict):
        raise VerificationError("Xcode result root is not a dictionary")
    devices = document.get("devices")
    if not isinstance(devices, list) or len(devices) != 1:
        raise VerificationError(f"Xcode result must name exactly one device: {devices!r}")
    device = devices[0]
    if not isinstance(device, dict):
        raise VerificationError("Xcode result device is not a dictionary")
    if device.get("platform") != "macOS" or device.get("architecture") != architecture:
        raise VerificationError(
            "Xcode result destination mismatch: "
            f"platform={device.get('platform')!r} architecture={device.get('architecture')!r}"
        )

    cases: list[tuple[str, str]] = []
    _walk_test_cases(document.get("testNodes"), cases)
    if not cases:
        raise VerificationError("Xcode result contains zero test cases")
    duplicates = sorted(name for name, count in Counter(name for name, _ in cases).items() if count != 1)
    if duplicates:
        raise VerificationError(f"Xcode result contains duplicate test cases: {duplicates[:5]}")
    return tuple(sorted(cases))


def verify(enumeration: Any, results: Any | None, architecture: str | None) -> str:
    expected = parse_enumeration(enumeration)
    module_counts = Counter(identifier.split("/", 1)[0] for identifier in expected)
    summary = ", ".join(f"{module}={module_counts[module]}" for module in sorted(module_counts))
    if results is None:
        return f"xcode-test-enumeration: tests={len(expected)} unique={len(set(expected))} {summary}"
    if architecture is None:
        raise VerificationError("architecture is required when validating results")

    cases = parse_results(results, architecture)
    actual = tuple(name for name, _ in cases)
    failed = [(name, result) for name, result in cases if result != "Passed"]
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    if failed or missing or unexpected or len(actual) != len(expected):
        raise VerificationError(
            "Xcode execution does not exactly match enumeration: "
            f"expected={len(expected)} actual={len(actual)} "
            f"failed={failed[:5]} missing={missing[:5]} unexpected={unexpected[:5]}"
        )
    return f"xcode-test-results: tests={len(actual)} unique={len(set(actual))} all=Passed {summary}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--enumeration", type=pathlib.Path, required=True)
    parser.add_argument("--results", type=pathlib.Path)
    parser.add_argument("--architecture", choices=("arm64", "x86_64"))
    args = parser.parse_args()
    try:
        enumeration = load_json(args.enumeration)
        results = load_json(args.results) if args.results else None
        print(verify(enumeration, results, args.architecture))
    except VerificationError as exc:
        print(f"xcode test evidence rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
