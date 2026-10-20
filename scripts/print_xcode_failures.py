#!/usr/bin/env python3
"""Print bounded, source-located issues using Xcode's test-results JSON API."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

from verify_xcode_tests import VerificationError, load_json


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def issue_lines(details):
    for node in walk(details.get("testRuns", [])):
        kind = node.get("nodeType")
        # Xcode 27 represents Swift Testing issues as failed Test Case Run
        # nodes; XCTest can nest Failure Message nodes inside the run instead.
        if kind == "Test Case Run" and node.get("result") == "Failed":
            if any(child.get("nodeType") == "Failure Message" for child in walk(node.get("children", []))):
                continue
        elif kind != "Failure Message":
            continue
        locations = [child["sourceLocation"] for child in walk(node) if "sourceLocation" in child]
        location = locations[0] if locations else {}
        yield f"{location.get('filePath', '<no recorded file>')}:{location.get('lineNumber', 0)}: {node.get('name', '<no recorded message>')}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=pathlib.Path, required=True)
    parser.add_argument("--result-bundle", type=pathlib.Path, required=True)
    args = parser.parse_args()
    # Full JSON stays beside the xcresult. Bound console output, command time,
    # and query count even when the execution has failed across the inventory.
    remaining = 64 * 1024

    def emit(message):
        nonlocal remaining
        message = message[:remaining]
        print(message, file=sys.stderr)
        remaining -= len(message)
        if remaining <= 0:
            print("xcode test issues: output truncated at 64K characters; see retained evidence", file=sys.stderr)
            raise SystemExit(0)

    try:
        results = load_json(args.results)
        failures = list(dict.fromkeys(
            node["nodeIdentifierURL"] for node in walk(results)
            if node.get("nodeType") == "Test Case" and node.get("result") == "Failed"
        ))
        for index, identifier in enumerate(failures[:100]):
            emit(f"xcode test issues: {identifier}")
            details_path = args.result_bundle.parent / f"failed-test-{index + 1}.json"
            error_path = details_path.with_suffix(".stderr")
            with details_path.open("wb") as output, error_path.open("wb") as errors:
                try:
                    result = subprocess.run([
                        "xcrun", "xcresulttool", "get", "test-results", "test-details",
                        "--path", str(args.result_bundle), "--test-id", identifier, "--compact",
                    ], stdout=output, stderr=errors, timeout=10, check=False)
                except subprocess.TimeoutExpired:
                    emit("  xcresulttool test-details exceeded 10s; see retained evidence")
                    continue
            if result.returncode != 0:
                with error_path.open("rb") as errors:
                    emit(f"  xcresulttool failed ({result.returncode}): {errors.read(4096).decode('utf-8', errors='replace')}")
                continue
            details = load_json(details_path)
            issues = list(issue_lines(details))
            for issue in issues:
                emit("  " + issue)
            if not issues:
                emit("  no recorded issue messages; see retained test-details and xcresult")
        if len(failures) > 100:
            emit(f"xcode test issues: omitted {len(failures) - 100} tests; see retained evidence")
        if not failures:
            emit("xcode test issues: no failed test cases recorded; see retained xcresult")
    except (OSError, KeyError, VerificationError) as exc:
        emit(f"xcode test issues: cannot extract diagnostics: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
