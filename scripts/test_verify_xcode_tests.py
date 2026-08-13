#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("verify_xcode_tests.py")
SPEC = importlib.util.spec_from_file_location("verify_xcode_tests", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verify_xcode_tests = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_xcode_tests)


def enumeration(*identifiers: str, disabled: list[dict[str, str]] | None = None) -> dict:
    return {
        "errors": [],
        "values": [
            {
                "disabledTests": [] if disabled is None else disabled,
                "enabledTests": [{"identifier": identifier} for identifier in identifiers],
            }
        ],
    }


def results(*cases: tuple[str, str], architecture: str = "arm64") -> dict:
    return {
        "devices": [{"architecture": architecture, "platform": "macOS"}],
        "testNodes": [
            {
                "children": [
                    {
                        "nodeType": "Test Case",
                        "nodeIdentifierURL": verify_xcode_tests.TEST_URL_PREFIX + identifier,
                        "result": result,
                    }
                    for identifier, result in cases
                ]
            }
        ],
    }


class XcodeEvidenceTests(unittest.TestCase):
    identifiers = (
        "PortableFSAppCoreTests/appCorePasses()",
        "PortableFSKitTests/PfsLocalMockDaemonTests/kitPasses()",
    )

    def test_exact_enumeration_and_results_pass(self) -> None:
        enum = enumeration(*self.identifiers)
        result = results(*(pair for pair in ((name, "Passed") for name in self.identifiers)))
        self.assertIn("tests=2 unique=2", verify_xcode_tests.verify(enum, result, "arm64"))

    def test_enumeration_rejects_errors_disabled_duplicates_and_unknown_modules(self) -> None:
        bad_error = enumeration(*self.identifiers)
        bad_error["errors"] = [{"message": "discovery failed"}]
        candidates = [
            bad_error,
            enumeration(*self.identifiers, disabled=[{"identifier": "PortableFSKitTests/disabled()"}]),
            enumeration(self.identifiers[0], self.identifiers[0], self.identifiers[1]),
            enumeration(self.identifiers[0], "OtherTests/untrusted()"),
        ]
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                with self.assertRaises(verify_xcode_tests.VerificationError):
                    verify_xcode_tests.parse_enumeration(candidate)

    def test_identifier_parser_accepts_nested_suites_and_rejects_noncanonical_paths(self) -> None:
        accepted = (
            "PortableFSKitTests/kitPasses()",
            "PortableFSKitTests/PfsLocalMockDaemonTests/kitPasses()",
            "PortableFSKitTests/OuterSuite/InnerSuite/kitPasses()",
        )
        for identifier in accepted:
            with self.subTest(identifier=identifier):
                self.assertEqual(
                    "/".join(verify_xcode_tests.parse_test_identifier(identifier, source="test")),
                    identifier,
                )

        rejected = (
            "PortableFSKitTests",
            "PortableFSKitTests//kitPasses()",
            "PortableFSKitTests/../kitPasses()",
            "PortableFSKitTests/Suite()/kitPasses()",
            "PortableFSKitTests/Suite/kitPasses",
            "PortableFSKitTests/Suite/kit passes()",
            "/PortableFSKitTests/kitPasses()",
            "OtherTests/Suite/kitPasses()",
        )
        for identifier in rejected:
            with self.subTest(identifier=identifier):
                with self.assertRaises(verify_xcode_tests.VerificationError):
                    verify_xcode_tests.parse_test_identifier(identifier, source="test")

    def test_results_reject_failure_missing_unexpected_duplicate_and_wrong_destination(self) -> None:
        enum = enumeration(*self.identifiers)
        candidates = [
            results((self.identifiers[0], "Failed"), (self.identifiers[1], "Passed")),
            results((self.identifiers[0], "Passed")),
            results(
                (self.identifiers[0], "Passed"),
                (self.identifiers[1], "Passed"),
                ("PortableFSKitTests/unexpected()", "Passed"),
            ),
            results(
                (self.identifiers[0], "Passed"),
                (self.identifiers[0], "Passed"),
                (self.identifiers[1], "Passed"),
            ),
            results(*(pair for pair in ((name, "Passed") for name in self.identifiers)), architecture="x86_64"),
        ]
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                with self.assertRaises(verify_xcode_tests.VerificationError):
                    verify_xcode_tests.verify(enum, candidate, "arm64")

    def test_json_loader_rejects_duplicate_keys_and_unbounded_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            duplicate = pathlib.Path(directory, "duplicate.json")
            duplicate.write_text('{"errors":[],"errors":[]}', encoding="utf-8")
            with self.assertRaises(verify_xcode_tests.VerificationError):
                verify_xcode_tests.load_json(duplicate)

            oversized = pathlib.Path(directory, "oversized.json")
            oversized.write_bytes(b" " * (verify_xcode_tests.MAX_JSON_BYTES + 1))
            with self.assertRaises(verify_xcode_tests.VerificationError):
                verify_xcode_tests.load_json(oversized)

    def test_real_json_round_trip_preserves_exact_contract(self) -> None:
        enum = json.loads(json.dumps(enumeration(*self.identifiers)))
        result = json.loads(
            json.dumps(results(*(pair for pair in ((name, "Passed") for name in self.identifiers))))
        )
        self.assertIn("all=Passed", verify_xcode_tests.verify(enum, result, "arm64"))


if __name__ == "__main__":
    unittest.main()
