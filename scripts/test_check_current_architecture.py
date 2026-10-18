#!/usr/bin/env python3
"""Unit tests for the parsers inside check-current-architecture.py.

The checker's assertions are only as strong as its parsing. These tests pin
the parsing on small fixtures so that a parser defect fails here rather than
silently weakening an architecture assertion over the real tree.
"""

from __future__ import annotations

import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).with_name("check-current-architecture.py")
SPEC = importlib.util.spec_from_file_location("check_current_architecture", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


PROTO = """
syntax = "proto3";
package demo.v1;
// reserved in a comment is not a declaration
message Outer {
  uint64 id = 1; // trailing comment = 9;
  message Inner { uint32 hidden = 7; }
  enum Kind { KIND_UNSPECIFIED = 0; KIND_A = 1; }
  repeated Inner inner = 2;
  oneof body {
    Inner first = 10;
    Inner second = 11;
  }
}
enum Profile {
  PROFILE_UNSPECIFIED = 0;
  PROFILE_LINUX = 1;
}
"""


class ProtoParsing(unittest.TestCase):
    def setUp(self) -> None:
        self.source = checker.strip_proto_comments(PROTO)

    def test_comments_are_not_declarations(self) -> None:
        self.assertNotIn("reserved", self.source)
        self.assertNotIn("= 9", self.source)

    def test_message_fields_skip_nested_declarations(self) -> None:
        fields = checker.proto_fields(checker.proto_block(self.source, "message", "Outer"))
        self.assertEqual(fields, {"id": 1, "inner": 2, "first": 10, "second": 11})

    def test_oneof_arms(self) -> None:
        outer = checker.proto_block(self.source, "message", "Outer")
        self.assertEqual(checker.proto_oneof(outer, "body"), {"first": 10, "second": 11})

    def test_enum_values_in_order(self) -> None:
        values = checker.proto_enum(checker.proto_block(self.source, "enum", "Profile"))
        self.assertEqual(values, [("PROFILE_UNSPECIFIED", 0), ("PROFILE_LINUX", 1)])

    def test_missing_declaration_fails(self) -> None:
        with self.assertRaises(checker.CheckFailure):
            checker.proto_block(self.source, "message", "Absent")


class WireFixtures(unittest.TestCase):
    # The current shared Hello fixtures: length prefix, request_id 1, then the
    # Hello (field 10) or HelloReply (field 60) body.
    HELLO_REQUEST = "120000000801520e08021a0573776966742203312e30"
    HELLO_REPLY = "1d0000000801e2031808021a10706f727461626c656673642d7465737420e0d403"

    def test_hello_versions(self) -> None:
        self.assertEqual(checker.hello_version(checker.pfslocal_frame(self.HELLO_REQUEST), 10), (2, 0))
        self.assertEqual(checker.hello_version(checker.pfslocal_frame(self.HELLO_REPLY), 60), (2, 0))

    def test_explicit_minor(self) -> None:
        # Hello{major 1, minor 16} under field 10.
        envelope = bytes([0x52, 0x04, 0x08, 0x01, 0x10, 0x10])
        self.assertEqual(checker.hello_version(envelope, 10), (1, 16))

    def test_length_prefix_must_match(self) -> None:
        with self.assertRaises(ValueError):
            checker.pfslocal_frame("05000000" + "0801")

    def test_truncated_varint(self) -> None:
        with self.assertRaises(ValueError):
            checker.protobuf_fields(bytes([0x08, 0x80]))


class GoConstants(unittest.TestCase):
    def test_forms(self) -> None:
        text = """
const ProtocolMajor uint32 = 8
const (
	ControlProtocolVersion = 2
	ControlPathPrefix      = "/v2/" // operational routes
)
"""
        self.assertEqual(checker.go_const(text, "ProtocolMajor"), "8")
        self.assertEqual(checker.go_const(text, "ControlProtocolVersion"), "2")
        self.assertEqual(checker.go_const(text, "ControlPathPrefix"), "/v2/")
        self.assertIsNone(checker.go_const(text, "Absent"))

    def test_flag_definitions(self) -> None:
        text = """
	flag.StringVar(&o.root, "root", "", "root")
	quiet := flag.Bool("quiet", false, "quiet")
	flag.Var(&rules, "local-dir", "refused")
	fs.DurationVar(&d, "withdrawal-timeout", time.Second, "bound")
"""
        names = set(checker.GO_FLAG.findall(text)) | set(checker.GO_FLAG_VAR.findall(text))
        self.assertEqual(names, {"root", "quiet", "local-dir", "withdrawal-timeout"})


class CommandLines(unittest.TestCase):
    def test_continuations_and_build_paths(self) -> None:
        text = "\n".join([
            "go build -o out ./cmd/portablefs-authority",
            "exec /home/portablefs/bin/portablefs-authority \\",
            "  --root /srv \\",
            "  -volume-id v",
            "systemctl start portablefs-authority@vol.service",
            "portablefs-authority --listen=:7443",
        ])
        commands = list(checker.command_lines(text, "portablefs-authority"))
        self.assertEqual([line for line, _ in commands], [2, 6])
        flags = [checker.SHELL_FLAG.findall(command) for _, command in commands]
        self.assertEqual(flags, [["root", "volume-id"], ["listen"]])

    def test_values_are_not_flags(self) -> None:
        self.assertEqual(checker.SHELL_FLAG.findall(' --offset -1 --name "a-b" x--y'), ["offset", "name"])


class Markdown(unittest.TestCase):
    def test_anchors(self) -> None:
        text = "# Title\n## Two limits that apply to every deployment\n## Repeat\n## Repeat\n```\n# not a heading\n```\n## `code` and [link](x.md)\n"
        self.assertEqual(
            checker.heading_anchors(text),
            {"title", "two-limits-that-apply-to-every-deployment", "repeat", "repeat-1", "code-and-link"},
        )

    def test_code_is_not_scanned_for_links(self) -> None:
        text = "see [a](a.md)\n```\n[b](b.md)\n```\n`[c](c.md)` and [d](d.md#x)\n"
        links = checker.LINK.findall(checker.markdown_without_code(text))
        self.assertEqual(links, ["a.md", "d.md#x"])

    def test_images_are_not_links(self) -> None:
        self.assertEqual(checker.LINK.findall("![alt](pic.png) [t](doc.md)"), ["doc.md"])


class ProtocolMentions(unittest.TestCase):
    def pattern(self):
        import re
        return re.compile(r"(?<![Ff][Uu][Ss][Ee] )\b[Pp]rotocol[- ]([0-9]+)\b(?![.0-9])")

    def test_generation_mentions(self) -> None:
        pattern = self.pattern()
        self.assertEqual(pattern.findall("protocol 8, protocol-7 and Protocol 6"), ["8", "7", "6"])

    def test_fuse_and_dotted_versions_are_not_generations(self) -> None:
        pattern = self.pattern()
        self.assertEqual(pattern.findall("FUSE protocol 7.31 and kernel protocol 7.31"), [])
        self.assertEqual(pattern.findall("fuse protocol 7"), [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
