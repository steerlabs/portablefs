#!/usr/bin/env python3
"""Exercise the real embedding script's target, configuration and slice mapping."""

import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
EMBED = ROOT / "swift/PortableFSApp/Scripts/embed-portablefs-tools.sh"


@unittest.skipUnless(sys.platform == "darwin", "embedding uses native macOS tools")
class EmbeddedCLIContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="portablefs-embed-")
        self.addCleanup(self.temporary.cleanup)
        self.work = pathlib.Path(self.temporary.name).resolve()
        self.log = self.work / "compiler.jsonl"
        self.compiler = self.work / "go-fixture"
        go_version = re.search(r"^go (\S+)$", (ROOT / "vcs/go.mod").read_text(), re.M).group(1)
        # The compiler records exact build inputs and emits genuine Mach-O
        # slices, so the script still runs its real lipo and plist operations.
        self.compiler.write_text(f"""#!{sys.executable}
import json, os, pathlib, subprocess, sys
args = sys.argv[1:]
if args == ['version']:
    print('go version go{go_version} darwin/arm64')
    sys.exit(0)
with open({str(self.log)!r}, 'a') as log:
    log.write(json.dumps({{'args': args, 'arch': os.environ['GOARCH'], 'cgo': os.environ['CGO_ENABLED']}}) + '\\n')
output = args[args.index('-o') + 1]
arch = {{'arm64': 'arm64', 'amd64': 'x86_64'}}[os.environ['GOARCH']]
subprocess.run(['/usr/bin/clang', '-arch', arch, '-x', 'c', '-', '-o', output], input=b'int main(void) {{ return 0; }}', check=True)
""")
        self.compiler.chmod(0o755)

    def environment(self, target, configuration):
        development = target == "PortableFSKitDev"
        product = "PortableFSKitDev" if development else "PortableFS"
        return dict(os.environ, TARGET_NAME=target, CONFIGURATION=configuration,
                    FULL_PRODUCT_NAME=product + ".app", EXECUTABLE_NAME=product,
                    PRODUCT_BUNDLE_IDENTIFIER="dev.portablefs.oss.KitDev" if development else "org.example.portablefs",
                    MACOSX_DEPLOYMENT_TARGET="26.0", MARKETING_VERSION=(ROOT / "VERSION").read_text().strip(),
                    CURRENT_PROJECT_VERSION="1", TARGET_BUILD_DIR=str(self.work / "products"),
                    CONTENTS_FOLDER_PATH=product + ".app/Contents", TARGET_TEMP_DIR=str(self.work / "intermediates"),
                    PORTABLEFS_GO=str(self.compiler), PORTABLEFS_APP_GROUP="B47U2LLKHW.pfsoss",
                    ARCHS="arm64 x86_64", CODE_SIGNING_ALLOWED="NO")

    def test_each_target_configuration_and_architecture_passes_only_cli_tag(self):
        for target in ("PortableFSApp", "PortableFSKitDev"):
            for configuration in ("Debug", "Release"):
                with self.subTest(target=target, configuration=configuration):
                    self.log.unlink(missing_ok=True)
                    result = subprocess.run(["/bin/sh", str(EMBED)], env=self.environment(target, configuration), capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    calls = [json.loads(line) for line in self.log.read_text().splitlines()]
                    self.assertEqual(len(calls), 4)
                    self.assertEqual({(call["args"][-1], call["arch"]) for call in calls},
                                     {(tool, arch) for tool in ("./cmd/portablefs", "./cmd/portablefsd") for arch in ("arm64", "amd64")})
                    for call in calls:
                        args = call["args"]
                        tags = args[args.index("-tags") + 1]
                        expected = "portablefs_devhost" if target == "PortableFSKitDev" and args[-1] == "./cmd/portablefs" else ""
                        self.assertEqual(tags, expected)
                        self.assertEqual(call["cgo"], "1")

    def test_unknown_or_inconsistent_target_refuses_before_building(self):
        for key, value in (("TARGET_NAME", "Unknown"), ("PRODUCT_BUNDLE_IDENTIFIER", "org.example.wrong"),
                           ("FULL_PRODUCT_NAME", "PortableFS.app"), ("EXECUTABLE_NAME", "PortableFS"),
                           ("MACOSX_DEPLOYMENT_TARGET", "27.0")):
            with self.subTest(key=key):
                env = self.environment("PortableFSKitDev", "Release")
                env[key] = value
                result = subprocess.run(["/bin/sh", str(EMBED)], env=env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.log.exists(), result.stderr)


if __name__ == "__main__":
    unittest.main()
