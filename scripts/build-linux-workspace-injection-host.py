#!/usr/bin/env python3
"""Build a disposable host-only root-console fixture for RTC ptrace tests.

The guest kernel, initramfs, system disk and client binaries remain the sealed
candidate. Neither the product service nor its VM adapter gains a debug mode.
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('output', type=pathlib.Path)
parser.add_argument('--repo', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
parser.add_argument('--source-commit', default='HEAD')
options = parser.parse_args()
repo = options.repo.resolve()
output = options.output.resolve()
assert not output.exists() or not any(output.iterdir()), 'output must be empty'
assert not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain']), 'commit fixture inputs first'
commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', '--verify', options.source_commit + '^{commit}'], text=True).strip()
output.mkdir(parents=True, exist_ok=True)
package = output / 'package'
package.mkdir()
targets = {'CWorkspacePower', 'PortableFSKit', 'PortableFSAppCore', 'PortableFSWorkspaceCore',
           'PortableFSWorkspaceVM', 'PortableFSWorkspaceDev'}
prefix = 'swift/PortableFSKit/'
paths = subprocess.check_output(['git', '-C', str(repo), 'ls-tree', '-rz', '--name-only', commit, '--', prefix + 'Sources']).decode().split('\0')
for name in paths:
    if not name:
        continue
    relative = pathlib.PurePosixPath(name.removeprefix(prefix))
    if relative.parts[1] not in targets or relative.suffix not in {'.swift', '.c', '.h', '.modulemap'}:
        continue
    destination = package / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(subprocess.check_output(['git', '-C', str(repo), 'show', commit + ':' + name]))

(package / 'Package.swift').write_text('''// swift-tools-version: 6.2
import PackageDescription
let commit = "COMMIT"
let package = Package(name: "WorkspaceRTCInjectionHost", platforms: [.macOS(.v26)],
    products: [.executable(name: "portablefs-workspace-dev", targets: ["PortableFSWorkspaceDev"])],
    dependencies: [.package(url: "https://github.com/apple/swift-protobuf.git", exact: "1.39.0")],
    targets: [
        .target(name: "CWorkspacePower", cSettings: [.define("PFS_WORKSPACE_BUILD_COMMIT", to: "\\\"" + commit + "\\\"")]),
        .target(name: "PortableFSKit", dependencies: [.product(name: "SwiftProtobuf", package: "swift-protobuf")]),
        .target(name: "PortableFSAppCore", dependencies: ["PortableFSKit"], linkerSettings: [.linkedLibrary("bsm")]),
        .target(name: "PortableFSWorkspaceCore", dependencies: ["PortableFSAppCore", .product(name: "SwiftProtobuf", package: "swift-protobuf")]),
        .target(name: "PortableFSWorkspaceVM", dependencies: ["PortableFSWorkspaceCore", "CWorkspacePower"]),
        .executableTarget(name: "PortableFSWorkspaceDev", dependencies: ["PortableFSWorkspaceVM"])
    ])
'''.replace('"COMMIT"', json.dumps(commit)))

proof = dict(source_commit=commit, guest_image_modified=False, host_only_changes=[], files={})


def patch(relative, replacements):
    path = package / relative
    original = path.read_text()
    changed = original
    for before, after in replacements:
        assert changed.count(before) == 1, ('fixture source changed', relative, before)
        changed = changed.replace(before, after)
    path.write_text(changed)
    proof['files'][relative] = dict(original_sha256=hashlib.sha256(original.encode()).hexdigest(),
                                   fixture_sha256=hashlib.sha256(changed.encode()).hexdigest())


patch('Sources/PortableFSWorkspaceVM/WorkspaceMachine.swift', [
    (' panic=-1 systemd.show_status=1 ', ' panic=-1 systemd.debug_shell=hvc0 systemd.show_status=1 '),
    ('    public func seed(_ payload:', '''    public func testConsoleInput(_ data: Data) throws {
        try serialInput.fileHandleForWriting.write(contentsOf: data)
    }
    public func seed(_ payload:'''),
])
patch('Sources/PortableFSWorkspaceDev/WorkspaceDev.swift', [
    ('            case "test-hold-host":', '''            case "test-root-input":
                guard ready, coordinator.phase == .running, let encoded = value["body"],
                      let data = Data(base64Encoded: encoded), data.count <= 8192 else {
                    event("refused", ["command": command]); continue
                }
                do { try vm.testConsoleInput(data); event("test-root-input-written") }
                catch { fail(error) }
            case "test-hold-host":'''),
])
proof['host_only_changes'] = ['systemd.debug_shell=hvc0 on the disposable VM kernel command line',
                              'bounded private dev stdin command to the existing console input']
subprocess.run(['swift', 'build', '--jobs', '4', '--package-path', str(package), '--product', 'portablefs-workspace-dev'], check=True)
binary_dir = pathlib.Path(subprocess.check_output(['swift', 'build', '--package-path', str(package), '--show-bin-path'], text=True).strip())
binary = output / 'portablefs-workspace-dev'
shutil.copy2(binary_dir / binary.name, binary)
subprocess.run(['codesign', '--force', '--sign', '-', '--entitlements',
                str(repo / 'deploy/linux-workspace/dev.entitlements'), str(binary)], check=True)
subprocess.run(['codesign', '--verify', '--strict', str(binary)], check=True)
proof['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
(output / 'host-fixture.json').write_text(json.dumps(proof, indent=2) + '\n')
print(binary)
