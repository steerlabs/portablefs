import Foundation
import PortableFSAppCore

enum MountCommandError: Error, CustomStringConvertible {
    case failed(command: String, exitCode: Int32, output: String)

    var description: String {
        switch self {
        case let .failed(command, exitCode, output):
            let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
            return "`\(command)` exited \(exitCode)" + (trimmed.isEmpty ? "" : ":\n\(trimmed)")
        }
    }
}

/// Kernel mount plumbing. The mount invocation is exactly the one the manual
/// FSKit verification loop and the live 15-check battery use:
/// `/sbin/mount -t pfs pfs://<attachRef> <mountPath>`.
enum MountCommand {
    static func hasLiveMount(attachRef: String, mountPath: String) -> Bool {
        MountTable.current().contains {
            $0.mountPoint == mountPath &&
                $0.fsTypeName == MountTable.portableFSRuntimeTypeName &&
                $0.mountedFrom == "pfs://\(attachRef)"
        }
    }

    static func mount(attachRef: String, mountPath: String) async throws {
        try await run([
            "/sbin/mount", "-t", MountTable.portableFSRegistrationTypeName,
            "pfs://\(attachRef)", mountPath,
        ])
    }

    static func waitUntilReady(
        attachRef: String,
        mountPath: String,
        timeout: Duration = .seconds(15)
    ) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        let expectedSource = "pfs://\(attachRef)"
        var lastDetail = "mount is not in the kernel mount table"
        while clock.now < deadline {
            if let mount = MountTable.current().first(where: { $0.mountPoint == mountPath }) {
                if mount.fsTypeName != MountTable.portableFSRuntimeTypeName {
                    lastDetail = "filesystem type is \(mount.fsTypeName), expected \(MountTable.portableFSRuntimeTypeName)"
                } else if mount.mountedFrom != expectedSource {
                    lastDetail = "mount source is \(mount.mountedFrom), expected \(expectedSource)"
                } else {
                    do {
                        _ = try FileManager.default.contentsOfDirectory(atPath: mountPath)
                        return
                    } catch {
                        lastDetail = "root enumeration failed: \(error)"
                    }
                }
            }
            try? await Task.sleep(for: .milliseconds(100))
        }
        throw MountCommandError.failed(
            command: "verify FSKit mount \(mountPath)",
            exitCode: 1,
            output: "mount did not become usable within \(timeout): \(lastDetail)"
        )
    }

    /// One explicit kernel-unmount path. A failure is surfaced to the caller;
    /// the app never switches to a second command with different semantics.
    static func unmount(mountPath: String) async throws {
        try await run(["/sbin/umount", mountPath])
    }

    private static func run(_ argv: [String]) async throws {
        let result = await capture(argv)
        guard result.exitCode == 0 else {
            throw MountCommandError.failed(
                command: argv.joined(separator: " "),
                exitCode: result.exitCode,
                output: result.output
            )
        }
    }

    private static func capture(_ argv: [String]) async -> (exitCode: Int32, output: String) {
        await withCheckedContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: argv[0])
            process.arguments = Array(argv.dropFirst())
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            process.terminationHandler = { finished in
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                continuation.resume(returning: (
                    finished.terminationStatus,
                    String(data: data, encoding: .utf8) ?? ""
                ))
            }
            do {
                try process.run()
            } catch {
                process.terminationHandler = nil
                continuation.resume(returning: (127, String(describing: error)))
            }
        }
    }
}
