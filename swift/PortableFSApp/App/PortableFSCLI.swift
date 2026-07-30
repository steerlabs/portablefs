import Foundation
import PortableFSAppCore

private final class LifecycleHandshakeDeadline: @unchecked Sendable {
    private let lock = NSLock()
    private var finished = false
    private var timedOut = false

    func fire() -> Bool {
        lock.withLock {
            guard !finished else {
                return false
            }
            timedOut = true
            return true
        }
    }

    func finish() -> Bool {
        lock.withLock {
            finished = true
            return timedOut
        }
    }
}

/// Owns the stdin lease for a CLI lifecycle guard. EOF is the explicit release
/// signal; a crashed app also closes the pipe at process teardown.
final class PortableFSCLILease: @unchecked Sendable {
    private let process: Process
    private var stdin: FileHandle?
    private let stdout: FileHandle
    private let stderr: FileHandle
    private let command: String
    private let stateLock = NSLock()
    private var releasing = false

    init(
        process: Process,
        stdin: FileHandle,
        stdout: FileHandle,
        stderr: FileHandle,
        command: String
    ) {
        self.process = process
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.command = command
    }

    func release() {
        let handle = stateLock.withLock {
            releasing = true
            let handle = stdin
            stdin = nil
            return handle
        }
        try? handle?.close()
    }

    func waitForUnexpectedExit() async -> PortableFSCLIError? {
        await Task.detached(priority: .utility) { [self] in
            process.waitUntilExit()
            let wasReleased = stateLock.withLock {
                releasing
            }
            guard !wasReleased else {
                return nil
            }
            let diagnostic = (try? stderr.readToEnd())
                .map { String(decoding: $0, as: UTF8.self) }
                ?? ""
            return PortableFSCLIError(
                command: command,
                status: process.terminationStatus,
                detail: diagnostic.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }.value
    }

    deinit {
        release()
        try? stdout.close()
        try? stderr.close()
    }
}

struct PortableFSCLIMount: Decodable, Sendable {
    let ok: Bool
    let mountPath: String
    let volumeId: String
    let branch: String
    let attachRef: String?
}

typealias PortableFSCLIMountRow = PortableFSMountInventoryRow

private struct PortableFSCLIMounts: Decodable {
    let mounts: [PortableFSCLIMountRow]
}

struct PortableFSCLIError: LocalizedError, Sendable {
    let command: String
    let status: Int32?
    let detail: String

    var errorDescription: String? {
        if let status {
            return "\(command) exited with status \(status): \(detail)"
        }
        return "\(command) could not start: \(detail)"
    }
}

/// Strict subprocess boundary to the one bundled mount implementation.
struct PortableFSCLI: Sendable {
    private let decoder = JSONDecoder()

    func mount(volumeID: String, branch: String, mountPath: String) async throws -> PortableFSCLIMount {
        let data = try await run([
            "mount",
            volumeID,
            mountPath,
            "--branch", branch,
            "--json"
        ])
        return try decode(PortableFSCLIMount.self, from: data, command: "portablefs mount")
    }

    func unmount(mountPath: String) async throws {
        _ = try await run(["umount", mountPath, "--json"])
    }

    func mounts() async throws -> [PortableFSCLIMountRow] {
        let data = try await run(["mounts", "--json"])
        let rows = try decode(
            PortableFSCLIMounts.self,
            from: data,
            command: "portablefs mounts"
        ).mounts
        guard Set(rows.map(\.mountPath)).count == rows.count else {
            throw PortableFSCLIError(
                command: "portablefs mounts",
                status: nil,
                detail: "mount inventory contains duplicate mount paths"
            )
        }
        return rows
    }

    func holdLifecycle() async throws -> PortableFSCLILease {
        try await hold(
            arguments: ["lifecycle", "hold-shared", "--json"],
            expectedReadiness: #"{"schemaVersion":1,"held":true}"#
        )
    }

    func holdAccountExclusive() async throws -> PortableFSCLILease {
        try await hold(
            arguments: ["lifecycle", "hold-account-exclusive", "--json"],
            expectedReadiness: #"{"schemaVersion":1,"held":true,"mounts":0,"attaches":0}"#
        )
    }

    private func hold(
        arguments: [String],
        expectedReadiness: String
    ) async throws -> PortableFSCLILease {
        let executable = bundledExecutable
        let command = ([executable.path] + arguments).joined(separator: " ")
        return try await Task.detached(priority: .userInitiated) {
            guard FileManager.default.isExecutableFile(atPath: executable.path) else {
                throw PortableFSCLIError(
                    command: command,
                    status: nil,
                    detail: "the signed app bundle has no executable Contents/Helpers/portablefs"
                )
            }

            let process = Process()
            let input = Pipe()
            let output = Pipe()
            let errors = Pipe()
            process.executableURL = executable
            process.arguments = arguments
            process.standardInput = input
            process.standardOutput = output
            process.standardError = errors
            do {
                try process.run()
            } catch {
                throw PortableFSCLIError(
                    command: command,
                    status: nil,
                    detail: error.localizedDescription
                )
            }
            try? input.fileHandleForReading.close()
            try? output.fileHandleForWriting.close()
            try? errors.fileHandleForWriting.close()

            let deadline = LifecycleHandshakeDeadline()
            let watchdog = Task.detached {
                do {
                    try await Task.sleep(for: .seconds(10))
                } catch {
                    return
                }
                if deadline.fire() {
                    try? input.fileHandleForWriting.close()
                    process.terminate()
                }
            }
            defer {
                watchdog.cancel()
            }
            var line = Data()
            while line.count <= 4096 {
                guard let byte = try output.fileHandleForReading.read(upToCount: 1),
                      !byte.isEmpty else {
                    let timedOut = deadline.finish()
                    process.waitUntilExit()
                    let diagnostic = (try? errors.fileHandleForReading.readToEnd())
                        .map { String(decoding: $0, as: UTF8.self) }
                        ?? ""
                    throw PortableFSCLIError(
                        command: command,
                        status: process.terminationStatus,
                        detail: timedOut
                            ? "readiness handshake timed out after 10 seconds"
                            : diagnostic.trimmingCharacters(in: .whitespacesAndNewlines)
                    )
                }
                if byte[0] == UInt8(ascii: "\n") {
                    break
                }
                line.append(byte)
            }
            let timedOut = deadline.finish()
            guard !timedOut else {
                throw PortableFSCLIError(
                    command: command,
                    status: process.terminationStatus,
                    detail: "readiness handshake timed out after 10 seconds"
                )
            }
            guard line.count <= 4096 else {
                try? input.fileHandleForWriting.close()
                throw PortableFSCLIError(
                    command: command,
                    status: nil,
                    detail: "readiness response exceeded 4096 bytes"
                )
            }

            let expected = Data(expectedReadiness.utf8)
            guard line == expected else {
                try? input.fileHandleForWriting.close()
                throw PortableFSCLIError(
                    command: command,
                    status: nil,
                    detail: "unexpected readiness response: \(String(decoding: line, as: UTF8.self))"
                )
            }
            return PortableFSCLILease(
                process: process,
                stdin: input.fileHandleForWriting,
                stdout: output.fileHandleForReading,
                stderr: errors.fileHandleForReading,
                command: command
            )
        }.value
    }

    private func decode<Value: Decodable>(
        _ type: Value.Type,
        from data: Data,
        command: String
    ) throws -> Value {
        do {
            return try decoder.decode(type, from: data)
        } catch {
            let output = String(decoding: data, as: UTF8.self)
            throw PortableFSCLIError(
                command: command,
                status: nil,
                detail: "invalid JSON output (\(error.localizedDescription)): \(output)"
            )
        }
    }

    private func run(_ arguments: [String]) async throws -> Data {
        let executable = bundledExecutable
        let command = ([executable.path] + arguments).joined(separator: " ")

        return try await Task.detached(priority: .userInitiated) {
            guard FileManager.default.isExecutableFile(atPath: executable.path) else {
                throw PortableFSCLIError(
                    command: command,
                    status: nil,
                    detail: "the signed app bundle has no executable Contents/Helpers/portablefs"
                )
            }

            let process = Process()
            process.executableURL = executable
            process.arguments = arguments

            let temporaryDirectory = FileManager.default.temporaryDirectory
                .appendingPathComponent("portablefs-app-\(UUID().uuidString)", isDirectory: true)
            do {
                try FileManager.default.createDirectory(
                    at: temporaryDirectory,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
            } catch {
                throw PortableFSCLIError(
                    command: command,
                    status: nil,
                    detail: "create output directory: \(error.localizedDescription)"
                )
            }
            defer {
                try? FileManager.default.removeItem(at: temporaryDirectory)
            }

            let stdoutURL = temporaryDirectory.appendingPathComponent("stdout")
            let stderrURL = temporaryDirectory.appendingPathComponent("stderr")
            guard FileManager.default.createFile(
                atPath: stdoutURL.path,
                contents: nil,
                attributes: [.posixPermissions: 0o600]
            ), FileManager.default.createFile(
                atPath: stderrURL.path,
                contents: nil,
                attributes: [.posixPermissions: 0o600]
            ) else {
                throw PortableFSCLIError(
                    command: command,
                    status: nil,
                    detail: "create output files"
                )
            }

            let stdout = try FileHandle(forWritingTo: stdoutURL)
            let stderr = try FileHandle(forWritingTo: stderrURL)
            process.standardOutput = stdout
            process.standardError = stderr
            do {
                try process.run()
            } catch {
                try? stdout.close()
                try? stderr.close()
                throw PortableFSCLIError(
                    command: command,
                    status: nil,
                    detail: error.localizedDescription
                )
            }
            process.waitUntilExit()
            try stdout.close()
            try stderr.close()

            let stdoutData = try Data(contentsOf: stdoutURL)
            let stderrData = try Data(contentsOf: stderrURL)
            guard process.terminationReason == .exit, process.terminationStatus == 0 else {
                let detail = String(decoding: stderrData, as: UTF8.self)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                throw PortableFSCLIError(
                    command: command,
                    status: process.terminationStatus,
                    detail: detail.isEmpty ? "no diagnostic output" : detail
                )
            }
            return stdoutData
        }.value
    }

    private var bundledExecutable: URL {
        Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/portablefs")
    }
}
