import Darwin
import Foundation
import ServiceManagement

public enum WorkspaceRemoval {
    public enum DataDisposition: String, Codable, Sendable { case keep, delete }
    public struct Outcome: Sendable { public let data: DataDisposition }

    /// Callers obtain explicit destructive confirmation before choosing delete.
    /// A synced checkpoint outside the data directory lets a second invocation
    /// finish after unregister, SSH removal, or a partial local-data deletion.
    @MainActor public static func remove(data: DataDisposition, bundle: Bundle = .main, home: URL? = nil) async throws -> Outcome {
        let home = try home ?? URL(fileURLWithPath: PortableFSAccountHome.resolve(), isDirectory: true)
        guard let id = bundle.bundleIdentifier else { throw PortableFSSignedServiceError.invalidBundle }
        _ = try PortableFSSignedRelease(bundle: bundle)
        let client = PortableFSWorkspaceClient(bundle: bundle, home: home)
        let service = SMAppService.agent(plistName: id + ".workspace.plist")
        if (service.status == .notRegistered || service.status == .notFound),
           !FileManager.default.fileExists(atPath: home.appendingPathComponent(".local/state/portablefs/workspace").path),
           !FileManager.default.fileExists(atPath: home.appendingPathComponent(".local/state/portablefs/workspace-removal.json").path) {
            try PortableFSWorkspaceSSH.remove(home: home)
            return Outcome(data: data)
        }
        return try await run(data: data, home: home, actions: Actions(
            stop: { try await client.perform(.stop) }, status: { try await client.perform(.status) },
            quiesce: { try await client.quiesce() },
            unregister: {
                if service.status != .notRegistered && service.status != .notFound { try await service.unregister() }
                guard service.status == .notRegistered || service.status == .notFound else { throw PortableFSWorkspaceError("Linux Workspace is still registered") }
            }, removeSSH: { try PortableFSWorkspaceSSH.remove(home: home) }
        ))
    }

    struct Actions {
        var stop: @MainActor () async throws -> PortableFSWorkspaceStatus
        var status: @MainActor () async throws -> PortableFSWorkspaceStatus
        var quiesce: @MainActor () async throws -> Void
        var unregister: @MainActor () async throws -> Void
        var removeSSH: @MainActor () throws -> Void
    }
    private struct Checkpoint: Codable { var version = 1; let data: DataDisposition; var phase: String }
    @MainActor static func run(data: DataDisposition, home: URL, actions: Actions) async throws -> Outcome {
        let account = home.appendingPathComponent(".local/state/portablefs", isDirectory: true)
        try FileManager.default.createDirectory(at: account, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let lock = try RemovalLock(account.appendingPathComponent("workspace-removal.lock"), create: true)
        defer { withExtendedLifetime(lock) {} }
        let journal = account.appendingPathComponent("workspace-removal.json")
        var checkpoint: Checkpoint
        if FileManager.default.fileExists(atPath: journal.path) {
            checkpoint = try JSONDecoder().decode(Checkpoint.self, from: readOwned(journal))
            guard checkpoint.version == 1, ["quiesced", "unregistered", "ssh-removed", "complete"].contains(checkpoint.phase) else { throw PortableFSWorkspaceError("Complete the previous Linux Workspace removal first") }
            if checkpoint.phase == "complete" {
                if data == .keep || checkpoint.data == .delete { return Outcome(data: data) }
                checkpoint = Checkpoint(data: data, phase: "ssh-removed")
                try save(checkpoint, to: journal)
            }
            guard checkpoint.data == data else { throw PortableFSWorkspaceError("Complete the previous Linux Workspace removal first") }
        } else {
            let deadline = ContinuousClock.now.advanced(by: .seconds(180))
            var state = try await actions.status()
            if state.state != "stopped" || state.desiredRunning { state = try await actions.stop() }
            while true {
                if state.someChangesWereNotSaved { throw PortableFSWorkspaceError("Some changes were not saved") }
                if state.previousWriteOutcomeUnknown { throw PortableFSWorkspaceError("Previous write outcome unknown") }
                if let busy = state.volumes.first(where: { $0.state == "busy" }) { throw PortableFSWorkspaceError(busy.message) }
                if ["refused", "cleanup-required", "busy"].contains(state.state) { throw PortableFSWorkspaceError(state.message) }
                if state.state == "stopped" && !state.desiredRunning { break }
                guard ContinuousClock.now < deadline else { throw PortableFSWorkspaceError("Linux Workspace is still running") }
                try await Task.sleep(for: .milliseconds(100))
                state = try await actions.status()
            }
            try await actions.quiesce()
            checkpoint = Checkpoint(data: data, phase: "quiesced")
            try save(checkpoint, to: journal)
        }
        if checkpoint.phase == "quiesced" {
            try await actions.unregister()
            checkpoint.phase = "unregistered"; try save(checkpoint, to: journal)
        }
        let directory = account.appendingPathComponent("workspace", isDirectory: true)
        var singleton: RemovalLock?
        if FileManager.default.fileExists(atPath: directory.path) {
            let deadline = ContinuousClock.now.advanced(by: .seconds(20))
            while singleton == nil {
                do { singleton = try RemovalLock(directory.appendingPathComponent("service.lock"), create: checkpoint.phase == "ssh-removed") }
                catch {
                    guard ContinuousClock.now < deadline else { throw PortableFSWorkspaceError("Linux Workspace service has not exited") }
                    try await Task.sleep(for: .milliseconds(100))
                }
            }
        }
        defer { withExtendedLifetime(singleton) {} }
        if checkpoint.phase == "unregistered" {
            try actions.removeSSH()
            checkpoint.phase = "ssh-removed"; try save(checkpoint, to: journal)
        }
        if data == .delete, FileManager.default.fileExists(atPath: directory.path) {
            guard directory.standardizedFileURL == directory.resolvingSymlinksInPath().standardizedFileURL else { throw PortableFSWorkspaceError("Unsafe workspace data directory") }
            try FileManager.default.removeItem(at: directory)
        }
        checkpoint.phase = "complete"; try save(checkpoint, to: journal)
        return Outcome(data: data)
    }
    public static func removalPending(home: URL) throws -> Bool {
        let journal = home.appendingPathComponent(".local/state/portablefs/workspace-removal.json")
        guard FileManager.default.fileExists(atPath: journal.path) else { return false }
        let checkpoint = try JSONDecoder().decode(Checkpoint.self, from: readOwned(journal))
        guard checkpoint.version == 1 else { throw PortableFSWorkspaceError("Invalid workspace removal checkpoint") }
        return checkpoint.phase != "complete"
    }
    static func completed(home: URL) throws -> Bool {
        let journal = home.appendingPathComponent(".local/state/portablefs/workspace-removal.json")
        guard FileManager.default.fileExists(atPath: journal.path) else { return false }
        let checkpoint = try JSONDecoder().decode(Checkpoint.self, from: readOwned(journal))
        guard checkpoint.version == 1 else { throw PortableFSWorkspaceError("Invalid workspace removal checkpoint") }
        return checkpoint.phase == "complete"
    }
    public static func prepareToStart(home: URL) throws {
        let account = home.appendingPathComponent(".local/state/portablefs")
        guard FileManager.default.fileExists(atPath: account.path) else { return }
        let lock = try RemovalLock(account.appendingPathComponent("workspace-removal.lock"), create: true)
        defer { withExtendedLifetime(lock) {} }
        guard try !removalPending(home: home) else { throw PortableFSWorkspaceError("Complete the previous Linux Workspace removal first") }
        let journal = account.appendingPathComponent("workspace-removal.json")
        if unlink(journal.path) != 0 && errno != ENOENT { throw PortableFSWorkspaceError("Cannot restart Linux Workspace") }
        try sync(account)
    }
    private static func readOwned(_ url: URL) throws -> Data {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw PortableFSWorkspaceError("Cannot read Linux Workspace removal") }
        defer { Darwin.close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_uid == geteuid(), st.st_nlink == 1, st.st_mode & 0o777 == 0o600, st.st_size <= 4096 else { throw PortableFSWorkspaceError("Unsafe Linux Workspace removal checkpoint") }
        return try FileHandle(fileDescriptor: fd, closeOnDealloc: false).readToEnd() ?? Data()
    }
    private static func save(_ checkpoint: Checkpoint, to url: URL) throws {
        let temporary = url.appendingPathExtension(UUID().uuidString)
        let fd = open(temporary.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw PortableFSWorkspaceError("Cannot save Linux Workspace removal") }
        defer { Darwin.close(fd); unlink(temporary.path) }
        try FileHandle(fileDescriptor: fd, closeOnDealloc: false).write(contentsOf: JSONEncoder().encode(checkpoint))
        guard fsync(fd) == 0, rename(temporary.path, url.path) == 0 else { throw PortableFSWorkspaceError("Cannot save Linux Workspace removal") }
        try sync(url.deletingLastPathComponent())
    }
    private static func sync(_ directory: URL) throws {
        let fd = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { throw PortableFSWorkspaceError("Cannot open Linux Workspace removal directory") }
        defer { Darwin.close(fd) }
        guard fsync(fd) == 0 else { throw PortableFSWorkspaceError("Cannot sync Linux Workspace removal") }
    }
    private final class RemovalLock {
        let fd: Int32
        init(_ url: URL, create: Bool) throws {
            guard url.deletingLastPathComponent().standardizedFileURL == url.deletingLastPathComponent().resolvingSymlinksInPath().standardizedFileURL else { throw PortableFSWorkspaceError("Unsafe workspace removal directory") }
            fd = open(url.path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | (create ? O_CREAT : 0), 0o600)
            guard fd >= 0 else { throw PortableFSWorkspaceError("Cannot lock Linux Workspace removal") }
            var st = stat()
            guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_uid == geteuid(), st.st_nlink == 1,
                  pfsWorkspaceRemovalFlock(fd, LOCK_EX | LOCK_NB) == 0 else { Darwin.close(fd); throw PortableFSWorkspaceError("Linux Workspace is in use") }
        }
        deinit { _ = pfsWorkspaceRemovalFlock(fd, LOCK_UN); Darwin.close(fd) }
    }
}
@_silgen_name("flock") private func pfsWorkspaceRemovalFlock(_ fd: Int32, _ operation: Int32) -> Int32
