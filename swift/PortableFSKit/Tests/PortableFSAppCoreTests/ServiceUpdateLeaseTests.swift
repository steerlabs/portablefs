import Darwin
import Foundation
import Testing
@testable import PortableFSAppCore

private final class LockedAcceptAttemptCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func next() -> Int {
        lock.lock()
        defer { lock.unlock() }
        value += 1
        return value
    }

    func load() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private func updateTestIdentity(_ marker: Character) -> PortableFSDReleaseIdentity {
    PortableFSDReleaseIdentity(
        codeDirectoryHash: String(repeating: marker, count: 40),
        executableSHA256: String(repeating: marker, count: 64),
        daemonVersion: marker == "a" ? "0.2.3" : "0.2.4",
        identitySchema: 1,
        controlProtocol: 1,
        pfslocalMajor: 1,
        pfslocalMinor: 15
    )
}

private func updateTestLease(
    phase: PortableFSDUpdatePhase = .preparingOld
) -> PortableFSDUpdateLease {
    let created: Int64 = 1_800_000_000_000
    return PortableFSDUpdateLease(
        schemaVersion: 1,
        phase: phase,
        tokenSHA256: String(repeating: "c", count: 64),
        oldRelease: updateTestIdentity("a"),
        targetRelease: updateTestIdentity("b"),
        createdAtUnixMs: created,
        deadlineUnixMs: created + PortableFSDUpdateLease.lifetimeMilliseconds
    )
}

private func withUpdateStore(
    _ body: (PortableFSDUpdateLeaseStore, URL) throws -> Void
) throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString,
        isDirectory: true
    )
    try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: directory.path
    )
    defer { try? FileManager.default.removeItem(at: directory) }
    try body(PortableFSDUpdateLeaseStore(directoryURL: directory), directory)
}

@Test func updateLeaseTransitionsAreExactDurableReplacements() throws {
    try withUpdateStore { store, directory in
        let preparing = updateTestLease()
        try store.create(preparing)
        #expect(try store.load() == preparing)

        let absent = PortableFSDUpdateLease(
            schemaVersion: preparing.schemaVersion,
            phase: .oldAbsent,
            tokenSHA256: preparing.tokenSHA256,
            oldRelease: preparing.oldRelease,
            targetRelease: preparing.targetRelease,
            createdAtUnixMs: preparing.createdAtUnixMs,
            deadlineUnixMs: preparing.deadlineUnixMs
        )
        try store.transition(from: preparing, to: absent)
        #expect(try store.load() == absent)
        let attributes = try FileManager.default.attributesOfItem(
            atPath: directory.appendingPathComponent("activation.json").path
        )
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        #expect((attributes[.referenceCount] as? NSNumber)?.intValue == 1)

        #expect(throws: PortableFSDUpdateLeaseError.stateChanged) {
            try store.transition(from: preparing, to: absent)
        }
        let completed = PortableFSDUpdateLease(
            schemaVersion: absent.schemaVersion,
            phase: .rollbackComplete,
            tokenSHA256: absent.tokenSHA256,
            oldRelease: absent.oldRelease,
            targetRelease: absent.targetRelease,
            createdAtUnixMs: absent.createdAtUnixMs,
            deadlineUnixMs: absent.deadlineUnixMs
        )
        try store.transition(from: absent, to: completed)
        #expect(try store.load() == completed)
    }
}

@Test func updateLeaseRefusesUnknownFieldsAndUnsafeInodes() throws {
    try withUpdateStore { store, directory in
        let lease = updateTestLease()
        let encoder = JSONEncoder()
        var object = try #require(
            JSONSerialization.jsonObject(with: encoder.encode(lease)) as? [String: Any]
        )
        object["unexpected"] = true
        let path = directory.appendingPathComponent("activation.json")
        try JSONSerialization.data(withJSONObject: object).write(to: path)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: path.path
        )
        #expect(throws: PortableFSDUpdateLeaseError.invalidEncoding) {
            _ = try store.load()
        }
    }

    try withUpdateStore { store, directory in
        let target = directory.appendingPathComponent("target")
        try Data("{}".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(
            at: directory.appendingPathComponent("activation.json"),
            withDestinationURL: target
        )
        #expect(throws: (any Error).self) {
            _ = try store.load()
        }
    }
}

@Test func updateLeaseRefusesDuplicateKeysAndTrailingGarbage() throws {
    try withUpdateStore { store, directory in
        let encoded = try JSONEncoder().encode(updateTestLease())
        let original = try #require(String(data: encoded, encoding: .utf8))
        let duplicate = original.replacingOccurrences(
            of: "\"schemaVersion\":1",
            with: "\"schemaVersion\":1,\"schema\\u0056ersion\":1"
        )
        let path = directory.appendingPathComponent("activation.json")
        try Data(duplicate.utf8).write(to: path)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: path.path
        )
        #expect(throws: PortableFSDUpdateLeaseError.invalidEncoding) {
            _ = try store.load()
        }

        try Data((original + " trailing").utf8).write(to: path)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: path.path
        )
        #expect(throws: PortableFSDUpdateLeaseError.invalidEncoding) {
            _ = try store.load()
        }
    }
}

@Test func updateLeaseAllowsSameReleaseAndMinorZero() throws {
    let release = PortableFSDReleaseIdentity(
        codeDirectoryHash: String(repeating: "a", count: 40),
        executableSHA256: String(repeating: "b", count: 64),
        daemonVersion: "0.2.3",
        identitySchema: 2,
        controlProtocol: 3,
        pfslocalMajor: 1,
        pfslocalMinor: 0
    )
    let created: Int64 = 1_800_000_000_000
    try PortableFSDUpdateLease(
        schemaVersion: 1,
        phase: .preparingOld,
        tokenSHA256: String(repeating: "c", count: 64),
        oldRelease: release,
        targetRelease: release,
        createdAtUnixMs: created,
        deadlineUnixMs: created + PortableFSDUpdateLease.lifetimeMilliseconds
    ).validate()
}

@Test func updateLeaseContractRejectsDriftAndNonFrozenReleases() {
    let lease = updateTestLease()
    #expect(throws: PortableFSDUpdateLeaseError.invalidContract) {
        try PortableFSDUpdateLease(
            schemaVersion: lease.schemaVersion,
            phase: lease.phase,
            tokenSHA256: lease.tokenSHA256,
            oldRelease: lease.oldRelease,
            targetRelease: lease.targetRelease,
            createdAtUnixMs: lease.createdAtUnixMs,
            deadlineUnixMs: lease.deadlineUnixMs + 1
        ).validate()
    }
}

@Test func updateListenerPublishes0600AndRefusesAReplacedInode() throws {
    try withUpdateStore { store, directory in
        let listener = try PortableFSDUpdateListener(store: store)
        let socket = directory.appendingPathComponent(
            PortableFSDUpdateLeaseStore.socketFilename
        )
        var status = stat()
        #expect(Darwin.lstat(socket.path, &status) == 0)
        #expect(status.st_mode & S_IFMT == S_IFSOCK)
        #expect(status.st_uid == geteuid())
        #expect(status.st_nlink == 1)
        #expect(status.st_mode & 0o777 == 0o600)

        #expect(Darwin.unlink(socket.path) == 0)
        try Data("replacement".utf8).write(to: socket)
        #expect(Darwin.chmod(socket.path, 0o600) == 0)
        #expect(throws: (any Error).self) {
            _ = try listener.accept()
        }
        #expect(throws: PortableFSDUpdateSocketError.unsafeSocket(socket.path)) {
            try listener.stopAndProveAbsent()
        }

        // Exit preparation removes only the inode it published; an
        // attacker-controlled replacement is never unlinked on its behalf.
        #expect(Darwin.lstat(socket.path, &status) == 0)
        #expect(status.st_mode & S_IFMT == S_IFREG)
    }
}

@Test func updateListenerStopPublishesExactSocketAbsenceIdempotently() throws {
    try withUpdateStore { store, directory in
        let listener = try PortableFSDUpdateListener(store: store)
        let socket = directory.appendingPathComponent(
            PortableFSDUpdateLeaseStore.socketFilename
        )
        try listener.stopAndProveAbsent()
        var status = stat()
        #expect(Darwin.lstat(socket.path, &status) != 0)
        #expect(errno == ENOENT)
        try listener.stopAndProveAbsent()
    }
}

@Test func updateListenerRetriesAbortedQueuedPeersAndKeepsItsExactInode() throws {
    try withUpdateStore { store, directory in
        let attempts = LockedAcceptAttemptCounter()
        let listener = try PortableFSDUpdateListener(
            store: store,
            acceptSystemCall: { descriptor in
                if attempts.next() <= 2 {
                    errno = ECONNABORTED
                    return -1
                }
                return Darwin.accept(descriptor, nil, nil)
            }
        )
        defer { listener.stop() }
        let socket = directory.appendingPathComponent(
            PortableFSDUpdateLeaseStore.socketFilename
        )
        var before = stat()
        #expect(Darwin.lstat(socket.path, &before) == 0)

        let client = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        #expect(client >= 0)
        guard client >= 0 else { return }
        defer { Darwin.close(client) }
        try PortableFSDUpdateListener.connect(client, to: socket.path)

        let connection = try listener.accept()
        connection.close()
        #expect(attempts.load() == 3)

        var after = stat()
        #expect(Darwin.lstat(socket.path, &after) == 0)
        #expect(after.st_dev == before.st_dev)
        #expect(after.st_ino == before.st_ino)
        #expect(after.st_mode & S_IFMT == S_IFSOCK)
    }
}

@Test func updateServerLoopStopsAndUnlinksOnNontransientAcceptFailure() throws {
    try withUpdateStore { store, directory in
        let listener = try PortableFSDUpdateListener(store: store)
        let socket = directory.appendingPathComponent(
            PortableFSDUpdateLeaseStore.socketFilename
        )
        var stopped = false
        PortableFSDServiceUpdateServer.runAcceptLoop(
            isStopped: { stopped },
            acceptAndHandle: {
                throw PortableFSDUpdateSocketError.inspect(
                    path: socket.path,
                    errno: EBADF
                )
            },
            stop: {
                stopped = true
                listener.stop()
            }
        )
        #expect(stopped)
        var status = stat()
        #expect(Darwin.lstat(socket.path, &status) != 0)
        #expect(errno == ENOENT)
    }
}

@Test func updateServerLoopTreatsAStopInducedAcceptExitAsClean() {
    var stopped = false
    var stopCalls = 0
    PortableFSDServiceUpdateServer.runAcceptLoop(
        isStopped: { stopped },
        acceptAndHandle: {
            stopped = true
            throw PortableFSDUpdateSocketError.closed
        },
        stop: { stopCalls += 1 }
    )
    #expect(stopped)
    #expect(stopCalls == 0)
}

@Test func updateListenerRefusesAnActiveExactSocketWithoutReclaimingIt() throws {
    try withUpdateStore { store, directory in
        let listener = try PortableFSDUpdateListener(store: store)
        defer { listener.stop() }
        #expect(throws: PortableFSDUpdateSocketError.listenerActive) {
            _ = try PortableFSDUpdateListener(store: store)
        }
        var status = stat()
        let socket = directory.appendingPathComponent(
            PortableFSDUpdateLeaseStore.socketFilename
        )
        #expect(Darwin.lstat(socket.path, &status) == 0)
        #expect(status.st_mode & S_IFMT == S_IFSOCK)
    }
}

@Test func updateSocketProbeHasAHardDeadlineWhenAcceptQueueIsFull() throws {
    try withUpdateStore { store, directory in
        let listener = try PortableFSDUpdateListener(store: store)
        defer { listener.stop() }
        let path = directory.appendingPathComponent(
            PortableFSDUpdateLeaseStore.socketFilename
        ).path
        var queued: [Int32] = []
        defer { queued.forEach { Darwin.close($0) } }
        var saturated = false
        for _ in 0..<16 {
            let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
            #expect(descriptor >= 0)
            guard descriptor >= 0 else { break }
            do {
                try PortableFSDUpdateListener.connectBounded(
                    descriptor,
                    to: path,
                    timeoutMilliseconds: 20
                )
                queued.append(descriptor)
            } catch PortableFSDUpdateSocketError.timeout {
                Darwin.close(descriptor)
                saturated = true
                break
            } catch PortableFSDUpdateSocketError.inspect(_, let code) where code == ECONNREFUSED {
                // Darwin may reject immediately instead of parking a connect
                // once the local accept queue is full; either result is safely
                // bounded and cannot authorize stale-name reclamation.
                Darwin.close(descriptor)
                saturated = true
                break
            }
        }
        try #require(saturated)

        let probe = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        try #require(probe >= 0)
        defer { Darwin.close(probe) }
        let started = Date()
        var boundedFailure = false
        do {
            try PortableFSDUpdateListener.connectBounded(
                probe,
                to: path,
                timeoutMilliseconds: 50
            )
        } catch PortableFSDUpdateSocketError.timeout {
            boundedFailure = true
        } catch PortableFSDUpdateSocketError.inspect(_, let code) where code == ECONNREFUSED {
            boundedFailure = true
        }
        #expect(boundedFailure)
        #expect(Date().timeIntervalSince(started) < 0.5)
    }
}
