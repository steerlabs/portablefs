import CryptoKit
import Darwin
import Foundation
import Testing
@testable import PortableFSAppCore

private let updateOldRelease = PortableFSDReleaseIdentity(
    codeDirectoryHash: String(repeating: "1", count: 40),
    executableSHA256: String(repeating: "2", count: 64),
    daemonVersion: "1.2.3",
    identitySchema: 1,
    controlProtocol: 1,
    pfslocalMajor: 1,
    pfslocalMinor: 15
)

private let updateTargetRelease = PortableFSDReleaseIdentity(
    codeDirectoryHash: String(repeating: "3", count: 40),
    executableSHA256: String(repeating: "4", count: 64),
    daemonVersion: "1.2.4",
    identitySchema: 1,
    controlProtocol: 1,
    pfslocalMajor: 1,
    pfslocalMinor: 15
)

private let updateToken = String(repeating: "a", count: 64)

private final class FakeUpdateConnection: PortableFSDUpdateConnectionIO {
    let peerPID: pid_t = getpid()
    var reads: [(FakeUpdateConnection) throws -> Data] = []
    var writes: [Data] = []
    var readIndex = 0
    var closed = false
    var failWriteAtIndex: Int?

    func readFrame() throws -> Data {
        guard readIndex < reads.count else {
            throw PortableFSDUpdateSocketError.closed
        }
        let read = reads[readIndex]
        readIndex += 1
        return try read(self)
    }

    func writeFrame(_ data: Data) throws {
        if failWriteAtIndex == writes.count {
            throw PortableFSDUpdateSocketError.closed
        }
        writes.append(data)
    }

    func close() {
        closed = true
    }
}

private final class UpdateActionRecorder: @unchecked Sendable {
    var prepared = 0
    var proven: [PortableFSDReleaseIdentity] = []
    var activated: [PortableFSDReleaseIdentity] = []
    var fenced: [PortableFSDReleaseIdentity] = []
    var restored: [PortableFSDReleaseIdentity] = []
    var quiesced = 0
    var resumed = 0
    var preparedForExit = 0
    var exited = 0
    var exitEvents: [String] = []
    var lifecycleEvents: [String] = []
    var activationError: Error?
    var exitPreparationError: Error?

    func actions(sealed: PortableFSDReleaseIdentity) -> PortableFSDServiceUpdateActions {
        PortableFSDServiceUpdateActions(
            sealedRelease: { sealed },
            proveActive: { self.proven.append($0) },
            prepareOld: {
                self.prepared += 1
                return sealed
            },
            activate: { release in
                self.activated.append(release)
                if let activationError = self.activationError { throw activationError }
            },
            fence: { self.fenced.append($0) },
            restoreCancelledOld: { self.restored.append($0) }
        )
    }

    var callbacks: PortableFSDServiceUpdateServer.Callbacks {
        PortableFSDServiceUpdateServer.Callbacks(
            quiesceNormalLifecycle: {
                self.quiesced += 1
                self.lifecycleEvents.append("quiesce")
            },
            resumeNormalLifecycle: {
                self.resumed += 1
                self.lifecycleEvents.append("resume-presentation")
            },
            prepareHostExit: {
                self.preparedForExit += 1
                self.exitEvents.append("listener-absent")
                if let exitPreparationError = self.exitPreparationError {
                    throw exitPreparationError
                }
            },
            requestHostExit: {
                self.exited += 1
                self.exitEvents.append("host-exit")
            }
        )
    }
}

private enum FakeActivationFailure: Error { case failed }

private final class DirectorySyncInjector: @unchecked Sendable {
    private(set) var calls = 0
    var failFromCall: Int?
    var failOnlyCall: Int?

    func sync(_ descriptor: Int32) -> Int32 {
        calls += 1
        if calls == failOnlyCall || failFromCall.map({ calls >= $0 }) == true {
            errno = EIO
            return -1
        }
        return Darwin.fsync(descriptor)
    }
}

@Test func updateServerPrepareCancelRestoresBeforePublishingRollbackComplete() throws {
    let fixture = try UpdateServerFixture()
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateOldRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "prepare-update",
            "targetRelease": releaseObject(updateTargetRelease),
        ]) },
        { connection in
            let prepared = try updateObject(connection.writes[0])
            let token = try #require(prepared["token"] as? String)
            return try updateFrame([
                "schemaVersion": 1,
                "operation": "cancel",
                "token": token,
            ])
        },
    ]

    handler.handle(connection)

    #expect(recorder.prepared == 1)
    #expect(recorder.restored == [updateOldRelease])
    #expect(recorder.quiesced == 1)
    #expect(recorder.resumed == 1)
    #expect(recorder.lifecycleEvents == ["quiesce", "resume-presentation"])
    #expect(recorder.exited == 0)
    #expect(try fixture.store.load()?.phase == .rollbackComplete)
    #expect(try updateObject(connection.writes[1])["state"] as? String == "cancelled")
}

@Test func updateServerRandomFailureNeverQuiescesOrCreatesALease() throws {
    let fixture = try UpdateServerFixture()
    let recorder = UpdateActionRecorder()
    let handler = PortableFSDServiceUpdateSessionHandler(
        store: fixture.store,
        actions: recorder.actions(sealed: updateOldRelease),
        callbacks: recorder.callbacks,
        nowMilliseconds: { fixture.now },
        tokenGenerator: { throw FakeActivationFailure.failed }
    )
    let connection = FakeUpdateConnection()
    connection.reads = [{ _ in try updateFrame([
        "schemaVersion": 1,
        "operation": "prepare-update",
        "targetRelease": releaseObject(updateTargetRelease),
    ]) }]

    handler.handle(connection)

    #expect(recorder.quiesced == 0)
    #expect(recorder.prepared == 0)
    #expect(recorder.resumed == 0)
    #expect(try fixture.store.load() == nil)
}

@Test func updateServerConsumesACompletedMarkerOnlyAfterExactActiveProof() throws {
    let fixture = try UpdateServerFixture()
    let completed = PortableFSDUpdateLease(
        schemaVersion: 1,
        phase: .rollbackComplete,
        tokenSHA256: hashToken(updateToken),
        oldRelease: updateOldRelease,
        targetRelease: updateTargetRelease,
        createdAtUnixMs: fixture.now - 86_400_000,
        deadlineUnixMs: fixture.now - 86_400_000
            + PortableFSDUpdateLease.lifetimeMilliseconds
    )
    try fixture.store.create(completed)
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateOldRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "prepare-update",
            "targetRelease": releaseObject(updateTargetRelease),
        ]) },
        { connection in
            let token = try #require(try updateObject(connection.writes[0])["token"] as? String)
            return try updateFrame([
                "schemaVersion": 1,
                "operation": "cancel",
                "token": token,
            ])
        },
    ]

    handler.handle(connection)

    #expect(recorder.proven == [updateOldRelease])
    #expect(recorder.prepared == 1)
    #expect(recorder.quiesced == 1)
    #expect(recorder.resumed == 1)
    #expect(try fixture.store.load()?.phase == .rollbackComplete)
}

@Test func updateServerRefusesMismatchedCompletedMarkerWithoutMutation() throws {
    let fixture = try UpdateServerFixture()
    let completed = fixture.lease(phase: .targetComplete)
    try fixture.store.create(completed)
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateOldRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [{ _ in try updateFrame([
        "schemaVersion": 1,
        "operation": "prepare-update",
        "targetRelease": releaseObject(updateTargetRelease),
    ]) }]

    handler.handle(connection)

    #expect(recorder.proven.isEmpty)
    #expect(recorder.quiesced == 0)
    #expect(recorder.prepared == 0)
    #expect(try fixture.store.load() == completed)
}

@Test func updateServerRefusesFutureCompletedMarkerWithoutMutation() throws {
    let fixture = try UpdateServerFixture()
    let future = PortableFSDUpdateLease(
        schemaVersion: 1,
        phase: .rollbackComplete,
        tokenSHA256: hashToken(updateToken),
        oldRelease: updateOldRelease,
        targetRelease: updateTargetRelease,
        createdAtUnixMs: fixture.now + 120_000,
        deadlineUnixMs: fixture.now + 120_000
            + PortableFSDUpdateLease.lifetimeMilliseconds
    )
    try fixture.store.create(future)
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateOldRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [{ _ in try updateFrame([
        "schemaVersion": 1,
        "operation": "prepare-update",
        "targetRelease": releaseObject(updateTargetRelease),
    ]) }]

    handler.handle(connection)

    #expect(recorder.proven.isEmpty)
    #expect(recorder.quiesced == 0)
    #expect(try fixture.store.load() == future)
}

@Test func updateServerPreparingPublicationFsyncFailureRestoresTerminalOldState() throws {
    let sync = DirectorySyncInjector()
    sync.failOnlyCall = 1
    let fixture = try UpdateServerFixture(directorySync: sync.sync)
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateOldRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [{ _ in try updateFrame([
        "schemaVersion": 1,
        "operation": "prepare-update",
        "targetRelease": releaseObject(updateTargetRelease),
    ]) }]

    handler.handle(connection)

    #expect(sync.calls == 2)
    #expect(recorder.quiesced == 1)
    #expect(recorder.resumed == 1)
    #expect(recorder.prepared == 0)
    #expect(try fixture.store.load()?.phase == .rollbackComplete)
}

@Test func updateServerCompletedMarkerConsumptionFsyncFailureRestoresBaseline() throws {
    let sync = DirectorySyncInjector()
    let fixture = try UpdateServerFixture(directorySync: sync.sync)
    let baseline = fixture.lease(phase: .rollbackComplete)
    try fixture.store.create(baseline)
    sync.failOnlyCall = 2
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateOldRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [{ _ in try updateFrame([
        "schemaVersion": 1,
        "operation": "prepare-update",
        "targetRelease": releaseObject(updateTargetRelease),
    ]) }]

    handler.handle(connection)

    #expect(sync.calls == 3)
    #expect(recorder.proven == [updateOldRelease])
    #expect(recorder.quiesced == 1)
    #expect(recorder.resumed == 1)
    #expect(recorder.prepared == 0)
    #expect(try fixture.store.load() == baseline)
}

@Test func updateServerPrepareCommitLeavesExactOldAbsentLeaseAndExits() throws {
    let fixture = try UpdateServerFixture()
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateOldRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "prepare-update",
            "targetRelease": releaseObject(updateTargetRelease),
        ]) },
        { connection in
            let token = try #require(try updateObject(connection.writes[0])["token"] as? String)
            return try updateFrame([
                "schemaVersion": 1,
                "operation": "commit-exit",
                "token": token,
            ])
        },
    ]

    handler.handle(connection)

    let loaded = try fixture.store.load()
    let lease = try #require(loaded)
    #expect(lease.phase == .oldAbsent)
    #expect(lease.oldRelease == updateOldRelease)
    #expect(lease.targetRelease == updateTargetRelease)
    #expect(recorder.preparedForExit == 1)
    #expect(recorder.exited == 1)
    #expect(recorder.exitEvents == ["listener-absent", "host-exit"])
    #expect(recorder.restored.isEmpty)
    #expect(recorder.resumed == 0)
}

@Test func updateServerRefusesHostExitWhenListenerAbsenceIsNotProven() throws {
    let fixture = try UpdateServerFixture()
    let recorder = UpdateActionRecorder()
    recorder.exitPreparationError = PortableFSDUpdateSocketError.unsafeSocket("update.sock")
    let handler = fixture.handler(recorder: recorder, sealed: updateOldRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "prepare-update",
            "targetRelease": releaseObject(updateTargetRelease),
        ]) },
        { connection in
            let token = try #require(try updateObject(connection.writes[0])["token"] as? String)
            return try updateFrame([
                "schemaVersion": 1,
                "operation": "commit-exit",
                "token": token,
            ])
        },
    ]

    handler.handle(connection)

    let lease = try #require(try fixture.store.load())
    #expect(lease.phase == .oldAbsent)
    #expect(recorder.preparedForExit == 1)
    #expect(recorder.exited == 0)
    #expect(recorder.exitEvents == ["listener-absent"])
    #expect(recorder.restored.isEmpty)
    #expect(connection.writes.count == 1)
}

@Test func updateServerWrongTokenDoesNotActivateOrMutateLease() throws {
    let fixture = try UpdateServerFixture()
    let lease = fixture.lease(phase: .oldAbsent)
    try fixture.store.create(lease)
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateTargetRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [{ _ in try activationFrame(
        operation: "activate-target",
        token: String(repeating: "b", count: 64),
        release: updateTargetRelease
    ) }]

    handler.handle(connection)

    #expect(recorder.activated.isEmpty)
    #expect(recorder.fenced.isEmpty)
    #expect(recorder.exited == 0)
    #expect(try fixture.store.load() == lease)
    #expect(connection.writes.isEmpty)
}

@Test func updateServerTargetAcceptAndCompletionPersistExactTerminalMarker() throws {
    let fixture = try UpdateServerFixture()
    try fixture.store.create(fixture.lease(phase: .oldAbsent))
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateTargetRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [
        { _ in try activationFrame(
            operation: "activate-target",
            token: updateToken,
            release: updateTargetRelease
        ) },
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "accept-target",
            "token": updateToken,
        ]) },
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "complete-target",
            "token": updateToken,
        ]) },
    ]

    handler.handle(connection)

    #expect(recorder.activated == [updateTargetRelease])
    #expect(recorder.fenced.isEmpty)
    #expect(recorder.resumed == 1)
    #expect(recorder.lifecycleEvents == ["resume-presentation"])
    #expect(recorder.exited == 0)
    #expect(try fixture.store.load()?.phase == .targetComplete)
    #expect(try connection.writes.map { try updateObject($0)["state"] as? String } == [
        "target-ready", "target-active", "complete",
    ])
}

@Test func updateServerCompletionFsyncAmbiguityRollsBackVisibleTerminalPhase() throws {
    let sync = DirectorySyncInjector()
    sync.failOnlyCall = 4
    let fixture = try UpdateServerFixture(directorySync: sync.sync)
    try fixture.store.create(fixture.lease(phase: .oldAbsent))
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateTargetRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [
        { _ in try activationFrame(
            operation: "activate-target",
            token: updateToken,
            release: updateTargetRelease
        ) },
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "accept-target",
            "token": updateToken,
        ]) },
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "complete-target",
            "token": updateToken,
        ]) },
    ]

    handler.handle(connection)

    #expect(sync.calls == 5)
    #expect(try fixture.store.load()?.phase == .targetActive)
    #expect(recorder.resumed == 0)
    #expect(try connection.writes.map { try updateObject($0)["state"] as? String } == [
        "target-ready", "target-active",
    ])
}

@Test func updateServerPersistentDirectoryFsyncFailureRemainsFailClosed() throws {
    let sync = DirectorySyncInjector()
    sync.failFromCall = 4
    let fixture = try UpdateServerFixture(directorySync: sync.sync)
    try fixture.store.create(fixture.lease(phase: .oldAbsent))
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateTargetRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [
        { _ in try activationFrame(
            operation: "activate-target",
            token: updateToken,
            release: updateTargetRelease
        ) },
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "accept-target",
            "token": updateToken,
        ]) },
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "complete-target",
            "token": updateToken,
        ]) },
    ]

    handler.handle(connection)

    #expect(sync.calls == 5)
    #expect(try fixture.store.load()?.phase == .targetActive)
    #expect(recorder.resumed == 0)
    #expect(connection.writes.count == 2)
}

@Test func updateServerReadyConnectionAbortFencesBeforePublishingAbsence() throws {
    let fixture = try UpdateServerFixture()
    try fixture.store.create(fixture.lease(phase: .oldAbsent))
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateTargetRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [
        { _ in try activationFrame(
            operation: "activate-target",
            token: updateToken,
            release: updateTargetRelease
        ) },
        { _ in throw PortableFSDUpdateSocketError.closed },
    ]

    handler.handle(connection)

    #expect(recorder.activated == [updateTargetRelease])
    #expect(recorder.fenced == [updateTargetRelease])
    #expect(recorder.preparedForExit == 1)
    #expect(recorder.exited == 1)
    #expect(recorder.exitEvents == ["listener-absent", "host-exit"])
    #expect(try fixture.store.load()?.phase == .rollbackAbsent)
}

@Test func updateServerActiveConnectionAbortNeverRollsBackAnAcceptedTarget() throws {
    let fixture = try UpdateServerFixture()
    try fixture.store.create(fixture.lease(phase: .oldAbsent))
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateTargetRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [
        { _ in try activationFrame(
            operation: "activate-target",
            token: updateToken,
            release: updateTargetRelease
        ) },
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "accept-target",
            "token": updateToken,
        ]) },
        { _ in throw PortableFSDUpdateSocketError.closed },
    ]

    handler.handle(connection)

    #expect(recorder.activated == [updateTargetRelease])
    #expect(recorder.fenced.isEmpty)
    #expect(recorder.exited == 0)
    #expect(try fixture.store.load()?.phase == .targetActive)
    let ready = try updateObject(connection.writes[0])
    #expect(Set(ready.keys) == [
        "schemaVersion", "state", "token", "hostPid", "release",
    ])
}

@Test func updateServerResumesExactActiveTargetAndCompletes() throws {
    let fixture = try UpdateServerFixture()
    try fixture.store.create(fixture.lease(phase: .targetActive))
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateTargetRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [
        { _ in try activationResumeFrame(
            operation: "resume-target",
            token: updateToken,
            release: updateTargetRelease
        ) },
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "complete-target",
            "token": updateToken,
        ]) },
    ]

    handler.handle(connection)

    #expect(recorder.proven == [updateTargetRelease])
    #expect(recorder.activated.isEmpty)
    #expect(recorder.fenced.isEmpty)
    #expect(recorder.resumed == 1)
    #expect(try fixture.store.load()?.phase == .targetComplete)
    #expect(try connection.writes.map { try updateObject($0)["state"] as? String } == [
        "target-active", "complete",
    ])
}

@Test func updateServerLostResumeReplyIsIdempotentlyRetryable() throws {
    let fixture = try UpdateServerFixture()
    try fixture.store.create(fixture.lease(phase: .rollbackActive))
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateOldRelease)
    let lost = FakeUpdateConnection()
    lost.failWriteAtIndex = 0
    lost.reads = [{ _ in try activationResumeFrame(
        operation: "resume-rollback",
        token: updateToken,
        release: updateOldRelease
    ) }]

    handler.handle(lost)

    #expect(try fixture.store.load()?.phase == .rollbackActive)
    #expect(recorder.proven == [updateOldRelease])
    #expect(recorder.resumed == 0)
    let retry = FakeUpdateConnection()
    retry.reads = [
        { _ in try activationResumeFrame(
            operation: "resume-rollback",
            token: updateToken,
            release: updateOldRelease
        ) },
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "complete-rollback",
            "token": updateToken,
        ]) },
    ]

    handler.handle(retry)

    #expect(recorder.proven == [updateOldRelease, updateOldRelease])
    #expect(recorder.activated.isEmpty)
    #expect(recorder.fenced.isEmpty)
    #expect(recorder.resumed == 1)
    #expect(try fixture.store.load()?.phase == .rollbackComplete)
    #expect(try retry.writes.map { try updateObject($0)["state"] as? String } == [
        "rollback-active", "complete",
    ])
}

@Test func updateServerResumeRejectsWrongTokenTupleExpiredAndTerminalWithoutMutation() throws {
    let cases: [(PortableFSDUpdateLease, String, PortableFSDReleaseIdentity)] = [
        (
            UpdateServerFixture.makeLease(phase: .targetActive),
            String(repeating: "b", count: 64),
            updateTargetRelease
        ),
        (
            UpdateServerFixture.makeLease(phase: .targetActive),
            updateToken,
            updateOldRelease
        ),
        (
            UpdateServerFixture.makeLease(phase: .targetComplete),
            updateToken,
            updateTargetRelease
        ),
        (
            UpdateServerFixture.makeLease(
                phase: .targetActive,
                createdAt: 1_800_000_000_000 - PortableFSDUpdateLease.lifetimeMilliseconds - 1
            ),
            updateToken,
            updateTargetRelease
        ),
    ]
    for (lease, token, release) in cases {
        let fixture = try UpdateServerFixture()
        try fixture.store.create(lease)
        let recorder = UpdateActionRecorder()
        let handler = fixture.handler(recorder: recorder, sealed: updateTargetRelease)
        let connection = FakeUpdateConnection()
        connection.reads = [{ _ in try activationResumeFrame(
            operation: "resume-target",
            token: token,
            release: release
        ) }]

        handler.handle(connection)

        #expect(try fixture.store.load() == lease)
        #expect(recorder.proven.isEmpty)
        #expect(recorder.activated.isEmpty)
        #expect(recorder.fenced.isEmpty)
        #expect(recorder.resumed == 0)
        #expect(connection.writes.isEmpty)
    }
}

@Test func updateServerResumeRejectsMismatchedTransactionTupleWithoutMutation() throws {
    let fixture = try UpdateServerFixture()
    let active = fixture.lease(phase: .targetActive)
    try fixture.store.create(active)
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateTargetRelease)
    let wrongOld = PortableFSDReleaseIdentity(
        codeDirectoryHash: String(repeating: "c", count: 40),
        executableSHA256: String(repeating: "d", count: 64),
        daemonVersion: "0.2.3",
        identitySchema: 1,
        controlProtocol: 1,
        pfslocalMajor: 1,
        pfslocalMinor: 15
    )
    let connection = FakeUpdateConnection()
    connection.reads = [{ _ in try activationResumeFrame(
        operation: "resume-target",
        token: updateToken,
        release: updateTargetRelease,
        oldRelease: wrongOld
    ) }]

    handler.handle(connection)

    #expect(try fixture.store.load() == active)
    #expect(recorder.proven.isEmpty)
    #expect(recorder.activated.isEmpty)
    #expect(recorder.fenced.isEmpty)
    #expect(recorder.resumed == 0)
    #expect(connection.writes.isEmpty)
}

@Test func updateServerDuplicateEscapedKeyAndExpiredLeaseCauseNoMutation() throws {
    let fixture = try UpdateServerFixture()
    let stale = PortableFSDUpdateLease(
        schemaVersion: 1,
        phase: .oldAbsent,
        tokenSHA256: hashToken(updateToken),
        oldRelease: updateOldRelease,
        targetRelease: updateTargetRelease,
        createdAtUnixMs: fixture.now - PortableFSDUpdateLease.lifetimeMilliseconds - 1,
        deadlineUnixMs: fixture.now - 1
    )
    try fixture.store.create(stale)
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateTargetRelease)
    let duplicate = try activationFrame(
        operation: "activate-target",
        token: updateToken,
        release: updateTargetRelease
    )
    var malformed = Data(#"{"schemaVersion":1,"operation":"activate-target","oper\u0061tion":"activate-target","token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release":{}}"#.utf8)
    malformed.append(0x0a)
    let duplicateConnection = FakeUpdateConnection()
    duplicateConnection.reads = [{ _ in malformed }]
    handler.handle(duplicateConnection)

    let staleConnection = FakeUpdateConnection()
    staleConnection.reads = [{ _ in duplicate }]
    handler.handle(staleConnection)

    #expect(recorder.activated.isEmpty)
    #expect(recorder.fenced.isEmpty)
    #expect(try fixture.store.load() == stale)
    #expect(duplicateConnection.writes.isEmpty)
    #expect(staleConnection.writes.isEmpty)
}

@Test func updateServerActivationFailureReturnsFencedOnlyAfterFenceSucceeds() throws {
    let fixture = try UpdateServerFixture()
    try fixture.store.create(fixture.lease(phase: .oldAbsent))
    let recorder = UpdateActionRecorder()
    recorder.activationError = FakeActivationFailure.failed
    let handler = fixture.handler(recorder: recorder, sealed: updateTargetRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [{ _ in try activationFrame(
        operation: "activate-target",
        token: updateToken,
        release: updateTargetRelease
    ) }]

    handler.handle(connection)

    #expect(recorder.fenced == [updateTargetRelease])
    #expect(recorder.preparedForExit == 1)
    #expect(recorder.exited == 1)
    #expect(recorder.exitEvents == ["listener-absent", "host-exit"])
    #expect(try fixture.store.load()?.phase == .rollbackAbsent)
    #expect(try updateObject(connection.writes[0])["state"] as? String == "target-fenced")
}

@Test func updateServerExplicitFenceStopsListenerBeforeReplyAndExit() throws {
    let fixture = try UpdateServerFixture()
    try fixture.store.create(fixture.lease(phase: .oldAbsent))
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateTargetRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [
        { _ in try activationFrame(
            operation: "activate-target",
            token: updateToken,
            release: updateTargetRelease
        ) },
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "fence-target",
            "token": updateToken,
        ]) },
    ]

    handler.handle(connection)

    #expect(try fixture.store.load()?.phase == .rollbackAbsent)
    #expect(recorder.fenced == [updateTargetRelease])
    #expect(recorder.exitEvents == ["listener-absent", "host-exit"])
    #expect(try connection.writes.map { try updateObject($0)["state"] as? String } == [
        "target-ready", "target-fenced",
    ])
}

@Test func updateServerFenceKeepsFencedPhaseAndRefusesExitWhenListenerIsAmbiguous() throws {
    let fixture = try UpdateServerFixture()
    try fixture.store.create(fixture.lease(phase: .oldAbsent))
    let recorder = UpdateActionRecorder()
    recorder.exitPreparationError = PortableFSDUpdateSocketError.unsafeSocket("update.sock")
    let handler = fixture.handler(recorder: recorder, sealed: updateTargetRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [
        { _ in try activationFrame(
            operation: "activate-target",
            token: updateToken,
            release: updateTargetRelease
        ) },
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "fence-target",
            "token": updateToken,
        ]) },
    ]

    handler.handle(connection)

    #expect(try fixture.store.load()?.phase == .rollbackAbsent)
    #expect(recorder.fenced == [updateTargetRelease])
    #expect(recorder.exitEvents == ["listener-absent"])
    #expect(recorder.exited == 0)
    #expect(try connection.writes.map { try updateObject($0)["state"] as? String } == [
        "target-ready",
    ])
}

@Test func updateServerAllowsPrepublicationRollbackFromOldAbsent() throws {
    let fixture = try UpdateServerFixture()
    try fixture.store.create(fixture.lease(phase: .oldAbsent))
    let recorder = UpdateActionRecorder()
    let handler = fixture.handler(recorder: recorder, sealed: updateOldRelease)
    let connection = FakeUpdateConnection()
    connection.reads = [
        { _ in try activationFrame(
            operation: "activate-rollback",
            token: updateToken,
            release: updateOldRelease
        ) },
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "accept-rollback",
            "token": updateToken,
        ]) },
        { _ in try updateFrame([
            "schemaVersion": 1,
            "operation": "complete-rollback",
            "token": updateToken,
        ]) },
    ]

    handler.handle(connection)

    #expect(recorder.activated == [updateOldRelease])
    #expect(try fixture.store.load()?.phase == .rollbackComplete)
    #expect(try connection.writes.map { try updateObject($0)["state"] as? String } == [
        "rollback-ready", "rollback-active", "complete",
    ])
}

@Test func updateServerLostCompletionReplyLeavesEveryAcceptedReleaseDurablyComplete() throws {
    let cases: [(
        phase: PortableFSDUpdatePhase,
        sealed: PortableFSDReleaseIdentity,
        activate: String,
        accept: String,
        complete: String
    )] = [
        (.oldAbsent, updateTargetRelease, "activate-target", "accept-target", "complete-target"),
        (.rollbackAbsent, updateOldRelease, "activate-rollback", "accept-rollback", "complete-rollback"),
        (.oldAbsent, updateOldRelease, "activate-rollback", "accept-rollback", "complete-rollback"),
    ]

    for testCase in cases {
        let fixture = try UpdateServerFixture()
        try fixture.store.create(fixture.lease(phase: testCase.phase))
        let recorder = UpdateActionRecorder()
        let handler = fixture.handler(recorder: recorder, sealed: testCase.sealed)
        let connection = FakeUpdateConnection()
        connection.failWriteAtIndex = 2
        connection.reads = [
            { _ in try activationFrame(
                operation: testCase.activate,
                token: updateToken,
                release: testCase.sealed
            ) },
            { _ in try updateFrame([
                "schemaVersion": 1,
                "operation": testCase.accept,
                "token": updateToken,
            ]) },
            { _ in try updateFrame([
                "schemaVersion": 1,
                "operation": testCase.complete,
                "token": updateToken,
            ]) },
        ]

        handler.handle(connection)

        let completed = try #require(try fixture.store.load())
        #expect(completed.phase == (
            testCase.activate == "activate-target" ? .targetComplete : .rollbackComplete
        ))
        #expect(recorder.activated == [testCase.sealed])
        #expect(recorder.fenced.isEmpty)
        #expect(recorder.resumed == 1)
        #expect(recorder.exited == 0)
        #expect(connection.writes.count == 2)
    }
}

private final class UpdateServerFixture {
    let root: URL
    let store: PortableFSDUpdateLeaseStore
    let now: Int64 = 1_800_000_000_000

    init(
        directorySync: @escaping (Int32) -> Int32 = Darwin.fsync
    ) throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        store = try PortableFSDUpdateLeaseStore(
            directoryURL: root,
            directorySync: directorySync
        )
    }

    deinit {
        try? FileManager.default.removeItem(at: root)
    }

    func lease(phase: PortableFSDUpdatePhase) -> PortableFSDUpdateLease {
        Self.makeLease(phase: phase, createdAt: now)
    }

    static func makeLease(
        phase: PortableFSDUpdatePhase,
        createdAt: Int64 = 1_800_000_000_000
    ) -> PortableFSDUpdateLease {
        PortableFSDUpdateLease(
            schemaVersion: 1,
            phase: phase,
            tokenSHA256: hashToken(updateToken),
            oldRelease: updateOldRelease,
            targetRelease: updateTargetRelease,
            createdAtUnixMs: createdAt,
            deadlineUnixMs: createdAt + PortableFSDUpdateLease.lifetimeMilliseconds
        )
    }

    func handler(
        recorder: UpdateActionRecorder,
        sealed: PortableFSDReleaseIdentity
    ) -> PortableFSDServiceUpdateSessionHandler {
        PortableFSDServiceUpdateSessionHandler(
            store: store,
            actions: recorder.actions(sealed: sealed),
            callbacks: recorder.callbacks,
            nowMilliseconds: { self.now + 1_000 }
        )
    }
}

private func activationFrame(
    operation: String,
    token: String,
    release: PortableFSDReleaseIdentity
) throws -> Data {
    try updateFrame([
        "schemaVersion": 1,
        "operation": operation,
        "token": token,
        "release": releaseObject(release),
    ])
}

private func activationResumeFrame(
    operation: String,
    token: String,
    release: PortableFSDReleaseIdentity,
    oldRelease: PortableFSDReleaseIdentity = updateOldRelease,
    targetRelease: PortableFSDReleaseIdentity = updateTargetRelease
) throws -> Data {
    try updateFrame([
        "schemaVersion": 1,
        "operation": operation,
        "token": token,
        "release": releaseObject(release),
        "oldRelease": releaseObject(oldRelease),
        "targetRelease": releaseObject(targetRelease),
    ])
}

private func releaseObject(_ release: PortableFSDReleaseIdentity) -> [String: Any] {
    [
        "codeDirectoryHash": release.codeDirectoryHash,
        "executableSHA256": release.executableSHA256,
        "daemonVersion": release.daemonVersion,
        "identitySchema": release.identitySchema,
        "controlProtocol": release.controlProtocol,
        "pfslocalMajor": release.pfslocalMajor,
        "pfslocalMinor": release.pfslocalMinor,
    ]
}

private func updateFrame(_ object: [String: Any]) throws -> Data {
    var data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    data.append(0x0a)
    return data
}

private func updateObject(_ frame: Data) throws -> [String: Any] {
    try #require(try JSONSerialization.jsonObject(with: frame.dropLast()) as? [String: Any])
}

private func hashToken(_ token: String) -> String {
    SHA256.hash(data: Data(token.utf8))
        .map { String(format: "%02x", $0) }
        .joined()
}
