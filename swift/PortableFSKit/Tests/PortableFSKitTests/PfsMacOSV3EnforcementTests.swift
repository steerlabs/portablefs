import Foundation
import Testing
@preconcurrency import Darwin
@testable import PortableFSKit

// MARK: - Shared fixtures

private let enforcementEpoch = Data(repeating: 0x7a, count: 16)
private let enforcementSecret = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 1) })
private let parentIdentity = try! PfsMacOSStableIdentity(Data(repeating: 0x51, count: 16))
private let itemIdentity = try! PfsMacOSStableIdentity(Data(repeating: 0x52, count: 16))
private let peerInitiator = try! PfsMacOSMutationInitiator(
    sessionID: Data(repeating: 0x11, count: 16),
    replaySlot: 1,
    mutationSequence: 5
)

private func makeAuthenticator() throws -> PfsMacOS26RepairAuthenticator {
    try PfsMacOS26RepairAuthenticator(mountSessionID: UUID(), secret: enforcementSecret)
}

private func makePlan(
    authenticator: PfsMacOS26RepairAuthenticator,
    kind: PfsMacOS26RepairKind,
    path: PfsMacOSRelativePath,
    sequence: UInt64 = 1,
    step: UInt32 = 0,
    expectedVFSFileID: UInt64? = nil,
    authoritativeSize: UInt64? = nil
) throws -> PfsMacOS26RepairPlan {
    let sourceName: Data? = kind == .negativeScratch ? nil : path.name
    let operand = try authenticator.makeOperand(
        epoch: enforcementEpoch,
        sequence: sequence,
        step: step,
        kind: kind,
        parentIdentity: parentIdentity,
        itemIdentity: kind == .negativeScratch ? .zero : itemIdentity,
        sourceName: sourceName
    )
    return PfsMacOS26RepairPlan(
        epoch: enforcementEpoch,
        sequence: sequence,
        step: step,
        kind: kind,
        path: path,
        parentIdentity: parentIdentity,
        itemIdentity: kind == .negativeScratch ? .zero : itemIdentity,
        expectedVFSFileID: expectedVFSFileID,
        authoritativeSize: authoritativeSize,
        operand: operand
    )
}

private func withTemporaryDirectory<T>(
    _ body: (URL, Int32) async throws -> T
) async throws -> T {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "portablefs-v3-enforce-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let rootFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    #expect(rootFD >= 0)
    defer { close(rootFD) }
    return try await body(directory, rootFD)
}

private func writeFile(_ url: URL, bytes: Int) throws {
    try Data(repeating: 0xAB, count: bytes).write(to: url)
}

// MARK: - R1: the enforcement half exists and is atomic

@Test func reservedOperandWithoutAnArmedTransactionIsRefused() async throws {
    let registry = PfsMacOS26RepairArmRegistry(authenticator: try makeAuthenticator())
    await #expect(throws: PfsMacOSCoherenceError.repairNotArmed) {
        try await registry.consume(
            callback: .createScratch,
            operand: PfsMacOS26RepairAuthenticator.reservedPrefix + Data("deadbeef".utf8),
            parentIdentity: parentIdentity.bytes
        )
    }
}

@Test func aForgedReservedNameCannotBeArmed() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    // Correct shape, attacker-chosen bytes: the HMAC is the only thing that
    // separates this from a genuine operand.
    let forged = PfsMacOS26RepairAuthenticator.reservedPrefix
        + Data(String(repeating: "ab", count: 38).utf8)
    let plan = PfsMacOS26RepairPlan(
        epoch: enforcementEpoch,
        sequence: 1,
        step: 0,
        kind: .negativeScratch,
        path: try PfsMacOSRelativePath(components: []),
        parentIdentity: parentIdentity,
        itemIdentity: .zero,
        expectedVFSFileID: nil,
        authoritativeSize: nil,
        operand: forged
    )
    await #expect(throws: PfsMacOSCoherenceError.invalidRepairOperand) {
        _ = try await registry.arm(plan)
    }
}

@Test func anOperandAuthenticatedForOneStepDoesNotAuthorizeAnother() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let honest = try makePlan(
        authenticator: authenticator,
        kind: .negativeScratch,
        path: try PfsMacOSRelativePath(components: []),
        sequence: 4,
        step: 0
    )
    // Same operand bytes, plan claims a different step.
    let shifted = PfsMacOS26RepairPlan(
        epoch: honest.epoch,
        sequence: honest.sequence,
        step: honest.step + 1,
        kind: honest.kind,
        path: honest.path,
        parentIdentity: honest.parentIdentity,
        itemIdentity: honest.itemIdentity,
        expectedVFSFileID: nil,
        authoritativeSize: nil,
        operand: honest.operand
    )
    await #expect(throws: PfsMacOSCoherenceError.invalidRepairOperand) {
        _ = try await registry.arm(shifted)
    }
}

@Test func sourceRemovalConsumptionIsAtomicUnderConcurrentCallbacks() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
    )
    _ = try await registry.arm(plan)
    let item = PortableFSItem(identity: .init(
        itemID: 7,
        generation: 1,
        stableIdentity: itemIdentity.bytes
    ))

    // Sixty racing callbacks all name the exact authenticated source. Exactly
    // one may be swallowed; the rest must fail closed, because each extra
    // success would authorize another kernel-only unlink.
    let successes = await withTaskGroup(of: Bool.self) { group in
        for _ in 0..<60 {
            group.addTask {
                do {
                    return try await registry.consumeArmedSourceRemoval(
                        parentIdentity: parentIdentity.bytes,
                        name: Data("victim".utf8),
                        item: item
                    ) != nil
                } catch {
                    return false
                }
            }
        }
        var count = 0
        for await ok in group where ok { count += 1 }
        return count
    }
    #expect(successes == 1)
}

@Test func armedSourceLookupRequiresTheExactAuthenticatedCoordinate() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
    )
    _ = try await registry.arm(plan)
    let operand = try #require(plan.operand)
    #expect(await registry.isArmedRepairSource(
        parentIdentity: parentIdentity.bytes,
        name: Data("victim".utf8)
    ))
    #expect(await registry.isArmedRepairSource(
        parentIdentity: parentIdentity.bytes,
        name: Data("someone-elses-file".utf8)
    ) == false)
    #expect(await registry.isArmedRepairSource(
        parentIdentity: itemIdentity.bytes,
        name: Data("victim".utf8)
    ) == false)
    #expect(await registry.isArmedRepairSourceOpenItem(itemIdentity: itemIdentity.bytes))
    #expect(await registry.isArmedRepairSourceOpenItem(itemIdentity: parentIdentity.bytes) == false)
    #expect(await registry.isArmedRepairSourceItem(itemIdentity: itemIdentity.bytes))
    #expect(await registry.isArmedRepairSourceItem(itemIdentity: parentIdentity.bytes) == false)
    #expect(await registry.pendingCallbacks(operand: operand) == [.removeSource])
}

@Test func armedSourceRemovalRequiresTheExactCoordinateAndStableObject() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
    )
    let lease = try await registry.arm(plan)
    let operand = try #require(plan.operand)
    let exact = PortableFSItem(identity: .init(
        itemID: 7,
        generation: 1,
        stableIdentity: itemIdentity.bytes
    ))
    let wrong = PortableFSItem(identity: .init(
        itemID: 8,
        generation: 1,
        stableIdentity: parentIdentity.bytes
    ))
    #expect(try await registry.consumeArmedSourceRemoval(
        parentIdentity: parentIdentity.bytes,
        name: Data("victim".utf8),
        item: wrong
    ) == nil)
    #expect(try await registry.consumeArmedSourceRemoval(
        parentIdentity: parentIdentity.bytes,
        name: Data("someone-else".utf8),
        item: exact
    ) == nil)
    #expect(try await registry.consumeArmedSourceRemoval(
        parentIdentity: itemIdentity.bytes,
        name: Data("victim".utf8),
        item: exact
    ) == nil)
    #expect(try await registry.consumeArmedSourceRemoval(
        parentIdentity: parentIdentity.bytes,
        name: Data("victim".utf8),
        item: exact
    ) == .positiveEviction)
    // FSKit carries no repair token on removeItem. A concurrent user's exact
    // same-coordinate unlink is intentionally indistinguishable from the
    // actuator callback and may win this one slot; every later callback is
    // refused, and XFS remains authoritative either way.
    await #expect(throws: PfsMacOSCoherenceError.repairCallbackOutOfOrder) {
        _ = try await registry.consumeArmedSourceRemoval(
            parentIdentity: parentIdentity.bytes,
            name: Data("victim".utf8),
            item: exact
        )
    }
    #expect(await registry.pendingCallbacks(operand: operand).isEmpty)
    #expect(await registry.isArmedRepairSourceOpenItem(itemIdentity: itemIdentity.bytes) == false)
    #expect(await registry.isArmedRepairSourceItem(itemIdentity: itemIdentity.bytes))
    try await lease.finish()
}

@Test func positiveEvictionMayFinishWhenTheKernelAlreadyProvedTheNameAbsent() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("already-absent".utf8)])
    )
    let lease = try await registry.arm(plan)
    try await lease.finish()
    #expect(await registry.armedOperandCount() == 0)
}

@Test func reservedCallbacksCannotSubstituteForDirectSourceRemoval() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
    )
    _ = try await registry.arm(plan)
    let operand = try #require(plan.operand)
    // The direct source-unlink plan never authorizes a hidden operand callback.
    await #expect(throws: PfsMacOSCoherenceError.repairCallbackOutOfOrder) {
        try await registry.consume(
            callback: .removeOperand,
            operand: operand,
            parentIdentity: parentIdentity.bytes
        )
    }
    #expect(await registry.pendingCallbacks(operand: operand) == [.removeSource])
}

@Test func dataInvalidationArmsUnderTheDeclaredMacOS26PolicyAndRestrictedRegistriesStillRefuse() async throws {
    let authenticator = try makeAuthenticator()
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .dataInvalidation,
        path: try PfsMacOSRelativePath(components: [Data("data.bin".utf8)]),
        expectedVFSFileID: 42,
        authoritativeSize: 0
    )

    // The declared macOS 26 compatibility policy arms the data path.
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let lease = try await registry.arm(plan)
    #expect(await registry.armedOperandCount() == 1)
    await lease.cancel()

    // A registry explicitly restricted to the namespace kinds refuses it, and
    // a data plan missing either authoritative coordinate cannot arm at all.
    let restricted = PfsMacOS26RepairArmRegistry(
        authenticator: authenticator,
        supportedKinds: [.negativeScratch, .positiveEviction]
    )
    await #expect(throws: PfsMacOSCoherenceError.repairKindUnsupported(.dataInvalidation)) {
        _ = try await restricted.arm(plan)
    }
    let incomplete = try makePlan(
        authenticator: authenticator,
        kind: .dataInvalidation,
        path: try PfsMacOSRelativePath(components: [Data("data.bin".utf8)]),
        sequence: 2,
        expectedVFSFileID: nil,
        authoritativeSize: nil
    )
    await #expect(throws: PfsMacOSCoherenceError.invalidRepairOperand) {
        _ = try await registry.arm(incomplete)
    }
}

@Test func armedTruncateConsumesOnlyTheExactIsolatedCoordinateInsideTheWindow() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .dataInvalidation,
        path: try PfsMacOSRelativePath(components: [Data("data.bin".utf8)]),
        expectedVFSFileID: 77,
        authoritativeSize: 4096
    )
    let lease = try await registry.arm(plan)
    let isolated = PortableFSItem(identity: .init(
        itemID: 9,
        generation: 1,
        stableIdentity: itemIdentity.bytes
    ))

    // Before the exact source removal there is no data-repair window.
    #expect(await registry.consumeArmedTruncate(
        itemIdentity: itemIdentity.bytes,
        size: 4096
    ) == nil)
    #expect(try await registry.consumeArmedSourceRemoval(
        parentIdentity: parentIdentity.bytes,
        name: Data("data.bin".utf8),
        item: isolated
    ) == .dataInvalidation)
    #expect(await registry.isArmedTruncateItem(itemIdentity: itemIdentity.bytes))

    // Wrong size, wrong item: never swallowed.
    #expect(await registry.consumeArmedTruncate(
        itemIdentity: itemIdentity.bytes,
        size: 4095
    ) == nil)
    #expect(await registry.consumeArmedTruncate(
        itemIdentity: parentIdentity.bytes,
        size: 4096
    ) == nil)

    let consumed = try #require(await registry.consumeArmedTruncate(
        itemIdentity: itemIdentity.bytes,
        size: 4096
    ))
    #expect(consumed == .init(expectedVFSFileID: 77, size: 4096))

    try await lease.finish()
    // The event boundary closes the window; nothing further is consumable.
    #expect(await registry.consumeArmedTruncate(
        itemIdentity: itemIdentity.bytes,
        size: 4096
    ) == nil)
    #expect(await registry.isArmedTruncateItem(itemIdentity: itemIdentity.bytes) == false)
    #expect(await registry.armedOperandCount() == 0)
}

@Test func armedTruncateWindowClosesOnCancellation() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .dataInvalidation,
        path: try PfsMacOSRelativePath(components: [Data("data.bin".utf8)]),
        expectedVFSFileID: 78,
        authoritativeSize: 1024
    )
    let lease = try await registry.arm(plan)
    let isolated = PortableFSItem(identity: .init(
        itemID: 10,
        generation: 1,
        stableIdentity: itemIdentity.bytes
    ))
    #expect(try await registry.consumeArmedSourceRemoval(
        parentIdentity: parentIdentity.bytes,
        name: Data("data.bin".utf8),
        item: isolated
    ) == .dataInvalidation)
    await lease.cancel()
    // Cancellation ends the event-scoped window immediately.
    #expect(await registry.consumeArmedTruncate(
        itemIdentity: itemIdentity.bytes,
        size: 1024
    ) == nil)
}

@Test func consumeRefusesASameBasenameCallbackFromADifferentParent() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
    )
    _ = try await registry.arm(plan)
    let operand = try #require(plan.operand)
    let exact = PortableFSItem(identity: .init(
        itemID: 7,
        generation: 1,
        stableIdentity: itemIdentity.bytes
    ))
    // Exact basename and object, wrong directory: never swallowed.
    #expect(try await registry.consumeArmedSourceRemoval(
        parentIdentity: itemIdentity.bytes,
        name: Data("victim".utf8),
        item: exact
    ) == nil)
    #expect(await registry.pendingCallbacks(operand: operand) == [.removeSource])
}

@Test func cancellingADirectEvictionNeverSealsFutureRepairs() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
    )
    let lease = try await registry.arm(plan)
    let exact = PortableFSItem(identity: .init(
        itemID: 7,
        generation: 1,
        stableIdentity: itemIdentity.bytes
    ))
    #expect(try await registry.consumeArmedSourceRemoval(
        parentIdentity: parentIdentity.bytes,
        name: Data("victim".utf8),
        item: exact
    ) == .positiveEviction)
    await lease.cancel()
    #expect(await registry.armedOperandCount() == 0)

    let next = try makePlan(
        authenticator: authenticator,
        kind: .negativeScratch,
        path: try PfsMacOSRelativePath(components: []),
        sequence: 2
    )
    let nextLease = try await registry.arm(next)
    await nextLease.cancel()
}

@Test func aCancelledUnconsumedPlanLeavesNoTear() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
    )
    let lease = try await registry.arm(plan)
    await lease.cancel()
}

@Test func aFullyConsumedTransactionFinishesAndReleasesTheOperand() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .negativeScratch,
        path: try PfsMacOSRelativePath(components: [])
    )
    let lease = try await registry.arm(plan)
    let operand = try #require(plan.operand)
    try await registry.consume(
        callback: .createScratch,
        operand: operand,
        parentIdentity: parentIdentity.bytes
    )
    try await registry.consume(
        callback: .removeOperand,
        operand: operand,
        parentIdentity: parentIdentity.bytes
    )
    try await lease.finish()
    #expect(await registry.armedOperandCount() == 0)
    // The name is now ordinary again — and therefore refused again.
    await #expect(throws: PfsMacOSCoherenceError.repairNotArmed) {
        try await registry.consume(
            callback: .createScratch,
            operand: operand,
            parentIdentity: parentIdentity.bytes
        )
    }
}

// MARK: - R2: exactly-once

private actor AckFailingTransport: PfsMacOSCoherenceTransport {
    private var remainingFailures: Int
    private(set) var acknowledgements: [PfsMacOSVisibilityCursor] = []

    init(failures: Int) { self.remainingFailures = failures }

    func nextEvent() async throws -> PfsMacOSCoherenceEvent? { nil }

    func acknowledge(epoch: Data, cursor: PfsMacOSVisibilityCursor) async throws {
        if remainingFailures > 0 {
            remainingFailures -= 1
            throw PfsMacOSCoherenceError.transportClosed
        }
        acknowledgements.append(cursor)
    }

    func failClosed(epoch: Data, cursor: PfsMacOSVisibilityCursor?, reason: String) async {}
    func acks() -> [PfsMacOSVisibilityCursor] { acknowledgements }
}

private actor CountingBackend: PfsMacOSCoherenceBackend {
    nonisolated let policy = PfsMacOSCachePolicy.synchronousVFSRepairV1
    private(set) var repairs = 0
    func repair(_ event: PfsMacOSCoherenceEvent) async throws { repairs += 1 }
    func acknowledged(_ event: PfsMacOSCoherenceEvent) async {}
    func count() -> Int { repairs }
}

@Test func aLostAcknowledgementNeverRerunsNamespaceSurgery() async throws {
    let backend = CountingBackend()
    let transport = AckFailingTransport(failures: 1)
    let runner = try PfsMacOSCoherenceRunner(
        epoch: enforcementEpoch,
        backend: backend,
        transport: transport
    )
    let event = try PfsMacOSCoherenceEvent(
        epoch: enforcementEpoch,
        sequence: 1,
        phase: .prepare,
        initiator: peerInitiator,
        repairs: []
    )

    // First delivery: the repair runs, the ack is lost on the wire.
    await #expect(throws: PfsMacOSCoherenceError.transportClosed) {
        try await runner.consume(event)
    }
    #expect(await backend.count() == 1)
    #expect(await runner.completedCursor() == PfsMacOSVisibilityCursor(sequence: 1, phase: .prepare))
    #expect(await runner.acknowledgedCursor() == nil)

    // Redelivery of the same barrier: re-ack, do NOT operate on the namespace
    // a second time with a fresh nonce.
    try await runner.consume(event)
    #expect(await backend.count() == 1)
    #expect(await transport.acks() == [PfsMacOSVisibilityCursor(sequence: 1, phase: .prepare)])
    #expect(await runner.acknowledgedCursor() == PfsMacOSVisibilityCursor(sequence: 1, phase: .prepare))
}

@Test func theBarrierAdvancesFromTheCompletedLedgerNotTheAcknowledgedOne() async throws {
    let backend = CountingBackend()
    let transport = AckFailingTransport(failures: 1)
    let runner = try PfsMacOSCoherenceRunner(
        epoch: enforcementEpoch,
        backend: backend,
        transport: transport
    )
    let prepare = try PfsMacOSCoherenceEvent(
        epoch: enforcementEpoch,
        sequence: 1,
        phase: .prepare,
        initiator: peerInitiator,
        repairs: []
    )
    let complete = try PfsMacOSCoherenceEvent(
        epoch: enforcementEpoch,
        sequence: 1,
        phase: .complete,
        initiator: peerInitiator,
        repairs: []
    )
    await #expect(throws: PfsMacOSCoherenceError.transportClosed) {
        try await runner.consume(prepare)
    }
    // COMPLETE(1) is the legal successor of a COMPLETED prepare, even though
    // the authority never heard the prepare ack.
    try await runner.consume(complete)
    #expect(await backend.count() == 2)
}

// MARK: - R2/R1: the dangerous actuator paths, on a real filesystem

@Test func positiveEvictionActuatorRemovesOnlyTheIsolatedBinding() async throws {
    try await withTemporaryDirectory { directory, rootFD in
        try writeFile(directory.appending(path: "victim"), bytes: 128)
        try writeFile(directory.appending(path: "bystander"), bytes: 64)

        let authenticator = try makeAuthenticator()
        let actuator = try PfsMacOS26POSIXActuator(rootFileDescriptor: rootFD)
        let plan = try makePlan(
            authenticator: authenticator,
            kind: .positiveEviction,
            path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
        )
        try await actuator.apply(plan)

        let remaining = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(remaining == ["bystander"])
    }
}

@Test func positiveEvictionRollsBackWhenTheRemovalCannotComplete() async throws {
    try await withTemporaryDirectory { directory, rootFD in
        // A non-empty directory: `renameat` moves it, `unlinkat(..., 0)`
        // cannot remove it. That is a real failure between the two halves of
        // the transaction, produced by the kernel rather than a stub.
        let victim = directory.appending(path: "victim")
        try FileManager.default.createDirectory(at: victim, withIntermediateDirectories: false)
        try writeFile(victim.appending(path: "payload"), bytes: 32)

        let authenticator = try makeAuthenticator()
        let actuator = try PfsMacOS26POSIXActuator(rootFileDescriptor: rootFD)
        let plan = try makePlan(
            authenticator: authenticator,
            kind: .positiveEviction,
            path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
        )
        await #expect(throws: PfsMacOSCoherenceError.self) {
            try await actuator.apply(plan)
        }

        // The user's directory is back under its own name with its contents.
        let remaining = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(remaining == ["victim"])
        #expect(try FileManager.default.contentsOfDirectory(atPath: victim.path) == ["payload"])
    }
}

@Test func dataInvalidationActuatorTruncatesTheIsolatedTargetAndRemovesTheName() async throws {
    try await withTemporaryDirectory { directory, rootFD in
        let target = directory.appending(path: "data.bin")
        try writeFile(target, bytes: 8192)
        try writeFile(directory.appending(path: "bystander"), bytes: 16)

        // Hold the descriptor across the repair the way an open-before-replace
        // reader would, so the truncation is observable after the name is gone.
        let held = open(target.path, O_RDONLY | O_CLOEXEC)
        #expect(held >= 0)
        defer { close(held) }
        var before = stat()
        #expect(fstat(held, &before) == 0)

        let authenticator = try makeAuthenticator()
        let actuator = try PfsMacOS26POSIXActuator(rootFileDescriptor: rootFD)
        let plan = try makePlan(
            authenticator: authenticator,
            kind: .dataInvalidation,
            path: try PfsMacOSRelativePath(components: [Data("data.bin".utf8)]),
            expectedVFSFileID: UInt64(before.st_ino),
            authoritativeSize: 4096
        )
        try await actuator.apply(plan)

        var after = stat()
        #expect(fstat(held, &after) == 0)
        #expect(after.st_size == 4096)
        let remaining = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(remaining == ["bystander"])
    }
}

@Test func dataInvalidationRefusesAMismatchedFileIDAndRestoresTheUsersFile() async throws {
    try await withTemporaryDirectory { directory, rootFD in
        let target = directory.appending(path: "data.bin")
        try writeFile(target, bytes: 8192)
        var status = stat()
        #expect(stat(target.path, &status) == 0)

        let authenticator = try makeAuthenticator()
        let actuator = try PfsMacOS26POSIXActuator(rootFileDescriptor: rootFD)
        let plan = try makePlan(
            authenticator: authenticator,
            kind: .dataInvalidation,
            path: try PfsMacOSRelativePath(components: [Data("data.bin".utf8)]),
            // The authority named an item this mount projects differently.
            expectedVFSFileID: UInt64(status.st_ino) &+ 1,
            authoritativeSize: 0
        )
        await #expect(throws: PfsMacOSCoherenceError.invalidRepairOperand) {
            try await actuator.apply(plan)
        }

        // Not truncated, not unlinked, not left under a hidden name.
        let remaining = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(remaining == ["data.bin"])
        var afterStatus = stat()
        #expect(stat(target.path, &afterStatus) == 0)
        #expect(afterStatus.st_size == 8192)
    }
}

@Test func aRefusedArmMeansTheDangerousActuatorPathNeverRuns() async throws {
    try await withTemporaryDirectory { directory, rootFD in
        try writeFile(directory.appending(path: "data.bin"), bytes: 4096)
        let authenticator = try makeAuthenticator()
        // Restricted deliberately: the test's claim is that a refused arm
        // stops the dangerous actuator path before its first syscall,
        // whatever the refused kind happens to be.
        let registry = PfsMacOS26RepairArmRegistry(
            authenticator: authenticator,
            supportedKinds: [.negativeScratch, .positiveEviction]
        )
        let backend = try PfsMacOS26CoherenceBackend(
            authenticator: authenticator,
            armer: registry,
            actuator: try PfsMacOS26POSIXActuator(rootFileDescriptor: rootFD),
            publicationBarrier: PassthroughPublicationBarrier()
        )
        let event = try PfsMacOSCoherenceEvent(
            epoch: enforcementEpoch,
            sequence: 1,
            phase: .complete,
            initiator: peerInitiator,
            repairs: [
                .invalidateData(
                    path: try PfsMacOSRelativePath(components: [Data("data.bin".utf8)]),
                    parentIdentity: parentIdentity,
                    itemIdentity: itemIdentity,
                    expectedVFSFileID: 1,
                    authoritativeSize: 0
                )
            ]
        )
        await #expect(throws: PfsMacOSCoherenceError.repairKindUnsupported(.dataInvalidation)) {
            try await backend.repair(event)
        }
        // Failing closed means the file is exactly as it was.
        let remaining = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(remaining == ["data.bin"])
    }
}

private struct PassthroughPublicationBarrier: PfsMacOSCallbackPublicationBarrier {
    func prepare(_ event: PfsMacOSCoherenceEvent) async throws {}
    func resume(_ event: PfsMacOSCoherenceEvent) async throws {}
    func acknowledged(_ event: PfsMacOSCoherenceEvent) async {}
}

private struct UnusedRepairActuator: PfsMacOS26RepairActuator {
    func apply(_ plan: PfsMacOS26RepairPlan) async throws {
        Issue.record("unrepresentable object repair reached the macOS 26 actuator")
    }
}

// MARK: - R3: the client derives path and VFS file id from stable identity

private func makeIndexFixture() async throws -> (PfsMacOSNamespaceIndex, PfsMacOSStableIdentity, PfsMacOSStableIdentity, PfsMacOSStableIdentity) {
    let root = try PfsMacOSStableIdentity(Data(repeating: 0x01, count: 16))
    let directory = try PfsMacOSStableIdentity(Data(repeating: 0x02, count: 16))
    let file = try PfsMacOSStableIdentity(Data(repeating: 0x03, count: 16))
    let index = PfsMacOSNamespaceIndex(rootIdentity: root)
    await index.record(
        identity: directory,
        entry: .init(parentIdentity: root, name: Data("projects".utf8), vfsFileID: 40)
    )
    await index.record(
        identity: file,
        entry: .init(parentIdentity: directory, name: Data("notes.txt".utf8), vfsFileID: 41)
    )
    return (index, root, directory, file)
}

@Test func plannerDerivesPathAndVFSFileIDTheAuthorityCannotKnow() async throws {
    let (index, root, directory, file) = try await makeIndexFixture()
    let planner = PfsMacOSRepairPlanner(index: index)
    let repairs = try await planner.repairs(for: [
        .namespace(
            parentIdentity: directory,
            name: Data("missing.txt".utf8)
        ),
        .data(identity: file, size: 4096)
    ])
    #expect(repairs.count == 2)
    guard case let .purgeNegative(parent, parentID, name) = repairs[0] else {
        Issue.record("expected a negative purge")
        return
    }
    #expect(parent.components == [Data("projects".utf8)])
    #expect(parentID == directory)
    #expect(name == Data("missing.txt".utf8))
    guard case let .invalidateData(path, _, _, fileID, size) = repairs[1] else {
        Issue.record("expected a data invalidation")
        return
    }
    #expect(path.components == [Data("projects".utf8), Data("notes.txt".utf8)])
    // Neither of these two values exists anywhere in `VisibilityTarget`.
    #expect(fileID == 41)
    #expect(size == 4096)
    _ = root
}

@Test func plannerSkipsIdentitiesThisMountNeverCached() async throws {
    let (index, _, _, _) = try await makeIndexFixture()
    let unknown = try PfsMacOSStableIdentity(Data(repeating: 0x77, count: 16))
    let planner = PfsMacOSRepairPlanner(index: index)
    let repairs = try await planner.repairs(for: [
        .attributes(identity: unknown)
    ])
    #expect(repairs.isEmpty)
}

@Test func plannerCoalescesParentAttributesIntoItsNamespaceRepairRegardlessOfTargetOrder() async throws {
    let (index, root, directory, _) = try await makeIndexFixture()
    let rootItem = PortableFSItem(identity: .init(
        itemID: 1,
        generation: 1,
        stableIdentity: root.bytes
    ))
    let directoryItem = PortableFSItem(identity: .init(
        itemID: 2,
        generation: 1,
        stableIdentity: directory.bytes
    ))
    let live = PfsMacOSLiveObjectIndex()
    try await live.record(item: rootItem, vfsFileID: 2)
    try await live.record(item: directoryItem, vfsFileID: 3)
    let planner = PfsMacOSRepairPlanner(index: index, liveObjects: live)

    for targets: [PfsMacOSVisibilityTarget] in [
        [
            .namespace(parentIdentity: directory, name: Data("peer-created".utf8)),
            .attributes(identity: directory),
        ],
        [
            .attributes(identity: directory),
            .namespace(parentIdentity: directory, name: Data("peer-created".utf8)),
        ],
    ] {
        let repairs = try await planner.repairs(for: targets)
        #expect(repairs.count == 1)
        guard case let .purgeNegative(parent, parentIdentity, name) = repairs.first else {
            Issue.record("expected the namespace repair to own its parent attribute refresh")
            continue
        }
        #expect(parent.components == [Data("projects".utf8)])
        #expect(parentIdentity == directory)
        #expect(name == Data("peer-created".utf8))
    }

    // A different directory's attribute obligation is not coalesced merely
    // because some namespace transaction exists in the event.
    let distinct = try await planner.repairs(for: [
        .namespace(parentIdentity: directory, name: Data("peer-created".utf8)),
        .attributes(identity: root),
    ])
    #expect(distinct.count == 2)
    guard case let .invalidateAttributesObject(_, identity) = distinct[1] else {
        Issue.record("expected the unrelated root attribute repair to remain")
        return
    }
    #expect(identity == root)
}

@Test func plannerNormalizesCompleteAuthorityMutationTargetShapes() async throws {
    let (index, _, directory, file) = try await makeIndexFixture()
    let planner = PfsMacOSRepairPlanner(index: index)
    let oldName = Data("notes.txt".utf8)
    let newName = Data("moved.txt".utf8)

    // Unlink repeats the removed item through NAMESPACE and ATTRIBUTES. The
    // exact same pathname surgery must run once, or the second rename addresses
    // a binding the first repair already retired.
    let unlink = try await planner.repairs(for: [
        .namespace(parentIdentity: directory, name: oldName),
        .attributes(identity: directory),
        .attributes(identity: file),
    ])
    #expect(unlink.count == 1)
    guard case let .evictBinding(unlinkPath, _, unlinkIdentity, _) = unlink.first else {
        Issue.record("expected one canonical unlink eviction")
        return
    }
    #expect(unlinkPath.name == oldName)
    #expect(unlinkIdentity == file)

    // Write/truncate carries DATA plus ATTRIBUTES for the same item. The data
    // actuator's post-apply getattr owns the attribute refresh; following it
    // with an eviction would address the name it just removed.
    for targets: [PfsMacOSVisibilityTarget] in [
        [.data(identity: file, size: 4096), .attributes(identity: file)],
        [.attributes(identity: file), .data(identity: file, size: 4096)],
    ] {
        let write = try await planner.repairs(for: targets)
        #expect(write.count == 1)
        guard case let .invalidateData(_, _, identity, _, size) = write.first else {
            Issue.record("expected one canonical data invalidation")
            continue
        }
        #expect(identity == file)
        #expect(size == 4096)
    }

    // Rename repeats both the parent and moved-item attribute obligations.
    // Its two namespace edges are the complete minimal repair set.
    let rename = try await planner.repairs(for: [
        .namespace(parentIdentity: directory, name: oldName),
        .namespace(parentIdentity: directory, name: newName),
        .attributes(identity: directory),
        .attributes(identity: directory),
        .attributes(identity: file),
    ])
    #expect(rename.count == 2)
    let renameKinds = rename.map { repair -> Int in
        switch repair {
        case .evictBinding: 1
        case .purgeNegative: 2
        default: 0
        }
    }
    guard Set(renameKinds) == Set([1, 2]) else {
        Issue.record("expected old-name eviction plus new-name negative purge")
        return
    }

    // Link creation refreshes the parent through its new-name scratch, but the
    // source inode's nlink change still needs one existing alias eviction.
    let link = try await planner.repairs(for: [
        .namespace(parentIdentity: directory, name: Data("linked.txt".utf8)),
        .attributes(identity: directory),
        .attributes(identity: file),
    ])
    #expect(link.count == 2)
    guard case .purgeNegative = link[0], case .refreshAttributes = link[1] else {
        Issue.record("expected link-name purge plus source-attribute refresh")
        return
    }
}


@Test func authorityPostBindingRepairsRetainedVNodeAfterRenameThenHardLink() async throws {
    let (index, _, directory, file) = try await makeIndexFixture()
    let live = PfsMacOSLiveObjectIndex()
    let item = PortableFSItem(identity: .init(
        itemID: 77,
        generation: 1,
        stableIdentity: file.bytes
    ))
    try await live.record(
        item: item,
        vfsFileID: 41,
        itemKind: .file
    )
    let planner = PfsMacOSRepairPlanner(index: index, liveObjects: live)
    let oldName = Data("notes.txt".utf8)
    let renamed = Data("renamed.txt".utf8)

    // The rename COMPLETE attests the moved identity at its destination. The
    // old positive coordinate is still the current local binding while the
    // plan is derived, so its exact eviction owns the immediate refresh.
    let rename = try await planner.repairs(for: [
        .namespace(parentIdentity: directory, name: oldName),
        .namespacePost(
            parentIdentity: directory,
            name: renamed,
            identity: file
        ),
        .attributes(identity: file),
    ])
    #expect(rename.contains { repair in
        if case let .evictBinding(path, _, identity, _) = repair {
            return path.name == oldName && identity == file
        }
        return false
    })

    // Model the successful positive-eviction callback: the old coordinate is
    // deliberately forgotten and must never become a repair locator.
    await index.forget(parentIdentity: directory, name: oldName)
    #expect(await index.entries(for: file).isEmpty)
    #expect(await index.repairLocatorEntries(for: file).isEmpty)

    // A later hard-link carries the new coordinate plus the same inode's nlink
    // obligation. The authority post-binding and retained vnode's published
    // kind/file-ID together make the alias an inode-attested repair source.
    let alias = Data("alias.txt".utf8)
    let link = try await planner.repairs(for: [
        .namespacePost(
            parentIdentity: directory,
            name: alias,
            identity: file
        ),
        .attributes(identity: file),
    ])
    #expect(link.count == 1)
    guard case let .refreshAttributes(
        path,
        parentIdentity,
        identity,
        expectedVFSFileID,
        itemKind
    ) = link.first else {
        Issue.record("expected post-binding attribute refresh through the new alias")
        return
    }
    #expect(path.name == alias)
    #expect(parentIdentity == directory)
    #expect(identity == file)
    #expect(expectedVFSFileID == 41)
    #expect(itemKind == .file)
    #expect(path.name != oldName)
}

@Test func plannerDeduplicatesOnlyTheExactHardLinkCoordinate() async throws {
    let (index, _, directory, file) = try await makeIndexFixture()
    let alias = Data("other-notes.txt".utf8)
    await index.record(
        identity: file,
        entry: .init(parentIdentity: directory, name: alias, vfsFileID: 41)
    )
    let planner = PfsMacOSRepairPlanner(index: index)
    let repairs = try await planner.repairs(for: [
        .namespace(parentIdentity: directory, name: Data("notes.txt".utf8)),
        .attributes(identity: directory),
        .attributes(identity: file),
    ])

    // The unlinked coordinate is repeated and collapses; the other hard-link
    // alias is a distinct cache obligation and must remain.
    #expect(repairs.count == 2)
    let names = repairs.compactMap { repair -> Data? in
        switch repair {
        case let .evictBinding(path, _, _, _),
             let .refreshAttributes(path, _, _, _, _):
            return path.name
        default:
            return nil
        }
    }
    #expect(Set(names) == Set([Data("notes.txt".utf8), alias]))
}

@Test func plannerNormalizationIsOrderIndependentAndRejectsConflictingDataTruth() async throws {
    let (index, _, directory, file) = try await makeIndexFixture()
    let planner = PfsMacOSRepairPlanner(index: index)
    let targets: [PfsMacOSVisibilityTarget] = [
        .namespace(parentIdentity: directory, name: Data("notes.txt".utf8)),
        .namespace(parentIdentity: directory, name: Data("notes.txt".utf8)),
        .attributes(identity: directory),
        .attributes(identity: file),
        .attributes(identity: file),
    ]
    let forward = try await planner.repairs(for: targets)
    let reverse = try await planner.repairs(for: Array(targets.reversed()))
    #expect(forward == reverse)
    #expect(forward.count == 1)

    await #expect(throws: PfsMacOSCoherenceError.invalidVisibilityTarget) {
        _ = try await planner.repairs(for: [
            .data(identity: file, size: 1),
            .data(identity: file, size: 2),
        ])
    }
}

@Test func plannerNeverAcknowledgesAKnownButUnpathableCachedTarget() async throws {
    let root = try PfsMacOSStableIdentity(Data(repeating: 0x41, count: 16))
    let missingAncestor = try PfsMacOSStableIdentity(Data(repeating: 0x42, count: 16))
    let directory = try PfsMacOSStableIdentity(Data(repeating: 0x43, count: 16))
    let file = try PfsMacOSStableIdentity(Data(repeating: 0x44, count: 16))
    let index = PfsMacOSNamespaceIndex(rootIdentity: root)
    await index.record(
        identity: directory,
        entry: .init(parentIdentity: missingAncestor, name: Data("detached".utf8), vfsFileID: 7)
    )
    await index.record(
        identity: file,
        entry: .init(parentIdentity: directory, name: Data("cached".utf8), vfsFileID: 8)
    )
    let planner = PfsMacOSRepairPlanner(index: index)

    await #expect(throws: PfsMacOSCoherenceError.cachedTargetUnrepresentable) {
        _ = try await planner.repairs(for: [
            .namespace(parentIdentity: directory, name: Data("cached".utf8)),
        ])
    }
    await #expect(throws: PfsMacOSCoherenceError.cachedTargetUnrepresentable) {
        _ = try await planner.repairs(for: [.attributes(identity: file)])
    }
}

@Test func rootAttributeTargetWithoutARepresentableRepairFailsClosed() async throws {
    let root = try PfsMacOSStableIdentity(Data(repeating: 0x4A, count: 16))
    let index = PfsMacOSNamespaceIndex(rootIdentity: root)
    let planner = PfsMacOSRepairPlanner(index: index)

    await #expect(throws: PfsMacOSCoherenceError.cachedTargetUnrepresentable) {
        _ = try await planner.repairs(for: [.attributes(identity: root)])
    }
}

@Test func plannerCoverageComesOnlyFromRepairsThatRemainSelected() async throws {
    let (index, root, directory, file) = try await makeIndexFixture()
    let live = PfsMacOSLiveObjectIndex()
    let rootItem = PortableFSItem(identity: .init(
        itemID: 1,
        generation: 1,
        stableIdentity: root.bytes
    ))
    try await live.record(item: rootItem, vfsFileID: 2)
    let planner = PfsMacOSRepairPlanner(index: index, liveObjects: live)

    let repairs = try await planner.repairs(for: [
        .attributes(identity: root),
        .attributes(identity: directory),
        .attributes(identity: file),
    ])
    // The deepest file eviction refreshes the directory, so the directory's
    // own eviction is removed. Because that removed repair never mutates root,
    // root's independently cached object obligation must remain.
    #expect(repairs.count == 2)
    #expect(repairs.contains { if case .refreshAttributes = $0 { true } else { false } })
    #expect(repairs.contains { repair in
        if case let .invalidateAttributesObject(_, identity) = repair {
            return identity == root
        }
        return false
    })
}

@Test func openObjectsOnBothMountsSurviveUnlinkAndPlanNativeDataAndAttributeRepair() async throws {
    let root = try PfsMacOSStableIdentity(Data(repeating: 0x61, count: 16))
    let directory = try PfsMacOSStableIdentity(Data(repeating: 0x62, count: 16))
    let file = try PfsMacOSStableIdentity(Data(repeating: 0x63, count: 16))

    func makeMount(
        itemID: UInt64,
        vfsFileID: UInt64
    ) async throws -> (PfsMacOSRepairPlanner, PortableFSItem, PfsMacOSNamespaceIndex, PfsMacOSLiveObjectIndex) {
        let namespace = PfsMacOSNamespaceIndex(rootIdentity: root)
        let live = PfsMacOSLiveObjectIndex()
        await namespace.record(
            identity: directory,
            entry: .init(parentIdentity: root, name: Data("dir".utf8), vfsFileID: 10)
        )
        await namespace.record(
            identity: file,
            entry: .init(parentIdentity: directory, name: Data("open.bin".utf8), vfsFileID: vfsFileID)
        )
        let item = PortableFSItem(identity: .init(
            itemID: itemID,
            generation: 1,
            stableIdentity: file.bytes
        ))
        try await live.record(item: item, vfsFileID: vfsFileID)
        // The last name disappeared, but each mount still has an open FSItem.
        await namespace.forget(parentIdentity: directory, name: Data("open.bin".utf8))
        return (
            PfsMacOSRepairPlanner(index: namespace, liveObjects: live),
            item,
            namespace,
            live
        )
    }

    let mounts = [
        try await makeMount(itemID: 40, vfsFileID: 401),
        try await makeMount(itemID: 50, vfsFileID: 501),
    ]
    for (planner, item, namespace, live) in mounts {
        #expect(await namespace.entries(for: file).isEmpty)
        #expect(await live.count() == 1)
        let repairs = try await planner.repairs(for: [
            .data(identity: file, size: 8_192),
            .attributes(identity: file),
        ])
        #expect(repairs.count == 2)
        guard case let .invalidateDataObject(object, identity, size) = repairs[0] else {
            Issue.record("expected direct live-object data invalidation")
            continue
        }
        #expect(object.item === item)
        #expect(identity == file)
        #expect(size == 8_192)
        guard case let .invalidateAttributesObject(attributeObject, attributeIdentity) = repairs[1] else {
            Issue.record("expected direct live-object attribute invalidation")
            continue
        }
        #expect(attributeObject.item === item)
        #expect(attributeIdentity == file)

        // Close/reclaim, not unlink, retires the object obligation.
        await live.forget(item: item)
        #expect(try await planner.repairs(for: [.data(identity: file, size: 0)]).isEmpty)
    }
}

@Test func macOS26CannotAckAnUnpathableLiveObjectRepair() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let backend = try PfsMacOS26CoherenceBackend(
        authenticator: authenticator,
        armer: registry,
        actuator: UnusedRepairActuator(),
        publicationBarrier: PassthroughPublicationBarrier()
    )
    let transport = AckFailingTransport(failures: 0)
    let runner = try PfsMacOSCoherenceRunner(
        epoch: enforcementEpoch,
        backend: backend,
        transport: transport
    )
    let prepare = try PfsMacOSCoherenceEvent(
        epoch: enforcementEpoch,
        sequence: 1,
        phase: .prepare,
        initiator: peerInitiator,
        repairs: []
    )
    let item = PortableFSItem(identity: .init(
        itemID: 70,
        generation: 1,
        stableIdentity: itemIdentity.bytes
    ))
    let complete = try PfsMacOSCoherenceEvent(
        epoch: enforcementEpoch,
        sequence: 1,
        phase: .complete,
        initiator: peerInitiator,
        repairs: [
            .purgeNegative(
                parent: try PfsMacOSRelativePath(components: []),
                parentIdentity: parentIdentity,
                name: Data("must-not-run".utf8)
            ),
            .invalidateDataObject(
                object: .init(item: item, vfsFileID: 71),
                itemIdentity: itemIdentity,
                authoritativeSize: 0
            )
        ]
    )

    try await runner.consume(prepare)
    await #expect(throws: PfsMacOSCoherenceError.unsupportedRepair) {
        try await runner.consume(complete)
    }
    #expect(await transport.acks() == [
        .init(sequence: 1, phase: .prepare),
    ])
    #expect(await runner.completedCursor() == .init(sequence: 1, phase: .prepare))
}

@Test func plannerEvictsTheExactKnownNamespaceCoordinate() async throws {
    let (index, _, directory, file) = try await makeIndexFixture()
    let planner = PfsMacOSRepairPlanner(index: index)
    let repairs = try await planner.repairs(for: [
        .namespace(
            parentIdentity: directory,
            name: Data("notes.txt".utf8)
        )
    ])
    #expect(repairs.count == 1)
    guard case let .evictBinding(path, parent, identity, _) = repairs[0] else {
        Issue.record("expected a binding eviction")
        return
    }
    #expect(path.components == [Data("projects".utf8), Data("notes.txt".utf8)])
    #expect(parent == directory)
    #expect(identity == file)
}

@Test func namespaceIndexRefusesAParentChainThatCycles() async throws {
    let root = try PfsMacOSStableIdentity(Data(repeating: 0x01, count: 16))
    let a = try PfsMacOSStableIdentity(Data(repeating: 0x0a, count: 16))
    let b = try PfsMacOSStableIdentity(Data(repeating: 0x0b, count: 16))
    let index = PfsMacOSNamespaceIndex(rootIdentity: root)
    await index.record(identity: a, entry: .init(parentIdentity: b, name: Data("a".utf8), vfsFileID: 1))
    await index.record(identity: b, entry: .init(parentIdentity: a, name: Data("b".utf8), vfsFileID: 2))
    await #expect(throws: PfsMacOSCoherenceError.namespaceCycle) {
        _ = try await index.path(for: a)
    }
}

@Test func attachParametersRefuseToPresentAnUnboundedRepairBudgetAsBounded() {
    let unbounded = PfsMacOSCoherenceAttachParameters(
        coherenceProfile: .synchronousVFSRepairV1,
        cachedNameCapacity: 4096,
        repairBudgetMillis: 0
    )
    #expect(!unbounded.offersBoundedRepair)
    #expect(unbounded.coherenceProfile.rawValue == "macos26-synchronous-vfs-repair-v1")

    let proof = PfsMacOSMountAbsenceProof(
        observedUnixNanos: 1,
        observation: Data(),
        component: "getfsstat"
    )
    #expect(!proof.isWellFormed)
}
