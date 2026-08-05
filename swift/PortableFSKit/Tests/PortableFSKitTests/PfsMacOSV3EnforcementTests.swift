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
            sourceName: nil,
            parentIdentity: parentIdentity.bytes,
            item: nil
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

@Test func oneShotConsumptionIsAtomicUnderConcurrentCallbacks() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
    )
    _ = try await registry.arm(plan)
    let operand = try #require(plan.operand)

    // Sixty racing callbacks all naming the same legitimate operand. Exactly
    // one may be swallowed; the rest must fail closed, because each extra
    // success would be a real rename of a real user file.
    let successes = await withTaskGroup(of: Bool.self) { group in
        for _ in 0..<60 {
            group.addTask {
                do {
                    try await registry.consume(
                        callback: .renameIntoOperand,
                        operand: operand,
                        sourceName: Data("victim".utf8),
                        parentIdentity: parentIdentity.bytes,
                        item: nil
                    )
                    return true
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

@Test func armedRenameRequiresTheExactAuthenticatedSourceName() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
    )
    _ = try await registry.arm(plan)
    let operand = try #require(plan.operand)
    await #expect(throws: PfsMacOSCoherenceError.invalidRepairOperand) {
        try await registry.consume(
            callback: .renameIntoOperand,
            operand: operand,
            sourceName: Data("someone-elses-file".utf8),
            parentIdentity: parentIdentity.bytes,
            item: nil
        )
    }
    #expect(await registry.pendingCallbacks(operand: operand) == [.renameIntoOperand, .removeOperand])
}

@Test func callbacksMustArriveInTheOrderThePlanDeclared() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
    )
    _ = try await registry.arm(plan)
    let operand = try #require(plan.operand)
    // Removal before the isolating rename would unlink the user's own name.
    await #expect(throws: PfsMacOSCoherenceError.repairCallbackOutOfOrder) {
        try await registry.consume(callback: .removeOperand, operand: operand, sourceName: nil, parentIdentity: parentIdentity.bytes, item: nil)
    }
    try await registry.consume(
        callback: .renameIntoOperand,
        operand: operand,
        sourceName: Data("victim".utf8),
        parentIdentity: parentIdentity.bytes,
        item: nil
    )
    await #expect(throws: PfsMacOSCoherenceError.repairAlreadyConsumed) {
        try await registry.consume(
            callback: .renameIntoOperand,
            operand: operand,
            sourceName: Data("victim".utf8),
            parentIdentity: parentIdentity.bytes,
            item: nil
        )
    }
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
    let operand = try #require(plan.operand)
    let isolated = PortableFSItem(identity: .init(
        itemID: 9,
        generation: 1,
        stableIdentity: itemIdentity.bytes
    ))

    // Before the isolating rename there is no window: nothing is consumable
    // and no reserved lookup is answerable.
    #expect(await registry.consumeArmedTruncate(
        itemIdentity: itemIdentity.bytes,
        size: 4096
    ) == nil)
    #expect(await registry.isolatedRepairItem(operand: operand) == nil)
    // Removal cannot end a window whose data half never executed.
    await #expect(throws: PfsMacOSCoherenceError.repairCallbackOutOfOrder) {
        try await registry.consume(
            callback: .removeOperand,
            operand: operand,
            sourceName: nil,
            parentIdentity: parentIdentity.bytes,
            item: nil
        )
    }

    try await registry.consume(
        callback: .renameIntoOperand,
        operand: operand,
        sourceName: Data("data.bin".utf8),
        parentIdentity: parentIdentity.bytes,
        item: isolated
    )
    #expect(await registry.isolatedRepairItem(operand: operand) === isolated)
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

    try await registry.consume(
        callback: .removeOperand,
        operand: operand,
        sourceName: nil,
        parentIdentity: parentIdentity.bytes,
        item: nil
    )
    // The window closed with the removal; nothing further is consumable.
    #expect(await registry.consumeArmedTruncate(
        itemIdentity: itemIdentity.bytes,
        size: 4096
    ) == nil)
    #expect(await registry.isolatedRepairItem(operand: operand) == nil)
    #expect(await registry.isArmedTruncateItem(itemIdentity: itemIdentity.bytes) == false)
    try await lease.finish()
    #expect(await registry.armedOperandCount() == 0)
}

@Test func armedTruncateWindowClosesOnRollback() async throws {
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
    let operand = try #require(plan.operand)
    let isolated = PortableFSItem(identity: .init(
        itemID: 10,
        generation: 1,
        stableIdentity: itemIdentity.bytes
    ))
    try await registry.consume(
        callback: .renameIntoOperand,
        operand: operand,
        sourceName: Data("data.bin".utf8),
        parentIdentity: parentIdentity.bytes,
        item: isolated
    )
    try await registry.consume(
        callback: .rollbackRename,
        operand: operand,
        sourceName: Data("data.bin".utf8),
        parentIdentity: parentIdentity.bytes,
        item: nil
    )
    // Rollback restored the user's name; the window and its one-shot are gone.
    #expect(await registry.consumeArmedTruncate(
        itemIdentity: itemIdentity.bytes,
        size: 1024
    ) == nil)
    #expect(await registry.isolatedRepairItem(operand: operand) == nil)
    await lease.cancel()
    #expect(await registry.tornRepairs().isEmpty)
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
    // Exact operand, exact source basename — wrong directory. The HMAC binds
    // the parent, and consumption re-checks it.
    await #expect(throws: PfsMacOSCoherenceError.invalidRepairOperand) {
        try await registry.consume(
            callback: .renameIntoOperand,
            operand: operand,
            sourceName: Data("victim".utf8),
            parentIdentity: itemIdentity.bytes,
            item: nil
        )
    }
    // A missing parent identity is refused too: fail closed, never open.
    await #expect(throws: PfsMacOSCoherenceError.invalidRepairOperand) {
        try await registry.consume(
            callback: .renameIntoOperand,
            operand: operand,
            sourceName: Data("victim".utf8),
            parentIdentity: nil,
            item: nil
        )
    }
    #expect(await registry.pendingCallbacks(operand: operand) == [.renameIntoOperand, .removeOperand])
}

@Test func aPartiallyConsumedTransactionIsTornAndSealsTheRegistry() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
    )
    let lease = try await registry.arm(plan)
    let operand = try #require(plan.operand)
    try await registry.consume(
        callback: .renameIntoOperand,
        operand: operand,
        sourceName: Data("victim".utf8),
        parentIdentity: parentIdentity.bytes,
        item: nil
    )
    await #expect(throws: PfsMacOSCoherenceError.self) { try await lease.finish() }

    let torn = await registry.tornRepairs()
    #expect(torn.count == 1)
    #expect(torn.first?.hiddenName == operand)
    #expect(torn.first?.sourceName == Data("victim".utf8))
    #expect(await registry.isSealed)

    let next = try makePlan(
        authenticator: authenticator,
        kind: .negativeScratch,
        path: try PfsMacOSRelativePath(components: []),
        sequence: 2
    )
    await #expect(throws: PfsMacOSCoherenceError.repairRegistrySealed) {
        _ = try await registry.arm(next)
    }
}

@Test func aRolledBackTransactionLeavesNoTear() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
    )
    let lease = try await registry.arm(plan)
    let operand = try #require(plan.operand)
    try await registry.consume(
        callback: .renameIntoOperand,
        operand: operand,
        sourceName: Data("victim".utf8),
        parentIdentity: parentIdentity.bytes,
        item: nil
    )
    try await registry.consume(
        callback: .rollbackRename,
        operand: operand,
        sourceName: Data("victim".utf8),
        parentIdentity: parentIdentity.bytes,
        item: nil
    )
    await lease.cancel()
    #expect(await registry.tornRepairs().isEmpty)
    #expect(await registry.isSealed == false)
}

@Test func rollbackIsNotAuthorizedBeforeTheIsolatingRename() async throws {
    let authenticator = try makeAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try makePlan(
        authenticator: authenticator,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("victim".utf8)])
    )
    _ = try await registry.arm(plan)
    let operand = try #require(plan.operand)
    await #expect(throws: PfsMacOSCoherenceError.repairCallbackOutOfOrder) {
        try await registry.consume(
            callback: .rollbackRename,
            operand: operand,
            sourceName: Data("victim".utf8),
            parentIdentity: parentIdentity.bytes,
            item: nil
        )
    }
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
    try await registry.consume(callback: .createScratch, operand: operand, sourceName: nil, parentIdentity: parentIdentity.bytes, item: nil)
    try await registry.consume(callback: .removeOperand, operand: operand, sourceName: nil, parentIdentity: parentIdentity.bytes, item: nil)
    try await lease.finish()
    #expect(await registry.armedOperandCount() == 0)
    // The name is now ordinary again — and therefore refused again.
    await #expect(throws: PfsMacOSCoherenceError.repairNotArmed) {
        try await registry.consume(callback: .createScratch, operand: operand, sourceName: nil, parentIdentity: parentIdentity.bytes, item: nil)
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
            localAuthoritySessionID: Data(repeating: 0x99, count: 16),
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
        localAuthoritySessionID: Data(repeating: 0x99, count: 16),
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
    guard case let .evictBinding(path, parent, identity) = repairs[0] else {
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
