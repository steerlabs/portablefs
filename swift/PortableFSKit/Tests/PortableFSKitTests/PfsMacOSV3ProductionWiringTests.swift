import Foundation
import FSKit
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

// MARK: - Fixtures

private let wiringEpoch = Data(repeating: 0xD4, count: 16)
private let wiringSecret = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 &* 13 &+ 5) })
private let wiringLocalSession = Data(repeating: 0xE5, count: 16)
private let wiringPeerSession = Data(repeating: 0xF6, count: 16)

private func peerEvent(
    sequence: UInt64 = 1,
    phase: PfsMacOSVisibilityPhase
) throws -> PfsMacOSCoherenceEvent {
    try PfsMacOSCoherenceEvent(
        epoch: wiringEpoch,
        sequence: sequence,
        phase: phase,
        initiator: try PfsMacOSMutationInitiator(
            sessionID: wiringPeerSession,
            replaySlot: 1,
            mutationSequence: 7
        ),
        repairs: []
    )
}

private func localEvent(
    sequence: UInt64 = 1,
    phase: PfsMacOSVisibilityPhase,
    localOperationID: UInt64
) throws -> PfsMacOSCoherenceEvent {
    try PfsMacOSCoherenceEvent(
        epoch: wiringEpoch,
        sequence: sequence,
        phase: phase,
        initiator: try PfsMacOSMutationInitiator(
            sessionID: wiringLocalSession,
            replaySlot: 1,
            mutationSequence: 7,
            localOperationID: localOperationID
        ),
        repairs: []
    )
}

@available(macOS 26.0, *)
private struct WiringHarness {
    let daemon: PfsLocalMockDaemon
    let core: VolumeCore
    let volume: PortableFSVolume
    let root: PortableFSItem
    let coherence: PfsMacOSV3VolumeCoherence
    let registry: PfsMacOS26RepairArmRegistry
    let authenticator: PfsMacOS26RepairAuthenticator

    var rootIdentity: PfsMacOSStableIdentity {
        try! PfsMacOSStableIdentity(root.identity.stableIdentity)
    }
}

/// A legacy-mock harness carrying an explicitly injected coherence bundle:
/// real indexes, real barrier, real registry — no transport/runner, so tests
/// can drive the barrier's phases directly.
@available(macOS 26.0, *)
private func makeWiringHarness(
    daemonConfiguration: PfsLocalMockDaemon.Configuration = .init(),
    namespaceCapacity: Int = PfsMacOSV3VolumeCoherence.defaultNamespaceCapacity,
    liveObjectCapacity: Int = PfsMacOSV3VolumeCoherence.defaultLiveObjectCapacity
) async throws -> WiringHarness {
    let daemon = try PfsLocalMockDaemon(configuration: daemonConfiguration)
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let rootIdentity = try PfsMacOSStableIdentity(root.identity.stableIdentity)
    let authenticator = try PfsMacOS26RepairAuthenticator(
        mountSessionID: UUID(),
        secret: wiringSecret
    )
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let coherence = PfsMacOSV3VolumeCoherence(
        contract: nil,
        namespaceIndex: PfsMacOSNamespaceIndex(rootIdentity: rootIdentity),
        liveObjects: PfsMacOSLiveObjectIndex(),
        barrier: try PfsMacOSFSKitPublicationBarrier(
            localAuthoritySessionID: wiringLocalSession
        ),
        repairGate: registry,
        namespaceCapacity: namespaceCapacity,
        liveObjectCapacity: liveObjectCapacity
    )
    let volume = try await PortableFSVolume.make(
        core: core,
        attachRef: "mock",
        coherence: coherence
    )
    await daemon.resetStats()
    return WiringHarness(
        daemon: daemon,
        core: core,
        volume: volume,
        root: root,
        coherence: coherence,
        registry: registry,
        authenticator: authenticator
    )
}

@available(macOS 26.0, *)
private final class AcceptAllDirectoryPacker: FSDirectoryEntryPacker {
    override func packEntry(
        name: FSFileName,
        itemType: FSItem.ItemType,
        itemID: FSItem.Identifier,
        nextCookie: FSDirectoryCookie,
        attributes: FSItem.Attributes?
    ) -> Bool {
        true
    }
}

private final class PfsReplyBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value?

    func set(_ value: Value) {
        lock.lock()
        stored = value
        lock.unlock()
    }

    func get() -> Value? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }
}

private func waitUntil(
    _ deadline: Duration = .seconds(2),
    _ condition: () async -> Bool
) async throws -> Bool {
    let clock = ContinuousClock()
    let end = clock.now + deadline
    while clock.now < end {
        if await condition() { return true }
        try await Task.sleep(for: .milliseconds(5))
    }
    return await condition()
}

private func expectEPERM(_ error: any Error) {
    #expect((error as NSError).code == Int(EPERM))
}

private func expectENOENT(_ error: any Error) {
    #expect((error as NSError).code == Int(ENOENT))
}

// MARK: - Index population

@available(macOS 26.0, *)
@Test func adapterPopulatesTheNamespaceIndexAcrossEveryBindingCallback() async throws {
    let harness = try await makeWiringHarness()
    let index = harness.coherence.namespaceIndex

    // create publishes a binding and a live object.
    let (created, _) = try await harness.volume.createItem(
        named: FSFileName(string: "a"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let file = try #require(created as? PortableFSItem)
    let fileIdentity = try PfsMacOSStableIdentity(file.identity.stableIdentity)
    let binding = try #require(await index.binding(
        parentIdentity: harness.rootIdentity,
        name: Data("a".utf8)
    ))
    #expect(binding.identity == fileIdentity)
    #expect(binding.entry.vfsFileID == file.identity.itemID + 1)
    #expect(await harness.coherence.liveObjects.objects(for: fileIdentity).count == 1)

    // mkdir and symlink publish bindings too.
    let (directory, _) = try await harness.volume.createItem(
        named: FSFileName(string: "dir"),
        type: .directory,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let directoryItem = try #require(directory as? PortableFSItem)
    #expect(await index.binding(
        parentIdentity: harness.rootIdentity,
        name: Data("dir".utf8)
    ) != nil)
    _ = try await harness.volume.createSymbolicLink(
        named: FSFileName(string: "ln"),
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest(),
        linkContents: FSFileName(string: "a")
    )
    #expect(await index.binding(
        parentIdentity: harness.rootIdentity,
        name: Data("ln".utf8)
    ) != nil)

    // Every hard-link alias is a distinct recorded obligation.
    _ = try await harness.volume.createLink(
        to: file,
        named: FSFileName(string: "b"),
        inDirectory: harness.root
    )
    #expect(await index.entries(for: fileIdentity).count == 2)

    // Rename retires the source edge and publishes the destination edge.
    _ = try await harness.volume.renameItem(
        file,
        inDirectory: harness.root,
        named: FSFileName(string: "a"),
        to: FSFileName(string: "c"),
        inDirectory: directoryItem,
        overItem: nil
    )
    #expect(await index.binding(
        parentIdentity: harness.rootIdentity,
        name: Data("a".utf8)
    ) == nil)
    let moved = try #require(await index.binding(
        parentIdentity: try PfsMacOSStableIdentity(directoryItem.identity.stableIdentity),
        name: Data("c".utf8)
    ))
    #expect(moved.identity == fileIdentity)
    #expect(await index.entries(for: fileIdentity).count == 2)

    // A lookup hit records the exact published coordinate.
    let lookedUp = try await harness.volume.lookupItem(
        named: FSFileName(string: "c"),
        inDirectory: directoryItem
    )
    #expect((lookedUp.0 as? PortableFSItem) === file)

    // Remove retires exactly the removed alias.
    try await harness.volume.removeItem(
        file,
        named: FSFileName(string: "b"),
        fromDirectory: harness.root
    )
    #expect(await index.binding(
        parentIdentity: harness.rootIdentity,
        name: Data("b".utf8)
    ) == nil)
    #expect(await index.entries(for: fileIdentity).count == 1)
}

@available(macOS 26.0, *)
@Test func adapterPopulatesTheNamespaceIndexFromEnumerationHits() async throws {
    let harness = try await makeWiringHarness()
    for name in ["one", "two", "three"] {
        _ = try await harness.volume.createItem(
            named: FSFileName(string: name),
            type: .file,
            inDirectory: harness.root,
            attributes: FSItem.SetAttributesRequest()
        )
    }
    // A fresh index proves enumeration itself records: the bindings created
    // above are already there, so wipe them by using names the packer walk
    // republishes and checking identity of the enumeration-recorded facts.
    let fresh = PfsMacOSNamespaceIndex(rootIdentity: harness.rootIdentity)
    let enumerating = PfsMacOSV3VolumeCoherence(
        contract: nil,
        namespaceIndex: fresh,
        liveObjects: PfsMacOSLiveObjectIndex(),
        barrier: try PfsMacOSFSKitPublicationBarrier(
            localAuthoritySessionID: wiringLocalSession
        ),
        repairGate: harness.registry
    )
    let volume = try await PortableFSVolume.make(
        core: harness.core,
        attachRef: "mock",
        coherence: enumerating
    )
    let packer = class_createInstance(
        AcceptAllDirectoryPacker.self, 0
    ) as! AcceptAllDirectoryPacker
    _ = try await volume.enumerateDirectory(
        harness.root,
        startingAt: .initial,
        verifier: .initial,
        attributes: nil,
        packer: packer
    )
    for name in ["one", "two", "three"] {
        #expect(await fresh.binding(
            parentIdentity: harness.rootIdentity,
            name: Data(name.utf8)
        ) != nil)
    }
}

@available(macOS 26.0, *)
@Test func liveObjectIndexSurvivesUnlinkAndRetiresOnReclaim() async throws {
    let harness = try await makeWiringHarness()
    let (created, _) = try await harness.volume.createItem(
        named: FSFileName(string: "open.bin"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let file = try #require(created as? PortableFSItem)
    let identity = try PfsMacOSStableIdentity(file.identity.stableIdentity)

    try await harness.volume.openItem(file, modes: .read)
    #expect(await harness.coherence.liveObjects.objects(for: identity).count == 1)

    // Unlink retires the namespace coordinate, never the live object.
    try await harness.volume.removeItem(
        file,
        named: FSFileName(string: "open.bin"),
        fromDirectory: harness.root
    )
    #expect(await harness.coherence.namespaceIndex.binding(
        parentIdentity: harness.rootIdentity,
        name: Data("open.bin".utf8)
    ) == nil)
    #expect(await harness.coherence.liveObjects.objects(for: identity).count == 1)

    try await harness.volume.closeItem(file, modes: [])
    #expect(await harness.coherence.liveObjects.objects(for: identity).count == 1)

    try await harness.volume.reclaimItem(file)
    #expect(await harness.coherence.liveObjects.objects(for: identity).isEmpty)
}

@available(macOS 26.0, *)
@Test func namespaceIndexCapacityRefusesNewBindingsInsteadOfDroppingOldOnes() async throws {
    let harness = try await makeWiringHarness(namespaceCapacity: 1)
    _ = try await harness.volume.createItem(
        named: FSFileName(string: "kept"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    do {
        _ = try await harness.volume.createItem(
            named: FSFileName(string: "over"),
            type: .file,
            inDirectory: harness.root,
            attributes: FSItem.SetAttributesRequest()
        )
        Issue.record("expected the over-capacity binding to be refused")
    } catch {
        #expect((error as NSError).code == Int(EIO))
    }
    // The exact record survives; nothing was silently evicted to make room.
    #expect(await harness.coherence.namespaceIndex.count() == 1)
    #expect(await harness.coherence.namespaceIndex.binding(
        parentIdentity: harness.rootIdentity,
        name: Data("kept".utf8)
    ) != nil)
}

// MARK: - Reserved-name lookups

@available(macOS 26.0, *)
@Test func reservedNameLookupsAreRefusedLocallyWithoutReachingTheDaemon() async throws {
    let harness = try await makeWiringHarness()
    let operand = try harness.authenticator.makeOperand(
        epoch: wiringEpoch,
        sequence: 1,
        step: 0,
        kind: .positiveEviction,
        parentIdentity: harness.rootIdentity,
        itemIdentity: .zero,
        sourceName: Data("x".utf8)
    )
    do {
        _ = try await harness.volume.lookupItem(
            named: PfsFSKitMapping.fileName(from: operand),
            inDirectory: harness.root
        )
        Issue.record("reserved lookup was answered")
    } catch { expectENOENT(error) }
    // Only the daemon can testify that no probe of the reserved namespace
    // ever became a request.
    #expect(await harness.daemon.stats().lookupRequests == 0)
}

// MARK: - Armed truncate through the adapter

@available(macOS 26.0, *)
@Test func armedTruncateIsConsumedLocallyAndEverythingElseFlowsThrough() async throws {
    let harness = try await makeWiringHarness()
    let (created, _) = try await harness.volume.createItem(
        named: FSFileName(string: "data.bin"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let file = try #require(created as? PortableFSItem)
    let fileIdentity = try PfsMacOSStableIdentity(file.identity.stableIdentity)

    // Outside any window a size change is an ordinary daemon setattr.
    let grow = FSItem.SetAttributesRequest()
    grow.size = 8192
    _ = try await harness.volume.setAttributes(grow, on: file)
    #expect(try await harness.core.getattr(item: file).size == 8192)
    await harness.daemon.resetStats()

    let operand = try harness.authenticator.makeOperand(
        epoch: wiringEpoch,
        sequence: 1,
        step: 0,
        kind: .dataInvalidation,
        parentIdentity: harness.rootIdentity,
        itemIdentity: fileIdentity,
        sourceName: Data("data.bin".utf8)
    )
    let lease = try await harness.registry.arm(PfsMacOS26RepairPlan(
        epoch: wiringEpoch,
        sequence: 1,
        step: 0,
        kind: .dataInvalidation,
        path: try PfsMacOSRelativePath(components: [Data("data.bin".utf8)]),
        parentIdentity: harness.rootIdentity,
        itemIdentity: fileIdentity,
        expectedVFSFileID: file.identity.itemID + 1,
        authoritativeSize: 4096,
        operand: operand
    ))
    let reserved = PfsFSKitMapping.fileName(from: operand)

    // The isolating rename is swallowed and retires the published source edge.
    _ = try await harness.volume.renameItem(
        file,
        inDirectory: harness.root,
        named: FSFileName(string: "data.bin"),
        to: reserved,
        inDirectory: harness.root,
        overItem: nil
    )
    #expect(await harness.coherence.namespaceIndex.binding(
        parentIdentity: harness.rootIdentity,
        name: Data("data.bin".utf8)
    ) == nil)

    // The actuator's own open path: the reserved lookup is answered with the
    // one isolated item, locally.
    let (isolated, _) = try await harness.volume.lookupItem(
        named: reserved,
        inDirectory: harness.root
    )
    #expect((isolated as? PortableFSItem) === file)
    try await harness.volume.openItem(file, modes: [.read, .write])

    // A mismatched size is never swallowed: it flows through and lands.
    let mismatched = FSItem.SetAttributesRequest()
    mismatched.size = 512
    _ = try await harness.volume.setAttributes(mismatched, on: file)
    #expect(try await harness.core.getattr(item: file).size == 512)

    // The exact armed truncate is consumed locally: the reply carries the
    // authoritative coordinates and the daemon sees no request at all.
    let exact = FSItem.SetAttributesRequest()
    exact.size = 4096
    let attributes = try await harness.volume.setAttributes(exact, on: file)
    #expect(attributes.size == 4096)
    #expect(attributes.fileID == FSItem.Identifier(rawValue: file.identity.itemID + 1))
    #expect(try await harness.core.getattr(item: file).size == 512)

    try await harness.volume.removeItem(
        file,
        named: reserved,
        fromDirectory: harness.root
    )
    try await lease.finish()

    let stats = await harness.daemon.stats()
    #expect(stats.renameRequests == 0)
    #expect(stats.removeRequests == 0)
    #expect(await harness.registry.tornRepairs().isEmpty)

    // The window is over: the reserved name is unresolvable again and an
    // identical size change is an ordinary daemon setattr.
    do {
        _ = try await harness.volume.lookupItem(named: reserved, inDirectory: harness.root)
        Issue.record("reserved lookup was answered after the window closed")
    } catch { expectENOENT(error) }
    let after = FSItem.SetAttributesRequest()
    after.size = 4096
    _ = try await harness.volume.setAttributes(after, on: file)
    #expect(try await harness.core.getattr(item: file).size == 4096)
}

@available(macOS 26.0, *)
@Test func sameBasenameRenameInAnotherDirectoryIsNeverSwallowed() async throws {
    let harness = try await makeWiringHarness()
    // The armed plan isolates root/"stale". A same-basename rename arriving
    // from a different directory must be refused, not swallowed.
    let (subdirectory, _) = try await harness.volume.createItem(
        named: FSFileName(string: "sub"),
        type: .directory,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let (victim, _) = try await harness.volume.createItem(
        named: FSFileName(string: "stale"),
        type: .file,
        inDirectory: subdirectory,
        attributes: FSItem.SetAttributesRequest()
    )
    let operand = try harness.authenticator.makeOperand(
        epoch: wiringEpoch,
        sequence: 1,
        step: 0,
        kind: .positiveEviction,
        parentIdentity: harness.rootIdentity,
        itemIdentity: boundaryItemIdentity,
        sourceName: Data("stale".utf8)
    )
    _ = try await harness.registry.arm(PfsMacOS26RepairPlan(
        epoch: wiringEpoch,
        sequence: 1,
        step: 0,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [Data("stale".utf8)]),
        parentIdentity: harness.rootIdentity,
        itemIdentity: boundaryItemIdentity,
        expectedVFSFileID: nil,
        authoritativeSize: nil,
        operand: operand
    ))
    await harness.daemon.resetStats()

    do {
        _ = try await harness.volume.renameItem(
            victim,
            inDirectory: subdirectory,
            named: FSFileName(string: "stale"),
            to: PfsFSKitMapping.fileName(from: operand),
            inDirectory: subdirectory,
            overItem: nil
        )
        Issue.record("a same-basename rename in another directory was swallowed")
    } catch { expectEPERM(error) }
    let stats = await harness.daemon.stats()
    #expect(stats.renameRequests == 0)
    #expect(await harness.registry.pendingCallbacks(operand: operand)
        == [.renameIntoOperand, .removeOperand])
}

private let boundaryItemIdentity = try! PfsMacOSStableIdentity(Data(repeating: 0x66, count: 16))

// MARK: - Publication barrier

@available(macOS 26.0, *)
@Test func barrierClosesAdmissionAtPrepareAndReopensAtPeerResume() async throws {
    let harness = try await makeWiringHarness()
    _ = try await harness.volume.createItem(
        named: FSFileName(string: "seen"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let barrier = harness.coherence.barrier

    try await barrier.prepare(try peerEvent(phase: .prepare))
    #expect(await barrier.isAdmissionClosed())

    let replied = PfsReplyBox<Bool>()
    harness.volume.lookupItem(
        named: FSFileName(string: "seen"),
        inDirectory: harness.root
    ) { item, _, _ in
        replied.set(item != nil)
    }
    // The callback is held at admission, not failed and not served.
    try await Task.sleep(for: .milliseconds(120))
    #expect(replied.get() == nil)

    try await barrier.resume(try peerEvent(phase: .complete))
    #expect(try await waitUntil { replied.get() == true })
    #expect(await barrier.isAdmissionClosed() == false)
}

@available(macOS 26.0, *)
@Test func prepareDrainsAdmittedCallbacksThroughTheirReplyBoundary() async throws {
    let harness = try await makeWiringHarness(
        daemonConfiguration: .init(lookupDelaysNanoseconds: ["slow": 250_000_000])
    )
    _ = try await harness.volume.createItem(
        named: FSFileName(string: "slow"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let barrier = harness.coherence.barrier

    let replied = PfsReplyBox<Bool>()
    harness.volume.lookupItem(
        named: FSFileName(string: "slow"),
        inDirectory: harness.root
    ) { item, _, _ in
        replied.set(item != nil)
    }
    #expect(try await waitUntil { await barrier.admittedCallbackCount() == 1 })

    let prepared = PfsReplyBox<Bool>()
    let prepareTask = Task {
        try await barrier.prepare(try peerEvent(phase: .prepare))
        prepared.set(true)
    }
    try await Task.sleep(for: .milliseconds(60))
    // The admitted lookup has not replied yet, so the drain must still be
    // waiting on it.
    #expect(prepared.get() == nil)
    #expect(try await waitUntil { prepared.get() == true })
    #expect(replied.get() == true)
    try await prepareTask.value
    try await barrier.resume(try peerEvent(phase: .complete))
}

@available(macOS 26.0, *)
@Test func prepareExemptsExactlyTheInitiatingCallbackAndResumeWaitsForItsReply() async throws {
    let harness = try await makeWiringHarness(
        daemonConfiguration: .init(lookupDelaysNanoseconds: ["mutant": 300_000_000])
    )
    let barrier = harness.coherence.barrier

    // The first publishing request on this connection takes logical operation
    // ID 1; the daemon's delay keeps the callback in flight across both
    // phases.
    let replied = PfsReplyBox<Bool>()
    harness.volume.lookupItem(
        named: FSFileName(string: "mutant"),
        inDirectory: harness.root
    ) { _, _, error in
        replied.set(error != nil)
    }
    #expect(try await waitUntil { await barrier.admittedCallbackCount() == 1 })

    // PREPARE with the initiator exemption returns without draining the
    // still-unpublished initiating callback: draining it would deadlock the
    // very mutation this barrier serves.
    let prepared = PfsReplyBox<Bool>()
    let prepareTask = Task {
        try await barrier.prepare(try localEvent(phase: .prepare, localOperationID: 1))
        prepared.set(true)
    }
    #expect(try await waitUntil(.milliseconds(150)) { prepared.get() == true })
    #expect(replied.get() == nil)
    try await prepareTask.value

    // The deferred source COMPLETE: resume returns only after the initiating
    // callback's reply crossed the publication boundary.
    let resumed = PfsReplyBox<Bool>()
    let resumeTask = Task {
        try await barrier.resume(try localEvent(phase: .complete, localOperationID: 1))
        resumed.set(true)
    }
    try await Task.sleep(for: .milliseconds(60))
    #expect(resumed.get() == nil)
    #expect(try await waitUntil { resumed.get() == true })
    #expect(replied.get() == true)
    try await resumeTask.value
    #expect(await barrier.isAdmissionClosed() == false)
}

@available(macOS 26.0, *)
@Test func aFailedBarrierRefusesAdmissionInsteadOfHanging() async throws {
    let harness = try await makeWiringHarness()
    _ = try await harness.volume.createItem(
        named: FSFileName(string: "seen"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let barrier = harness.coherence.barrier
    try await barrier.prepare(try peerEvent(phase: .prepare))

    let replied = PfsReplyBox<Int>()
    harness.volume.lookupItem(
        named: FSFileName(string: "seen"),
        inDirectory: harness.root
    ) { _, _, error in
        replied.set((error as NSError?)?.code ?? 0)
    }
    try await Task.sleep(for: .milliseconds(50))
    #expect(replied.get() == nil)

    await barrier.fail(PfsMacOSCoherenceError.transportClosed)
    #expect(try await waitUntil { replied.get() != nil })
    #expect(replied.get() == Int(EIO))
}

// MARK: - Composition

private func wiringV3Contract(repairBudgetMillis: UInt64 = 2_500) -> PfsV3CoherenceContract {
    var contract = PfsV3CoherenceContract()
    contract.authorityProtocolMajor = 2
    contract.authorityEpoch = wiringEpoch
    contract.sessionID = wiringLocalSession
    contract.cachePolicy = PfsMacOSCachePolicy.synchronousVFSRepairV1.rawValue
    contract.repairBudgetMillis = repairBudgetMillis
    return contract
}

@available(macOS 26.0, *)
@Test func aResolveDeclaringTheMacOS26PolicyMountsWithTheFullCoherenceStack() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(v3Coherence: wiringV3Contract()))
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let volume = try await PortableFSVolume.make(core: core, attachRef: "mock")
    defer { Task { await volume.shutdown() } }
    let root = try await core.rootItem()
    await daemon.resetStats()

    // The composed mount installed the repair gate: an unarmed reserved name
    // is refused locally and never crosses the socket.
    let coherence = try #require(volume.coherence)
    #expect(coherence.contract?.cachePolicy == .synchronousVFSRepairV1)
    let forged = PfsMacOS26RepairAuthenticator.reservedPrefix + Data("00".utf8)
    do {
        _ = try await volume.createItem(
            named: PfsFSKitMapping.fileName(from: forged),
            type: .file,
            inDirectory: root,
            attributes: FSItem.SetAttributesRequest()
        )
        Issue.record("composed mount accepted an unarmed reserved name")
    } catch { expectEPERM(error) }
    #expect(await daemon.stats().createRequests == 0)

    // Ordinary serving populates the composed indexes.
    let (created, _) = try await volume.createItem(
        named: FSFileName(string: "wired"),
        type: .file,
        inDirectory: root,
        attributes: FSItem.SetAttributesRequest()
    )
    let rootIdentity = try PfsMacOSStableIdentity(root.identity.stableIdentity)
    #expect(await coherence.namespaceIndex.binding(
        parentIdentity: rootIdentity,
        name: Data("wired".utf8)
    ) != nil)
    _ = created

    // The composed runner consumes visibility barriers end to end: both
    // phases are actuated (empty repair footprint here) and acknowledged on
    // the priority lane.
    var wirePrepare = PfsV3VisibilityEvent()
    wirePrepare.authorityEpoch = wiringEpoch
    var prepareCursor = PfsVisibilityCursor()
    prepareCursor.sequence = 1
    prepareCursor.phase = .prepare
    wirePrepare.cursor = prepareCursor
    wirePrepare.initiatorSessionID = wiringPeerSession
    wirePrepare.mutationSlot = 3
    wirePrepare.mutationSequence = 11
    var target = PfsVisibilityTarget()
    target.scope = .attributes
    target.identity = Data(repeating: 0x21, count: 16)
    wirePrepare.targets = [target]
    daemon.emitVisibility(wirePrepare)

    var wireComplete = wirePrepare
    var completeCursor = PfsVisibilityCursor()
    completeCursor.sequence = 1
    completeCursor.phase = .complete
    wireComplete.cursor = completeCursor
    wireComplete.targets = []

    #expect(try await waitUntil { await daemon.stats().visibilityAcks == 1 })
    daemon.emitVisibility(wireComplete)
    #expect(try await waitUntil { await daemon.stats().visibilityAcks == 2 })
    let acknowledgements = await daemon.visibilityAcknowledgements()
    #expect(acknowledgements.map(\.cursor.phase) == [.prepare, .complete])
    #expect(acknowledgements.allSatisfy { !$0.blocked })

    // The mount keeps serving after the barrier.
    _ = try await volume.lookupItem(named: FSFileName(string: "wired"), inDirectory: root)
}
