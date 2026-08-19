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
    phase: PfsMacOSVisibilityPhase,
    repairs: [PfsMacOSCacheRepair] = []
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
        repairs: repairs
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
    liveObjectCapacity: Int = PfsMacOSV3VolumeCoherence.defaultLiveObjectCapacity,
    cachePolicy: PfsMacOSCachePolicy? = nil
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
    let contract = cachePolicy.map { policy in
        PfsMacOSV3LocalContract(
            authorityProtocolMajor: 6,
            epoch: wiringEpoch,
            sessionID: wiringLocalSession,
            cachePolicy: policy,
            repairBudgetMillis: 2_500,
            initialAcknowledgedCursor: nil
        )
    }
    let coherence = PfsMacOSV3VolumeCoherence(
        contract: contract,
        namespaceIndex: PfsMacOSNamespaceIndex(rootIdentity: rootIdentity),
        liveObjects: PfsMacOSLiveObjectIndex(),
        barrier: try PfsMacOSFSKitPublicationBarrier(
            localAuthoritySessionID: wiringLocalSession,
            policy: cachePolicy ?? .synchronousVFSRepairV2
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

extension PfsLocalMockDaemonTests {
@available(macOS 26.0, *)
@Test func nativeDataCacheUpgradePublishesAfterTheRealReplyReturns() async throws {
    let harness = try await makeWiringHarness(
        cachePolicy: .nativeFSKitRevocationV1
    )
    let replyEntered = PfsReplyBox<Int>()
    let releaseReply = DispatchSemaphore(value: 0)

    harness.volume.admitNativeDataCacheUpgrade(harness.root) { error in
        replyEntered.set((error as NSError?)?.code ?? 0)
        releaseReply.wait()
    }

    #expect(try await waitUntil { replyEntered.get() != nil })
    #expect(replyEntered.get() == 0)
    #expect(await harness.coherence.barrier.admittedCallbackCount() == 1)

    releaseReply.signal()
    #expect(try await waitUntil {
        await harness.coherence.barrier.admittedCallbackCount() == 0
    })
}

@available(macOS 26.0, *)
@Test func nativeDataCacheCloseFailureRetiresBeforeItsRealReply() async throws {
    let harness = try await makeWiringHarness(
        cachePolicy: .nativeFSKitRevocationV1
    )
    try await harness.volume.openItem(harness.root, modes: [.read])
    await harness.daemon.failNextClose()

    let replyEntered = PfsReplyBox<Bool>()
    let releaseReply = DispatchSemaphore(value: 0)
    harness.volume.closeNativeDataCacheItem(harness.root) {
        replyEntered.set(true)
        releaseReply.wait()
    }

    #expect(try await waitUntil { replyEntered.get() == true })
    #expect(await harness.coherence.barrier.admittedCallbackCount() == 1)
    do {
        _ = try await harness.core.statfs()
        Issue.record("native data-cache close failure left the volume live")
    } catch {
        #expect(error is PfsLocalClientError)
    }

    releaseReply.signal()
    #expect(try await waitUntil {
        await harness.coherence.barrier.admittedCallbackCount() == 0
    })
}

@available(macOS 26.0, *)
@Test func productionVolumeAdvertisesTheXFSXattrCeiling() async throws {
    let harness = try await makeWiringHarness()
    #expect(harness.volume.maximumXattrSize == 64 * 1024)
}

private func expectEPERM(_ error: any Error) {
    #expect((error as NSError).code == Int(EPERM))
}

private func expectENOENT(_ error: any Error) {
    #expect((error as NSError).code == Int(ENOENT))
}

private func expectEIO(_ error: any Error) {
    #expect((error as NSError).code == Int(EIO))
}

// MARK: - Index population

@available(macOS 26.0, *)
@Test func activationPinsTheRootForExactAttributeRepair() async throws {
    let harness = try await makeWiringHarness()
    _ = try await harness.volume.pinRootForCoherence()
    _ = try await harness.volume.pinRootForCoherence()

    let objects = await harness.coherence.liveObjects.objects(for: harness.rootIdentity)
    #expect(objects.count == 1)
    let planner = PfsMacOSRepairPlanner(
        index: harness.coherence.namespaceIndex,
        liveObjects: harness.coherence.liveObjects
    )
    let repairs = try await planner.repairs(for: [.attributes(identity: harness.rootIdentity)])
    #expect(repairs.count == 1)
    guard case let .invalidateAttributesObject(_, identity) = repairs[0] else {
        Issue.record("root attribute target did not use its exact live vnode")
        return
    }
    #expect(identity == harness.rootIdentity)
}

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
    let createdObjects = await harness.coherence.liveObjects.objects(for: fileIdentity)
    #expect(createdObjects.count == 1)
    #expect(createdObjects.first?.itemKind == .file)

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
@Test func locallyCreatedFileUsesPostBindingAfterItsOldCoordinateIsEvicted() async throws {
    let harness = try await makeWiringHarness()
    let (created, _) = try await harness.volume.createItem(
        named: FSFileName(string: "old"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let file = try #require(created as? PortableFSItem)
    let identity = try PfsMacOSStableIdentity(file.identity.stableIdentity)
    await harness.coherence.namespaceIndex.forget(
        parentIdentity: harness.rootIdentity,
        name: Data("old".utf8)
    )

    let planner = PfsMacOSRepairPlanner(
        index: harness.coherence.namespaceIndex,
        liveObjects: harness.coherence.liveObjects
    )
    let repairs = try await planner.repairs(for: [
        .namespacePost(
            parentIdentity: harness.rootIdentity,
            name: Data("new-alias".utf8),
            identity: identity
        ),
        .attributes(identity: identity),
    ])
    #expect(repairs.count == 1)
    guard case let .refreshAttributes(
        path,
        parentIdentity,
        repairedIdentity,
        expectedVFSFileID,
        itemKind
    ) = repairs.first else {
        Issue.record("locally created live object lost its published file kind")
        return
    }
    #expect(path.components == [Data("new-alias".utf8)])
    #expect(parentIdentity == harness.rootIdentity)
    #expect(repairedIdentity == identity)
    #expect(expectedVFSFileID == file.identity.itemID + 1)
    #expect(itemKind == .file)
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

@available(macOS 26.0, *)
@Test func renameWithMissingPublicationLedgerIsRefusedBeforeAuthorityApply() async throws {
    let harness = try await makeWiringHarness()
    let (source, _) = try await harness.volume.createItem(
        named: FSFileName(string: "source"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    await harness.coherence.namespaceIndex.forget(
        parentIdentity: harness.rootIdentity,
        name: Data("source".utf8)
    )
    await harness.daemon.resetStats()

    do {
        _ = try await harness.volume.renameItem(
            source,
            inDirectory: harness.root,
            named: FSFileName(string: "source"),
            to: FSFileName(string: "destination"),
            inDirectory: harness.root,
            overItem: nil
        )
        Issue.record("rename applied without a representable local ledger transaction")
    } catch {
        #expect((error as NSError).code == Int(EIO))
    }

    #expect(await harness.daemon.stats().renameRequests == 0)
    _ = try await harness.core.lookup(in: harness.root, name: Data("source".utf8))
    do {
        _ = try await harness.core.lookup(in: harness.root, name: Data("destination".utf8))
        Issue.record("preflight-refused rename created its destination")
    } catch let error as PfsLocalClientError {
        guard case let .daemon(errnoValue, _) = error else {
            Issue.record("unexpected destination lookup error: \(error)")
            return
        }
        #expect(errnoValue == ENOENT)
    }
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
    _ = try await harness.volume.createLink(
        to: file,
        named: FSFileName(string: "data-link.bin"),
        inDirectory: harness.root
    )

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
    // The daemon opens the exact source before its kernel-only unlink so data
    // invalidation can continue through the held descriptor.
    try await harness.volume.openItem(file, modes: [.read, .write])
    try await harness.volume.removeItem(
        file,
        named: FSFileName(string: "data.bin"),
        fromDirectory: harness.root
    )
    #expect(await harness.coherence.namespaceIndex.binding(
        parentIdentity: harness.rootIdentity,
        name: Data("data.bin".utf8)
    ) == nil)

    // A mismatched size is never swallowed: it flows through and lands.
    let mismatched = FSItem.SetAttributesRequest()
    mismatched.size = 512
    _ = try await harness.volume.setAttributes(mismatched, on: file)
    #expect(try await harness.core.getattr(item: file).size == 512)

    // Model XFS apply before peer COMPLETE. The repair callback must return
    // this full authority snapshot, including values a size-only repair plan
    // neither carries nor can truthfully invent.
    let authoritative = try await harness.core.setattr(
        item: file,
        attributes: PfsSetAttributes(
            mode: 0o640,
            uid: 501,
            gid: 502,
            size: 4096,
            mtimeMilliseconds: 123_456,
            atimeMilliseconds: 234_567
        )
    )
    await harness.daemon.resetStats()

    // The exact armed truncate emits no mutation. One authority GetAttr joins
    // the callback's publication boundary and supplies the complete post-apply
    // snapshot FSKit needs to finish ftruncate(2).
    let exact = FSItem.SetAttributesRequest()
    exact.size = 4096
    let attributes = try await harness.volume.setAttributes(exact, on: file)
    #expect(attributes.size == 4096)
    #expect(attributes.fileID == FSItem.Identifier(rawValue: file.identity.itemID + 1))
    #expect(attributes.mode == authoritative.mode)
    #expect(attributes.uid == authoritative.uid)
    #expect(attributes.gid == authoritative.gid)
    #expect(attributes.linkCount == authoritative.nlink)
    #expect(attributes.allocSize == authoritative.allocSize)
    let expectedAccessTime = PfsFSKitMapping.timespec(milliseconds: authoritative.atimeMs)
    let expectedModifyTime = PfsFSKitMapping.timespec(milliseconds: authoritative.mtimeMs)
    #expect(attributes.accessTime.tv_sec == expectedAccessTime.tv_sec)
    #expect(attributes.accessTime.tv_nsec == expectedAccessTime.tv_nsec)
    #expect(attributes.modifyTime.tv_sec == expectedModifyTime.tv_sec)
    #expect(attributes.modifyTime.tv_nsec == expectedModifyTime.tv_nsec)
    for attribute: FSItem.Attribute in [
        .type, .mode, .linkCount, .uid, .gid, .flags, .size, .allocSize,
        .fileID, .parentID, .accessTime, .modifyTime, .changeTime, .birthTime,
    ] {
        #expect(attributes.isValid(attribute))
    }
    var stats = await harness.daemon.stats()
    #expect(stats.getAttrRequests == 1)
    #expect(stats.setAttrRequests == 0)

    try await lease.finish()

    stats = await harness.daemon.stats()
    #expect(stats.renameRequests == 0)
    #expect(stats.removeRequests == 0)

    // The window is over: the reserved control name was never published, and
    // an identical size change is an ordinary daemon setattr.
    let reserved = PfsFSKitMapping.fileName(from: operand)
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
@Test func armedTruncateRefusesAnAuthoritySnapshotThatDoesNotMatchThePlan() async throws {
    let harness = try await makeWiringHarness()
    let sourceName = Data("mismatch.bin".utf8)
    let (created, _) = try await harness.volume.createItem(
        named: PfsFSKitMapping.fileName(from: sourceName),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let file = try #require(created as? PortableFSItem)
    let fileIdentity = try PfsMacOSStableIdentity(file.identity.stableIdentity)
    let operand = try harness.authenticator.makeOperand(
        epoch: wiringEpoch,
        sequence: 2,
        step: 0,
        kind: .dataInvalidation,
        parentIdentity: harness.rootIdentity,
        itemIdentity: fileIdentity,
        sourceName: sourceName
    )
    let lease = try await harness.registry.arm(PfsMacOS26RepairPlan(
        epoch: wiringEpoch,
        sequence: 2,
        step: 0,
        kind: .dataInvalidation,
        path: try PfsMacOSRelativePath(components: [sourceName]),
        parentIdentity: harness.rootIdentity,
        itemIdentity: fileIdentity,
        expectedVFSFileID: file.identity.itemID + 1,
        authoritativeSize: 4096,
        operand: operand
    ))
    try await harness.volume.openItem(file, modes: [.read, .write])
    try await harness.volume.removeItem(
        file,
        named: PfsFSKitMapping.fileName(from: sourceName),
        fromDirectory: harness.root
    )
    await harness.daemon.resetStats()

    let exact = FSItem.SetAttributesRequest()
    exact.size = 4096
    do {
        _ = try await harness.volume.setAttributes(exact, on: file)
        Issue.record("armed truncate accepted a stale authority size")
    } catch {
        expectEIO(error)
    }
    let stats = await harness.daemon.stats()
    #expect(stats.getAttrRequests == 1)
    #expect(stats.setAttrRequests == 0)

    // Direct source eviction never creates hidden namespace state. Cancelling
    // the failed event closes its truncate window; authority truth can be
    // republished by a later lookup.
    await lease.cancel()
    let (reloaded, _) = try await harness.volume.lookupItem(
        named: PfsFSKitMapping.fileName(from: sourceName),
        inDirectory: harness.root
    )
    #expect((reloaded as? PortableFSItem)?.identity.stableIdentity == file.identity.stableIdentity)
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
        == [.removeSource])
}

}

private let boundaryItemIdentity = try! PfsMacOSStableIdentity(Data(repeating: 0x66, count: 16))

// MARK: - Publication barrier

extension PfsLocalMockDaemonTests {
@available(macOS 26.0, *)
@Test func barrierClosesAdmissionAtPrepareAndReopensAfterPeerCompleteAck() async throws {
    let harness = try await makeWiringHarness(cachePolicy: .synchronousVFSRepairV2)
    _ = try await harness.volume.createItem(
        named: FSFileName(string: "seen"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    _ = try await harness.volume.createItem(
        named: FSFileName(string: "sibling"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let barrier = harness.coherence.barrier
    let repairs: [PfsMacOSCacheRepair] = [
        .purgeNegative(
            parent: try PfsMacOSRelativePath(components: []),
            parentIdentity: harness.rootIdentity,
            name: Data("seen".utf8)
        ),
    ]
    await harness.daemon.resetStats()

    try await barrier.prepare(try peerEvent(phase: .prepare, repairs: repairs))
    #expect(await barrier.isAdmissionClosed())

    let replied = PfsReplyBox<Int>()
    harness.volume.lookupItem(
        named: FSFileName(string: "seen"),
        inDirectory: harness.root
    ) { _, _, error in
        replied.set((error as NSError?)?.code ?? 0)
    }
    // An exact overlapping lookup must release its kernel pathname lock so
    // the repair actuator can enter the same coordinate.
    #expect(try await waitUntil { replied.get() == Int(ECANCELED) })
    #expect(await harness.daemon.stats().lookupRequests == 0)

    // A sibling lookup is one exact namespace coordinate, not a snapshot of
    // the whole parent directory. It remains independent of this repair.
    let siblingReplied = PfsReplyBox<Bool>()
    harness.volume.lookupItem(
        named: FSFileName(string: "sibling"),
        inDirectory: harness.root
    ) { item, _, error in
        siblingReplied.set(item != nil && error == nil)
    }
    #expect(try await waitUntil { siblingReplied.get() == true })
    #expect(await harness.daemon.stats().lookupRequests == 1)

    // An overlapping mutation is refused before any daemon request so its
    // namespace lane is free for the nested VFS repair.
    let mutationReplied = PfsReplyBox<Int>()
    harness.volume.createItem(
        named: FSFileName(string: "after-peer-repair"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    ) { item, _, error in
        mutationReplied.set((error as NSError?)?.code ?? (item == nil ? -1 : 0))
    }
    #expect(try await waitUntil { mutationReplied.get() == Int(ECANCELED) })
    #expect(await harness.daemon.stats().createRequests == 0)

    let complete = try peerEvent(phase: .complete, repairs: repairs)
    try await barrier.resume(complete)
    #expect(await barrier.isAdmissionClosed())

    let mutationAfterResume = PfsReplyBox<Bool>()
    harness.volume.createItem(
        named: FSFileName(string: "after-peer-repair"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    ) { item, _, error in
        mutationAfterResume.set(item != nil && error == nil)
    }
    // Mounted-VFS repair is finished, so this callback may safely wait without
    // blocking the actuator. It must not reach the daemon while authority
    // mutation order is still held for COMPLETE.
    try await Task.sleep(for: .milliseconds(30))
    #expect(mutationAfterResume.get() == nil)
    #expect(await harness.daemon.stats().createRequests == 0)

    await barrier.acknowledged(complete)
    #expect(await barrier.isAdmissionClosed() == false)
    #expect(try await waitUntil { mutationAfterResume.get() == true })

    let afterResume = PfsReplyBox<Bool>()
    harness.volume.lookupItem(
        named: FSFileName(string: "seen"),
        inDirectory: harness.root
    ) { item, _, error in
        afterResume.set(item != nil && error == nil)
    }
    #expect(try await waitUntil { afterResume.get() == true })
}

@available(macOS 26.0, *)
@Test func unsupportedXattrSetPreflightsBeforeAClosedPeerBarrier() async throws {
    let harness = try await makeWiringHarness(
        daemonConfiguration: .init(xattrSetSupported: false),
        cachePolicy: .synchronousVFSRepairV2
    )
    defer { harness.daemon.stop() }
    let (created, _) = try await harness.volume.createItem(
        named: FSFileName(string: "xattr-read-only"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let item = try #require(created as? PortableFSItem)
    let (staleCreated, _) = try await harness.volume.createItem(
        named: FSFileName(string: "xattr-stale"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let staleItem = try #require(staleCreated as? PortableFSItem)
    try await harness.core.reclaim(item: staleItem)
    await harness.daemon.resetStats()

    let barrier = harness.coherence.barrier
    try await barrier.prepare(try peerEvent(phase: .prepare))
    #expect(await barrier.isAdmissionClosed())

    // The negotiated read-only-xattr capability is independent of peer cache
    // repair. It must win before publication admission, even though this
    // ordered callback would otherwise be refused by the closed barrier.
    for policy: FSVolume.SetXattrPolicy in [.mustCreate, .mustReplace, .alwaysSet] {
        let unsupportedReply = PfsReplyBox<Int>()
        harness.volume.setXattr(
            named: FSFileName(string: "user.test"),
            to: Data("value".utf8),
            on: item,
            policy: policy
        ) { error in
            unsupportedReply.set((error as NSError?)?.code ?? 0)
        }
        #expect(try await waitUntil { unsupportedReply.get() != nil })
        #expect(unsupportedReply.get() == Int(EOPNOTSUPP))
    }

    var stats = await harness.daemon.stats()
    #expect(stats.xattrSetRequests == 0)

    // Request validation remains ahead of capability refusal as well. An
    // invalid name is EINVAL, never EOPNOTSUPP or the barrier's ECANCELED.
    let invalidReply = PfsReplyBox<Int>()
    harness.volume.setXattr(
        named: FSFileName(data: Data([0xff])),
        to: Data(),
        on: item,
        policy: .alwaysSet
    ) { error in
        invalidReply.set((error as NSError?)?.code ?? 0)
    }
    #expect(try await waitUntil { invalidReply.get() != nil })
    #expect(invalidReply.get() == Int(EINVAL))

    // Reclaimed identity also retains its stronger verdict ahead of the
    // negotiated capability and the closed admission gate.
    let staleReply = PfsReplyBox<Int>()
    harness.volume.setXattr(
        named: FSFileName(string: "user.test"),
        to: Data(),
        on: staleItem,
        policy: .alwaysSet
    ) { error in
        staleReply.set((error as NSError?)?.code ?? 0)
    }
    #expect(try await waitUntil { staleReply.get() != nil })
    #expect(staleReply.get() == Int(ESTALE))

    let compoundReply = PfsReplyBox<Int>()
    harness.volume.setXattr(
        named: FSFileName(data: Data([0xff])),
        to: Data(),
        on: staleItem,
        policy: .alwaysSet
    ) { error in
        compoundReply.set((error as NSError?)?.code ?? 0)
    }
    #expect(try await waitUntil { compoundReply.get() != nil })
    #expect(compoundReply.get() == Int(EINVAL))

    stats = await harness.daemon.stats()
    #expect(stats.xattrSetRequests == 0)

    let complete = try peerEvent(phase: .complete)
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
}

// v2 PREPARE closes future admission for an affected callback, lets its already
// issued read finish normally, and waits for that reply to cross the framework
// publication boundary before the actuator can reuse the callback lane.
@available(macOS 26.0, *)
@Test func prepareNaturallyDrainsAnInFlightReadAndWaitsForItsReply() async throws {
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
    let repairs: [PfsMacOSCacheRepair] = [
        .purgeNegative(
            parent: try PfsMacOSRelativePath(components: []),
            parentIdentity: harness.rootIdentity,
            name: Data("slow".utf8)
        ),
    ]

    let replied = PfsReplyBox<Int>()
    harness.volume.lookupItem(
        named: FSFileName(string: "slow"),
        inDirectory: harness.root
    ) { _, _, error in
        replied.set((error as NSError?)?.code ?? 0)
    }
    #expect(try await waitUntil { await barrier.admittedCallbackCount() == 1 })

    let prepared = PfsReplyBox<Bool>()
    let prepareTask = Task {
        try await barrier.prepare(try peerEvent(phase: .prepare, repairs: repairs))
        prepared.set(true)
    }
    try await Task.sleep(for: .milliseconds(100))
    #expect(replied.get() == nil)
    #expect(prepared.get() == nil)
    #expect(try await waitUntil(.milliseconds(500)) { replied.get() == 0 })
    #expect(try await waitUntil(.milliseconds(500)) { prepared.get() == true })
    try await prepareTask.value
    let complete = try peerEvent(phase: .complete, repairs: repairs)
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
    try await Task.sleep(for: .milliseconds(300))
    _ = try await harness.core.statfs()
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
    await barrier.fail(PfsMacOSCoherenceError.transportClosed)

    let replied = PfsReplyBox<Int>()
    harness.volume.lookupItem(
        named: FSFileName(string: "seen"),
        inDirectory: harness.root
    ) { _, _, error in
        replied.set((error as NSError?)?.code ?? 0)
    }
    #expect(try await waitUntil { replied.get() == Int(EIO) })
    #expect(replied.get() == Int(EIO))
}

// MARK: - Composition

private func wiringV3Contract(repairBudgetMillis: UInt64 = 2_500) -> PfsV3CoherenceContract {
    var contract = PfsV3CoherenceContract()
    contract.authorityProtocolMajor = 6
    contract.authorityEpoch = wiringEpoch
    contract.sessionID = wiringLocalSession
    contract.cachePolicy = PfsMacOSCachePolicy.synchronousVFSRepairV2.rawValue
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
    #expect(coherence.contract?.cachePolicy == .synchronousVFSRepairV2)
    let rootIdentity = try PfsMacOSStableIdentity(root.identity.stableIdentity)
    #expect(await coherence.liveObjects.objects(for: rootIdentity).count == 1)
    let rootRepairs = try await PfsMacOSRepairPlanner(
        index: coherence.namespaceIndex,
        liveObjects: coherence.liveObjects
    ).repairs(for: [.attributes(identity: rootIdentity)])
    #expect(rootRepairs.count == 1)
    // Production repairs are daemon-actuated. Installing the unused POSIX
    // actuator would retain a duplicate root vnode for the mount lifetime and
    // make every otherwise-clean kernel unmount answer EBUSY.
    #expect(coherence.mountActuator == nil)
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
}
