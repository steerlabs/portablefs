import Foundation
import FSKit
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

private let boundaryEpoch = Data(repeating: 0x5e, count: 16)
private let boundarySecret = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 &* 11 &+ 3) })
private let boundaryParent = try! PfsMacOSStableIdentity(Data(repeating: 0x61, count: 16))
private let boundaryItem = try! PfsMacOSStableIdentity(Data(repeating: 0x62, count: 16))

@available(macOS 26.0, *)
private struct BoundaryHarness {
    let daemon: PfsLocalMockDaemon
    let core: VolumeCore
    let volume: PortableFSVolume
    let root: PortableFSItem

    /// The stable identity the mock daemon mints for its root. Armed plans
    /// must name the directory the callbacks will actually arrive from, or
    /// the gate's parent re-check refuses them.
    var rootIdentity: PfsMacOSStableIdentity {
        try! PfsMacOSStableIdentity(root.identity.stableIdentity)
    }
}

@available(macOS 26.0, *)
private func makeBoundaryHarness(
    repairGate: (any PfsMacOS26RepairGate)? = nil,
    configuration: PfsLocalMockDaemon.Configuration = .init()
) async throws -> BoundaryHarness {
    let daemon = try PfsLocalMockDaemon(configuration: configuration)
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let volume = try await PortableFSVolume.make(
        core: core,
        attachRef: "mock",
        repairGate: repairGate
    )
    let root = try await core.rootItem()
    await daemon.resetStats()
    return BoundaryHarness(daemon: daemon, core: core, volume: volume, root: root)
}

private func reservedName(
    authenticator: PfsMacOS26RepairAuthenticator,
    kind: PfsMacOS26RepairKind,
    sequence: UInt64 = 1,
    step: UInt32 = 0,
    parent: PfsMacOSStableIdentity = boundaryParent,
    item: PfsMacOSStableIdentity? = nil,
    sourceName: Data?
) throws -> Data {
    try authenticator.makeOperand(
        epoch: boundaryEpoch,
        sequence: sequence,
        step: step,
        kind: kind,
        parentIdentity: parent,
        itemIdentity: item ?? (kind == .negativeScratch ? .zero : boundaryItem),
        sourceName: sourceName
    )
}

private func plan(
    for kind: PfsMacOS26RepairKind,
    operand: Data,
    path: PfsMacOSRelativePath,
    sequence: UInt64 = 1,
    step: UInt32 = 0,
    parent: PfsMacOSStableIdentity = boundaryParent,
    item: PfsMacOSStableIdentity? = nil,
    expectedVFSFileID: UInt64? = nil,
    authoritativeSize: UInt64? = nil
) -> PfsMacOS26RepairPlan {
    PfsMacOS26RepairPlan(
        epoch: boundaryEpoch,
        sequence: sequence,
        step: step,
        kind: kind,
        path: path,
        parentIdentity: parent,
        itemIdentity: item ?? (kind == .negativeScratch ? .zero : boundaryItem),
        expectedVFSFileID: expectedVFSFileID,
        authoritativeSize: authoritativeSize,
        operand: operand
    )
}

private func expectEPERM(_ error: any Error) {
    #expect((error as NSError).code == Int(EPERM))
}

private func expectENOATTR(_ error: any Error) {
    #expect((error as NSError).code == Int(ENOATTR))
}

private func expectEEXIST(_ error: any Error) {
    #expect((error as NSError).code == Int(EEXIST))
}

private func waitForBoundaryCallback(
    _ deadline: Duration = .seconds(2),
    _ delivered: () async -> Bool
) async throws -> Bool {
    let clock = ContinuousClock()
    let end = clock.now + deadline
    while clock.now < end {
        if await delivered() { return true }
        try await Task.sleep(for: .milliseconds(5))
    }
    return await delivered()
}

private actor BoundaryXattrReply {
    private var result: (delivered: Bool, hadValue: Bool, errno: Int?) = (false, false, nil)

    func record(value: Data?, error: Error?) {
        result = (true, value != nil, error.map { ($0 as NSError).code })
    }

    func snapshot() -> (delivered: Bool, hadValue: Bool, errno: Int?) { result }
}

private actor BoundaryLookupReply {
    private var result: (delivered: Bool, hadItem: Bool, name: Data?, errno: Int?) =
        (false, false, nil, nil)

    func record(hadItem: Bool, name: Data?, errno: Int?) {
        result = (true, hadItem, name, errno)
    }

    func snapshot() -> (delivered: Bool, hadItem: Bool, name: Data?, errno: Int?) { result }
}

private actor BoundaryAttributesReply {
    private(set) var delivered = false
    private(set) var hadAttributes = false
    private(set) var errno: Int?

    func record(hadAttributes: Bool, errno: Int?) {
        delivered = true
        self.hadAttributes = hadAttributes
        self.errno = errno
    }

    func snapshot() -> (delivered: Bool, hadAttributes: Bool, errno: Int?) {
        (delivered, hadAttributes, errno)
    }
}

private actor BoundaryErrorReply {
    private(set) var delivered = false
    private(set) var errno: Int?

    func record(errno: Int?) {
        delivered = true
        self.errno = errno
    }

    func snapshot() -> (delivered: Bool, errno: Int?) {
        (delivered, errno)
    }
}

private actor BoundaryCallbackGate {
    private var openState = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if openState { return }
        await withCheckedContinuation { continuation in
            if openState {
                continuation.resume()
            } else {
                waiters.append(continuation)
            }
        }
    }

    func open() {
        guard !openState else { return }
        openState = true
        let waiting = waiters
        waiters.removeAll()
        for waiter in waiting { waiter.resume() }
    }
}

@available(macOS 26.0, *)
@Test func adapterReservesCallbackSynchronouslyBeforeItsTaskCanEnterPreflight() async throws {
    let daemon = try PfsLocalMockDaemon()
    let core = try await VolumeCore.connect(
        socketPath: daemon.socketPath,
        attachRef: "mock"
    )
    let root = try await core.rootItem()
    let rootIdentity = try PfsMacOSStableIdentity(root.identity.stableIdentity)
    let localSession = Data(repeating: 0x81, count: 16)
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: localSession
    )
    let authenticator = try PfsMacOS26RepairAuthenticator(
        mountSessionID: UUID(),
        secret: boundarySecret
    )
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let coherence = PfsMacOSV3VolumeCoherence(
        contract: nil,
        namespaceIndex: PfsMacOSNamespaceIndex(rootIdentity: rootIdentity),
        liveObjects: PfsMacOSLiveObjectIndex(),
        barrier: barrier,
        repairGate: registry
    )
    let volume = try await PortableFSVolume.make(
        core: core,
        attachRef: "mock",
        coherence: coherence
    )
    let preflightGate = BoundaryCallbackGate()
    let replyBox = BoundaryErrorReply()
    volume.testOnlyPublishAfterReply(
        preflight: { await preflightGate.wait() },
        admissionScope: PfsMacOSCallbackScope(selectors: [.orderedMutation]),
        operation: {},
        reply: { result in
            Task {
                switch result {
                case .success:
                    await replyBox.record(errno: nil)
                case let .failure(error):
                    await replyBox.record(errno: (error as NSError).code)
                }
            }
        }
    )

    // This observation is made after the synchronous helper returned but while
    // its Task is still stopped in preflight: the ingress cut is already real.
    #expect(await barrier.pendingIngressReservationCount() == 1)
    let prepare = try PfsMacOSCoherenceEvent(
        epoch: boundaryEpoch,
        sequence: 120,
        phase: .prepare,
        initiator: PfsMacOSMutationInitiator(
            sessionID: Data(repeating: 0x82, count: 16),
            replaySlot: 1,
            mutationSequence: 120
        ),
        repairs: []
    )
    let prepareDone = BoundaryErrorReply()
    let preparing = Task {
        try await barrier.prepare(prepare)
        await prepareDone.record(errno: nil)
    }
    while await barrier.pendingIngressReservationCount() != 0 {
        await Task.yield()
    }
    #expect(await barrier.admittedCallbackCount() == 1)
    #expect(!(await prepareDone.snapshot()).delivered)

    await preflightGate.open()
    try await preparing.value
    #expect((await prepareDone.snapshot()).delivered)
    for _ in 0..<100 where !(await replyBox.snapshot()).delivered {
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    let reply = await replyBox.snapshot()
    #expect(reply.delivered)
    #expect(reply.errno == nil)
    #expect(await barrier.pendingIngressReservationCount() == 0)
    #expect(await barrier.admittedCallbackCount() == 0)

    let complete = try PfsMacOSCoherenceEvent(
        epoch: prepare.epoch,
        sequence: prepare.sequence,
        phase: .complete,
        initiator: prepare.initiator,
        repairs: prepare.repairs
    )
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
    await core.shutdown()
}

@available(macOS 26.0, *)
@Test func adapterRefusesTheReservedNamespaceWhenNoRepairMachineryIsInstalled() async throws {
    let harness = try await makeBoundaryHarness()
    let authenticator = try PfsMacOS26RepairAuthenticator(
        mountSessionID: UUID(),
        secret: boundarySecret
    )
    // A perfectly authenticated operand is still refused: with no gate, the
    // reserved prefix is simply not part of the user namespace.
    let operand = try reservedName(
        authenticator: authenticator,
        kind: .negativeScratch,
        sourceName: nil
    )
    let reserved = PfsFSKitMapping.fileName(from: operand)

    do {
        _ = try await harness.volume.createItem(
            named: reserved,
            type: .file,
            inDirectory: harness.root,
            attributes: FSItem.SetAttributesRequest()
        )
        Issue.record("createItem accepted a reserved name")
    } catch { expectEPERM(error) }

    do {
        _ = try await harness.volume.createSymbolicLink(
            named: reserved,
            inDirectory: harness.root,
            attributes: FSItem.SetAttributesRequest(),
            linkContents: FSFileName(string: "/etc/passwd")
        )
        Issue.record("createSymbolicLink accepted a reserved name")
    } catch { expectEPERM(error) }

    do {
        _ = try await harness.volume.createLink(
            to: harness.root,
            named: reserved,
            inDirectory: harness.root
        )
        Issue.record("createLink accepted a reserved name")
    } catch { expectEPERM(error) }

    // And a user process cannot move one of its own files into the reserved
    // form either, which is what would let it later be claimed as repair.
    let (victim, victimName) = try await harness.volume.createItem(
        named: FSFileName(string: "victim"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    do {
        _ = try await harness.volume.renameItem(
            victim,
            inDirectory: harness.root,
            named: victimName,
            to: reserved,
            inDirectory: harness.root,
            overItem: nil
        )
        Issue.record("renameItem accepted a reserved destination")
    } catch { expectEPERM(error) }

    let stats = await harness.daemon.stats()
    // Exactly one create: the user's own "victim". Nothing reserved crossed.
    #expect(stats.createRequests == 1)
    #expect(stats.renameRequests == 0)
    #expect(stats.removeRequests == 0)
}

@available(macOS 26.0, *)
@Test func adapterConsumesAnArmedNegativeScratchWithoutAnyDaemonRequest() async throws {
    let authenticator = try PfsMacOS26RepairAuthenticator(
        mountSessionID: UUID(),
        secret: boundarySecret
    )
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let harness = try await makeBoundaryHarness(
        repairGate: registry,
        configuration: .init(xattrSetSupported: false)
    )

    let operand = try reservedName(
        authenticator: authenticator,
        kind: .negativeScratch,
        parent: harness.rootIdentity,
        sourceName: nil
    )
    let lease = try await registry.arm(
        plan(
            for: .negativeScratch,
            operand: operand,
            path: try PfsMacOSRelativePath(components: []),
            parent: harness.rootIdentity
        )
    )
    let reserved = PfsFSKitMapping.fileName(from: operand)

    let (scratch, name) = try await harness.volume.createItem(
        named: reserved,
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    #expect(name.data == operand)
    let scratchItem = try #require(scratch as? PortableFSItem)
    #expect(await harness.core.isLocalRepairItem(scratchItem))

    // FSKit asks for this complete standard snapshot before it completes the
    // actuator's open(2). Missing even one requested field leaves the kernel
    // syscall parked forever rather than advancing to the reserved remove.
    let standard: FSItem.Attribute = [
        .type, .mode, .linkCount, .uid, .gid, .flags, .size, .allocSize,
        .fileID, .parentID, .accessTime, .modifyTime, .changeTime, .birthTime,
    ]
    let request = FSItem.GetAttributesRequest()
    request.wantedAttributes = standard
    let scratchAttributes = try await harness.volume.attributes(request, of: scratchItem)
    for attribute: FSItem.Attribute in [
        .type, .mode, .linkCount, .uid, .gid, .flags, .size, .allocSize,
        .fileID, .parentID, .accessTime, .modifyTime, .changeTime, .birthTime,
    ] {
        #expect(scratchAttributes.isValid(attribute))
    }
    #expect(scratchAttributes.parentID == (try PfsFSKitMapping.itemIdentifier(from: harness.root.identity.itemID)))
    #expect(scratchAttributes.size == 0)
    #expect(scratchAttributes.allocSize == 0)

    // The scratch item is a namespace device, not a data or metadata channel.
    do {
        _ = try await harness.volume.setAttributes(
            FSItem.SetAttributesRequest(),
            on: scratchItem
        )
        Issue.record("setAttributes reached the repair scratch item")
    } catch { expectEPERM(error) }
    do {
        _ = try await harness.volume.write(contents: Data([0x1]), to: scratchItem, at: 0)
        Issue.record("write reached the repair scratch item")
    } catch { expectEPERM(error) }
    do {
        _ = try await harness.volume.xattr(
            named: FSFileName(string: "com.apple.FinderInfo"),
            of: scratchItem
        )
        Issue.record("getXattr reached the repair scratch item")
    } catch { expectENOATTR(error) }
    let xattrName = FSFileName(string: "com.apple.FinderInfo")
    #expect(try await harness.volume.xattrs(of: scratchItem).isEmpty)
    try await harness.volume.setXattr(
        named: xattrName,
        to: Data([0x1]),
        on: scratchItem,
        policy: .alwaysSet
    )
    #expect(try await harness.volume.xattr(named: xattrName, of: scratchItem) == Data([0x1]))
    #expect(
        try await harness.volume.xattrs(of: scratchItem).map {
            String(decoding: $0.data, as: UTF8.self)
        } == ["com.apple.FinderInfo"]
    )
    do {
        try await harness.volume.setXattr(
            named: xattrName,
            to: Data([0x2]),
            on: scratchItem,
            policy: .mustCreate
        )
        Issue.record("mustCreate replaced a local repair xattr")
    } catch { expectEEXIST(error) }
    try await harness.volume.setXattr(
        named: xattrName,
        to: nil,
        on: scratchItem,
        policy: .delete
    )
    do {
        _ = try await harness.volume.xattr(named: xattrName, of: scratchItem)
        Issue.record("deleted local repair xattr still exists")
    } catch { expectENOATTR(error) }

    // unlinkat may ask FSKit to resolve the just-created scratch name before
    // delivering removeItem. The local binding must return the exact object;
    // forwarding or answering ENOENT skips the removal callback and tears the
    // one-shot repair transaction.
    let (resolvedScratch, resolvedName) = try await harness.volume.lookupItem(
        named: reserved,
        inDirectory: harness.root
    )
    #expect(resolvedScratch === scratchItem)
    #expect(resolvedName.data == operand)

    try await harness.volume.removeItem(
        scratchItem,
        named: reserved,
        fromDirectory: harness.root
    )
    #expect(await harness.core.localRepairItem(in: harness.root, named: operand) == nil)
    #expect(await harness.core.isLocalRepairItem(scratchItem))
    try await lease.finish()
    // Event completion ends name ownership, not vnode ownership. macOS can
    // deliver getattrs/close well after unlinkat returns; only reclaim ends
    // this object's local classification.
    #expect(await harness.core.isLocalRepairItem(scratchItem))
    _ = try await harness.volume.attributes(FSItem.GetAttributesRequest(), of: scratchItem)
    try await harness.volume.reclaimItem(scratchItem)

    let stats = await harness.daemon.stats()
    #expect(stats.createRequests == 0)
    #expect(stats.removeRequests == 0)
    #expect(stats.renameRequests == 0)
    #expect(stats.xattrGetRequests == 0)
    #expect(stats.xattrSetRequests == 0)
    #expect(stats.xattrListRequests == 0)
    #expect(stats.xattrRemoveRequests == 0)
    #expect(await harness.core.localRepairItemCount() == 0)
}

@available(macOS 26.0, *)
@Test func scratchXattrProbeCompletesWhilePublicationAdmissionIsClosed() async throws {
    let daemon = try PfsLocalMockDaemon()
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let rootIdentity = try PfsMacOSStableIdentity(root.identity.stableIdentity)
    let authenticator = try PfsMacOS26RepairAuthenticator(
        mountSessionID: UUID(),
        secret: boundarySecret
    )
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let localSession = Data(repeating: 0x71, count: 16)
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: localSession
    )
    let coherence = PfsMacOSV3VolumeCoherence(
        contract: nil,
        namespaceIndex: PfsMacOSNamespaceIndex(rootIdentity: rootIdentity),
        liveObjects: PfsMacOSLiveObjectIndex(),
        barrier: barrier,
        repairGate: registry
    )
    let volume = try await PortableFSVolume.make(
        core: core,
        attachRef: "mock",
        coherence: coherence
    )
    await daemon.resetStats()

    let operand = try reservedName(
        authenticator: authenticator,
        kind: .negativeScratch,
        parent: rootIdentity,
        sourceName: nil
    )
    let lease = try await registry.arm(
        plan(
            for: .negativeScratch,
            operand: operand,
            path: try PfsMacOSRelativePath(components: []),
            parent: rootIdentity
        )
    )
    let (item, _) = try await volume.createItem(
        named: PfsFSKitMapping.fileName(from: operand),
        type: .file,
        inDirectory: root,
        attributes: FSItem.SetAttributesRequest()
    )

    // An empty repair set is the barrier's deliberately conservative global
    // scope. Ordinary callbacks cannot pass it, so completion here proves the
    // synthetic item is classified as repair-owned before admission rather
    // than merely avoiding one particular affected name.
    let prepare = try PfsMacOSCoherenceEvent(
        epoch: boundaryEpoch,
        sequence: 91,
        phase: .prepare,
        initiator: PfsMacOSMutationInitiator(
            sessionID: Data(repeating: 0x72, count: 16),
            replaySlot: 1,
            mutationSequence: 91,
            localOperationID: nil
        ),
        repairs: []
    )
    try await barrier.prepare(prepare)

    let reply = BoundaryXattrReply()
    volume.getXattr(
        named: FSFileName(string: "com.apple.FinderInfo"),
        of: item
    ) { value, error in
        Task { await reply.record(value: value, error: error) }
    }
    #expect(try await waitForBoundaryCallback {
        (await reply.snapshot()).delivered
    })
    let snapshot = await reply.snapshot()
    #expect(snapshot.delivered)
    #expect(!snapshot.hadValue)
    #expect(snapshot.errno == Int(ENOATTR))

    try await volume.removeItem(
        item,
        named: PfsFSKitMapping.fileName(from: operand),
        fromDirectory: root
    )
    let scratchItem = try #require(item as? PortableFSItem)
    #expect(await core.localRepairItem(in: root, named: operand) == nil)
    #expect(await core.isLocalRepairItem(scratchItem))

    // Removing the name does not end the synthetic vnode lifecycle. Every
    // trailing callback stays process-local even with publication admission
    // closed, and reclaim may release the object before the event lease does.
    _ = try await volume.attributes(FSItem.GetAttributesRequest(), of: item)
    try await volume.openItem(item, modes: [.read])
    try await volume.closeItem(item, modes: [])
    try await volume.reclaimItem(item)
    #expect(await core.isLocalRepairItem(scratchItem) == false)

    let complete = try PfsMacOSCoherenceEvent(
        epoch: prepare.epoch,
        sequence: prepare.sequence,
        phase: .complete,
        initiator: prepare.initiator,
        repairs: prepare.repairs
    )
    try await barrier.resume(complete)
    try await lease.finish()

    let stats = await daemon.stats()
    #expect(stats.xattrGetRequests == 0)
    #expect(await core.localRepairItemCount() == 0)
}

@available(macOS 26.0, *)
@Test func armedRepairSourceLookupCompletesWhileItsCoordinateIsClosed() async throws {
    let daemon = try PfsLocalMockDaemon()
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let rootIdentity = try PfsMacOSStableIdentity(root.identity.stableIdentity)
    let authenticator = try PfsMacOS26RepairAuthenticator(
        mountSessionID: UUID(),
        secret: boundarySecret
    )
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: Data(repeating: 0x73, count: 16)
    )
    let coherence = PfsMacOSV3VolumeCoherence(
        contract: nil,
        namespaceIndex: PfsMacOSNamespaceIndex(rootIdentity: rootIdentity),
        liveObjects: PfsMacOSLiveObjectIndex(),
        barrier: barrier,
        repairGate: registry
    )
    let volume = try await PortableFSVolume.make(
        core: core,
        attachRef: "mock",
        coherence: coherence
    )
    let sourceName = Data("stale".utf8)
    let (sourceItem, _) = try await volume.createItem(
        named: PfsFSKitMapping.fileName(from: sourceName),
        type: .file,
        inDirectory: root,
        attributes: FSItem.SetAttributesRequest()
    )
    let portableSource = try #require(sourceItem as? PortableFSItem)
    try await volume.closeItem(portableSource, modes: [])
    let sourceIdentity = try PfsMacOSStableIdentity(portableSource.identity.stableIdentity)
    let operand = try reservedName(
        authenticator: authenticator,
        kind: .positiveEviction,
        parent: rootIdentity,
        item: sourceIdentity,
        sourceName: sourceName
    )
    let lease = try await registry.arm(
        plan(
            for: .positiveEviction,
            operand: operand,
            path: try PfsMacOSRelativePath(components: [sourceName]),
            parent: rootIdentity,
            item: sourceIdentity
        )
    )
    let prepare = try PfsMacOSCoherenceEvent(
        epoch: boundaryEpoch,
        sequence: 92,
        phase: .prepare,
        initiator: PfsMacOSMutationInitiator(
            sessionID: Data(repeating: 0x74, count: 16),
            replaySlot: 1,
            mutationSequence: 92,
            localOperationID: nil
        ),
        repairs: [.evictBinding(
            path: try PfsMacOSRelativePath(components: [sourceName]),
            parentIdentity: rootIdentity,
            itemIdentity: sourceIdentity,
            itemKind: .file
        )]
    )
    try await barrier.prepare(prepare)

    // The POSIX actuator must traverse/open the exact parent directory before
    // it can issue the child unlink. That lifecycle is repair-owned too; a
    // closed child-coordinate barrier must not park its own parent traversal.
    #expect(await registry.isArmedRepairParentItem(
        itemIdentity: rootIdentity.bytes
    ))
    let parentOpenReply = BoundaryErrorReply()
    volume.openItem(root, modes: .read) { error in
        let errorCode = error.map { ($0 as NSError).code }
        Task { await parentOpenReply.record(errno: errorCode) }
    }
    #expect(try await waitForBoundaryCallback {
        (await parentOpenReply.snapshot()).delivered
    })
    let parentOpenSnapshot = await parentOpenReply.snapshot()
    #expect(parentOpenSnapshot.delivered)
    #expect(parentOpenSnapshot.errno == nil)
    let parentCloseReply = BoundaryErrorReply()
    volume.closeItem(root, modes: []) { error in
        let errorCode = error.map { ($0 as NSError).code }
        Task { await parentCloseReply.record(errno: errorCode) }
    }
    #expect(try await waitForBoundaryCallback {
        (await parentCloseReply.snapshot()).delivered
    })
    let parentCloseSnapshot = await parentCloseReply.snapshot()
    #expect(parentCloseSnapshot.delivered)
    #expect(parentCloseSnapshot.errno == nil)

    let reply = BoundaryLookupReply()
    volume.lookupItem(
        named: PfsFSKitMapping.fileName(from: sourceName),
        inDirectory: root
    ) { item, name, error in
        let hadItem = item != nil
        let nameData = name?.data
        let errorCode = error.map { ($0 as NSError).code }
        Task {
            await reply.record(hadItem: hadItem, name: nameData, errno: errorCode)
        }
    }
    #expect(try await waitForBoundaryCallback {
        (await reply.snapshot()).delivered
    })
    let snapshot = await reply.snapshot()
    #expect(snapshot.delivered)
    #expect(snapshot.hadItem)
    #expect(snapshot.name == sourceName)
    #expect(snapshot.errno == nil)

    // Live FSKit performs this getattr between its source lookup and the
    // rename callback. It carries no name, so prove the plan's exact source
    // identity authenticates it without opening admission for another item.
    let attributesReply = BoundaryAttributesReply()
    volume.getAttributes(FSItem.GetAttributesRequest(), of: portableSource) { attributes, error in
        let hadAttributes = attributes != nil
        let errorCode = error.map { ($0 as NSError).code }
        Task {
            await attributesReply.record(hadAttributes: hadAttributes, errno: errorCode)
        }
    }
    #expect(try await waitForBoundaryCallback {
        (await attributesReply.snapshot()).delivered
    })
    let attributesSnapshot = await attributesReply.snapshot()
    #expect(attributesSnapshot.delivered)
    #expect(attributesSnapshot.hadAttributes)
    #expect(attributesSnapshot.errno == nil)

    do {
        try await volume.setXattr(
            named: FSFileName(string: "com.apple.provenance"),
            to: Data([1]),
            on: portableSource,
            policy: .alwaysSet
        )
        Issue.record("armed repair-source bookkeeping xattr unexpectedly succeeded")
    } catch {
        #expect((error as NSError).code == Int(EOPNOTSUPP))
    }
    for malformedName in [FSFileName(string: ""), FSFileName(data: Data([0xff]))] {
        do {
            try await volume.setXattr(
                named: malformedName,
                to: Data([1]),
                on: portableSource,
                policy: .alwaysSet
            )
            Issue.record("malformed armed-source xattr unexpectedly succeeded")
        } catch {
            #expect((error as NSError).code == Int(EINVAL))
        }
    }
    #expect(await daemon.stats().xattrSetRequests == 0)

    // unlinkat may make FSKit open and close the source vnode before it emits
    // removeItem. Both callbacks are part of the local cache actuator: neither
    // may wait on, or create descriptor state inside, the authority gate that
    // this COMPLETE repair itself holds closed.
    let descriptorStatsBefore = await daemon.stats()
    let openReply = BoundaryErrorReply()
    volume.openItem(portableSource, modes: .read) { error in
        let errorCode = error.map { ($0 as NSError).code }
        Task { await openReply.record(errno: errorCode) }
    }
    #expect(try await waitForBoundaryCallback {
        (await openReply.snapshot()).delivered
    })
    let openSnapshot = await openReply.snapshot()
    #expect(openSnapshot.delivered)
    #expect(openSnapshot.errno == nil)

    let closeReply = BoundaryErrorReply()
    volume.closeItem(portableSource, modes: []) { error in
        let errorCode = error.map { ($0 as NSError).code }
        Task { await closeReply.record(errno: errorCode) }
    }
    #expect(try await waitForBoundaryCallback {
        (await closeReply.snapshot()).delivered
    })
    let closeSnapshot = await closeReply.snapshot()
    #expect(closeSnapshot.delivered)
    #expect(closeSnapshot.errno == nil)
    let descriptorStatsAfter = await daemon.stats()
    #expect(descriptorStatsAfter.openRequests == descriptorStatsBefore.openRequests)
    #expect(descriptorStatsAfter.closeRequests == descriptorStatsBefore.closeRequests)

    let removeReply = BoundaryErrorReply()
    volume.removeItem(
        portableSource,
        named: PfsFSKitMapping.fileName(from: sourceName),
        fromDirectory: root
    ) { error in
        let errorCode = error.map { ($0 as NSError).code }
        Task { await removeReply.record(errno: errorCode) }
    }
    #expect(try await waitForBoundaryCallback {
        (await removeReply.snapshot()).delivered
    })
    let removeSnapshot = await removeReply.snapshot()
    #expect(removeSnapshot.delivered)
    #expect(removeSnapshot.errno == nil)
    // A positive eviction belongs to an authority namespace target. Its old
    // item/coordinate pair is not a reusable repair locator after COMPLETE.
    #expect(await coherence.namespaceIndex.binding(
        parentIdentity: rootIdentity,
        name: sourceName
    ) == nil)
    #expect(await coherence.namespaceIndex.repairLocator(
        parentIdentity: rootIdentity,
        name: sourceName
    ) == nil)
    #expect(await registry.pendingCallbacks(operand: operand).isEmpty)
    let sourceCoordinateStillArmed = await registry.isArmedRepairSource(
        parentIdentity: rootIdentity.bytes,
        name: sourceName
    )
    #expect(!sourceCoordinateStillArmed)
    #expect(await registry.isArmedRepairSourceItem(
        itemIdentity: sourceIdentity.bytes
    ))

    // The name is gone, but unlinkat has not returned until FSKit finishes
    // its vnode teardown. Reclaim must remain repair-owned for that entire
    // tail and must retire only the local FSItem—not send an authority
    // Reclaim for the XFS object that still owns this binding.
    let reclaimStatsBefore = await daemon.stats()
    let reclaimReply = BoundaryErrorReply()
    volume.reclaimItem(portableSource) { error in
        let errorCode = error.map { ($0 as NSError).code }
        Task { await reclaimReply.record(errno: errorCode) }
    }
    #expect(try await waitForBoundaryCallback {
        (await reclaimReply.snapshot()).delivered
    })
    let reclaimSnapshot = await reclaimReply.snapshot()
    #expect(reclaimSnapshot.delivered)
    #expect(reclaimSnapshot.errno == nil)
    #expect(await daemon.stats().reclaimRequests == reclaimStatsBefore.reclaimRequests)

    let complete = try PfsMacOSCoherenceEvent(
        epoch: prepare.epoch,
        sequence: prepare.sequence,
        phase: .complete,
        initiator: prepare.initiator,
        repairs: prepare.repairs
    )
    try await barrier.resume(complete)
    try await lease.finish()
    let sourceItemStillArmed = await registry.isArmedRepairSourceItem(
        itemIdentity: sourceIdentity.bytes
    )
    #expect(!sourceItemStillArmed)
    #expect(await daemon.stats().removeRequests == 0)
}

@available(macOS 26.0, *)
@Test func adapterRefusesAReservedNameThatIsNotTheArmedOne() async throws {
    let authenticator = try PfsMacOS26RepairAuthenticator(
        mountSessionID: UUID(),
        secret: boundarySecret
    )
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let harness = try await makeBoundaryHarness(repairGate: registry)

    let armedOperand = try reservedName(
        authenticator: authenticator,
        kind: .negativeScratch,
        sourceName: nil
    )
    _ = try await registry.arm(
        plan(
            for: .negativeScratch,
            operand: armedOperand,
            path: try PfsMacOSRelativePath(components: [])
        )
    )
    // A second, equally well-formed operand for a step nobody armed.
    let otherOperand = try reservedName(
        authenticator: authenticator,
        kind: .negativeScratch,
        sequence: 2,
        sourceName: nil
    )
    do {
        _ = try await harness.volume.createItem(
            named: PfsFSKitMapping.fileName(from: otherOperand),
            type: .file,
            inDirectory: harness.root,
            attributes: FSItem.SetAttributesRequest()
        )
        Issue.record("createItem accepted an unarmed operand")
    } catch { expectEPERM(error) }

    let stats = await harness.daemon.stats()
    #expect(stats.createRequests == 0)
    #expect(await harness.core.localRepairItemCount() == 0)
}

@available(macOS 26.0, *)
@Test func adapterRefusesAnArmedEvictionRenameOfSomeoneElsesFile() async throws {
    let authenticator = try PfsMacOS26RepairAuthenticator(
        mountSessionID: UUID(),
        secret: boundarySecret
    )
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let harness = try await makeBoundaryHarness(repairGate: registry)

    let operand = try reservedName(
        authenticator: authenticator,
        kind: .positiveEviction,
        parent: harness.rootIdentity,
        sourceName: Data("stale".utf8)
    )
    _ = try await registry.arm(
        plan(
            for: .positiveEviction,
            operand: operand,
            path: try PfsMacOSRelativePath(components: [Data("stale".utf8)]),
            parent: harness.rootIdentity
        )
    )

    let (precious, preciousName) = try await harness.volume.createItem(
        named: FSFileName(string: "precious"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    // The transaction authorizes moving "stale" and nothing else. A callback
    // naming a different file must not be swallowed, and must not be
    // forwarded either.
    do {
        _ = try await harness.volume.renameItem(
            precious,
            inDirectory: harness.root,
            named: preciousName,
            to: PfsFSKitMapping.fileName(from: operand),
            inDirectory: harness.root,
            overItem: nil
        )
        Issue.record("renameItem swallowed a rename of an unrelated file")
    } catch { expectEPERM(error) }

    let stats = await harness.daemon.stats()
    #expect(stats.renameRequests == 0)
    #expect(stats.createRequests == 1)
    #expect(await registry.pendingCallbacks(operand: operand) == [.removeSource])
}

@available(macOS 26.0, *)
@Test func adapterConsumesExactSourceRemovalWithoutAuthorityMutation() async throws {
    let authenticator = try PfsMacOS26RepairAuthenticator(
        mountSessionID: UUID(),
        secret: boundarySecret
    )
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let harness = try await makeBoundaryHarness(repairGate: registry)

    let (stale, staleName) = try await harness.volume.createItem(
        named: FSFileName(string: "stale"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let staleItem = try #require(stale as? PortableFSItem)
    let staleIdentity = try PfsMacOSStableIdentity(staleItem.identity.stableIdentity)
    let operand = try reservedName(
        authenticator: authenticator,
        kind: .positiveEviction,
        parent: harness.rootIdentity,
        item: staleIdentity,
        sourceName: Data("stale".utf8)
    )
    let lease = try await registry.arm(
        plan(
            for: .positiveEviction,
            operand: operand,
            path: try PfsMacOSRelativePath(components: [Data("stale".utf8)]),
            parent: harness.rootIdentity,
            item: staleIdentity
        )
    )
    await harness.daemon.resetStats()

    try await harness.volume.removeItem(
        stale,
        named: staleName,
        fromDirectory: harness.root
    )
    try await lease.finish()

    let stats = await harness.daemon.stats()
    #expect(stats.removeRequests == 0)
    #expect(await registry.armedOperandCount() == 0)

    // XFS/mock authority still owns the binding; a later lookup republishes it.
    let (reloaded, _) = try await harness.volume.lookupItem(
        named: staleName,
        inDirectory: harness.root
    )
    #expect((reloaded as? PortableFSItem)?.identity.stableIdentity == staleItem.identity.stableIdentity)
}

@available(macOS 26.0, *)
@Test func adapterConsumesExactAttributeRefreshAndReturnsAuthoritySnapshot() async throws {
    let authenticator = try PfsMacOS26RepairAuthenticator(
        mountSessionID: UUID(),
        secret: boundarySecret
    )
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let harness = try await makeBoundaryHarness(repairGate: registry)
    let (item, name) = try await harness.volume.createItem(
        named: FSFileName(string: "attrs"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let portable = try #require(item as? PortableFSItem)
    let identity = try PfsMacOSStableIdentity(portable.identity.stableIdentity)
    let fileID = try PfsFSKitMapping.itemIdentifier(from: portable.identity.itemID).rawValue
    let operand = try authenticator.makeOperand(
        epoch: boundaryEpoch,
        sequence: 2,
        step: 0,
        kind: .attributeRefresh,
        parentIdentity: harness.rootIdentity,
        itemIdentity: identity,
        sourceName: name.data,
        itemKind: .file
    )
    let lease = try await registry.arm(.init(
        epoch: boundaryEpoch,
        sequence: 2,
        step: 0,
        kind: .attributeRefresh,
        path: try PfsMacOSRelativePath(components: [name.data]),
        parentIdentity: harness.rootIdentity,
        itemIdentity: identity,
        expectedVFSFileID: fileID,
        authoritativeSize: nil,
        operand: operand
    ))
    await harness.daemon.resetStats()
    let authorityBefore = try await harness.core.getattr(item: portable)

    // FSKit provides no caller token, so a racing different-mode callback on
    // the exact item is the declared event-scoped ambiguity: it is coalesced
    // locally. The gate must remain armed so this cannot strand the actuator's
    // later existing-mode fchmod callback.
    let wrongMode = FSItem.SetAttributesRequest()
    wrongMode.mode = authorityBefore.mode ^ 0o111
    #expect(wrongMode.mode != authorityBefore.mode)
    _ = try await harness.volume.setAttributes(wrongMode, on: portable)
    #expect(await registry.isArmedAttributeRefreshItem(
        itemIdentity: portable.identity.stableIdentity
    ))
    #expect(wrongMode.consumedAttributes.contains(.mode))
    #expect((await harness.daemon.stats()).setAttrRequests == 0)

    let authorityAfterWrongMode = try await harness.core.getattr(item: portable)
    #expect(authorityAfterWrongMode.mode == authorityBefore.mode)
    let request = FSItem.SetAttributesRequest()
    request.mode = authorityAfterWrongMode.mode
    let attributes = try await harness.volume.setAttributes(request, on: portable)
    #expect(request.consumedAttributes.contains(.mode))
    #expect(attributes.fileID.rawValue == fileID)
    #expect(attributes.mode == authorityAfterWrongMode.mode)
    #expect((await harness.daemon.stats()).setAttrRequests == 0)
    try await lease.finish()
}


@available(macOS 26.0, *)
@Test func attributeRefreshRacingModeIsCoalescedWithoutStrandingActuatorCallback() async throws {
    let daemon = try PfsLocalMockDaemon()
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let rootIdentity = try PfsMacOSStableIdentity(root.identity.stableIdentity)
    let authenticator = try PfsMacOS26RepairAuthenticator(
        mountSessionID: UUID(),
        secret: boundarySecret
    )
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: Data(repeating: 0x91, count: 16)
    )
    let coherence = PfsMacOSV3VolumeCoherence(
        contract: nil,
        namespaceIndex: PfsMacOSNamespaceIndex(rootIdentity: rootIdentity),
        liveObjects: PfsMacOSLiveObjectIndex(),
        barrier: barrier,
        repairGate: registry
    )
    let volume = try await PortableFSVolume.make(
        core: core,
        attachRef: "mock",
        coherence: coherence
    )
    let (item, name) = try await volume.createItem(
        named: FSFileName(string: "attrs-closed"),
        type: .file,
        inDirectory: root,
        attributes: FSItem.SetAttributesRequest()
    )
    let portable = try #require(item as? PortableFSItem)
    let identity = try PfsMacOSStableIdentity(portable.identity.stableIdentity)
    let fileID = try PfsFSKitMapping.itemIdentifier(from: portable.identity.itemID).rawValue
    let operand = try authenticator.makeOperand(
        epoch: boundaryEpoch,
        sequence: 93,
        step: 0,
        kind: .attributeRefresh,
        parentIdentity: rootIdentity,
        itemIdentity: identity,
        sourceName: name.data,
        itemKind: .file
    )
    let lease = try await registry.arm(.init(
        epoch: boundaryEpoch,
        sequence: 93,
        step: 0,
        kind: .attributeRefresh,
        path: try PfsMacOSRelativePath(components: [name.data]),
        parentIdentity: rootIdentity,
        itemIdentity: identity,
        expectedVFSFileID: fileID,
        authoritativeSize: nil,
        operand: operand
    ))
    let prepare = try PfsMacOSCoherenceEvent(
        epoch: boundaryEpoch,
        sequence: 93,
        phase: .prepare,
        initiator: PfsMacOSMutationInitiator(
            sessionID: Data(repeating: 0x92, count: 16),
            replaySlot: 1,
            mutationSequence: 93,
            localOperationID: nil
        ),
        repairs: []
    )
    try await barrier.prepare(prepare)
    await daemon.resetStats()

    let authority = try await core.getattr(item: portable)

    // Request shapes the actuator never emits are not exempt merely because
    // they name the armed item. Each must be refused before any authority frame.
    func expectRefused(_ request: FSItem.SetAttributesRequest) async throws {
        let refusal = BoundaryAttributesReply()
        volume.setAttributes(request, on: portable) { attributes, error in
            let hadAttributes = attributes != nil
            let errno = error.map { ($0 as NSError).code }
            Task {
                await refusal.record(hadAttributes: hadAttributes, errno: errno)
            }
        }
        try await Task.sleep(for: .milliseconds(100))
        let result = await refusal.snapshot()
        #expect(result.delivered)
        #expect(!result.hadAttributes)
        #expect(result.errno == Int(ECANCELED))
        #expect((await daemon.stats()).setAttrRequests == 0)
    }

    let ownershipShape = FSItem.SetAttributesRequest()
    ownershipShape.mode = authority.mode
    ownershipShape.uid = authority.uid
    try await expectRefused(ownershipShape)

    let modifyTimeShape = FSItem.SetAttributesRequest()
    modifyTimeShape.mode = authority.mode
    modifyTimeShape.modifyTime = timespec(tv_sec: 1, tv_nsec: 0)
    try await expectRefused(modifyTimeShape)

    let accessTimeShape = FSItem.SetAttributesRequest()
    accessTimeShape.mode = authority.mode
    accessTimeShape.accessTime = timespec(tv_sec: 1, tv_nsec: 0)
    try await expectRefused(accessTimeShape)


    // This may be a user callback or the actuator: macOS 26 supplies no
    // discriminator. It is deliberately coalesced, and the multi-consumption
    // window must still admit the actuator's subsequent callback.
    let wrongMode = FSItem.SetAttributesRequest()
    wrongMode.mode = authority.mode ^ 0o111
    let wrongReply = BoundaryAttributesReply()
    volume.setAttributes(wrongMode, on: portable) { attributes, error in
        let hadAttributes = attributes != nil
        let errno = error.map { ($0 as NSError).code }
        Task {
            await wrongReply.record(hadAttributes: hadAttributes, errno: errno)
        }
    }
    try await Task.sleep(for: .milliseconds(100))
    let wrong = await wrongReply.snapshot()
    #expect(wrong.delivered)
    #expect(wrong.hadAttributes)
    #expect(wrong.errno == nil)
    #expect(wrongMode.consumedAttributes.contains(.mode))
    #expect((await daemon.stats()).setAttrRequests == 0)

    let exactMode = FSItem.SetAttributesRequest()
    exactMode.mode = authority.mode
    let exactReply = BoundaryAttributesReply()
    volume.setAttributes(exactMode, on: portable) { attributes, error in
        let hadAttributes = attributes != nil
        let errno = error.map { ($0 as NSError).code }
        Task {
            await exactReply.record(hadAttributes: hadAttributes, errno: errno)
        }
    }
    try await Task.sleep(for: .milliseconds(100))
    let exact = await exactReply.snapshot()
    #expect(exact.delivered)
    #expect(exact.hadAttributes)
    #expect(exact.errno == nil)
    #expect(exactMode.consumedAttributes.contains(.mode))
    #expect((await daemon.stats()).setAttrRequests == 0)

    let complete = try PfsMacOSCoherenceEvent(
        epoch: prepare.epoch,
        sequence: prepare.sequence,
        phase: .complete,
        initiator: prepare.initiator,
        repairs: prepare.repairs
    )
    try await barrier.resume(complete)
    try await lease.finish()
}

@available(macOS 26.0, *)
@Test func ordinaryNamesAreUnaffectedByTheReservedNamespaceCheck() async throws {
    let harness = try await makeBoundaryHarness()
    let (item, name) = try await harness.volume.createItem(
        named: FSFileName(string: "ordinary.txt"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    #expect(name.string == "ordinary.txt")
    _ = try await harness.volume.renameItem(
        item,
        inDirectory: harness.root,
        named: name,
        to: FSFileName(string: "renamed.txt"),
        inDirectory: harness.root,
        overItem: nil
    )
    try await harness.volume.removeItem(
        item,
        named: FSFileName(string: "renamed.txt"),
        fromDirectory: harness.root
    )
    let stats = await harness.daemon.stats()
    #expect(stats.createRequests == 1)
    #expect(stats.renameRequests == 1)
    #expect(stats.removeRequests == 1)
}

@available(macOS 26.0, *)
@Test func daemonItemIdentifiersCannotEnterTheLocalRepairRange() throws {
    #expect(throws: PfsLocalClientError.self) {
        _ = try PfsFSKitMapping.itemIdentifier(
            from: PfsFSKitMapping.localRepairIdentifierFloor
        )
    }
    #expect(throws: PfsLocalClientError.self) {
        _ = try PfsFSKitMapping.itemIdentifier(from: UInt64.max - 1)
    }
    _ = try PfsFSKitMapping.itemIdentifier(
        from: PfsFSKitMapping.localRepairIdentifierFloor - 1
    )
}
