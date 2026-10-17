import Foundation
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

private func round1Wait(_ predicate: () async -> Bool) async throws {
    let deadline = ContinuousClock.now + .seconds(3)
    while !(await predicate()), ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(2))
    }
    #expect(await predicate())
}

private actor Round1SettlementPause {
    private var continuation: CheckedContinuation<Void, Never>?
    private(set) var arrived = false

    func wait() async {
        await withCheckedContinuation {
            continuation = $0
            arrived = true
        }
    }

    func resume() {
        let waiter = continuation
        continuation = nil
        waiter?.resume()
    }
}

private enum Round1AttrReply: Sendable {
    case lookup, create, mkdir, symlink, hardLink, getattr, setattr, write, enumerate, resolve

    func replacingAttributes(in envelope: PfsEnvelope, _ change: (inout PfsAttr) -> Void) -> PfsEnvelope? {
        var envelope = envelope
        switch (self, envelope.body) {
        case (.lookup, .lookupReply(var reply)):
            change(&reply.attr); envelope.body = .lookupReply(reply)
        case (.create, .createReply(var reply)):
            change(&reply.attr); envelope.body = .createReply(reply)
        case (.mkdir, .mkdirReply(var reply)):
            change(&reply.attr); envelope.body = .mkdirReply(reply)
        case (.symlink, .symlinkReply(var reply)):
            change(&reply.attr); envelope.body = .symlinkReply(reply)
        case (.hardLink, .hardLinkReply(var reply)):
            change(&reply.attr); envelope.body = .hardLinkReply(reply)
        case (.getattr, .getAttrReply(var reply)):
            change(&reply.attr); envelope.body = .getAttrReply(reply)
        case (.setattr, .setAttrReply(var reply)):
            change(&reply.attr); envelope.body = .setAttrReply(reply)
        case (.write, .writeReply(var reply)):
            change(&reply.attr); envelope.body = .writeReply(reply)
        case (.enumerate, .enumerateEntriesReply(var reply)):
            guard !reply.entries.isEmpty else { return nil }
            change(&reply.entries[0].attr); envelope.body = .enumerateEntriesReply(reply)
        case (.resolve, .resolveReply(var reply)):
            change(&reply.rootAttr); envelope.body = .resolveReply(reply)
        default:
            return nil
        }
        return envelope
    }
}

extension PfsLocalMockDaemonTests {
@Test func lookupWithNewHandleDoesNotWaitForOldReclaimOrLoseItsReplacement() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let previous = try await core.createFile(in: root, name: Data("new-handle".utf8), mode: 0o644).item
    await daemon.pauseReclaims()
    let reclaim = Task { try await core.reclaim(item: previous) }
    try await round1Wait { await daemon.stats().reclaimRequests == 1 }
    let lookup = Task { try await core.lookup(in: root, name: Data("new-handle".utf8)) }
    try await round1Wait { await core.testingDebugState().objectIdentityCount == 3 }
    #expect(await core.testingDebugState().retirementWaiterCount == 0)
    #expect(!previous.reclaimed)
    await daemon.resumeReclaims()
    try await reclaim.value
    let replacement = try await lookup.value.item
    #expect(replacement !== previous)
    #expect(replacement.identity.itemID != previous.identity.itemID)
    #expect(replacement.identity.stableIdentity == previous.identity.stableIdentity)
    #expect(replacement.fileID == previous.fileID)
    #expect(previous.reclaimed)
    #expect(!replacement.reclaimed)
    #expect(try await core.lookup(in: root, name: Data("new-handle".utf8)).item === replacement)
    #expect(await core.testingDebugState().objectIdentityCount == 2)
}

@Test func reclaimWithProvisionalReplyReturnsBeforeDispositionAndRetiresAfterAbandonment() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let previous = try await core.createFile(in: root, name: Data("provisional-reclaim".utf8), mode: 0o644).item
    try await core.close(item: previous)
    let client = await core.client
    // A raw reply holds daemon provisional ownership without adopting it in
    // VolumeCore. Reclaim must return while this disposition is still withheld.
    let (result, abandon) = await client.withDeferredPublication {
        var request = PfsLookupRequest()
        request.dir = root.identity.proto
        request.name = Data("provisional-reclaim".utf8)
        return try await client.request(.lookup(request))
    }
    guard case let .lookupReply(reply)? = try result.get().body else {
        Issue.record("expected lookup reply")
        return
    }
    #expect(PfsItemIdentity(reply.attr.item) == previous.identity)
    try await core.reclaim(item: previous)
    #expect(previous.reclaimed)
    await abandon(false)
    let replacement = try await core.lookup(in: root, name: Data("provisional-reclaim".utf8)).item
    #expect(replacement.identity.itemID != previous.identity.itemID)
    #expect(replacement.fileID == previous.fileID)
    #expect(!replacement.reclaimed)
}

@Test func failedDispositionWriteSettlesAllTicketsResumesReclaimAndTerminatesCreate() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let existing = try await core.createFile(in: root, name: Data("settlement".utf8), mode: 0o644).item
    try await core.close(item: existing)
    let client = await core.client
    let (result, complete) = await client.withDeferredPublication {
        let first = try await core.lookup(in: root, name: Data("settlement".utf8)).item
        let second = try await core.lookup(in: root, name: Data("settlement".utf8)).item
        let created = try await core.createFile(in: root, name: Data("must-publish".utf8), mode: 0o644).item
        return [first, second, created]
    }
    let items = try result.get()
    #expect(await core.testingDebugState().provisionalItemCount == 3)
    let reclaim = Task { try await core.reclaim(item: existing) }
    try await round1Wait { await core.testingDebugState().retiringItemCount == 1 }
    #expect(await daemon.stats().reclaimRequests == 0)
    await client.testingFailResourceDispositionWrites()
    await complete(true)
    await #expect(throws: PfsLocalClientError.self) { try await reclaim.value }
    let state = await core.testingDebugState()
    #expect(state.provisionalItemCount == 0)
    #expect(state.retiringItemCount == 0)
    #expect(state.retirementWaiterCount == 0)
    #expect(state.objectIdentityCount == 0)
    #expect(state.openHandleCount == 0)
    #expect(items.allSatisfy { $0.reclaimed })
    #expect(root.reclaimed)
    await #expect(throws: PfsLocalClientError.self) { try await core.statfs() }
}

@Test func abandonedObjectCanRemainRegisteredWhileNewHandleIsAdopted() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let client = await core.client
    // Populate the namespace without leaving an accepted child record. The
    // raw fixture owns no frontend object and may abandon its create resources.
    let (_, abandonFixture) = await client.withDeferredPublication {
        var request = PfsCreateRequest()
        request.dir = root.identity.proto
        request.name = Data("abandoned".utf8)
        request.exclusive = true
        return try await client.request(.create(request))
    }
    await abandonFixture(false)
    let (result, abandon) = await client.withDeferredPublication {
        try await core.lookup(in: root, name: Data("abandoned".utf8)).item
    }
    let previous = try result.get()
    let pause = Round1SettlementPause()
    await client.testingBeforeNextResourceSettlement { await pause.wait() }
    let settlement = Task { await abandon(false) }
    try await round1Wait { await pause.arrived }
    let replacement = try await core.lookup(in: root, name: Data("abandoned".utf8)).item
    #expect(previous !== replacement)
    #expect(previous.identity.itemID != replacement.identity.itemID)
    #expect(previous.fileID == replacement.fileID)
    #expect(previous.identity.stableIdentity == replacement.identity.stableIdentity)
    #expect(!previous.reclaimed)
    #expect(!replacement.reclaimed)
    #expect(await core.testingDebugState().objectIdentityCount == 3)
    #expect(await core.testingDebugState().itemCount == 3)
    await pause.resume()
    await settlement.value
    #expect(previous.reclaimed)
    #expect(!replacement.reclaimed)
    #expect(await core.testingDebugState().objectIdentityCount == 2)
    #expect(try await core.lookup(in: root, name: Data("abandoned".utf8)).item === replacement)
}

@Test func preReclaimCloseFailureTerminatesWithoutAnotherLookup() async throws {
    for retiredClose in [false, true] {
        let daemon = try PfsLocalMockDaemon()
        defer { daemon.stop() }
        let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
        let root = try await core.rootItem()
        let previous = try await core.createFile(in: root, name: Data("close-failure".utf8), mode: 0o644).item
        if retiredClose { await daemon.retireNextCloseWithError() }
        else { await daemon.failNextClose() }
        await #expect(throws: PfsLocalClientError.self) { try await core.reclaim(item: previous) }
        #expect(previous.reclaimed)
        #expect(root.reclaimed)
        let stats = await daemon.stats()
        #expect(stats.closeRequests == 1)
        #expect(stats.reclaimRequests == 0)
        #expect(stats.lookupRequests == 0)
        #expect(stats.activeHandles == (retiredClose ? 0 : 1))
        let state = await core.testingDebugState()
        #expect(state.objectIdentityCount == 0)
        #expect(state.openHandleCount == 0)
        #expect(state.retiringItemCount == 0)
        #expect(state.retirementWaiterCount == 0)
        // The mock retains its fixture descriptors after disconnect. The
        // session must be terminal even when Close left a daemon handle live.
        await #expect(throws: PfsLocalClientError.shutdown) { try await core.statfs() }
    }
}

@Test func cancelledReclaimGateCompletesOwnershipCleanupWithoutAnotherLookup() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let previous = try await core.createFile(in: root, name: Data("gate-cancel".utf8), mode: 0o644).item
    await daemon.pauseReads()
    let read = Task { try await core.read(item: previous, offset: 0, length: 1) }
    try await round1Wait { await daemon.stats().readRequests == 1 }
    let reclaim = Task { try await core.reclaim(item: previous) }
    try await round1Wait { await core.testingDebugState().retiringItemCount == 1 }
    reclaim.cancel()
    #expect(await daemon.stats().reclaimRequests == 0)
    await daemon.resumeReads()
    _ = try await read.value
    try await reclaim.value
    #expect(previous.reclaimed)
    #expect(!root.reclaimed)
    let stats = await daemon.stats()
    #expect(stats.closeRequests == 1)
    #expect(stats.reclaimRequests == 1)
    #expect(stats.activeHandles == 0)
    #expect(stats.lookupRequests == 0)
    let state = await core.testingDebugState()
    #expect(state.objectIdentityCount == 1)
    #expect(state.openHandleCount == 0)
    #expect(state.retiringItemCount == 0)
    // Probe the retired capability directly, without re-adopting its pathname.
    var request = PfsGetAttrRequest()
    request.item = previous.identity.proto
    let client = await core.client
    await #expect(throws: PfsLocalClientError.daemon(errno: ESTALE, message: "stale item")) {
        try await client.request(.getAttr(request))
    }
    _ = try await core.statfs()
}

@Test func alreadyCancelledReclaimRetiresAnItemWithoutDescriptorsOrAnotherLookup() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let previous = try await core.mkdir(in: root, name: Data("cancelled-directory".utf8), mode: 0o755).item
    let reclaim = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        try await core.reclaim(item: previous)
    }
    try await reclaim.value
    #expect(previous.reclaimed)
    #expect(!root.reclaimed)
    let stats = await daemon.stats()
    #expect(stats.reclaimRequests == 1)
    #expect(stats.closeRequests == 0)
    #expect(stats.activeHandles == 0)
    #expect(stats.lookupRequests == 0)
    #expect(await core.testingDebugState().objectIdentityCount == 1)
    var request = PfsGetAttrRequest()
    request.item = previous.identity.proto
    let client = await core.client
    await #expect(throws: PfsLocalClientError.daemon(errno: ESTALE, message: "stale item")) {
        try await client.request(.getAttr(request))
    }
    _ = try await core.statfs()
}

@Test func detachingReclaimRetiresOnlyTheFrontendObject() async throws {
    for hasHandle in [false, true] {
        let daemon = try PfsLocalMockDaemon()
        defer { daemon.stop() }
        let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
        let root = try await core.rootItem()
        let previous: PortableFSItem
        if hasHandle {
            previous = try await core.createFile(in: root, name: Data("detaching".utf8), mode: 0o644).item
        } else {
            previous = try await core.mkdir(in: root, name: Data("detaching".utf8), mode: 0o755).item
        }
        let events = try await core.subscribeEvents()
        daemon.emitAttachState(.detaching)
        var iterator = events.makeAsyncIterator()
        _ = await iterator.next()
        await #expect(throws: PfsLocalClientError.self) { try await core.reclaim(item: previous) }
        #expect(previous.reclaimed)
        #expect(!root.reclaimed)
        #expect(await daemon.stats().reclaimRequests == 0)
        #expect(await core.testingDebugState().objectIdentityCount == 1)
        #expect(await core.testingDebugState().openHandleCount == (hasHandle ? 1 : 0))
        await core.shutdown()
        #expect(root.reclaimed)
        #expect(await core.testingDebugState().openHandleCount == 0)
    }
}

@Test func repairSourceHandleInvariantTerminatesWithoutReadoption() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let previous = try await core.createFile(in: root, name: Data("repair-handle".utf8), mode: 0o644).item
    await #expect(throws: PfsLocalClientError.self) { try await core.reclaimLocalRepairSource(item: previous) }
    #expect(previous.reclaimed)
    #expect(root.reclaimed)
    #expect(await daemon.stats().lookupRequests == 0)
    #expect(await daemon.stats().reclaimRequests == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
    await #expect(throws: PfsLocalClientError.shutdown) { try await core.statfs() }
}

@Test func cancellationAfterCreateDispatchStillAdoptsTheDurableReply() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    await daemon.delayNextCreate(nanoseconds: 150_000_000)
    let create = Task { try await core.createFile(in: root, name: Data("cancel-create".utf8), mode: 0o644) }
    try await round1Wait { await daemon.stats().createRequests == 1 }
    create.cancel()
    let created = try await create.value
    #expect(!created.item.reclaimed)
    #expect(try await core.lookup(in: root, name: Data("cancel-create".utf8)).item === created.item)
    #expect(await daemon.stats().activeHandles == 1)
    _ = try await core.statfs()
}

@Test func malformedMutationAttributesTerminateTheMount() async throws {
    for operation: Round1AttrReply in [.create, .mkdir, .symlink, .hardLink, .setattr, .write] {
        let daemon = try PfsLocalMockDaemon()
        defer { daemon.stop() }
        let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
        let root = try await core.rootItem()
        let file = try await core.createFile(in: root, name: Data("source".utf8), mode: 0o644).item
        await daemon.transformNextReply {
            operation.replacingAttributes(in: $0) { $0.fileID = 1 }
        }
        await #expect(throws: PfsLocalClientError.self) {
            switch operation {
            case .create: _ = try await core.createFile(in: root, name: Data("bad".utf8), mode: 0o644)
            case .mkdir: _ = try await core.mkdir(in: root, name: Data("bad".utf8), mode: 0o755)
            case .symlink: _ = try await core.symlink(in: root, name: Data("bad".utf8), target: Data("source".utf8))
            case .hardLink: _ = try await core.hardLink(item: file, in: root, name: Data("bad".utf8))
            case .setattr: _ = try await core.setattr(item: file, attributes: .init(mode: 0o600))
            case .write: _ = try await core.write(item: file, offset: 0, data: Data([1]))
            default: Issue.record("unexpected mutation test case")
            }
        }
        #expect(root.reclaimed)
        #expect(file.reclaimed)
        await #expect(throws: PfsLocalClientError.self) { try await core.statfs() }
    }
}

@Test func malformedRenameReplyTerminatesTheMount() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let file = try await core.createFile(in: root, name: Data("source".utf8), mode: 0o644).item
    await daemon.transformNextReply { envelope in
        guard case var .renameReply(reply)? = envelope.body else { return nil }
        reply.newPostIdentity = Data([1])
        var envelope = envelope
        envelope.body = .renameReply(reply)
        return envelope
    }
    await #expect(throws: PfsLocalClientError.self) {
        try await core.rename(item: file, from: root, sourceName: Data("source".utf8), to: root, destinationName: Data("renamed".utf8), noReplace: true)
    }
    await #expect(throws: PfsLocalClientError.self) { try await core.statfs() }
}

@Test func malformedNonmutatingAttributesFailOnlyTheCallback() async throws {
    for operation: Round1AttrReply in [.lookup, .getattr, .write, .enumerate] {
        let daemon = try PfsLocalMockDaemon()
        defer { daemon.stop() }
        let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
        let root = try await core.rootItem()
        let file = try await core.createFile(in: root, name: Data("source".utf8), mode: 0o644).item
        await daemon.transformNextReply {
            operation.replacingAttributes(in: $0) { $0.fileID = 1 }
        }
        await #expect(throws: PfsLocalClientError.self) {
            switch operation {
            case .lookup: _ = try await core.lookup(in: root, name: Data("source".utf8))
            case .getattr: _ = try await core.getattr(item: file)
            case .write: _ = try await core.write(item: file, offset: 0, data: Data())
            case .enumerate: _ = try await core.enumerate(directory: root, startingAt: 0, wantAttributes: true)
            default: Issue.record("unexpected read-only test case")
            }
        }
        #expect(!root.reclaimed)
        #expect(!file.reclaimed)
        #expect(try await core.lookup(in: root, name: Data("source".utf8)).item === file)
        _ = try await core.statfs()
    }
}

@Test func liveFileIDReuseInLookupFailsOnlyThatCallback() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let first = try await core.createFile(in: root, name: Data("first".utf8), mode: 0o644).item
    let second = try await core.createFile(in: root, name: Data("second".utf8), mode: 0o644).item
    try await core.close(item: second)
    try await core.reclaimLocalRepairSource(item: second)
    await daemon.transformNextReply {
        Round1AttrReply.lookup.replacingAttributes(in: $0) { $0.fileID = first.fileID }
    }
    await #expect(throws: PfsLocalClientError.self) { try await core.lookup(in: root, name: Data("second".utf8)) }
    #expect(!first.reclaimed)
    #expect(try await core.lookup(in: root, name: Data("second".utf8)).item.fileID == second.fileID)
    _ = try await core.statfs()
}

@Test func namespaceRepliesMustMatchTheirRequestedParent() async throws {
    for operation: Round1AttrReply in [.lookup, .create, .mkdir, .symlink] {
        let daemon = try PfsLocalMockDaemon()
        defer { daemon.stop() }
        let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
        let root = try await core.rootItem()
        let directory = try await core.mkdir(in: root, name: Data("parent".utf8), mode: 0o755).item
        _ = try await core.createFile(in: directory, name: Data("existing".utf8), mode: 0o644)
        await daemon.transformNextReply {
            operation.replacingAttributes(in: $0) { $0.parentFileID = root.fileID }
        }
        await #expect(throws: PfsLocalClientError.self) {
            switch operation {
            case .lookup: _ = try await core.lookup(in: directory, name: Data("existing".utf8))
            case .create: _ = try await core.createFile(in: directory, name: Data("bad".utf8), mode: 0o644)
            case .mkdir: _ = try await core.mkdir(in: directory, name: Data("bad".utf8), mode: 0o755)
            case .symlink: _ = try await core.symlink(in: directory, name: Data("bad".utf8), target: Data("existing".utf8))
            default: Issue.record("unexpected namespace test case")
            }
        }
        if operation == .lookup { _ = try await core.statfs() }
        else { await #expect(throws: PfsLocalClientError.self) { try await core.statfs() } }
    }
}

@Test func invalidRootClosesClientBeforeInstallingVolumeState() async throws {
    for badParent in [false, true] {
        var contract = PfsV3CoherenceContract()
        contract.authorityProtocolMajor = 7
        contract.authorityEpoch = Data(repeating: 0xE1, count: 16)
        contract.sessionID = Data(repeating: 0x51, count: 16)
        contract.cachePolicy = PfsMacOSCachePolicy.synchronousVFSRepairV1.rawValue
        contract.repairBudgetMillis = 2_500
        let daemon = try PfsLocalMockDaemon(configuration: .init(v3Coherence: contract))
        defer { daemon.stop() }
        let client = PfsLocalClient(socketPath: daemon.socketPath)
        let core = VolumeCore(client: client)
        await daemon.transformNextReply {
            Round1AttrReply.resolve.replacingAttributes(in: $0) {
                if badParent { $0.parentFileID = 1 }
                else { $0.fileID = 2 }
            }
        }
        await #expect(throws: PfsLocalClientError.self) { try await core.resolve(attachRef: "mock") }
        #expect(await core.strictV3ResolveReply == nil)
        #expect(await core.strictV3Contract == nil)
        #expect(await core.resolvedVolume == nil)
        await #expect(throws: PfsLocalClientError.shutdown) { try await client.request(.statfs(PfsStatfsRequest())) }
    }
}
}
