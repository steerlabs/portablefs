import Foundation
import FSKit
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

private func rootFixAttr(handle: UInt64, fileID: UInt64, identity: UInt8 = 1) -> PfsAttr {
    var attr = PfsAttr()
    attr.item.itemID = handle
    attr.item.itemGeneration = 1
    attr.item.stableIdentity = Data(repeating: identity, count: 16)
    attr.fileID = fileID
    attr.kind = .file
    return attr
}

@Test func fileNumbersAreIndependentOfOwnershipHandlesAndParents() throws {
    var attr = rootFixAttr(handle: UInt64.max, fileID: 700)
    attr.parent.itemID = 90_000
    attr.parentFileID = 33
    let mapped = try PfsFSKitMapping.attributes(from: attr)
    #expect(mapped.fileID.rawValue == 701)
    #expect(mapped.parentID.rawValue == 34)
    #expect(try PfsFSKitMapping.parentDirectoryIdentifier(from: attr).rawValue == 34)

    attr.fileID = 1
    attr.kind = .directory
    #expect(try PfsFSKitMapping.attributes(from: attr).fileID == .rootDirectory)
    #expect(try PfsFSKitMapping.attributes(from: attr).parentID == .parentOfRoot)
    #expect(try PfsFSKitMapping.parentDirectoryIdentifier(from: attr) == .rootDirectory)

    attr.fileID = 700
    attr.parentFileID = 0
    #expect(try PfsFSKitMapping.attributes(from: attr).parentID == .invalid)
    #expect(try PfsFSKitMapping.parentDirectoryIdentifier(from: attr).rawValue == 701)

    // The former high-half partition holds ordinary daemon file IDs.
    attr.fileID = UInt64(1) << 63
    #expect(try PfsFSKitMapping.attributes(from: attr).fileID.rawValue == attr.fileID + 1)
}

@Test func itemIngestionRejectsChangedIdentityAndUnknownKind() async throws {
    let core = VolumeCore(client: PfsLocalClient(socketPath: "/unused-root-fix-test"))
    let attr = rootFixAttr(handle: UInt64.max, fileID: 700)
    let item = try await core.testingAdoptAttributes(attr)
    #expect(item.fileID == 700)
    #expect(item.kind == .file)
    var changed = attr
    changed.fileID = 701
    await #expect(throws: PfsLocalClientError.self) { try await core.testingAdoptAttributes(changed) }
    changed = attr
    changed.kind = .directory
    await #expect(throws: PfsLocalClientError.self) { try await core.testingAdoptAttributes(changed) }
    changed = attr
    changed.kind = .unspecified
    await #expect(throws: PfsLocalClientError.self) { try await core.testingAdoptAttributes(changed) }
    changed = rootFixAttr(handle: 90_001, fileID: 700, identity: 2)
    await #expect(throws: PfsLocalClientError.self) { try await core.testingAdoptAttributes(changed) }
    changed = rootFixAttr(handle: 90_001, fileID: 700)
    changed.kind = .directory
    await #expect(throws: PfsLocalClientError.self) { try await core.testingAdoptAttributes(changed) }
    changed = rootFixAttr(handle: UInt64.max, fileID: 701, identity: 2)
    await #expect(throws: PfsLocalClientError.self) { try await core.testingAdoptAttributes(changed) }
}

private func waitForRootFixState(_ predicate: () async -> Bool) async throws {
    let deadline = ContinuousClock.now + .seconds(3)
    while !(await predicate()), ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(2))
    }
    #expect(await predicate(), "the expected lifecycle transition did not occur")
}

extension PfsLocalMockDaemonTests {
@Test func fileIDSurvivesRetirementAndANewOwnershipHandle() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(fileIDOffset: 700))
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let previous = try await core.createFile(in: root, name: Data("retired".utf8), mode: 0o644).item
    try await core.reclaim(item: previous)
    let current = try await core.lookup(in: root, name: Data("retired".utf8)).item
    #expect(previous !== current)
    #expect(previous.reclaimed)
    #expect(current.fileID == previous.fileID)
    #expect(current.identity.itemID != previous.identity.itemID)
    #expect(current.identity.stableIdentity == previous.identity.stableIdentity)
    #expect(try PfsFSKitMapping.itemIdentifier(from: current.fileID).rawValue == current.fileID + 1)
}

@Test func volumeCoreRequiresTheExactPairedLocalProtocol() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    await daemon.transformNextReply { envelope in
        guard case var .helloReply(reply)? = envelope.body else { return nil }
        reply.protocolMinor = 1
        var changed = envelope
        changed.body = .helloReply(reply)
        return changed
    }
    await #expect(throws: PfsLocalClientError.protocolMismatch(major: 2, minor: 1)) {
        _ = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    }
}

@Test func hardLinksShareFileIDAndCanonicalItem() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(fileIDOffset: 5_000))
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: Data("one".utf8), mode: 0o644)
    let linked = try await core.hardLink(item: created.item, in: root, name: Data("two".utf8))
    let alias = try await core.lookup(in: root, name: Data("two".utf8))
    #expect(alias.item === created.item)
    #expect(alias.item.fileID != alias.item.identity.itemID)
    #expect(linked.attr.fileID == created.attr.fileID)
    #expect(alias.attr.fileID == created.item.fileID)
    #expect(alias.attr.parentFileID == root.fileID)
    #expect(try PfsFSKitMapping.attributes(from: alias.attr).fileID == PfsFSKitMapping.attributes(from: linked.attr).fileID)
}

@Test func openAndImplicitOpenDoNotFetchAttributes() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let file = try await core.createFile(in: root, name: Data("opened".utf8), mode: 0o644)
    try await core.close(item: file.item)
    await daemon.resetStats()
    try await core.open(item: file.item, mode: .read)
    try await core.close(item: file.item)
    _ = try await core.read(item: file.item, offset: 0, length: 1)
    #expect(await daemon.stats().getAttrRequests == 0)
    #expect(await daemon.stats().openRequests == 2)
}

@Test func linkAndRemoveUseImmutableKindWithoutGetattr() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let volume = try await PortableFSVolume.make(core: core, attachRef: "mock")
    let file = try await core.createFile(in: root, name: Data("source".utf8), mode: 0o644)
    let directory = try await core.mkdir(in: root, name: Data("directory".utf8), mode: 0o755)
    await daemon.resetStats()
    _ = try await volume.createLink(to: file.item, named: FSFileName(string: "alias"), inDirectory: root)
    try await volume.removeItem(file.item, named: FSFileName(string: "alias"), fromDirectory: root)
    try await volume.removeItem(directory.item, named: FSFileName(string: "directory"), fromDirectory: root)
    #expect(await daemon.stats().getAttrRequests == 0)
    #expect(await daemon.stats().removeRequests == 2)
}

@Test func createCallbackRequiresExclusiveCreation() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let volume = try await PortableFSVolume.make(core: core, attachRef: "mock")
    _ = try await volume.createItem(named: FSFileName(string: "exists"), type: .file, inDirectory: root, attributes: FSItem.SetAttributesRequest())
    do {
        _ = try await volume.createItem(named: FSFileName(string: "exists"), type: .file, inDirectory: root, attributes: FSItem.SetAttributesRequest())
        Issue.record("exclusive create replaced an existing name")
    } catch {
        #expect((error as NSError).domain == NSPOSIXErrorDomain)
        #expect((error as NSError).code == Int(EEXIST))
    }
    #expect(await daemon.stats().createExclusiveFlags == [true, true])
}

@Test func directoryCreatePreservesExplicitMode() async throws {
    for mode: UInt32 in [0, 0o300, 0o644, 0o755] {
        let daemon = try PfsLocalMockDaemon()
        defer { daemon.stop() }
        let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
        let volume = try await PortableFSVolume.make(core: core, attachRef: "mock")
        let attrs = FSItem.SetAttributesRequest()
        attrs.mode = mode
        let (item, _) = try await volume.createItem(named: FSFileName(string: "mode"), type: .directory, inDirectory: core.rootItem(), attributes: attrs)
        let portable = try #require(item as? PortableFSItem)
        #expect(try await core.getattr(item: portable).mode == mode)
    }
}

@Test func createDefaultsDependOnTypeOnlyWhenModeIsAbsent() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let volume = try await PortableFSVolume.make(core: core, attachRef: "mock")
    for (type, mode): (FSItem.ItemType, UInt32) in [(.file, 0o644), (.directory, 0o755)] {
        let (item, _) = try await volume.createItem(named: FSFileName(string: "type-\(mode)"), type: type, inDirectory: root, attributes: FSItem.SetAttributesRequest())
        #expect(try await core.getattr(item: #require(item as? PortableFSItem)).mode == mode)
    }
}

@Test func lookupDuringReclaimWaitsForSettlementAndPublishesANewObject() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let file = try await core.createFile(in: root, name: Data("racing".utf8), mode: 0o644)
    await daemon.delayNextClose(nanoseconds: 250_000_000)
    await daemon.pauseReclaims()
    let reclaim = Task { try await core.reclaim(item: file.item) }
    try await waitForRootFixState { await daemon.stats().closeRequests == 1 }
    #expect(await core.testingDebugState().retiringItemCount == 1)
    let lookup = Task { try await core.lookup(in: root, name: Data("racing".utf8)) }
    try await waitForRootFixState { await core.testingDebugState().retirementWaiterCount == 1 }
    try await waitForRootFixState { await daemon.stats().reclaimRequests == 1 }
    await daemon.resumeReclaims()
    try await reclaim.value
    let replacement = try await lookup.value
    #expect(replacement.item !== file.item)
    #expect(file.item.reclaimed)
    #expect(!replacement.item.reclaimed)
    #expect(replacement.item.fileID == file.item.fileID)
    #expect(try await core.lookup(in: root, name: Data("racing".utf8)).item === replacement.item)
    let state = await core.testingDebugState()
    #expect(state.itemCount == 2)
    #expect(state.objectIdentityCount == 2)
    #expect(state.publishedItemCount == 2)
    #expect(state.provisionalItemCount == 0)
    #expect(state.retiringItemCount == 0)
    #expect(state.retirementWaiterCount == 0)
}

@Test func reclaimWaitsForPriorPhysicalPublicationAndResourceSettlement() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: Data("held".utf8), mode: 0o644)
    try await core.close(item: created.item)
    let client = await core.client
    let (result, complete) = await client.withDeferredPublication {
        try await core.lookup(in: root, name: Data("held".utf8))
    }
    let lookedUp = try result.get()
    await daemon.resetStats()
    await daemon.pauseReclaims()
    let reclaim = Task { try await core.reclaim(item: lookedUp.item) }
    try await waitForRootFixState { await core.testingDebugState().retiringItemCount == 1 }
    #expect(await daemon.stats().reclaimRequests == 0)
    #expect(await core.testingDebugState().provisionalItemCount == 1)
    await complete(true)
    try await waitForRootFixState { await daemon.stats().reclaimRequests == 1 }
    await daemon.resumeReclaims()
    try await reclaim.value
    #expect(await core.testingDebugState().publishedItemCount == 1)
    #expect(await core.testingDebugState().provisionalItemCount == 0)
}

@Test func failedReclaimResumesWaitingPublicationWithTerminalFailure() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: Data("failed".utf8), mode: 0o644)
    await daemon.pauseReclaims()
    await daemon.failNextReclaim()
    let reclaim = Task { try await core.reclaim(item: created.item) }
    try await waitForRootFixState { await daemon.stats().reclaimRequests == 1 }
    let lookup = Task { try await core.lookup(in: root, name: Data("failed".utf8)) }
    try await waitForRootFixState { await core.testingDebugState().retirementWaiterCount == 1 }
    await daemon.resumeReclaims()
    await #expect(throws: PfsLocalClientError.self) { try await reclaim.value }
    await #expect(throws: PfsLocalClientError.connectionClosed) { try await lookup.value }
    let state = await core.testingDebugState()
    #expect(state.itemCount == 0)
    #expect(state.publishedItemCount == 0)
    #expect(state.retirementWaiterCount == 0)
}

@Test func publishedOwnershipIsBoundedByLiveObjectsDuringChurn() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    for index in 0..<100 {
        let file = try await core.createFile(in: root, name: Data("churn-\(index)".utf8), mode: 0o644)
        try await core.reclaim(item: file.item)
    }
    let state = await core.testingDebugState()
    #expect(state.itemCount == 1)
    #expect(state.objectIdentityCount == 1)
    #expect(state.publishedItemCount == 1)
    #expect(state.provisionalItemCount == 0)
    #expect(state.openHandleCount == 0)
}
@Test func terminalFailureAfterDurableChunkNeverReportsFullWrite() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let file = try await core.createFile(in: root, name: Data("uncertain".utf8), mode: 0o644)
    await daemon.loseWriteReply(atIndex: 1)
    let chunk = 1 << 20
    let result = try await core.write(item: file.item, offset: 0, data: Data(repeating: 0x41, count: 2 * chunk))
    #expect(result.written == UInt32(chunk))
    #expect(result.attr.size == UInt64(chunk))
    #expect(await daemon.stats().writeRequests == 2)
}

@Test func abandoningOneLookupPreservesAnotherProvisionalOwner() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: Data("shared".utf8), mode: 0o644)
    try await core.close(item: created.item)
    try await core.reclaim(item: created.item)
    let client = await core.client
    let (first, abandon) = await client.withDeferredPublication {
        try await core.lookup(in: root, name: Data("shared".utf8))
    }
    let (second, publish) = await client.withDeferredPublication {
        try await core.lookup(in: root, name: Data("shared".utf8))
    }
    let item = try first.get().item
    #expect(try second.get().item === item)
    #expect(await core.testingDebugState().provisionalItemCount == 2)
    await abandon(false)
    #expect(!item.reclaimed)
    #expect(await core.testingDebugState().provisionalItemCount == 1)
    await publish(true)
    #expect(!item.reclaimed)
    #expect(await core.testingDebugState().publishedItemCount == 2)
    #expect(await core.testingDebugState().provisionalItemCount == 0)
}

@Test func reclaimDetachesBeforeWaitingForAnActiveDescriptorOperation() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: Data("reading".utf8), mode: 0o644)
    await daemon.pauseReads()
    await daemon.pauseReclaims()
    let read = Task { try await core.read(item: created.item, offset: 0, length: 1) }
    try await waitForRootFixState { await daemon.stats().readRequests == 1 }
    let reclaim = Task { try await core.reclaim(item: created.item) }
    try await waitForRootFixState { await core.testingDebugState().retiringItemCount == 1 }
    let lookup = Task { try await core.lookup(in: root, name: Data("reading".utf8)) }
    try await waitForRootFixState { await core.testingDebugState().retirementWaiterCount == 1 }
    #expect(await daemon.stats().reclaimRequests == 0)
    await daemon.resumeReads()
    _ = try await read.value
    try await waitForRootFixState { await daemon.stats().reclaimRequests == 1 }
    await daemon.resumeReclaims()
    try await reclaim.value
    #expect(try await lookup.value.item !== created.item)
}

}
