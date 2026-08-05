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
    repairGate: (any PfsMacOS26RepairGate)? = nil
) async throws -> BoundaryHarness {
    let daemon = try PfsLocalMockDaemon()
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
    let harness = try await makeBoundaryHarness(repairGate: registry)

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

    try await harness.volume.removeItem(
        scratchItem,
        named: reserved,
        fromDirectory: harness.root
    )
    try await lease.finish()

    let stats = await harness.daemon.stats()
    #expect(stats.createRequests == 0)
    #expect(stats.removeRequests == 0)
    #expect(stats.renameRequests == 0)
    #expect(await harness.core.localRepairItemCount() == 0)
    #expect(await registry.tornRepairs().isEmpty)
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
    #expect(await registry.pendingCallbacks(operand: operand) == [.renameIntoOperand, .removeOperand])
}

@available(macOS 26.0, *)
@Test func adapterSwallowsTheEvictionRenameAndItsRollback() async throws {
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
    let lease = try await registry.arm(
        plan(
            for: .positiveEviction,
            operand: operand,
            path: try PfsMacOSRelativePath(components: [Data("stale".utf8)]),
            parent: harness.rootIdentity
        )
    )
    let (stale, staleName) = try await harness.volume.createItem(
        named: FSFileName(string: "stale"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let reserved = PfsFSKitMapping.fileName(from: operand)

    _ = try await harness.volume.renameItem(
        stale,
        inDirectory: harness.root,
        named: staleName,
        to: reserved,
        inDirectory: harness.root,
        overItem: nil
    )
    // The actuator's rollback path: the hidden name goes back to the user's.
    _ = try await harness.volume.renameItem(
        stale,
        inDirectory: harness.root,
        named: reserved,
        to: staleName,
        inDirectory: harness.root,
        overItem: nil
    )
    await lease.cancel()

    let stats = await harness.daemon.stats()
    #expect(stats.renameRequests == 0)
    #expect(await registry.tornRepairs().isEmpty)
    #expect(await registry.isSealed == false)
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
