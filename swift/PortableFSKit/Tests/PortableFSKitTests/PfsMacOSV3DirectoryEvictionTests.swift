import Foundation
import Testing
@preconcurrency import Darwin
@testable import PortableFSKit

private let directoryEvictionEpoch = Data(repeating: 0xA7, count: 16)
private let directoryEvictionParent = try! PfsMacOSStableIdentity(Data(repeating: 0xB8, count: 16))
private let directoryEvictionItem = try! PfsMacOSStableIdentity(Data(repeating: 0xC9, count: 16))

private func directoryEvictionAuthenticator() throws -> PfsMacOS26RepairAuthenticator {
    try PfsMacOS26RepairAuthenticator(
        mountSessionID: UUID(uuidString: "5C24AAE4-48F1-4452-A03F-AB5902723DF8")!,
        secret: Data(repeating: 0xDA, count: 32)
    )
}

private func evictionPlan(
    name: Data,
    itemKind: PfsMacOSCachedItemKind
) throws -> PfsMacOS26RepairPlan {
    let authenticator = try directoryEvictionAuthenticator()
    let operand = try authenticator.makeOperand(
        epoch: directoryEvictionEpoch,
        sequence: 1,
        step: 0,
        kind: .positiveEviction,
        parentIdentity: directoryEvictionParent,
        itemIdentity: directoryEvictionItem,
        sourceName: name,
        itemKind: itemKind
    )
    return PfsMacOS26RepairPlan(
        epoch: directoryEvictionEpoch,
        sequence: 1,
        step: 0,
        kind: .positiveEviction,
        path: try PfsMacOSRelativePath(components: [name]),
        parentIdentity: directoryEvictionParent,
        itemIdentity: directoryEvictionItem,
        expectedVFSFileID: nil,
        authoritativeSize: nil,
        operand: operand
    )
}

private func attributeRefreshPlan(
    name: Data,
    itemKind: PfsMacOSCachedItemKind,
    expectedVFSFileID: UInt64,
    sequence: UInt64 = 2,
    step: UInt32 = 0
) throws -> PfsMacOS26RepairPlan {
    let authenticator = try directoryEvictionAuthenticator()
    let operand = try authenticator.makeOperand(
        epoch: directoryEvictionEpoch,
        sequence: sequence,
        step: step,
        kind: .attributeRefresh,
        parentIdentity: directoryEvictionParent,
        itemIdentity: directoryEvictionItem,
        sourceName: name,
        itemKind: itemKind
    )
    return .init(
        epoch: directoryEvictionEpoch,
        sequence: sequence,
        step: step,
        kind: .attributeRefresh,
        path: try PfsMacOSRelativePath(components: [name]),
        parentIdentity: directoryEvictionParent,
        itemIdentity: directoryEvictionItem,
        expectedVFSFileID: expectedVFSFileID,
        authoritativeSize: nil,
        operand: operand
    )
}

@Test func namespacePlannerPreservesDirectoryKindAndRenameMovesItAtomically() async throws {
    let root = directoryEvictionParent
    let directory = directoryEvictionItem
    let index = PfsMacOSNamespaceIndex(rootIdentity: root)
    await index.record(
        identity: directory,
        entry: .init(
            parentIdentity: root,
            name: Data("tree".utf8),
            vfsFileID: 42,
            itemKind: .directory
        )
    )

    let repairs = try await PfsMacOSRepairPlanner(index: index).repairs(for: [
        .namespace(parentIdentity: root, name: Data("tree".utf8)),
    ])
    guard case let .evictBinding(path, parent, identity, itemKind) = repairs.first else {
        Issue.record("expected a typed positive eviction")
        return
    }
    #expect(path.components == [Data("tree".utf8)])
    #expect(parent == root)
    #expect(identity == directory)
    #expect(itemKind == .directory)

    try await index.move(
        parentIdentity: root,
        name: Data("tree".utf8),
        toParentIdentity: root,
        toName: Data("moved".utf8),
        expectedIdentity: directory
    )
    #expect(await index.binding(parentIdentity: root, name: Data("tree".utf8)) == nil)
    let moved = try #require(await index.binding(
        parentIdentity: root,
        name: Data("moved".utf8)
    ))
    #expect(moved.identity == directory)
    #expect(moved.entry.vfsFileID == 42)
    #expect(moved.entry.itemKind == .directory)
}

@Test func consecutiveAttributeTargetsReuseARepairLocatorWithoutPublishedPolarity() async throws {
    let index = PfsMacOSNamespaceIndex(rootIdentity: directoryEvictionParent)
    let planner = PfsMacOSRepairPlanner(index: index)
    let name = Data("tree".utf8)
    await index.record(
        identity: directoryEvictionItem,
        entry: .init(
            parentIdentity: directoryEvictionParent,
            name: name,
            vfsFileID: 42,
            itemKind: .directory
        )
    )

    let first = try await planner.repairs(for: [
        .attributes(identity: directoryEvictionItem),
    ])
    guard case .refreshAttributes = first.first else {
        Issue.record("first attribute repair must refresh the published vnode")
        return
    }

    try await index.retainDataRepairLocator(
        parentIdentity: directoryEvictionParent,
        name: name,
        expectedIdentity: directoryEvictionItem
    )
    #expect(await index.binding(parentIdentity: directoryEvictionParent, name: name) == nil)
    let locator = try #require(await index.repairLocator(
        parentIdentity: directoryEvictionParent,
        name: name
    ))
    #expect(locator.identity == directoryEvictionItem)
    #expect(locator.entry.vfsFileID == 42)
    #expect(locator.entry.itemKind == .directory)

    // Ordinary namespace polarity ignores the locator: only the exact identity
    // fallback may reuse it.
    let namespace = try await planner.repairs(for: [
        .namespace(parentIdentity: directoryEvictionParent, name: name),
    ])
    guard case .purgeNegative = namespace.first else {
        Issue.record("a repair locator must not masquerade as a published binding")
        return
    }

    let second = try await planner.repairs(for: [
        .attributes(identity: directoryEvictionItem),
    ])
    guard case let .refreshAttributes(path, parent, identity, fileID, kind) = second.first else {
        Issue.record("rapid successor must reuse the exact repair locator")
        return
    }
    #expect(path.components == [name])
    #expect(parent == directoryEvictionParent)
    #expect(identity == directoryEvictionItem)
    #expect(fileID == 42)
    #expect(kind == .directory)
}

@Test func namespaceTargetInvalidatesADataLocatorBeforeRenameThenHardLinkAttributes() async throws {
    let root = directoryEvictionParent
    let sourceParent = try PfsMacOSStableIdentity(Data(repeating: 0x31, count: 16))
    let destinationParent = try PfsMacOSStableIdentity(Data(repeating: 0x32, count: 16))
    let item = directoryEvictionItem
    let oldName = Data("rename-me".utf8)
    let aliasName = Data("hard-link".utf8)
    let index = PfsMacOSNamespaceIndex(rootIdentity: root)
    await index.record(
        identity: sourceParent,
        entry: .init(
            parentIdentity: root,
            name: Data("A".utf8),
            vfsFileID: 31,
            itemKind: .directory
        )
    )
    await index.record(
        identity: destinationParent,
        entry: .init(
            parentIdentity: root,
            name: Data("B".utf8),
            vfsFileID: 32,
            itemKind: .directory
        )
    )
    await index.record(
        identity: item,
        entry: .init(
            parentIdentity: sourceParent,
            name: oldName,
            vfsFileID: 42,
            itemKind: .file
        )
    )
    try await index.retainDataRepairLocator(
        parentIdentity: sourceParent,
        name: oldName,
        expectedIdentity: item
    )
    let planner = PfsMacOSRepairPlanner(index: index)

    // PREPARE announces only intent; a refused/no-op mutation must not discard
    // a still-authoritative data locator before the outcome is known.
    _ = try await planner.repairs(for: [
        .namespace(parentIdentity: sourceParent, name: oldName),
    ])
    #expect(await index.repairLocator(parentIdentity: sourceParent, name: oldName) != nil)

    // COMPLETE for the peer rename invalidates the data-only attestation even
    // though this mount has no current positive binding.
    let renameRepairs = try await planner.repairs(
        for: [.namespace(parentIdentity: sourceParent, name: oldName)],
        authorityNamespaceTruthChanged: true
    )
    #expect(renameRepairs.contains { repair in
        if case .purgeNegative = repair { return true }
        return false
    })
    #expect(await index.repairLocator(parentIdentity: sourceParent, name: oldName) == nil)

    // A following peer hard-link may carry an ATTRIBUTES(item) dependency. It
    // must never resurrect A/rename-me as the refresh source; without a fresh
    // published alias the only safe pathname action is the new-coordinate
    // negative purge (a retained live vnode would use object repair or fail).
    let hardLinkRepairs = try await planner.repairs(for: [
        .namespace(parentIdentity: destinationParent, name: aliasName),
        .attributes(identity: item),
    ])
    #expect(!hardLinkRepairs.contains { repair in
        if case let .refreshAttributes(path, _, identity, _, _) = repair {
            return identity == item && path.components == [Data("A".utf8), oldName]
        }
        return false
    })
}

@Test func publicationAtomicallyReplacesARepairLocatorAtTheSameCoordinate() async throws {
    let index = PfsMacOSNamespaceIndex(rootIdentity: directoryEvictionParent)
    let name = Data("tree".utf8)
    await index.record(
        identity: directoryEvictionItem,
        entry: .init(
            parentIdentity: directoryEvictionParent,
            name: name,
            vfsFileID: 42,
            itemKind: .directory
        )
    )
    try await index.retainDataRepairLocator(
        parentIdentity: directoryEvictionParent,
        name: name,
        expectedIdentity: directoryEvictionItem
    )
    let replacement = try PfsMacOSStableIdentity(Data(repeating: 0xE1, count: 16))
    #expect(await index.record(
        identity: replacement,
        entry: .init(
            parentIdentity: directoryEvictionParent,
            name: name,
            vfsFileID: 84,
            itemKind: .file
        ),
        capacity: 1
    ))
    #expect(await index.repairLocator(parentIdentity: directoryEvictionParent, name: name) == nil)
    let binding = try #require(await index.binding(
        parentIdentity: directoryEvictionParent,
        name: name
    ))
    #expect(binding.identity == replacement)
    #expect(binding.entry.vfsFileID == 84)
    #expect(await index.count() == 1)
}

@Test func dataTargetUsesExactRepairLocatorWithoutWeakeningDataPlan() async throws {
    let index = PfsMacOSNamespaceIndex(rootIdentity: directoryEvictionParent)
    let name = Data("data.bin".utf8)
    await index.record(
        identity: directoryEvictionItem,
        entry: .init(
            parentIdentity: directoryEvictionParent,
            name: name,
            vfsFileID: 42,
            itemKind: .file
        )
    )
    try await index.retainDataRepairLocator(
        parentIdentity: directoryEvictionParent,
        name: name,
        expectedIdentity: directoryEvictionItem
    )

    let repairs = try await PfsMacOSRepairPlanner(index: index).repairs(for: [
        .data(identity: directoryEvictionItem, size: 9),
    ])
    guard case let .invalidateData(path, parent, identity, fileID, size) = repairs.first else {
        Issue.record("exact data target must retain strict pathname invalidation")
        return
    }
    #expect(path.components == [name])
    #expect(parent == directoryEvictionParent)
    #expect(identity == directoryEvictionItem)
    #expect(fileID == 42)
    #expect(size == 9)
}

@Test func liveObjectCapacityIsAtomicAndExactRerecordIsIdempotent() async throws {
    let liveObjects = PfsMacOSLiveObjectIndex()
    let first = PortableFSItem(identity: .init(
        itemID: 42,
        generation: 1,
        stableIdentity: directoryEvictionItem.bytes
    ))
    let secondIdentity = try PfsMacOSStableIdentity(Data(repeating: 0xE2, count: 16))
    let second = PortableFSItem(identity: .init(
        itemID: 43,
        generation: 1,
        stableIdentity: secondIdentity.bytes
    ))
    #expect(try await liveObjects.record(item: first, vfsFileID: 42, capacity: 1))
    #expect(try await liveObjects.record(item: first, vfsFileID: 42, capacity: 1))
    #expect(try await liveObjects.record(item: second, vfsFileID: 43, capacity: 1) == false)
    #expect(await liveObjects.count() == 1)
}

@Test func concurrentLiveObjectRecordsCannotOverrunCapacity() async throws {
    let liveObjects = PfsMacOSLiveObjectIndex()
    let first = PortableFSItem(identity: .init(
        itemID: 45,
        generation: 1,
        stableIdentity: Data(repeating: 0xE4, count: 16)
    ))
    let second = PortableFSItem(identity: .init(
        itemID: 46,
        generation: 1,
        stableIdentity: Data(repeating: 0xE5, count: 16)
    ))
    async let firstRecorded = liveObjects.record(item: first, vfsFileID: 45, capacity: 1)
    async let secondRecorded = liveObjects.record(item: second, vfsFileID: 46, capacity: 1)
    let admitted = try await [firstRecorded, secondRecorded].filter { $0 }
    #expect(admitted.count == 1)
    #expect(await liveObjects.count() == 1)
}

@Test func namespaceDirectRecordCapacityCountsLocatorAsTheSameCoordinateSlot() async throws {
    let index = PfsMacOSNamespaceIndex(rootIdentity: directoryEvictionParent)
    let name = Data("one".utf8)
    #expect(await index.record(
        identity: directoryEvictionItem,
        entry: .init(
            parentIdentity: directoryEvictionParent,
            name: name,
            vfsFileID: 42
        ),
        capacity: 1
    ))
    try await index.retainDataRepairLocator(
        parentIdentity: directoryEvictionParent,
        name: name,
        expectedIdentity: directoryEvictionItem
    )
    #expect(await index.record(
        identity: directoryEvictionItem,
        entry: .init(
            parentIdentity: directoryEvictionParent,
            name: name,
            vfsFileID: 43
        ),
        capacity: 1
    ))
    let other = try PfsMacOSStableIdentity(Data(repeating: 0xE3, count: 16))
    #expect(await index.record(
        identity: other,
        entry: .init(
            parentIdentity: directoryEvictionParent,
            name: Data("two".utf8),
            vfsFileID: 44
        ),
        capacity: 1
    ) == false)
    #expect(await index.count() == 1)
}

@Test func alreadyAbsentPositiveEvictionRetiresTheIndexedCoordinateWithoutARemoveCallback() async throws {
    let authenticator = try directoryEvictionAuthenticator()
    let index = PfsMacOSNamespaceIndex(rootIdentity: directoryEvictionParent)
    let name = Data("tree".utf8)
    await index.record(
        identity: directoryEvictionItem,
        entry: .init(
            parentIdentity: directoryEvictionParent,
            name: name,
            vfsFileID: 42,
            itemKind: .directory
        )
    )
    let registry = PfsMacOS26RepairArmRegistry(
        authenticator: authenticator,
        namespaceIndex: index
    )
    let plan = try evictionPlan(name: name, itemKind: .directory)
    let lease = try await registry.arm(plan)

    // The POSIX/daemon actuator accepts ENOENT because the kernel has already
    // proved the cached name absent, so FSKit emits no remove callback. Lease
    // validation must still retire the old authority attestation before ACK.
    try await lease.finish()
    #expect(await registry.armedOperandCount() == 0)
    #expect(await index.binding(parentIdentity: directoryEvictionParent, name: name) == nil)
    #expect(await index.repairLocator(parentIdentity: directoryEvictionParent, name: name) == nil)
}

@Test func failedLocatorTransferLeavesThePublishedBindingUntouched() async throws {
    let index = PfsMacOSNamespaceIndex(rootIdentity: directoryEvictionParent)
    let name = Data("tree".utf8)
    await index.record(
        identity: directoryEvictionItem,
        entry: .init(
            parentIdentity: directoryEvictionParent,
            name: name,
            vfsFileID: 42,
            itemKind: .directory
        )
    )
    let wrong = try PfsMacOSStableIdentity(Data(repeating: 0xE6, count: 16))
    await #expect(throws: PfsMacOSCoherenceError.cachedTargetUnrepresentable) {
        try await index.retainDataRepairLocator(
            parentIdentity: directoryEvictionParent,
            name: name,
            expectedIdentity: wrong
        )
    }
    #expect(await index.binding(parentIdentity: directoryEvictionParent, name: name)?.identity == directoryEvictionItem)
    #expect(await index.repairLocator(parentIdentity: directoryEvictionParent, name: name) == nil)
}

@Test func ordinaryForgetClearsARepairLocatorAtTheExactCoordinate() async throws {
    let index = PfsMacOSNamespaceIndex(rootIdentity: directoryEvictionParent)
    let name = Data("tree".utf8)
    await index.record(
        identity: directoryEvictionItem,
        entry: .init(
            parentIdentity: directoryEvictionParent,
            name: name,
            vfsFileID: 42
        )
    )
    try await index.retainDataRepairLocator(
        parentIdentity: directoryEvictionParent,
        name: name,
        expectedIdentity: directoryEvictionItem
    )
    await index.forget(parentIdentity: directoryEvictionParent, name: name)
    #expect(await index.repairLocator(parentIdentity: directoryEvictionParent, name: name) == nil)
    #expect(await index.count() == 0)
}

@Test func attributeRefreshWindowCoalescesRacingModeCallbacksAndRequiresOneForFinish() async throws {
    let authenticator = try directoryEvictionAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let plan = try attributeRefreshPlan(
        name: Data("tree".utf8),
        itemKind: .directory,
        expectedVFSFileID: 42
    )
    let lease = try await registry.arm(plan)
    #expect(await registry.consumeArmedAttributeRefresh(
        itemIdentity: Data(repeating: 0xEE, count: 16)
    ) == nil)
    let consumed = try #require(await registry.consumeArmedAttributeRefresh(
        itemIdentity: directoryEvictionItem.bytes
    ))
    #expect(consumed.expectedVFSFileID == 42)
    #expect(await registry.isArmedAttributeRefreshItem(
        itemIdentity: directoryEvictionItem.bytes
    ))
    #expect(await registry.isArmedRepairSourceOpenItem(
        itemIdentity: directoryEvictionItem.bytes
    ))
    let raced = try #require(await registry.consumeArmedAttributeRefresh(
        itemIdentity: directoryEvictionItem.bytes
    ))
    #expect(raced.expectedVFSFileID == 42)
    try await lease.finish()
}

@Test func prearmedHardLinkAttributeAliasesConsumeOnlyTheActivePlan() async throws {
    let authenticator = try directoryEvictionAuthenticator()
    let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
    let first = try attributeRefreshPlan(
        name: Data("first-link".utf8),
        itemKind: .file,
        expectedVFSFileID: 41,
        sequence: 3,
        step: 0
    )
    let second = try attributeRefreshPlan(
        name: Data("second-link".utf8),
        itemKind: .file,
        expectedVFSFileID: 42,
        sequence: 3,
        step: 1
    )
    let firstLease = try await registry.arm(first)
    let secondLease = try await registry.arm(second)

    // Both aliases share the stable identity and are pre-armed before mounted-
    // VFS surgery. Explicit actuation makes callback attribution independent
    // of Dictionary iteration order.
    try await firstLease.activate()
    let firstConsumption = try #require(await registry.consumeArmedAttributeRefresh(
        itemIdentity: directoryEvictionItem.bytes
    ))
    #expect(firstConsumption.expectedVFSFileID == 41)
    try await firstLease.validate()

    try await secondLease.activate()
    let secondConsumption = try #require(await registry.consumeArmedAttributeRefresh(
        itemIdentity: directoryEvictionItem.bytes
    ))
    #expect(secondConsumption.expectedVFSFileID == 42)
    try await secondLease.validate()

    try await firstLease.release()
    try await secondLease.release()
    #expect(await registry.armedOperandCount() == 0)
}

@Test func attributeRefreshDaemonWireCarriesKindAndFileID() throws {
    let plan = try attributeRefreshPlan(
        name: Data("tree".utf8),
        itemKind: .directory,
        expectedVFSFileID: 42
    )
    let encoded = try PfsMacOS26DaemonActuator.encode(plan)
    let object = try #require(
        JSONSerialization.jsonObject(with: encoded) as? [String: Any]
    )
    #expect(object["kind"] as? String == "refresh")
    #expect(object["itemKind"] as? String == "directory")
    #expect(object["expectedFileId"] as? UInt64 == 42)
}

@Test func posixAttributeRefreshAttestsAndPreservesModeWithoutFollowingSymlink() async throws {
    let root = FileManager.default.temporaryDirectory
        .appending(path: "portablefs-attribute-refresh-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }
    let directory = root.appending(path: "tree")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    try FileManager.default.setAttributes([.posixPermissions: 0o751], ofItemAtPath: directory.path)
    let rootFD = open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    #expect(rootFD >= 0)
    defer { close(rootFD) }
    var status = stat()
    #expect(lstat(directory.path, &status) == 0)
    let actuator = try PfsMacOS26POSIXActuator(rootFileDescriptor: rootFD)
    let plan = try attributeRefreshPlan(
        name: Data("tree".utf8),
        itemKind: .directory,
        expectedVFSFileID: status.st_ino
    )
    try await actuator.apply(plan)
    let mode = (try FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as? NSNumber)?.uint16Value
    #expect(mode == 0o751)

    let link = root.appending(path: "link")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: directory)
    var linkStatus = stat()
    #expect(lstat(link.path, &linkStatus) == 0)
    let linkPlan = try attributeRefreshPlan(
        name: Data("link".utf8),
        itemKind: .symlink,
        expectedVFSFileID: linkStatus.st_ino
    )
    await #expect(throws: PfsMacOSCoherenceError.invalidRepairOperand) {
        try await actuator.apply(linkPlan)
    }
}

@Test func itemKindIsAuthenticatedInsideTheRepairOperandAndDaemonWire() throws {
    let name = Data("directory".utf8)
    let plan = try evictionPlan(name: name, itemKind: .directory)
    #expect(plan.itemKind == .directory)

    let authenticator = try directoryEvictionAuthenticator()
    let operand = try #require(plan.operand)
    #expect(authenticator.validate(
        operand: operand,
        epoch: plan.epoch,
        sequence: plan.sequence,
        step: plan.step,
        kind: plan.kind,
        parentIdentity: plan.parentIdentity,
        itemIdentity: plan.itemIdentity,
        sourceName: name
    ))

    // The third signed body byte is the item kind. Flip only its low hex digit;
    // the unchanged tag must make validation fail.
    var tampered = operand
    let kindNibble = PfsMacOS26RepairAuthenticator.reservedPrefix.count + 5
    tampered[kindNibble] = Character("1").asciiValue!
    #expect(!authenticator.validate(
        operand: tampered,
        epoch: plan.epoch,
        sequence: plan.sequence,
        step: plan.step,
        kind: plan.kind,
        parentIdentity: plan.parentIdentity,
        itemIdentity: plan.itemIdentity,
        sourceName: name
    ))

    let encoded = try PfsMacOS26DaemonActuator.encode(plan)
    let object = try #require(
        JSONSerialization.jsonObject(with: encoded) as? [String: Any]
    )
    #expect(object["kind"] as? String == "evict")
    #expect(object["itemKind"] as? String == "directory")
}

@Test func posixActuatorUsesRmdirForDirectoriesAndRefusesAMismatch() async throws {
    let root = FileManager.default.temporaryDirectory
        .appending(path: "portablefs-directory-eviction-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }
    let rootFD = open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    #expect(rootFD >= 0)
    defer { close(rootFD) }
    let actuator = try PfsMacOS26POSIXActuator(rootFileDescriptor: rootFD)

    let directory = root.appending(path: "directory")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    let bystander = root.appending(path: "bystander")
    #expect(FileManager.default.createFile(atPath: bystander.path, contents: Data("safe".utf8)))
    try await actuator.apply(try evictionPlan(
        name: Data("directory".utf8),
        itemKind: .directory
    ))
    #expect(!FileManager.default.fileExists(atPath: directory.path))
    #expect(FileManager.default.fileExists(atPath: bystander.path))

    let file = root.appending(path: "file")
    #expect(FileManager.default.createFile(atPath: file.path, contents: Data("data".utf8)))
    await #expect(throws: (any Error).self) {
        try await actuator.apply(try evictionPlan(
            name: Data("file".utf8),
            itemKind: .directory
        ))
    }
    #expect(FileManager.default.fileExists(atPath: file.path))
}

@Test func unknownPortableItemKindsFailClosed() throws {
    #expect(throws: PfsMacOSCoherenceError.invalidRepairOperand) {
        _ = try PfsMacOSCachedItemKind(.unspecified)
    }
    #expect(throws: PfsMacOSCoherenceError.invalidRepairOperand) {
        _ = try PfsMacOSCachedItemKind(.UNRECOGNIZED(99))
    }
}
