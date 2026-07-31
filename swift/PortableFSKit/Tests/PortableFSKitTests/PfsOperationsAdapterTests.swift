import Foundation
import FSKit
import ObjectiveC.runtime
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

private func adapterBytes(_ string: String) -> Data {
    Data(string.utf8)
}

@available(macOS 26.0, *)
private struct RecordedDirectoryEntry: Sendable, Equatable {
    var name: String
    var itemType: Int
    var itemID: UInt64
    var nextCookie: UInt64
    var hasAttributes: Bool
}

@available(macOS 26.0, *)
private final class RecordingPackerState: @unchecked Sendable {
    private let lock = NSLock()
    private let capacity: Int
    private var storage: [RecordedDirectoryEntry] = []
    private var refused = false

    init(capacity: Int) {
        self.capacity = capacity
    }

    var entries: [RecordedDirectoryEntry] {
        lock.lock()
        let snapshot = storage
        lock.unlock()
        return snapshot
    }

    var didRefuse: Bool {
        lock.lock()
        let value = refused
        lock.unlock()
        return value
    }

    func pack(
        name: FSFileName,
        itemType: FSItem.ItemType,
        itemID: FSItem.Identifier,
        nextCookie: FSDirectoryCookie,
        attributes: FSItem.Attributes?
    ) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard storage.count < capacity else {
            refused = true
            return false
        }
        storage.append(
            RecordedDirectoryEntry(
                name: name.string ?? String(data: name.data, encoding: .utf8) ?? name.debugDescription,
                itemType: itemType.rawValue,
                itemID: itemID.rawValue,
                nextCookie: nextCookie.rawValue,
                hasAttributes: attributes != nil
            )
        )
        return true
    }
}

@available(macOS 26.0, *)
private final class RecordingPackerRegistry: @unchecked Sendable {
    static let shared = RecordingPackerRegistry()
    private let lock = NSLock()
    private var states: [ObjectIdentifier: RecordingPackerState] = [:]

    func install(_ packer: FSDirectoryEntryPacker, state: RecordingPackerState) {
        lock.lock()
        states[ObjectIdentifier(packer)] = state
        lock.unlock()
    }

    func uninstall(_ packer: FSDirectoryEntryPacker) {
        lock.lock()
        states.removeValue(forKey: ObjectIdentifier(packer))
        lock.unlock()
    }

    func pack(
        _ packer: FSDirectoryEntryPacker,
        name: FSFileName,
        itemType: FSItem.ItemType,
        itemID: FSItem.Identifier,
        nextCookie: FSDirectoryCookie,
        attributes: FSItem.Attributes?
    ) -> Bool {
        lock.lock()
        let state = states[ObjectIdentifier(packer)]
        lock.unlock()
        return state?.pack(name: name, itemType: itemType, itemID: itemID, nextCookie: nextCookie, attributes: attributes) ?? false
    }
}

@available(macOS 26.0, *)
private final class RecordingDirectoryEntryPacker: FSDirectoryEntryPacker {
    override func packEntry(
        name: FSFileName,
        itemType: FSItem.ItemType,
        itemID: FSItem.Identifier,
        nextCookie: FSDirectoryCookie,
        attributes: FSItem.Attributes?
    ) -> Bool {
        RecordingPackerRegistry.shared.pack(
            self,
            name: name,
            itemType: itemType,
            itemID: itemID,
            nextCookie: nextCookie,
            attributes: attributes
        )
    }
}

@available(macOS 26.0, *)
private final class EmptyDataStringFileName: FSFileName {
    private let value: String

    init(_ value: String) {
        self.value = value
        super.init(data: Data())
    }

    required init?(coder: NSCoder) {
        nil
    }

    override var data: Data {
        Data()
    }

    override var string: String? {
        value
    }
}

@available(macOS 26.0, *)
private struct AdapterHarness: @unchecked Sendable {
    var daemon: PfsLocalMockDaemon
    var core: VolumeCore
    var volume: PortableFSVolume
    var root: FSItem
}

// Compile-only fixture: these are the three public call shapes shipped before
// module identity became injectable. Keeping them type-checked prevents a
// future identity refactor from breaking existing OSS embedders.
@available(macOS 26.0, *)
private func legacyAdapterAPISourceCompatibility(
    core: VolumeCore,
    statReply: PfsStatfsReply,
    capabilities: PfsCapabilities
) async throws {
    _ = PortableFSFileSystem(
        resolverFactory: { PfsSocketPathResolver(bundle: .main) }
    )
    _ = try await PortableFSVolume.make(core: core, attachRef: "compat")
    _ = PfsFSKitMapping.statfs(
        from: statReply,
        capabilities: capabilities
    )
}

@available(macOS 26.0, *)
private func makeAdapterHarness() async throws -> AdapterHarness {
    let daemon = try PfsLocalMockDaemon()
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let volume = try await PortableFSVolume.make(
        core: core,
        attachRef: "mock"
    )
    let root = try await core.rootItem()
    return AdapterHarness(daemon: daemon, core: core, volume: volume, root: root)
}

@available(macOS 26.0, *)
@Test func operationsAdapterRoutesOnlyItsInjectedResourceScheme() async throws {
    let identity = try PortableFSModuleIdentity(
        fileSystemTypeName: PortableFSIdentity.fileSystemTypeName,
        resourceScheme: PortableFSIdentity.resourceScheme
    )
    let fileSystem = PortableFSFileSystem(moduleIdentity: identity)

    func probe(_ rawURL: String) async -> FSMatchResult {
        await withCheckedContinuation { continuation in
            fileSystem.probeResource(
                resource: FSGenericURLResource(url: URL(string: rawURL)!)
            ) { result, error in
                #expect(error == nil)
                continuation.resume(returning: result?.result ?? .notRecognized)
            }
        }
    }

    #expect(await probe("dev.portablefs.oss://att_AAAAAAAAAAAAAAAAAAAAAA") == .usable)
    #expect(await probe("pfs://att_AAAAAAAAAAAAAAAAAAAAAA") == .notRecognized)
}

@available(macOS 26.0, *)
@Test func operationsAdapterNamespacesStableFSKitEntityIdentifiersByModule() throws {
    let ossIdentity = try PortableFSModuleIdentity(
        fileSystemTypeName: "pfs",
        resourceScheme: "dev.portablefs.oss"
    )
    let openSteerIdentity = try PortableFSModuleIdentity(
        fileSystemTypeName: "portablefs",
        resourceScheme: "pfs"
    )

    let ossVolume = PortableFSFileSystem.stableEntityUUID(
        kind: "volume",
        stableID: "prod-smoke",
        moduleIdentity: ossIdentity
    )
    #expect(
        ossVolume == PortableFSFileSystem.stableEntityUUID(
            kind: "volume",
            stableID: "prod-smoke",
            moduleIdentity: ossIdentity
        )
    )
    #expect(
        ossVolume != PortableFSFileSystem.stableEntityUUID(
            kind: "volume",
            stableID: "prod-smoke",
            moduleIdentity: openSteerIdentity
        )
    )
    #expect(
        ossVolume != PortableFSFileSystem.stableEntityUUID(
            kind: "container",
            stableID: "prod-smoke",
            moduleIdentity: ossIdentity
        )
    )

    let bytes = withUnsafeBytes(of: ossVolume.uuid) { Array($0) }
    #expect(bytes[6] >> 4 == 8)
    #expect(bytes[8] >> 6 == 2)
}

@available(macOS 26.0, *)
private func makeRecordingPacker(capacity: Int) -> (RecordingDirectoryEntryPacker, RecordingPackerState) {
    let packer = class_createInstance(RecordingDirectoryEntryPacker.self, 0) as! RecordingDirectoryEntryPacker
    let state = RecordingPackerState(capacity: capacity)
    RecordingPackerRegistry.shared.install(packer, state: state)
    return (packer, state)
}

@available(macOS 26.0, *)
private func waitForPublicationAcks(
    _ daemon: PfsLocalMockDaemon,
    atLeast expected: Int
) async throws -> PfsLocalMockDaemon.Stats {
    let deadline = ContinuousClock.now + .seconds(1)
    while ContinuousClock.now < deadline {
        let stats = await daemon.stats()
        if stats.publicationAcks >= expected {
            return stats
        }
        try await Task.sleep(for: .milliseconds(5))
    }
    return await daemon.stats()
}

@available(macOS 26.0, *)
private final class PublicationReplyGate: @unchecked Sendable {
    private let lock = NSLock()
    private var entered = false
    private var released = false
    private var returned = false
    private var capturedError: Error?

    func block(error: Error?) {
        lock.lock()
        capturedError = error
        entered = true
        lock.unlock()
        while true {
            lock.lock()
            let canReturn = released
            lock.unlock()
            if canReturn {
                break
            }
            Thread.sleep(forTimeInterval: 0.001)
        }
        lock.lock()
        returned = true
        lock.unlock()
    }

    func release() {
        lock.lock()
        released = true
        lock.unlock()
    }

    func snapshot() -> (entered: Bool, returned: Bool, error: Error?) {
        lock.lock()
        let result = (entered, returned, capturedError)
        lock.unlock()
        return result
    }
}

@available(macOS 26.0, *)
private func waitForReplyGate(
    _ gate: PublicationReplyGate,
    returned: Bool = false
) async throws -> (entered: Bool, returned: Bool, error: Error?) {
    let deadline = ContinuousClock.now + .seconds(1)
    while ContinuousClock.now < deadline {
        let state = gate.snapshot()
        if state.entered, !returned || state.returned {
            return state
        }
        try await Task.sleep(for: .milliseconds(5))
    }
    return gate.snapshot()
}

@available(macOS 26.0, *)
private struct DirectoryCollection: Sendable {
    var entries: [RecordedDirectoryEntry]
    var refusedPages: Int
    var calls: Int
}

@available(macOS 26.0, *)
private func collectDirectoryEntries(
    volume: PortableFSVolume,
    directory: FSItem,
    attributesRequested: Bool,
    packerCapacity: Int
) async throws -> [RecordedDirectoryEntry] {
    try await collectDirectoryEntriesWithStats(
        volume: volume,
        directory: directory,
        attributesRequested: attributesRequested,
        packerCapacity: packerCapacity
    ).entries
}

@available(macOS 26.0, *)
private func collectDirectoryEntriesWithStats(
    volume: PortableFSVolume,
    directory: FSItem,
    attributesRequested: Bool,
    packerCapacity: Int
) async throws -> DirectoryCollection {
    var cookie = FSDirectoryCookie.initial
    var verifier = FSDirectoryVerifier.initial
    var all: [RecordedDirectoryEntry] = []
    var refusedPages = 0
    var calls = 0

    for _ in 0..<10_000 {
        let (packer, state) = makeRecordingPacker(capacity: packerCapacity)
        defer {
            RecordingPackerRegistry.shared.uninstall(packer)
        }
        let request = attributesRequested ? FSItem.GetAttributesRequest() : nil
        verifier = try await volume.enumerateDirectory(
            directory,
            startingAt: cookie,
            verifier: verifier,
            attributes: request,
            packer: packer
        )
        calls += 1
        let entries = state.entries
        all.append(contentsOf: entries)
        guard state.didRefuse else {
            break
        }
        refusedPages += 1
        guard let nextCookie = entries.last?.nextCookie else {
            throw PfsLocalClientError.daemon(errno: EINVAL, message: "packer refused before accepting an entry")
        }
        if PfsEnumerationCookies.isTerminal(nextCookie) {
            break
        }
        #expect(nextCookie != cookie.rawValue || !entries.isEmpty)
        cookie = FSDirectoryCookie(nextCookie)
    }
    return DirectoryCollection(entries: all, refusedPages: refusedPages, calls: calls)
}

@available(macOS 26.0, *)
private func createAdapterFile(
    volume: PortableFSVolume,
    in directory: FSItem,
    name: String,
    contents: Data? = nil
) async throws -> FSItem {
    let (item, _) = try await volume.createItem(
        named: FSFileName(string: name),
        type: .file,
        inDirectory: directory,
        attributes: FSItem.SetAttributesRequest()
    )
    if let contents {
        let written = try await volume.write(contents: contents, to: item, at: 0)
        #expect(written == contents.count)
    }
    try await volume.closeItem(item, modes: [])
    return item
}

@available(macOS 26.0, *)
private func readViaCore(_ core: VolumeCore, item: FSItem, length: Int) async throws -> Data {
    guard let portable = item as? PortableFSItem else {
        throw PfsLocalClientError.daemon(errno: ESTALE, message: "test item is not PortableFSItem")
    }
    return try await core.read(item: portable, offset: 0, length: UInt32(length))
}

@available(macOS 26.0, *)
@Test func operationsAdapterAcknowledgesSuccessfulAndNegativePublications() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }
    try await Task.sleep(for: .milliseconds(20))
    let initialStats = await harness.daemon.stats()
    let baseline = initialStats.publicationAcks
    let baselineGetattrs = initialStats.getAttrRequests

    let attributesGate = PublicationReplyGate()
    harness.volume.getAttributes(FSItem.GetAttributesRequest(), of: harness.root) { _, error in
        attributesGate.block(error: error)
    }
    var gateState = try await waitForReplyGate(attributesGate)
    #expect(gateState.entered)
    #expect(gateState.error == nil)
    #expect(await harness.daemon.stats().publicationAcks == baseline)
    attributesGate.release()
    gateState = try await waitForReplyGate(attributesGate, returned: true)
    #expect(gateState.returned)
    var stats = try await waitForPublicationAcks(harness.daemon, atLeast: baseline + 1)
    #expect(stats.publicationAcks >= baseline + 1)
    #expect(stats.getAttrRequests == baselineGetattrs + 1)

    let lookupGate = PublicationReplyGate()
    harness.volume.lookupItem(
        named: FSFileName(string: "missing"),
        inDirectory: harness.root
    ) { _, _, error in
        lookupGate.block(error: error)
    }
    gateState = try await waitForReplyGate(lookupGate)
    #expect(gateState.entered)
    #expect(PfsErrorMapper.fsKitError(for: gateState.error!).code == Int(ENOENT))
    #expect(await harness.daemon.stats().publicationAcks == baseline + 1)
    lookupGate.release()
    gateState = try await waitForReplyGate(lookupGate, returned: true)
    #expect(gateState.returned)
    stats = try await waitForPublicationAcks(harness.daemon, atLeast: baseline + 2)
    #expect(stats.publicationAcks >= baseline + 2)
}

@available(macOS 26.0, *)
@Test func operationsAdapterDrainsPublicationAcksUnderConcurrentLoad() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }
    try await Task.sleep(for: .milliseconds(20))

    let baseline = await harness.daemon.stats().publicationAcks
    let workerCount = 1_200
    let operationsPerWorker = 2

    try await withThrowingTaskGroup(of: Void.self) { group in
        for _ in 0..<workerCount {
            group.addTask {
                for _ in 0..<operationsPerWorker {
                    try await withCheckedThrowingContinuation {
                        (continuation: CheckedContinuation<Void, Error>) in
                        harness.volume.getAttributes(
                            FSItem.GetAttributesRequest(),
                            of: harness.root
                        ) { _, error in
                            if let error {
                                continuation.resume(throwing: error)
                            } else {
                                continuation.resume()
                            }
                        }
                    }
                }
            }
        }
        try await group.waitForAll()
    }

    let expected = baseline + workerCount * operationsPerWorker
    let stats = try await waitForPublicationAcks(harness.daemon, atLeast: expected)
    #expect(stats.publicationAcks == expected)
}

@available(macOS 26.0, *)
@Test func operationsAdapterSymlinkCreateReadlinkPreservesTarget() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }

    _ = try await createAdapterFile(volume: harness.volume, in: harness.root, name: "a.txt", contents: adapterBytes("hi"))
    let (link, _) = try await harness.volume.createSymbolicLink(
        named: FSFileName(string: "link.txt"),
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest(),
        linkContents: EmptyDataStringFileName("a.txt")
    )

    let target = try await harness.volume.readSymbolicLink(link)
    #expect(target.string == "a.txt")
    #expect(target.data == adapterBytes("a.txt"))
}

@available(macOS 26.0, *)
@Test func operationsAdapterRenameThenEnumerateShowsNewNameOnly() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }

    let item = try await createAdapterFile(volume: harness.volume, in: harness.root, name: "old.txt")
    _ = try await harness.volume.renameItem(
        item,
        inDirectory: harness.root,
        named: FSFileName(string: "old.txt"),
        to: FSFileName(string: "new.txt"),
        inDirectory: harness.root,
        overItem: nil
    )

    let entries = try await collectDirectoryEntries(
        volume: harness.volume,
        directory: harness.root,
        attributesRequested: true,
        packerCapacity: 2
    )
    let names = Set(entries.map(\.name))
    #expect(names.contains("new.txt"))
    #expect(!names.contains("old.txt"))
}

@available(macOS 26.0, *)
@Test func operationsAdapterDirectoryWalkContainingSymlinkCanResolveTarget() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }

    let (dir, _) = try await harness.volume.createItem(
        named: FSFileName(string: "dir"),
        type: .directory,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    _ = try await createAdapterFile(volume: harness.volume, in: dir, name: "a.txt", contents: adapterBytes("hi"))
    let (link, _) = try await harness.volume.createSymbolicLink(
        named: FSFileName(string: "link.txt"),
        inDirectory: dir,
        attributes: FSItem.SetAttributesRequest(),
        linkContents: EmptyDataStringFileName("a.txt")
    )

    let entries = try await collectDirectoryEntries(
        volume: harness.volume,
        directory: dir,
        attributesRequested: true,
        packerCapacity: 1
    )
    #expect(Set(entries.map(\.name)) == Set(["a.txt", "link.txt"]))
    let target = try await harness.volume.readSymbolicLink(link)
    #expect(target.string == "a.txt")
    let (targetItem, _) = try await harness.volume.lookupItem(named: target, inDirectory: dir)
    let attr = try await harness.volume.attributes(FSItem.GetAttributesRequest(), of: targetItem)
    #expect(attr.type == .file)
}

@available(macOS 26.0, *)
@Test func operationsAdapterEnumerationPagerHasNoLossAcrossBoundarySizes() async throws {
    for entryCount in [1, 2, 59, 60, 61, 300] {
        for attributesRequested in [false, true] {
            let harness = try await makeAdapterHarness()
            defer { harness.daemon.stop() }
            let (dir, _) = try await harness.volume.createItem(
                named: FSFileName(string: "dir-\(entryCount)-\(attributesRequested)"),
                type: .directory,
                inDirectory: harness.root,
                attributes: FSItem.SetAttributesRequest()
            )
            for index in 1...entryCount {
                let name = String(format: "f%02d", index)
                _ = try await createAdapterFile(volume: harness.volume, in: dir, name: name)
            }

            let entries = try await collectDirectoryEntries(
                volume: harness.volume,
                directory: dir,
                attributesRequested: attributesRequested,
                packerCapacity: 7
            )
            let expectedFiles = Set((1...entryCount).map { String(format: "f%02d", $0) })
            let names = Set(entries.map(\.name))
            if attributesRequested {
                #expect(names == expectedFiles)
                #expect(entries.allSatisfy { $0.hasAttributes })
            } else {
                #expect(names == expectedFiles.union([".", ".."]))
                #expect(entries.allSatisfy { !$0.hasAttributes })
            }
        }
    }
}

@available(macOS 26.0, *)
@Test func operationsAdapterTerminalCookiePacksNothingAndDoesNotRestart() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }
    let (dir, _) = try await harness.volume.createItem(
        named: FSFileName(string: "terminal"),
        type: .directory,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    _ = try await createAdapterFile(volume: harness.volume, in: dir, name: "a.txt")
    _ = try await createAdapterFile(volume: harness.volume, in: dir, name: "b.txt")

    let (firstPacker, firstState) = makeRecordingPacker(capacity: 4)
    defer { RecordingPackerRegistry.shared.uninstall(firstPacker) }
    let verifier = try await harness.volume.enumerateDirectory(
        dir,
        startingAt: .initial,
        verifier: .initial,
        attributes: nil,
        packer: firstPacker
    )
    let firstEntries = firstState.entries
    #expect(firstEntries.map(\.name) == [".", "..", "a.txt", "b.txt"])
    let terminalCookie = try #require(firstEntries.last?.nextCookie)
    #expect(PfsEnumerationCookies.isTerminal(terminalCookie))

    await harness.daemon.resetStats()
    let (secondPacker, secondState) = makeRecordingPacker(capacity: 10)
    defer { RecordingPackerRegistry.shared.uninstall(secondPacker) }
    let resumedVerifier = try await harness.volume.enumerateDirectory(
        dir,
        startingAt: FSDirectoryCookie(terminalCookie),
        verifier: verifier,
        attributes: nil,
        packer: secondPacker
    )
    let stats = await harness.daemon.stats()
    #expect(resumedVerifier.rawValue == verifier.rawValue)
    #expect(secondState.entries.isEmpty)
    #expect(stats.enumerateRequests == 0)
}

@available(macOS 26.0, *)
@Test func operationsAdapterEnumerationContinuesAfterDirectoryMutation() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }
    let (dir, _) = try await harness.volume.createItem(
        named: FSFileName(string: "mutable"),
        type: .directory,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    for index in 1...60 {
        _ = try await createAdapterFile(volume: harness.volume, in: dir, name: String(format: "f%02d", index))
    }

    let (firstPacker, firstState) = makeRecordingPacker(capacity: 7)
    defer { RecordingPackerRegistry.shared.uninstall(firstPacker) }
    let verifier = try await harness.volume.enumerateDirectory(
        dir,
        startingAt: .initial,
        verifier: .initial,
        attributes: FSItem.GetAttributesRequest(),
        packer: firstPacker
    )
    let firstEntries = firstState.entries
    let resumeCookie = try #require(firstEntries.last?.nextCookie)
    #expect(resumeCookie != 0)

    _ = try await createAdapterFile(volume: harness.volume, in: dir, name: "f61")

    let (secondPacker, secondState) = makeRecordingPacker(capacity: 100)
    defer { RecordingPackerRegistry.shared.uninstall(secondPacker) }
    _ = try await harness.volume.enumerateDirectory(
        dir,
        startingAt: FSDirectoryCookie(resumeCookie),
        verifier: verifier,
        attributes: FSItem.GetAttributesRequest(),
        packer: secondPacker
    )
    #expect(!secondState.entries.isEmpty)
}

@available(macOS 26.0, *)
@Test func operationsAdapterConcurrentEnumerationsOnSameDirectoryAreComplete() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }
    let (dir, _) = try await harness.volume.createItem(
        named: FSFileName(string: "concurrent"),
        type: .directory,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    for index in 1...1201 {
        _ = try await createAdapterFile(volume: harness.volume, in: dir, name: String(format: "f%04d", index))
    }
    let expected = Set((1...1201).map { String(format: "f%04d", $0) })
    let volume = harness.volume
    let directory = try #require(dir as? PortableFSItem)

    let (boundaryPacker, boundaryState) = makeRecordingPacker(capacity: 920)
    defer { RecordingPackerRegistry.shared.uninstall(boundaryPacker) }
    _ = try await volume.enumerateDirectory(
        directory,
        startingAt: .initial,
        verifier: .initial,
        attributes: FSItem.GetAttributesRequest(),
        packer: boundaryPacker
    )
    #expect(boundaryState.entries.count == 920)
    #expect(boundaryState.didRefuse)
    #expect(boundaryState.entries.last?.nextCookie != PfsEnumerationCookies.terminalCookie)

    try await withThrowingTaskGroup(of: DirectoryCollection.self) { group in
        for capacity in [7, 17, 127, 511, 920] {
            group.addTask {
                try await collectDirectoryEntriesWithStats(
                    volume: volume,
                    directory: directory,
                    attributesRequested: true,
                    packerCapacity: capacity
                )
            }
        }

        for try await collection in group {
            let names = Set(collection.entries.map(\.name))
            #expect(names == expected)
            #expect(collection.entries.count == expected.count)
            #expect(collection.refusedPages > 0)
        }
    }
}

@available(macOS 26.0, *)
@Test func operationsAdapterRenameOverOpenTargetFetchesAttrsWhenSnapshotIsMissing() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }

    let v1 = adapterBytes("old-config")
    let v2 = adapterBytes("new-config")
    let target = try await createAdapterFile(volume: harness.volume, in: harness.root, name: "config", contents: v1)
    try await harness.volume.openItem(target, modes: [.read])
    let portableTarget = try #require(target as? PortableFSItem)
    await harness.core.testingClearOpenAttrSnapshot(item: portableTarget)
    let lock = try await createAdapterFile(volume: harness.volume, in: harness.root, name: "config.lock", contents: v2)

    _ = try await harness.volume.renameItem(
        lock,
        inDirectory: harness.root,
        named: FSFileName(string: "config.lock"),
        to: FSFileName(string: "config"),
        inDirectory: harness.root,
        overItem: target
    )

    let oldAttr = try await harness.volume.attributes(FSItem.GetAttributesRequest(), of: target)
    #expect(oldAttr.size == UInt64(v1.count))
    #expect(try await readViaCore(harness.core, item: target, length: v1.count) == v1)

    let (newTarget, _) = try await harness.volume.lookupItem(named: FSFileName(string: "config"), inDirectory: harness.root)
    try await harness.volume.openItem(newTarget, modes: [.read])
    #expect(try await readViaCore(harness.core, item: newTarget, length: v2.count) == v2)
    try await harness.volume.closeItem(newTarget, modes: [])
    try await harness.volume.closeItem(target, modes: [])
}

@available(macOS 26.0, *)
@Test func operationsAdapterRenameOverCachedTargetStatsRelookupPath() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }

    let (git, _) = try await harness.volume.createItem(
        named: FSFileName(string: ".git"),
        type: .directory,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let v1 = adapterBytes("[core]\n\trepositoryformatversion = 0\n")
    let v2 = adapterBytes("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n")
    let config = try await createAdapterFile(volume: harness.volume, in: git, name: "config", contents: v1)
    _ = try await harness.volume.attributes(FSItem.GetAttributesRequest(), of: config)
    let lock = try await createAdapterFile(volume: harness.volume, in: git, name: "config.lock", contents: v2)

    _ = try await harness.volume.renameItem(
        lock,
        inDirectory: git,
        named: FSFileName(string: "config.lock"),
        to: FSFileName(string: "config"),
        inDirectory: git,
        overItem: config
    )

    do {
        _ = try await harness.volume.attributes(FSItem.GetAttributesRequest(), of: config)
        Issue.record("expected cached clobbered target getattr to force relookup")
    } catch {
        #expect(PfsErrorMapper.fsKitError(for: error).code == Int(ENOENT))
    }

    let (newConfig, _) = try await harness.volume.lookupItem(named: FSFileName(string: "config"), inDirectory: git)
    _ = try await harness.volume.attributes(FSItem.GetAttributesRequest(), of: newConfig)
    try await harness.volume.openItem(newConfig, modes: [.read])
    let readBack = try await readViaCore(harness.core, item: newConfig, length: v2.count)
    try await harness.volume.closeItem(newConfig, modes: [])
    #expect(readBack == v2)
}

@available(macOS 26.0, *)
@Test func operationsAdapterRenameOverOpenTargetPreservesOldHandleBytes() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }

    let v1 = adapterBytes("v1")
    let v2 = adapterBytes("v2")
    let target = try await createAdapterFile(volume: harness.volume, in: harness.root, name: "config", contents: v1)
    try await harness.volume.openItem(target, modes: [.read, .write])
    let lock = try await createAdapterFile(volume: harness.volume, in: harness.root, name: "config.lock", contents: v2)

    _ = try await harness.volume.renameItem(
        lock,
        inDirectory: harness.root,
        named: FSFileName(string: "config.lock"),
        to: FSFileName(string: "config"),
        inDirectory: harness.root,
        overItem: target
    )

    let portableTarget = try #require(target as? PortableFSItem)
    let exactAttr = try await harness.core.setattr(
        item: portableTarget,
        attributes: PfsSetAttributes(
            mode: 0o600,
            size: 1,
            mtimeMilliseconds: 123_456,
            atimeMilliseconds: 234_567
        )
    )
    #expect(exactAttr.mode == 0o600)
    #expect(exactAttr.size == 1)
    #expect(exactAttr.mtimeMs == 123_456)
    #expect(exactAttr.atimeMs == 234_567)
    try await harness.core.xattrSet(
        item: portableTarget,
        name: "user.detached",
        value: adapterBytes("old"),
        createOnly: false,
        replaceOnly: false
    )
    #expect(
        try await harness.core.xattrGet(item: portableTarget, name: "user.detached")
            == adapterBytes("old")
    )
    #expect(try await harness.core.xattrList(item: portableTarget) == ["user.detached"])
    #expect(try await readViaCore(harness.core, item: target, length: v1.count) == adapterBytes("v"))
    let oldAttr = try await harness.volume.attributes(FSItem.GetAttributesRequest(), of: target)
    #expect(oldAttr.size == 1)

    let (newTarget, _) = try await harness.volume.lookupItem(named: FSFileName(string: "config"), inDirectory: harness.root)
    try await harness.volume.openItem(newTarget, modes: [.read])
    #expect(try await readViaCore(harness.core, item: newTarget, length: v2.count) == v2)
    let portableNewTarget = try #require(newTarget as? PortableFSItem)
    do {
        _ = try await harness.core.xattrGet(item: portableNewTarget, name: "user.detached")
        Issue.record("replacement unexpectedly inherited detached xattr")
    } catch {
        #expect(PfsErrorMapper.fsKitError(for: error).code == Int(ENOATTR))
    }
    try await harness.volume.closeItem(newTarget, modes: [])

    try await harness.core.xattrRemove(item: portableTarget, name: "user.detached")
    try await harness.volume.closeItem(target, modes: [])
    do {
        _ = try await harness.volume.attributes(FSItem.GetAttributesRequest(), of: target)
        Issue.record("expected closed clobbered target to relookup")
    } catch {
        #expect(PfsErrorMapper.fsKitError(for: error).code == Int(ENOENT))
    }
}

@available(macOS 26.0, *)
@Test func operationsAdapterRenameOverTargetRetainsSurvivingHardLinkIdentity() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }

    let oldBytes = adapterBytes("old-target")
    let newBytes = adapterBytes("new-target")
    let target = try await createAdapterFile(
        volume: harness.volume, in: harness.root, name: "config", contents: oldBytes
    )
    _ = try await harness.volume.createLink(
        to: target,
        named: FSFileName(string: "survivor"),
        inDirectory: harness.root
    )
    let lock = try await createAdapterFile(
        volume: harness.volume, in: harness.root, name: "config.lock", contents: newBytes
    )

    _ = try await harness.volume.renameItem(
        lock,
        inDirectory: harness.root,
        named: FSFileName(string: "config.lock"),
        to: FSFileName(string: "config"),
        inDirectory: harness.root,
        overItem: target
    )

    let (survivor, _) = try await harness.volume.lookupItem(
        named: FSFileName(string: "survivor"), inDirectory: harness.root
    )
    let portableTarget = try #require(target as? PortableFSItem)
    let portableSurvivor = try #require(survivor as? PortableFSItem)
    #expect(portableSurvivor === portableTarget)
    let survivorAttr = try await harness.core.getattr(item: portableSurvivor)
    #expect(survivorAttr.nlink == 1)
    try await harness.volume.openItem(survivor, modes: [.read])
    #expect(try await readViaCore(harness.core, item: survivor, length: oldBytes.count) == oldBytes)
    try await harness.volume.closeItem(survivor, modes: [])

    let (replacement, _) = try await harness.volume.lookupItem(
        named: FSFileName(string: "config"), inDirectory: harness.root
    )
    #expect(replacement !== target)
    try await harness.volume.openItem(replacement, modes: [.read])
    #expect(try await readViaCore(harness.core, item: replacement, length: newBytes.count) == newBytes)
    try await harness.volume.closeItem(replacement, modes: [])
}

@available(macOS 26.0, *)
@Test func operationsAdapterRenameBetweenSameInodeLinksIsNoOp() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }

    let item = try await createAdapterFile(
        volume: harness.volume, in: harness.root, name: "a", contents: adapterBytes("same-inode")
    )
    _ = try await harness.volume.createLink(
        to: item, named: FSFileName(string: "b"), inDirectory: harness.root
    )
    let (alias, _) = try await harness.volume.lookupItem(
        named: FSFileName(string: "b"), inDirectory: harness.root
    )

    _ = try await harness.volume.renameItem(
        item,
        inDirectory: harness.root,
        named: FSFileName(string: "a"),
        to: FSFileName(string: "b"),
        inDirectory: harness.root,
        overItem: alias
    )

    let (a, _) = try await harness.volume.lookupItem(
        named: FSFileName(string: "a"), inDirectory: harness.root
    )
    let (b, _) = try await harness.volume.lookupItem(
        named: FSFileName(string: "b"), inDirectory: harness.root
    )
    #expect(a === item)
    #expect(b === item)
    let attr = try await harness.core.getattr(item: try #require(item as? PortableFSItem))
    #expect(attr.nlink == 2)
}
