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
    var attributeMask: Int
    var parentID: UInt64?
    var flags: UInt32?
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
        let publicFields: [FSItem.Attribute] = [
            .type, .mode, .linkCount, .uid, .gid, .flags, .size, .allocSize,
            .fileID, .parentID, .accessTime, .modifyTime, .changeTime, .birthTime,
            .backupTime, .addedTime, .supportsLimitedXAttrs, .inhibitKernelOffloadedIO,
        ]
        let validMask = publicFields.reduce(into: FSItem.Attribute()) { mask, field in
            if attributes?.isValid(field) == true {
                mask.insert(field)
            }
        }
        storage.append(
            RecordedDirectoryEntry(
                name: name.string ?? String(data: name.data, encoding: .utf8) ?? name.debugDescription,
                itemType: itemType.rawValue,
                itemID: itemID.rawValue,
                nextCookie: nextCookie.rawValue,
                hasAttributes: attributes != nil,
                attributeMask: validMask.rawValue,
                parentID: attributes?.isValid(.parentID) == true
                    ? attributes?.parentID.rawValue
                    : nil,
                flags: attributes?.isValid(.flags) == true
                    ? attributes?.flags
                    : nil
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
private func makeAdapterHarness(
    configuration: PfsLocalMockDaemon.Configuration = .init()
) async throws -> AdapterHarness {
    let daemon = try PfsLocalMockDaemon(configuration: configuration)
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let volume = try await PortableFSVolume.make(
        core: core,
        attachRef: "mock"
    )
    let root = try await core.rootItem()
    return AdapterHarness(daemon: daemon, core: core, volume: volume, root: root)
}

@available(macOS 26.0, *)
@Test func enumerationTransfersOnlyTheExactPackedItemPrefix() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }

    // Populate authority truth through another frontend so VolumeCore has not
    // already canonicalized the children before this enumeration reply.
    let peer = PfsLocalClient(socketPath: harness.daemon.socketPath)
    let resolved = try await peer.resolve(attachRef: "mock")
    for name in ["prefix-a", "prefix-b", "suffix-rejected"] {
        var create = PfsCreateRequest()
        create.dir = resolved.root
        create.name = adapterBytes(name)
        create.mode = 0o644
        let envelope = try await peer.request(.create(create))
        guard case let .createReply(reply)? = envelope.body else {
            Issue.record("peer create omitted its reply")
            return
        }
        var close = PfsCloseRequest()
        close.handle = reply.handle
        _ = try await peer.request(.close(close))
    }
    #expect(await harness.core.testingDebugState().itemCount == 1)
    await harness.daemon.resetStats()

    let (packer, state) = makeRecordingPacker(capacity: 2)
    defer { RecordingPackerRegistry.shared.uninstall(packer) }
    _ = try await harness.volume.enumerateDirectory(
        harness.root,
        startingAt: .initial,
        verifier: .initial,
        attributes: FSItem.GetAttributesRequest(),
        packer: packer
    )
    #expect(state.entries.count == 2)
    #expect(state.didRefuse)
    for _ in 0..<100 {
        if await harness.daemon.stats().resourceAcceptedItemCounts.count >= 2 {
            break
        }
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    let stats = await harness.daemon.stats()
    #expect(stats.resourceAcceptedItemCounts.filter { $0 > 0 } == [2])
    #expect(await harness.core.testingDebugState().itemCount == 3)
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

/// Captures an acknowledgement baseline that a later `==` can be trusted
/// against. See the transport-test twin for the full argument; the short
/// version is that an ack is one-way, so a `stats()` snapshot taken after a
/// publishing request can land on either side of an ack still in flight, and
/// the resulting off-by-one surfaces on a downstream assertion rather than
/// here.
///
/// `makeAdapterHarness` owes nothing — hello, resolve and statfs do not
/// publish, and `rootItem()` is answered from the resolve reply without a
/// request — so the harness settles at zero. Asserting that is what keeps it
/// true: a harness that later gains a publishing step fails here rather than
/// making every ack count in this file quietly wrong.
@available(macOS 26.0, *)
private func settledAckBaseline(
    _ daemon: PfsLocalMockDaemon,
    owed: Int,
    sourceLocation: SourceLocation = #_sourceLocation
) async throws -> Int {
    let stats = try await waitForPublicationAcks(daemon, atLeast: owed)
    #expect(
        stats.publicationAcks == owed,
        "setup owed \(owed) publication acks",
        sourceLocation: sourceLocation
    )
    return owed
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
private func adapterErrno(
    _ label: String,
    operation: () async throws -> Void
) async -> Int? {
    do {
        try await operation()
        Issue.record("\(label) unexpectedly succeeded")
        return nil
    } catch {
        let mapped = error as NSError
        #expect(mapped.domain == NSPOSIXErrorDomain)
        return mapped.code
    }
}

@available(macOS 26.0, *)
@Test func unsupportedXattrSetIsLocalButReadListAndDeleteStillForward() async throws {
    let harness = try await makeAdapterHarness(configuration: .init(
        xattrSetSupported: false
    ))
    defer { harness.daemon.stop() }
    let item = try await createAdapterFile(
        volume: harness.volume,
        in: harness.root,
        name: "xattr-read-only"
    )
    let portable = try #require(item as? PortableFSItem)
    let name = FSFileName(string: "user.test")
    let beforeSets = await harness.daemon.stats()

    for policy: FSVolume.SetXattrPolicy in [.mustCreate, .mustReplace, .alwaysSet] {
        #expect(await adapterErrno("unsupported xattr set mode \(policy.rawValue)") {
            try await harness.volume.setXattr(
                named: name,
                to: adapterBytes("value"),
                on: item,
                policy: policy
            )
        } == Int(EOPNOTSUPP))
    }
    do {
        try await harness.core.xattrSet(
            item: portable,
            name: "user.direct",
            value: adapterBytes("value"),
            createOnly: false,
            replaceOnly: false
        )
        Issue.record("VolumeCore forwarded an unsupported xattr set")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == ENOTSUP)
    }

    let afterSets = await harness.daemon.stats()
    #expect(afterSets.xattrSetRequests == beforeSets.xattrSetRequests)
    #expect(
        afterSets.orderedMutationSourcePhaseQueueable ==
            beforeSets.orderedMutationSourcePhaseQueueable
    )

    // Invalid input keeps its own verdict even when every valid set would be
    // refused by capability negotiation.
    do {
        try await harness.core.xattrSet(
            item: portable,
            name: "",
            value: Data(),
            createOnly: false,
            replaceOnly: false
        )
        Issue.record("empty xattr name was hidden by capability refusal")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EINVAL)
    }
    #expect(await adapterErrno("invalid UTF-8 xattr name") {
        try await harness.volume.setXattr(
            named: FSFileName(data: Data([0xff])),
            to: Data(),
            on: item,
            policy: .alwaysSet
        )
    } == Int(EINVAL))
    let afterInvalid = await harness.daemon.stats()
    #expect(afterInvalid.xattrSetRequests == beforeSets.xattrSetRequests)
    #expect(
        afterInvalid.orderedMutationSourcePhaseQueueable ==
            beforeSets.orderedMutationSourcePhaseQueueable
    )

    // Seed a pre-existing portable attribute through a peer that talks to the
    // writable mock directly. The negotiated gate is frontend-local; it must
    // not hide the read/list/remove operations that remain supported.
    let peer = PfsLocalClient(socketPath: harness.daemon.socketPath)
    _ = try await peer.resolve(attachRef: "mock")
    var seed = PfsXattrSetRequest()
    seed.item = portable.identity.proto
    seed.name = "user.test"
    seed.value = adapterBytes("seed")
    _ = try await peer.request(.xattrSet(seed))
    let beforeForwarding = await harness.daemon.stats()

    #expect(try await harness.volume.xattr(named: name, of: item) == adapterBytes("seed"))
    #expect(
        try await harness.volume.xattrs(of: item).map {
            String(decoding: $0.data, as: UTF8.self)
        } == ["user.test"]
    )
    try await harness.volume.setXattr(
        named: name,
        to: nil,
        on: item,
        policy: .delete
    )

    let afterForwarding = await harness.daemon.stats()
    #expect(afterForwarding.xattrGetRequests == beforeForwarding.xattrGetRequests + 1)
    #expect(afterForwarding.xattrListRequests == beforeForwarding.xattrListRequests + 1)
    #expect(afterForwarding.xattrRemoveRequests == beforeForwarding.xattrRemoveRequests + 1)
    await peer.close()

    // Item validation also precedes capability refusal. A reclaimed object is
    // ESTALE, not ENOTSUP, and still emits no mutation frame.
    let staleItem = try await createAdapterFile(
        volume: harness.volume,
        in: harness.root,
        name: "xattr-stale"
    )
    let stalePortable = try #require(staleItem as? PortableFSItem)
    try await harness.core.reclaim(item: stalePortable)
    let beforeStale = await harness.daemon.stats()
    do {
        try await harness.core.xattrSet(
            item: stalePortable,
            name: "user.test",
            value: Data(),
            createOnly: false,
            replaceOnly: false
        )
        Issue.record("reclaimed xattr target was hidden by capability refusal")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == ESTALE)
    }
    let afterStale = await harness.daemon.stats()
    #expect(afterStale.xattrSetRequests == beforeStale.xattrSetRequests)
    #expect(
        afterStale.orderedMutationSourcePhaseQueueable ==
            beforeStale.orderedMutationSourcePhaseQueueable
    )

    // Grammar wins even when the same callback also names a reclaimed item.
    // This cross-product pins EINVAL > ESTALE > EOPNOTSUPP rather than testing
    // each dimension only against an otherwise valid request.
    do {
        try await harness.core.xattrSet(
            item: stalePortable,
            name: "",
            value: Data(),
            createOnly: false,
            replaceOnly: false
        )
        Issue.record("malformed reclaimed xattr set unexpectedly succeeded")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EINVAL)
    }
    #expect(await adapterErrno("malformed reclaimed adapter xattr set") {
        try await harness.volume.setXattr(
            named: FSFileName(data: Data([0xff])),
            to: Data(),
            on: staleItem,
            policy: .alwaysSet
        )
    } == Int(EINVAL))
    let afterCompoundInvalid = await harness.daemon.stats()
    #expect(afterCompoundInvalid.xattrSetRequests == beforeStale.xattrSetRequests)
    #expect(
        afterCompoundInvalid.orderedMutationSourcePhaseQueueable ==
            beforeStale.orderedMutationSourcePhaseQueueable
    )
}

@available(macOS 26.0, *)
@Test func operationsAdapterMapsDaemonENOTSUPForEveryXattrOperation() async throws {
    let harness = try await makeAdapterHarness(configuration: .init(
        xattrGetErrno: ENOTSUP,
        xattrSetErrno: ENOTSUP,
        xattrListErrno: ENOTSUP,
        xattrRemoveErrno: ENOTSUP
    ))
    defer { harness.daemon.stop() }
    let item = try await createAdapterFile(
        volume: harness.volume,
        in: harness.root,
        name: "xattr-enotsup"
    )
    let name = FSFileName(string: "user.test")

    #expect(await adapterErrno("get xattr") {
        _ = try await harness.volume.xattr(named: name, of: item)
    } == Int(EOPNOTSUPP))
    #expect(await adapterErrno("set xattr") {
        try await harness.volume.setXattr(
            named: name,
            to: adapterBytes("value"),
            on: item,
            policy: .alwaysSet
        )
    } == Int(EOPNOTSUPP))
    #expect(await adapterErrno("list xattrs") {
        _ = try await harness.volume.xattrs(of: item)
    } == Int(EOPNOTSUPP))
    #expect(await adapterErrno("remove xattr") {
        try await harness.volume.setXattr(
            named: name,
            to: nil,
            on: item,
            policy: .delete
        )
    } == Int(EOPNOTSUPP))

    let stats = await harness.daemon.stats()
    #expect(stats.xattrGetRequests == 1)
    #expect(stats.xattrSetRequests == 1)
    #expect(stats.xattrListRequests == 1)
    #expect(stats.xattrRemoveRequests == 1)
}

@available(macOS 26.0, *)
@Test func operationsAdapterPreservesNonENOTSUPXattrErrnos() async throws {
    let harness = try await makeAdapterHarness(configuration: .init(
        xattrGetErrno: EIO,
        xattrSetErrno: EACCES,
        xattrListErrno: EINVAL,
        xattrRemoveErrno: ENOATTR
    ))
    defer { harness.daemon.stop() }
    let item = try await createAdapterFile(
        volume: harness.volume,
        in: harness.root,
        name: "xattr-other-errors"
    )
    let name = FSFileName(string: "user.test")

    #expect(await adapterErrno("get xattr") {
        _ = try await harness.volume.xattr(named: name, of: item)
    } == Int(EIO))
    #expect(await adapterErrno("set xattr") {
        try await harness.volume.setXattr(
            named: name,
            to: adapterBytes("value"),
            on: item,
            policy: .alwaysSet
        )
    } == Int(EACCES))
    #expect(await adapterErrno("list xattrs") {
        _ = try await harness.volume.xattrs(of: item)
    } == Int(EINVAL))
    #expect(await adapterErrno("remove xattr") {
        try await harness.volume.setXattr(
            named: name,
            to: nil,
            on: item,
            policy: .delete
        )
    } == Int(ENOATTR))

    let stats = await harness.daemon.stats()
    #expect(stats.xattrGetRequests == 1)
    #expect(stats.xattrSetRequests == 1)
    #expect(stats.xattrListRequests == 1)
    #expect(stats.xattrRemoveRequests == 1)
}

@available(macOS 26.0, *)
@Test func operationsAdapterAcknowledgesSuccessfulAndNegativePublications() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }
    let baseline = try await settledAckBaseline(harness.daemon, owed: 0)
    let baselineGetattrs = await harness.daemon.stats().getAttrRequests

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

/// The retraction contract at the FSKit boundary: a crossed operation's values
/// must never reach the reply handler, because the reply handler IS the
/// framework install. The daemon's gate is still released — retraction governs
/// what the framework caches, not the daemon's bookkeeping.
///
/// What the FRAMEWORK sees is a REISSUE, not an interruption. Surfacing EINTR
/// here assumed the kernel would restart the syscall against a frontend holding
/// nothing; FSKit on macOS 26 does not restart rmdir(2), so that EINTR reached
/// userspace and failed the application on an idle mount. The extension retries
/// below userspace instead: the retracted attempt is acknowledged in full, the
/// operation is reissued, and only the surviving attempt's values are installed.
@available(macOS 26.0, *)
@Test func operationsAdapterReissuesRetractedOperationAndAcknowledgesBoth() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }
    let baseline = try await settledAckBaseline(harness.daemon, owed: 0)
    let baselineGetattrs = await harness.daemon.stats().getAttrRequests

    await harness.daemon.retractNextPublications()

    // The framework is handed the REISSUE's values. Nothing from the retracted
    // attempt reaches it, and no EINTR reaches userspace: `delivered` is true
    // and `failure` is nil.
    let (delivered, failure): (Bool, Int32?) = await withCheckedContinuation { continuation in
        harness.volume.getAttributes(
            FSItem.GetAttributesRequest(),
            of: harness.root
        ) { attributes, error in
            if let error {
                continuation.resume(returning: (false, Int32((error as NSError).code)))
                return
            }
            continuation.resume(returning: (attributes != nil, nil))
        }
    }
    #expect(failure == nil)
    #expect(delivered)

    // TWO daemon getattrs for ONE framework callback: the retracted attempt and
    // the reissue. That count IS the proof the retry happened below userspace.
    let stats = try await waitForPublicationAcks(harness.daemon, atLeast: baseline + 2)
    #expect(stats.getAttrRequests == baselineGetattrs + 2)
    // BOTH attempts are acknowledged. The retracted attempt still owes its ack —
    // that ack is what releases the daemon's handoff gate — and it is sent
    // BEFORE the reissue so the reissue cannot queue behind the handoff that is
    // waiting for it.
    #expect(stats.publicationAcks == baseline + 2)

    // Only the retracted operation is affected; the next one publishes once.
    _ = try await harness.volume.attributes(
        FSItem.GetAttributesRequest(),
        of: harness.root
    )
    let after = try await waitForPublicationAcks(harness.daemon, atLeast: baseline + 3)
    #expect(after.publicationAcks == baseline + 3)
}

@available(macOS 26.0, *)
@Test func operationsAdapterDrainsPublicationAcksUnderConcurrentLoad() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }
    let baseline = try await settledAckBaseline(harness.daemon, owed: 0)
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
    let typeRequest = FSItem.GetAttributesRequest()
    typeRequest.wantedAttributes = [.type]
    let attr = try await harness.volume.attributes(typeRequest, of: targetItem)
    #expect(attr.type == .file)
}

@available(macOS 26.0, *)
@Test func operationsAdapterFiltersGetattrAndEnumerationToWantedAttributes() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }

    let wanted: FSItem.Attribute = [.flags, .parentID]
    let rootRequest = FSItem.GetAttributesRequest()
    rootRequest.wantedAttributes = wanted
    let rootAttributes = try await harness.volume.attributes(rootRequest, of: harness.root)
    #expect(rootAttributes.isValid(.flags))
    #expect(rootAttributes.flags == 0)
    #expect(rootAttributes.isValid(.parentID))
    #expect(rootAttributes.parentID == .parentOfRoot)
    #expect(!rootAttributes.isValid(.uid))
    #expect(!rootAttributes.isValid(.gid))

    let child = try await createAdapterFile(
        volume: harness.volume,
        in: harness.root,
        name: "wanted-mask"
    )
    let childRequest = FSItem.GetAttributesRequest()
    childRequest.wantedAttributes = wanted
    let childAttributes = try await harness.volume.attributes(childRequest, of: child)
    #expect(childAttributes.isValid(.flags))
    #expect(childAttributes.flags == 0)
    #expect(childAttributes.isValid(.parentID))
    #expect(childAttributes.parentID == .rootDirectory)
    #expect(!childAttributes.isValid(.uid))
    #expect(!childAttributes.isValid(.gid))

    let (packer, state) = makeRecordingPacker(capacity: 10)
    defer { RecordingPackerRegistry.shared.uninstall(packer) }
    let enumerateRequest = FSItem.GetAttributesRequest()
    enumerateRequest.wantedAttributes = wanted
    _ = try await harness.volume.enumerateDirectory(
        harness.root,
        startingAt: .initial,
        verifier: .initial,
        attributes: enumerateRequest,
        packer: packer
    )
    let entry = try #require(state.entries.first { $0.name == "wanted-mask" })
    #expect(entry.attributeMask == wanted.rawValue)
    #expect(entry.parentID == FSItem.Identifier.rootDirectory.rawValue)
    #expect(entry.flags == 0)
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
    // Enumeration order past the synthetics is the daemon's own name-cursor
    // order, so assert membership rather than an alphabetical listing.
    #expect(firstEntries.prefix(2).map(\.name) == [".", ".."])
    #expect(Set(firstEntries.dropFirst(2).map(\.name)) == ["a.txt", "b.txt"])
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

    let sizeRequest = FSItem.GetAttributesRequest()
    sizeRequest.wantedAttributes = [.size]
    let oldAttr = try await harness.volume.attributes(sizeRequest, of: target)
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
    let sizeRequest = FSItem.GetAttributesRequest()
    sizeRequest.wantedAttributes = [.size]
    let oldAttr = try await harness.volume.attributes(sizeRequest, of: target)
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

@available(macOS 26.0, *)
@Test func operationsAdapterPacksParentDirectoryIdentityForDotDot() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }
    let (parent, _) = try await harness.volume.createItem(
        named: FSFileName(string: "parent"),
        type: .directory,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let (child, _) = try await harness.volume.createItem(
        named: FSFileName(string: "child"),
        type: .directory,
        inDirectory: parent,
        attributes: FSItem.SetAttributesRequest()
    )
    _ = try await createAdapterFile(volume: harness.volume, in: child, name: "leaf.txt")

    let parentID = try PfsFSKitMapping.itemIdentifier(
        from: try #require(parent as? PortableFSItem).identity.itemID
    ).rawValue
    let childID = try PfsFSKitMapping.itemIdentifier(
        from: try #require(child as? PortableFSItem).identity.itemID
    ).rawValue

    let entries = try await collectDirectoryEntries(
        volume: harness.volume,
        directory: child,
        attributesRequested: false,
        packerCapacity: 16
    )
    #expect(entries.map(\.name) == [".", "..", "leaf.txt"])
    #expect(entries[0].itemID == childID)
    #expect(entries[1].itemID == parentID)

    // POSIX makes the root its own parent, so "." and ".." agree there.
    let rootEntries = try await collectDirectoryEntries(
        volume: harness.volume,
        directory: harness.root,
        attributesRequested: false,
        packerCapacity: 16
    )
    let rootID = FSItem.Identifier.rootDirectory.rawValue
    #expect(rootEntries.prefix(2).map(\.name) == [".", ".."])
    #expect(rootEntries[0].itemID == rootID)
    #expect(rootEntries[1].itemID == rootID)

    // Readdir-plus must stay synthetic-free: FSKit's contract is "Don't pack
    // `.` and `..` if `attributes` isn't `nil`."
    let plusEntries = try await collectDirectoryEntries(
        volume: harness.volume,
        directory: child,
        attributesRequested: true,
        packerCapacity: 16
    )
    #expect(plusEntries.map(\.name) == ["leaf.txt"])
}

@available(macOS 26.0, *)
@Test func operationsAdapterKeepsVerifierStableWhileDirectoryMutatesBetweenPages() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }
    let (dir, _) = try await harness.volume.createItem(
        named: FSFileName(string: "churn"),
        type: .directory,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    for index in 0..<400 {
        _ = try await createAdapterFile(volume: harness.volume, in: dir, name: String(format: "file-%06d.dat", index))
    }

    let (firstPacker, firstState) = makeRecordingPacker(capacity: 120)
    defer { RecordingPackerRegistry.shared.uninstall(firstPacker) }
    let verifier = try await harness.volume.enumerateDirectory(
        dir,
        startingAt: .initial,
        verifier: .initial,
        attributes: nil,
        packer: firstPacker
    )
    #expect(verifier.rawValue != FSDirectoryVerifier.initial.rawValue)
    let resumeCookie = try #require(firstState.entries.last?.nextCookie)
    #expect(!PfsEnumerationCookies.isTerminal(resumeCookie))

    // A writer lands a file in the directory while the kernel is holding a
    // resumption cookie. Daemon cookies resume by name, so this is not a
    // restart: reporting a new verifier here would tell FSKit the walk it is
    // in the middle of is no longer valid.
    _ = try await createAdapterFile(volume: harness.volume, in: dir, name: "renamed-in.dat")

    let (secondPacker, secondState) = makeRecordingPacker(capacity: 400)
    defer { RecordingPackerRegistry.shared.uninstall(secondPacker) }
    let resumedVerifier = try await harness.volume.enumerateDirectory(
        dir,
        startingAt: FSDirectoryCookie(resumeCookie),
        verifier: verifier,
        attributes: nil,
        packer: secondPacker
    )
    #expect(resumedVerifier.rawValue == verifier.rawValue)
    #expect(!secondState.entries.isEmpty)

    // A genuine restart — cookie back to initial — is the one place a new
    // verifier belongs.
    let (thirdPacker, thirdState) = makeRecordingPacker(capacity: 8)
    defer { RecordingPackerRegistry.shared.uninstall(thirdPacker) }
    let restartVerifier = try await harness.volume.enumerateDirectory(
        dir,
        startingAt: .initial,
        verifier: .initial,
        attributes: nil,
        packer: thirdPacker
    )
    #expect(restartVerifier.rawValue != verifier.rawValue)
    #expect(!thirdState.entries.isEmpty)

    // FSKit may restart at cookie zero while retaining the verifier from the
    // previous walk. Echo it: changing the verifier on this successful page
    // makes the framework discard the packed entries with EAGAIN and repeat
    // the same request indefinitely.
    let (retainedPacker, retainedState) = makeRecordingPacker(capacity: 512)
    defer { RecordingPackerRegistry.shared.uninstall(retainedPacker) }
    let retainedVerifier = try await harness.volume.enumerateDirectory(
        dir,
        startingAt: .initial,
        verifier: verifier,
        attributes: nil,
        packer: retainedPacker
    )
    #expect(retainedVerifier.rawValue == verifier.rawValue)
    #expect(retainedState.entries.contains { $0.name == "renamed-in.dat" })
}

@available(macOS 26.0, *)
@Test func operationsAdapterEnumeratesFiveHundredEntriesWhenPackerRefusesInsideFinalDaemonPage() async throws {
    let harness = try await makeAdapterHarness()
    defer { harness.daemon.stop() }
    let (dir, _) = try await harness.volume.createItem(
        named: FSFileName(string: "five-hundred"),
        type: .directory,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    var expected: Set<String> = []
    for index in 0..<500 {
        let name = String(format: "file-%06d.dat", index)
        _ = try await createAdapterFile(volume: harness.volume, in: dir, name: name)
        expected.insert(name)
    }

    // 303 is where the live host's readdir buffer filled up: inside the second
    // and final 256-entry daemon page the adapter had already drained.
    for capacity in [303, 457, 256, 257] {
        let entries = try await collectDirectoryEntries(
            volume: harness.volume,
            directory: dir,
            attributesRequested: false,
            packerCapacity: capacity
        )
        let names = entries.map(\.name)
        #expect(names.count == 502, "packer capacity \(capacity) returned \(names.count) entries")
        #expect(Set(names) == expected.union([".", ".."]), "packer capacity \(capacity) lost or repeated entries")
        #expect(Set(names).count == names.count, "packer capacity \(capacity) repeated an entry")
    }
}
