import Foundation
import FSKit
@preconcurrency import Darwin

/// Stable item identity carried by pfslocal and surfaced to FSKit.
public struct PfsItemIdentity: Hashable, Sendable {
    public var itemID: UInt64
    public var generation: UInt64

    public init(itemID: UInt64, generation: UInt64) {
        self.itemID = itemID
        self.generation = generation
    }

    public init(_ item: PfsItem) {
        self.init(itemID: item.itemID, generation: item.itemGeneration)
    }

    public var proto: PfsItem {
        var item = PfsItem()
        item.itemID = itemID
        item.itemGeneration = generation
        return item
    }
}

/// FSKit item object owned by `VolumeCore`.
public final class PortableFSItem: FSItem, @unchecked Sendable {
    public let identity: PfsItemIdentity
    public private(set) var reclaimed = false

    init(identity: PfsItemIdentity) {
        self.identity = identity
        super.init()
    }

    func markReclaimed() {
        reclaimed = true
    }
}

public struct PfsResolvedVolume: Sendable {
    public var root: PortableFSItem
    public var rootAttr: PfsAttr
    public var volumeID: String
    public var branch: String
    public var volumeName: String
    public var capabilities: PfsCapabilities
}

public struct PfsCreateResult: Sendable {
    public var item: PortableFSItem
    public var attr: PfsAttr
    public var canonicalName: Data
}

public struct PfsLookupResult: Sendable {
    public var item: PortableFSItem
    public var attr: PfsAttr
    public var canonicalName: Data
}

public struct PfsDirectoryEntry: Sendable {
    public var name: Data
    public var item: PortableFSItem
    public var attr: PfsAttr
    public var nextCookie: UInt64
}

public struct PfsEnumerateResult: Sendable {
    public var entries: [PfsDirectoryEntry]
    public var verifier: UInt64
    public var nextCookie: UInt64
}

public struct PfsSetAttributes: Sendable {
    public var mode: UInt32?
    public var uid: UInt32?
    public var gid: UInt32?
    public var size: UInt64?
    public var mtimeMilliseconds: Int64?
    public var atimeMilliseconds: Int64?

    public init(
        mode: UInt32? = nil,
        uid: UInt32? = nil,
        gid: UInt32? = nil,
        size: UInt64? = nil,
        mtimeMilliseconds: Int64? = nil,
        atimeMilliseconds: Int64? = nil
    ) {
        self.mode = mode
        self.uid = uid
        self.gid = gid
        self.size = size
        self.mtimeMilliseconds = mtimeMilliseconds
        self.atimeMilliseconds = atimeMilliseconds
    }
}

public struct VolumeCoreDebugState: Sendable, Equatable {
    public var itemCount: Int
    public var objectIdentityCount: Int
    public var generationCount: Int
    public var openHandleCount: Int
}

/// Frontend-independent volume brain shared by current and future FSKit adapters.
///
/// `VolumeCore` owns the pfslocal client, the FSItem identity table, and the
/// open-handle table. Adapters must not cache filesystem state: they translate
/// their platform callbacks into these typed async operations and translate
/// returned values back to frontend-specific types. `OperationsAdapter` uses
/// this actor for macOS 26's `FSVolume.Operations` family; a future macOS 27
/// adapter can call the same methods while adding newer SDK integration.
public actor VolumeCore {
    private static let maximumIOChunkBytes = 8 * 1024 * 1024

    public let client: PfsLocalClient
    public private(set) var resolvedVolume: PfsResolvedVolume?

    private var itemsByIdentity: [PfsItemIdentity: PortableFSItem] = [:]
    private var identitiesByObject: [ObjectIdentifier: PfsItemIdentity] = [:]
    private var itemsByObject: [ObjectIdentifier: PortableFSItem] = [:]
    private var deletedItemsByObject: [ObjectIdentifier: DeletedItemState] = [:]
    private var currentGenerationByItemID: [UInt64: UInt64] = [:]
    private var openHandles: [ObjectIdentifier: OpenState] = [:]

    private struct OpenState: Sendable {
        var identity: PfsItemIdentity
        var handle: UInt64
        var mode: PfsOpenMode
        var isImplicit: Bool
        var attrSnapshot: PfsAttr?
    }

    private struct DeletedItemState: Sendable {
        var identity: PfsItemIdentity
        var attrSnapshot: PfsAttr?
    }

    public init(client: PfsLocalClient) {
        self.client = client
    }

    public static func connect(socketPath: String, attachRef: String, configuration: PfsLocalClient.Configuration = .init()) async throws -> VolumeCore {
        let client = PfsLocalClient(socketPath: socketPath, configuration: configuration)
        let core = VolumeCore(client: client)
        try await core.resolve(attachRef: attachRef)
        return core
    }

    @discardableResult
    public func resolve(attachRef: String) async throws -> PfsResolvedVolume {
        let reply = try await client.resolve(attachRef: attachRef)
        let root = item(for: reply.root)
        let resolved = PfsResolvedVolume(
            root: root,
            rootAttr: reply.rootAttr,
            volumeID: reply.volumeID,
            branch: reply.branch,
            volumeName: reply.volumeName.isEmpty ? attachRef : reply.volumeName,
            capabilities: reply.capabilities
        )
        resolvedVolume = resolved
        return resolved
    }

    @discardableResult
    public func subscribeEvents() async throws -> AsyncStream<PfsEvent> {
        try await client.subscribeEvents()
    }

    public func rootItem() throws -> PortableFSItem {
        guard let root = resolvedVolume?.root else {
            throw PfsLocalClientError.unexpectedReply("volume has not been resolved")
        }
        return root
    }

    public func lookup(in directory: PortableFSItem, name: Data) async throws -> PfsLookupResult {
        var request = PfsLookupRequest()
        request.dir = try identity(for: directory).proto
        request.name = name
        let envelope = try await client.request(.lookup(request))
        guard case let .lookupReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        let item = item(for: reply.attr.item)
        return PfsLookupResult(item: item, attr: reply.attr, canonicalName: name)
    }

    public func enumerate(
        directory: PortableFSItem,
        startingAt cookie: UInt64,
        wantAttributes: Bool,
        maxEntries: UInt32 = 256
    ) async throws -> PfsEnumerateResult {
        var request = PfsEnumerateRequest()
        request.dir = try identity(for: directory).proto
        request.cookie = cookie
        request.maxEntries = max(1, maxEntries)
        request.wantAttrs = wantAttributes
        let envelope = try await client.request(.enumerate(request))
        guard case let .enumerateReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }

        let entries = reply.entries.map { entry in
            PfsDirectoryEntry(
                name: entry.name,
                item: item(for: entry.attr.item),
                attr: entry.attr,
                nextCookie: entry.cookie
            )
        }
        return PfsEnumerateResult(entries: entries, verifier: reply.dirVersion, nextCookie: reply.nextCookie)
    }

    public func getattr(item: PortableFSItem) async throws -> PfsAttr {
        let objectID = ObjectIdentifier(item)
        if let deleted = deletedItemsByObject[objectID] {
            if openHandles[objectID] != nil {
                if let snapshot = openHandles[objectID]?.attrSnapshot ?? deleted.attrSnapshot {
                    return snapshot
                }
                do {
                    var attr = try await fetchAttr(identity: deleted.identity)
                    attr.nlink = 0
                    rememberAttrSnapshot(attr, for: objectID)
                    return attr
                } catch let error as PfsLocalClientError where error.posixErrno == ENOENT || error.posixErrno == ESTALE {
                    throw PfsLocalClientError.daemon(errno: ENOENT, message: "item was unlinked")
                }
            }
            throw PfsLocalClientError.daemon(errno: ENOENT, message: "item was unlinked")
        }

        var request = PfsGetAttrRequest()
        request.item = try identity(for: item).proto
        let envelope = try await client.request(.getAttr(request))
        guard case let .getAttrReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        _ = self.item(for: reply.attr.item)
        rememberAttrSnapshot(reply.attr, for: objectID)
        return reply.attr
    }

    public func setattr(item: PortableFSItem, attributes: PfsSetAttributes) async throws -> PfsAttr {
        var request = PfsSetAttrRequest()
        request.item = try identity(for: item).proto
        if let mode = attributes.mode { request.mode = mode }
        if let uid = attributes.uid { request.uid = uid }
        if let gid = attributes.gid { request.gid = gid }
        if let size = attributes.size { request.size = size }
        if let mtime = attributes.mtimeMilliseconds { request.mtimeMs = mtime }
        if let atime = attributes.atimeMilliseconds { request.atimeMs = atime }

        let envelope = try await client.request(.setAttr(request))
        guard case let .setAttrReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        _ = self.item(for: reply.attr.item)
        rememberAttrSnapshot(reply.attr, for: ObjectIdentifier(item))
        return reply.attr
    }

    public func open(item: PortableFSItem, mode: PfsOpenMode) async throws {
        let objectID = ObjectIdentifier(item)
        if deletedItemsByObject[objectID] != nil && openHandles[objectID] == nil {
            throw PfsLocalClientError.daemon(errno: ENOENT, message: "item was unlinked")
        }
        let identity = try identity(for: item)
        let attrSnapshot: PfsAttr?
        if let deletedSnapshot = deletedItemsByObject[objectID]?.attrSnapshot {
            attrSnapshot = deletedSnapshot
        } else {
            attrSnapshot = try? await fetchAttr(identity: identity)
        }
        try await reconcileOpenHandle(
            objectID: objectID,
            identity: identity,
            requestedMode: mode,
            implicit: false,
            attrSnapshot: attrSnapshot
        )
    }

    public func close(item: PortableFSItem, retainingModes: PfsOpenMode? = nil) async throws {
        let objectID = ObjectIdentifier(item)
        let identity = try identity(for: item)
        guard let state = openHandles[objectID] else {
            return
        }

        let retainedMode = retainingModes ?? .unspecified
        if retainedMode == .unspecified {
            openHandles.removeValue(forKey: objectID)
            try await closeDaemonHandle(state.handle)
            return
        }

        if state.mode == retainedMode {
            return
        }

        let newHandle = try await openDaemonHandle(identity: identity, mode: retainedMode)
        openHandles[objectID] = OpenState(
            identity: identity,
            handle: newHandle,
            mode: retainedMode,
            isImplicit: state.isImplicit,
            attrSnapshot: state.attrSnapshot
        )
        try await closeDaemonHandle(state.handle)
    }

    public func read(item: PortableFSItem, offset: UInt64, length: UInt32) async throws -> Data {
        let handle = try await handle(for: item, mode: .read)
        if length == 0 {
            return try await readChunk(handle: handle, offset: offset, length: 0)
        }

        var output = Data()
        output.reserveCapacity(Int(length))
        var remaining = Int(length)
        var currentOffset = offset
        let chunkSize = ioChunkSize()
        while remaining > 0 {
            let chunkLength = min(remaining, chunkSize)
            let data = try await readChunk(handle: handle, offset: currentOffset, length: UInt32(chunkLength))
            output.append(data)
            if data.count < chunkLength {
                break
            }
            remaining -= chunkLength
            currentOffset += UInt64(chunkLength)
        }
        return output
    }

    private func readChunk(handle: UInt64, offset: UInt64, length: UInt32) async throws -> Data {
        var request = PfsReadRequest()
        request.handle = handle
        request.offset = offset
        request.length = length
        let envelope = try await client.request(.read(request))
        guard case let .readReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return reply.data
    }

    @discardableResult
    public func write(item: PortableFSItem, offset: UInt64, data: Data) async throws -> (written: UInt32, attr: PfsAttr) {
        let objectID = ObjectIdentifier(item)
        let handle = try await handle(for: item, mode: .readWrite)
        if data.isEmpty {
            let result = try await writeChunk(handle: handle, offset: offset, data: data)
            rememberAttrSnapshot(result.attr, for: objectID)
            return result
        }

        var totalWritten = 0
        var currentOffset = offset
        var latestAttr: PfsAttr?
        let chunkSize = ioChunkSize()
        while totalWritten < data.count {
            let end = min(data.count, totalWritten + chunkSize)
            let chunk = data.subdata(in: totalWritten..<end)
            let result = try await writeChunk(handle: handle, offset: currentOffset, data: chunk)
            latestAttr = result.attr
            rememberAttrSnapshot(result.attr, for: objectID)
            let written = Int(result.written)
            if written <= 0 {
                throw PfsLocalClientError.daemon(errno: EIO, message: "daemon write made no progress")
            }
            totalWritten += written
            currentOffset += UInt64(written)
            if written < chunk.count {
                break
            }
        }
        return (UInt32(clamping: totalWritten), latestAttr ?? openHandles[objectID]?.attrSnapshot ?? PfsAttr())
    }

    private func writeChunk(handle: UInt64, offset: UInt64, data: Data) async throws -> (written: UInt32, attr: PfsAttr) {
        var request = PfsWriteRequest()
        request.handle = handle
        request.offset = offset
        request.data = data
        let envelope = try await client.request(.write(request))
        guard case let .writeReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return (reply.written, reply.attr)
    }

    public func createFile(in directory: PortableFSItem, name: Data, mode: UInt32, exclusive: Bool = false) async throws -> PfsCreateResult {
        var request = PfsCreateRequest()
        request.dir = try identity(for: directory).proto
        request.name = name
        request.mode = mode
        request.exclusive = exclusive
        let envelope = try await client.request(.create(request))
        guard case let .createReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        let newItem = item(for: reply.attr.item)
        if reply.handle != 0 {
            openHandles[ObjectIdentifier(newItem)] = OpenState(
                identity: PfsItemIdentity(reply.attr.item),
                handle: reply.handle,
                mode: .readWrite,
                isImplicit: false,
                attrSnapshot: reply.attr
            )
        }
        return PfsCreateResult(item: newItem, attr: reply.attr, canonicalName: name)
    }

    public func mkdir(in directory: PortableFSItem, name: Data, mode: UInt32) async throws -> PfsCreateResult {
        var request = PfsMkdirRequest()
        request.dir = try identity(for: directory).proto
        request.name = name
        request.mode = mode
        let envelope = try await client.request(.mkdir(request))
        guard case let .mkdirReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return PfsCreateResult(item: item(for: reply.attr.item), attr: reply.attr, canonicalName: name)
    }

    public func remove(item: PortableFSItem, named name: Data, from directory: PortableFSItem, isDirectory: Bool) async throws {
        var request = PfsRemoveRequest()
        request.dir = try identity(for: directory).proto
        request.name = name
        request.directory = isDirectory
        let envelope = try await client.request(.remove(request))
        guard case .removeReply? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
    }

    public func rename(
        item: PortableFSItem,
        from sourceDirectory: PortableFSItem,
        sourceName: Data,
        to destinationDirectory: PortableFSItem,
        destinationName: Data,
        noReplace: Bool
    ) async throws {
        _ = try identity(for: item)
        var request = PfsRenameRequest()
        request.fromDir = try identity(for: sourceDirectory).proto
        request.fromName = sourceName
        request.toDir = try identity(for: destinationDirectory).proto
        request.toName = destinationName
        request.noReplace = noReplace
        let envelope = try await client.request(.rename(request))
        guard case .renameReply? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
    }

    public func recordRenameReplacement(replacedItem: PortableFSItem) throws {
        let replacedObjectID = ObjectIdentifier(replacedItem)
        guard let replacedIdentity = identitiesByObject[replacedObjectID] else {
            return
        }

        if let canonical = itemsByIdentity[replacedIdentity], canonical === replacedItem {
            itemsByIdentity.removeValue(forKey: replacedIdentity)
        }
        var snapshot = openHandles[replacedObjectID]?.attrSnapshot
        if snapshot != nil {
            snapshot?.nlink = 0
        }
        deletedItemsByObject[replacedObjectID] = DeletedItemState(identity: replacedIdentity, attrSnapshot: snapshot)
        pruneGenerationIfUnused(itemID: replacedIdentity.itemID)
    }

    public func symlink(in directory: PortableFSItem, name: Data, target: Data) async throws -> PfsCreateResult {
        var request = PfsSymlinkRequest()
        request.dir = try identity(for: directory).proto
        request.name = name
        request.target = target
        let envelope = try await client.request(.symlink(request))
        guard case let .symlinkReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return PfsCreateResult(item: item(for: reply.attr.item), attr: reply.attr, canonicalName: name)
    }

    public func readlink(item: PortableFSItem) async throws -> Data {
        var request = PfsReadlinkRequest()
        request.item = try identity(for: item).proto
        let envelope = try await client.request(.readlink(request))
        guard case let .readlinkReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return reply.target
    }

    public func hardLink(item: PortableFSItem, in directory: PortableFSItem, name: Data) async throws -> Data {
        var request = PfsHardLinkRequest()
        request.item = try identity(for: item).proto
        request.dir = try identity(for: directory).proto
        request.name = name
        let envelope = try await client.request(.hardLink(request))
        guard case let .hardLinkReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return reply.name.isEmpty ? name : reply.name
    }

    public func xattrGet(item: PortableFSItem, name: String) async throws -> Data {
        var request = PfsXattrGetRequest()
        request.item = try identity(for: item).proto
        request.name = name
        let envelope = try await client.request(.xattrGet(request))
        guard case let .xattrGetReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return reply.value
    }

    public func xattrSet(item: PortableFSItem, name: String, value: Data, createOnly: Bool, replaceOnly: Bool) async throws {
        var request = PfsXattrSetRequest()
        request.item = try identity(for: item).proto
        request.name = name
        request.value = value
        request.createOnly = createOnly
        request.replaceOnly = replaceOnly
        let envelope = try await client.request(.xattrSet(request))
        guard case .xattrSetReply? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
    }

    public func xattrList(item: PortableFSItem) async throws -> [String] {
        var request = PfsXattrListRequest()
        request.item = try identity(for: item).proto
        let envelope = try await client.request(.xattrList(request))
        guard case let .xattrListReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return reply.names
    }

    public func xattrRemove(item: PortableFSItem, name: String) async throws {
        var request = PfsXattrRemoveRequest()
        request.item = try identity(for: item).proto
        request.name = name
        let envelope = try await client.request(.xattrRemove(request))
        guard case .xattrRemoveReply? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
    }

    public func statfs() async throws -> PfsStatfsReply {
        let envelope = try await client.request(.statfs(PfsStatfsRequest()))
        guard case let .statfsReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return reply
    }

    /// The REAL volume barrier: the daemon drains outstanding write-back to
    /// the authority, and success means authority-durable, applied, AND
    /// acknowledged by every live protocol subscriber at its supported
    /// frontend boundary. macOS 26 exposes no kernel-cache invalidation hook,
    /// so FSKit kernel-cache visibility is not part of that acknowledgment.
    /// There is
    /// no degraded local-only success: an unreachable or slow authority
    /// or a local WAL sync failure FAILS the barrier and surfaces to the
    /// kernel caller.
    public func syncVolume() async throws {
        let envelope = try await client.request(.syncVolume(PfsSyncVolumeRequest()))
        guard case .syncVolumeReply? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
    }

    public func fsync(item: PortableFSItem) async throws {
        let objectID = ObjectIdentifier(item)
        _ = try identity(for: item)
        guard let state = openHandles[objectID] else {
            return
        }
        var request = PfsFsyncRequest()
        request.handle = state.handle
        let envelope = try await client.request(.fsync(request))
        guard case .fsyncReply? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
    }

    public func reclaim(item: PortableFSItem) async throws {
        let objectID = ObjectIdentifier(item)
        let identity = try identity(for: item)

        identitiesByObject.removeValue(forKey: objectID)
        itemsByObject.removeValue(forKey: objectID)
        deletedItemsByObject.removeValue(forKey: objectID)
        item.markReclaimed()

        if let canonical = itemsByIdentity[identity], canonical === item {
            itemsByIdentity.removeValue(forKey: identity)
        }

        if let state = openHandles.removeValue(forKey: objectID) {
            try await closeDaemonHandle(state.handle)
        }
        var request = PfsReclaimRequest()
        request.item = identity.proto
        let envelope = try await client.request(.reclaim(request))
        guard case .reclaimReply? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        pruneGenerationIfUnused(itemID: identity.itemID)
    }

    public func shutdown() async {
        await client.close()
        itemsByIdentity.removeAll()
        identitiesByObject.removeAll()
        itemsByObject.removeAll()
        deletedItemsByObject.removeAll()
        currentGenerationByItemID.removeAll()
        openHandles.removeAll()
    }

    func testingAdoptItem(identity: PfsItemIdentity) -> PortableFSItem {
        item(for: identity.proto)
    }

    func testingDebugState() -> VolumeCoreDebugState {
        VolumeCoreDebugState(
            itemCount: itemsByIdentity.count,
            objectIdentityCount: identitiesByObject.count + deletedItemsByObject.count,
            generationCount: currentGenerationByItemID.count,
            openHandleCount: openHandles.count
        )
    }

    func testingClearOpenAttrSnapshot(item: PortableFSItem) {
        let objectID = ObjectIdentifier(item)
        if var state = openHandles[objectID] {
            state.attrSnapshot = nil
            openHandles[objectID] = state
        }
        if var deleted = deletedItemsByObject[objectID] {
            deleted.attrSnapshot = nil
            deletedItemsByObject[objectID] = deleted
        }
    }

    private func handle(for item: PortableFSItem, mode: PfsOpenMode) async throws -> UInt64 {
        let objectID = ObjectIdentifier(item)
        if deletedItemsByObject[objectID] != nil && openHandles[objectID] == nil {
            throw PfsLocalClientError.daemon(errno: ENOENT, message: "item was unlinked")
        }
        let identity = try identity(for: item)
        if let state = openHandles[objectID], Self.mode(state.mode, covers: mode) {
            return state.handle
        }
        let attrSnapshot: PfsAttr?
        if let deletedSnapshot = deletedItemsByObject[objectID]?.attrSnapshot {
            attrSnapshot = deletedSnapshot
        } else {
            attrSnapshot = try? await fetchAttr(identity: identity)
        }
        try await reconcileOpenHandle(
            objectID: objectID,
            identity: identity,
            requestedMode: mode,
            implicit: true,
            attrSnapshot: attrSnapshot
        )
        guard let state = openHandles[objectID] else {
            throw PfsLocalClientError.unexpectedReply("open did not produce a handle")
        }
        return state.handle
    }

    private func reconcileOpenHandle(
        objectID: ObjectIdentifier,
        identity: PfsItemIdentity,
        requestedMode: PfsOpenMode,
        implicit: Bool,
        attrSnapshot: PfsAttr?
    ) async throws {
        guard requestedMode != .unspecified else {
            return
        }

        if var state = openHandles[objectID] {
            if Self.mode(state.mode, covers: requestedMode) {
                if !implicit {
                    state.isImplicit = false
                    if state.attrSnapshot == nil {
                        state.attrSnapshot = attrSnapshot
                    }
                    openHandles[objectID] = state
                }
                return
            }

            let targetMode = Self.union(state.mode, requestedMode)
            let newHandle = try await openDaemonHandle(identity: identity, mode: targetMode)
            openHandles[objectID] = OpenState(
                identity: identity,
                handle: newHandle,
                mode: targetMode,
                isImplicit: implicit && state.isImplicit,
                attrSnapshot: state.attrSnapshot ?? attrSnapshot
            )
            try await closeDaemonHandle(state.handle)
            return
        }

        let handle = try await openDaemonHandle(identity: identity, mode: requestedMode)
        openHandles[objectID] = OpenState(
            identity: identity,
            handle: handle,
            mode: requestedMode,
            isImplicit: implicit,
            attrSnapshot: attrSnapshot
        )
    }

    private func openDaemonHandle(identity: PfsItemIdentity, mode: PfsOpenMode) async throws -> UInt64 {
        var request = PfsOpenRequest()
        request.item = identity.proto
        request.mode = mode
        let envelope = try await client.request(.open(request))
        guard case let .openReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return reply.handle
    }

    private func closeDaemonHandle(_ handle: UInt64) async throws {
        var request = PfsCloseRequest()
        request.handle = handle
        let envelope = try await client.request(.close(request))
        guard case .closeReply? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
    }

    private func item(for proto: PfsItem) -> PortableFSItem {
        let identity = PfsItemIdentity(proto)
        if let currentGeneration = currentGenerationByItemID[identity.itemID],
           currentGeneration != identity.generation {
            let oldIdentity = PfsItemIdentity(itemID: identity.itemID, generation: currentGeneration)
            forgetKnownItems(for: oldIdentity)
            removeOpenHandles(for: oldIdentity)
        }
        currentGenerationByItemID[identity.itemID] = identity.generation
        if let existing = itemsByIdentity[identity], !existing.reclaimed {
            return existing
        }
        let item = PortableFSItem(identity: identity)
        itemsByIdentity[identity] = item
        register(item: item, identity: identity)
        return item
    }

    private func identity(for item: PortableFSItem) throws -> PfsItemIdentity {
        let objectID = ObjectIdentifier(item)
        if let deleted = deletedItemsByObject[objectID] {
            return deleted.identity
        }
        guard let identity = identitiesByObject[objectID] else {
            throw PfsLocalClientError.daemon(errno: ESTALE, message: "item was reclaimed")
        }
        if let currentGeneration = currentGenerationByItemID[identity.itemID],
           currentGeneration != identity.generation {
            throw PfsLocalClientError.daemon(errno: ESTALE, message: "item generation mismatch")
        }
        return identity
    }

    private func register(item: PortableFSItem, identity: PfsItemIdentity) {
        let objectID = ObjectIdentifier(item)
        identitiesByObject[objectID] = identity
        itemsByObject[objectID] = item
    }

    private func forgetKnownItems(for identity: PfsItemIdentity) {
        itemsByIdentity.removeValue(forKey: identity)
        let objectIDs = identitiesByObject.compactMap { objectID, knownIdentity in
            knownIdentity == identity ? objectID : nil
        }
        for objectID in objectIDs {
            identitiesByObject.removeValue(forKey: objectID)
            if let item = itemsByObject.removeValue(forKey: objectID) {
                item.markReclaimed()
            }
        }
        let deletedObjectIDs = deletedItemsByObject.compactMap { objectID, deleted in
            deleted.identity == identity ? objectID : nil
        }
        for objectID in deletedObjectIDs {
            deletedItemsByObject.removeValue(forKey: objectID)
        }
    }

    private func removeOpenHandles(for identity: PfsItemIdentity) {
        let objectIDs = openHandles.compactMap { objectID, state in
            state.identity == identity ? objectID : nil
        }
        for objectID in objectIDs {
            openHandles.removeValue(forKey: objectID)
        }
    }

    private func pruneGenerationIfUnused(itemID: UInt64) {
        let stillKnown = itemsByIdentity.keys.contains { $0.itemID == itemID }
            || identitiesByObject.values.contains { $0.itemID == itemID }
            || deletedItemsByObject.values.contains { $0.identity.itemID == itemID }
            || openHandles.values.contains { $0.identity.itemID == itemID }
        if !stillKnown {
            currentGenerationByItemID.removeValue(forKey: itemID)
        }
    }

    private func fetchAttr(identity: PfsItemIdentity) async throws -> PfsAttr {
        var request = PfsGetAttrRequest()
        request.item = identity.proto
        let envelope = try await client.request(.getAttr(request))
        guard case let .getAttrReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return reply.attr
    }

    private func rememberAttrSnapshot(_ attr: PfsAttr, for objectID: ObjectIdentifier) {
        var snapshot = attr
        if deletedItemsByObject[objectID] != nil {
            snapshot.nlink = 0
        }
        if var state = openHandles[objectID] {
            state.attrSnapshot = snapshot
            openHandles[objectID] = state
        }
        if var deleted = deletedItemsByObject[objectID] {
            deleted.attrSnapshot = snapshot
            deletedItemsByObject[objectID] = deleted
        }
    }

    private func ioChunkSize() -> Int {
        let preferred = Int(resolvedVolume?.capabilities.preferredIoBytes ?? 0)
        let base = preferred > 0 ? preferred : Self.maximumIOChunkBytes
        return max(1, min(base, Self.maximumIOChunkBytes))
    }

    private static func mode(_ existing: PfsOpenMode, covers requested: PfsOpenMode) -> Bool {
        switch (existing, requested) {
        case (_, .unspecified):
            return true
        case (.readWrite, .read), (.readWrite, .write), (.readWrite, .readWrite):
            return true
        case (.read, .read), (.write, .write):
            return true
        default:
            return false
        }
    }

    private static func union(_ lhs: PfsOpenMode, _ rhs: PfsOpenMode) -> PfsOpenMode {
        if lhs == .readWrite || rhs == .readWrite {
            return .readWrite
        }
        if lhs == .unspecified {
            return rhs
        }
        if rhs == .unspecified {
            return lhs
        }
        if lhs != rhs {
            return .readWrite
        }
        return lhs
    }
}
