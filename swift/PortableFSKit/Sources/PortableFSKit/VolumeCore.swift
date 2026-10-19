import Foundation
import FSKit
import OSLog
@preconcurrency import Darwin

/// A syntactically valid request to set a user xattr: the one validator
/// for that grammar. It holds no item, so a caller can only obtain one by
/// deciding the request's syntax before it converts or looks up the target:
/// EINVAL outranks every item verdict, including a foreign FSItem that
/// never was a PortableFS item.
public struct PfsXattrSetRequest: Sendable, Equatable {
    public let name: String
    public let createOnly: Bool
    public let replaceOnly: Bool

    public init(name: String, createOnly: Bool, replaceOnly: Bool) throws {
        let nameBytes = name.utf8
        guard !nameBytes.isEmpty,
              nameBytes.count <= 255,
              !nameBytes.contains(0),
              !(createOnly && replaceOnly) else {
            throw PfsLocalClientError.daemon(
                errno: EINVAL,
                message: "invalid xattr set request"
            )
        }
        self.name = name
        self.createOnly = createOnly
        self.replaceOnly = replaceOnly
    }
}

/// Stable item identity carried by pfslocal and surfaced to FSKit.
public struct PfsItemIdentity: Hashable, Sendable {
    public var itemID: UInt64
    public var generation: UInt64
    public var stableIdentity: Data

    public init(itemID: UInt64, generation: UInt64, stableIdentity: Data = Data()) {
        self.itemID = itemID
        self.generation = generation
        self.stableIdentity = stableIdentity
    }

    public init(_ item: PfsItem) {
        self.init(itemID: item.itemID, generation: item.itemGeneration, stableIdentity: item.stableIdentity)
    }

    public var proto: PfsItem {
        var item = PfsItem()
        item.itemID = itemID
        item.itemGeneration = generation
        item.stableIdentity = stableIdentity
        return item
    }
}

/// FSKit item object owned by `VolumeCore`.
public final class PortableFSItem: FSItem, @unchecked Sendable {
    public let identity: PfsItemIdentity
    public let fileID: UInt64
    public let kind: PfsItemKind
    public private(set) var reclaimed = false

    init(identity: PfsItemIdentity, fileID: UInt64, kind: PfsItemKind) {
        self.identity = identity
        self.fileID = fileID
        self.kind = kind
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

public struct PfsHardLinkResult: Sendable {
    public var canonicalName: Data
    /// Fresh attributes for the linked item, including its immutable type and
    /// post-link count.
    public var attr: PfsAttr
}

public struct PfsDirectoryEntry: Sendable {
    public var name: Data
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
    /// chflags(2): the ABSOLUTE new BSD file-flag word, not a delta. `nil`
    /// means "this setattr changes no flags"; `.some(0)` is a real request to
    /// clear every flag, which is why this is an Optional rather than a
    /// sentinel value.
    ///
    /// The extension always forwards the intent: the daemon decides per
    /// object and refuses the whole SetAttr before applying any of it.
    public var flags: UInt32?

    public init(
        mode: UInt32? = nil,
        uid: UInt32? = nil,
        gid: UInt32? = nil,
        size: UInt64? = nil,
        mtimeMilliseconds: Int64? = nil,
        atimeMilliseconds: Int64? = nil,
        flags: UInt32? = nil
    ) {
        self.mode = mode
        self.uid = uid
        self.gid = gid
        self.size = size
        self.mtimeMilliseconds = mtimeMilliseconds
        self.atimeMilliseconds = atimeMilliseconds
        self.flags = flags
    }
}

public struct VolumeCoreDebugState: Sendable, Equatable {
    public var itemCount: Int
    public var objectIdentityCount: Int
    public var publishedItemCount: Int
    public var provisionalItemCount: Int
    public var retiringItemCount: Int
    public var retirementWaiterCount: Int
    public var openHandleCount: Int
}

/// The volume brain behind the FSKit adapter.
///
/// `VolumeCore` owns the pfslocal client, the FSItem identity table, and the
/// open-handle table. Adapters must not cache filesystem state: they translate
/// their platform callbacks into these typed async operations and translate
/// returned values back to FSKit types.
public actor VolumeCore {
    private static let maximumIOChunkBytes = 8 * 1024 * 1024

    public let client: PfsLocalClient
    public private(set) var resolvedVolume: PfsResolvedVolume?
    /// The bound connection's request-trace label, kept from Resolve: a
    /// session never changes connections after Hello.
    private(set) var traceConnection = ""

    private var itemsByIdentity: [PfsItemIdentity: PortableFSItem] = [:]
    private var identitiesByObject: [ObjectIdentifier: PfsItemIdentity] = [:]
    private var canonicalItemsByFileID: [UInt64: [PfsItemIdentity: PortableFSItem]] = [:]
    // Index registered objects by ownership handle to reject handle reuse
    // without scanning unrelated items during a kernel teardown burst.
    private var objectIDsByItemID: [UInt64: Set<ObjectIdentifier>] = [:]
    private var itemsByObject: [ObjectIdentifier: PortableFSItem] = [:]
    private var publishedItems: Set<ObjectIdentifier> = []
    private var provisionalItemReferences: [ObjectIdentifier: Int] = [:]
    // Retiring identities are detached before suspension. Publications wait on
    // continuations so ownership dispositions and reclaim can still make progress.
    private var retiringItems: [PfsItemIdentity: ObjectIdentifier] = [:]
    private var retirementWaiters: [PfsItemIdentity: [CheckedContinuation<Void, Never>]] = [:]
    private var settlementWaiters: [ObjectIdentifier: [CheckedContinuation<Void, Never>]] = [:]
    private var kernelCache: PfsKernelCache?
    private var testingNativeReclaim: (@Sendable (PortableFSItem, () -> Void) -> Bool)?

    func installKernelCache(_ cache: PfsKernelCache) {
        kernelCache = cache
        for item in itemsByObject.values {
            cache.retain(item)
            cache.ownership(item, access: openHandles[ObjectIdentifier(item)]?.heldAccess ?? .unspecified)
        }
    }

    func pushDirtyData(_ items: [PortableFSItem]) async throws {
        for item in items { _ = try identity(for: item) }
        try await kernelCache?.push(items)
        // The kernel call can reenter final close, reclaim or terminal loss.
        try client.publicationGate.check()
        for item in items { _ = try identity(for: item) }
    }

    private var stopped = false
    private var shutdownTask: Task<Void, Never>?
    private var openHandles: [ObjectIdentifier: OpenState] = [:]
    private var lifecycleGates: [ObjectIdentifier: LifecycleGateState] = [:]

    /// The open file descriptions one object holds. Each keeps exactly the
    /// access it was opened with. A missing right is acquired as its own
    /// description, never by reopening the union: a fresh OPEN re-checks
    /// every right it names against the current mode, so reopening could
    /// lose a right an earlier open was granted. An object therefore holds at
    /// most one read-capable and one write-capable description, and they are
    /// the same description when one open granted both.
    private struct OpenState: Sendable {
        var readHandle: UInt64?
        var writeHandle: UInt64?
        // Descriptions FSKit no longer needs remain owned here until the
        // daemon confirms each close. This prevents a failed close from
        // turning a live daemon descriptor into unreachable state.
        var pendingCloseHandles: [UInt64] = []
        /// The read/write description CREATE returned, while it is held.
        /// Attribution only: it never changes which description serves.
        var creationHandle: UInt64?

        /// The one description that covers `mode`, if any.
        func handle(covering mode: PfsOpenMode) -> UInt64? {
            switch mode {
            case .read:
                return readHandle
            case .write:
                return writeHandle
            case .readWrite:
                return readHandle == writeHandle ? readHandle : nil
            default:
                return nil
            }
        }

        /// A description to name the object by when no access is needed.
        var anyHandle: UInt64? { readHandle ?? writeHandle }

        /// The access `requested` needs that no held description grants.
        func missing(_ requested: PfsOpenMode) -> PfsOpenMode {
            PfsOpenMode(
                read: requested.grantsRead && readHandle == nil,
                write: requested.grantsWrite && writeHandle == nil
            )
        }

        mutating func install(_ handle: UInt64, granting mode: PfsOpenMode) {
            if mode.grantsRead { readHandle = handle }
            if mode.grantsWrite { writeHandle = handle }
        }

        /// FSKit reports the modes that stay open. A description that
        /// carries none of them is no longer needed; one that carries any is
        /// kept whole. A read/write description therefore survives a partial
        /// close, which matters because it may be the only remaining
        /// capability for an unlinked or rename-replaced object.
        mutating func retireDescriptions(notCarrying retained: PfsOpenMode) {
            if let read = readHandle, read == writeHandle {
                if !retained.grantsRead && !retained.grantsWrite { retireAll() }
                return
            }
            if let read = readHandle, !retained.grantsRead {
                pendingCloseHandles.append(read)
                readHandle = nil
            }
            if let write = writeHandle, !retained.grantsWrite {
                pendingCloseHandles.append(write)
                writeHandle = nil
            }
            forgetRetiredCreationHandle()
        }

        mutating func retireAll() {
            if let read = readHandle { pendingCloseHandles.append(read) }
            if let write = writeHandle, write != readHandle { pendingCloseHandles.append(write) }
            readHandle = nil
            writeHandle = nil
            creationHandle = nil
        }

        private mutating func forgetRetiredCreationHandle() {
            if let creation = creationHandle, creation != readHandle, creation != writeHandle {
                creationHandle = nil
            }
        }

        var heldAccess: PfsOpenMode {
            PfsOpenMode(read: readHandle != nil, write: writeHandle != nil)
        }

        var handleCount: Int {
            Set([readHandle, writeHandle].compactMap { $0 }).count + pendingCloseHandles.count
        }

        var isEmpty: Bool { handleCount == 0 }
    }

    private enum LifecycleGateMode {
        case shared
        case exclusive
    }

    private struct LifecycleWaiter {
        var id: UUID
        var mode: LifecycleGateMode
        var continuation: CheckedContinuation<Bool, Never>
    }

    private struct LifecycleGateState {
        var sharedOwners = 0
        var exclusiveOwner = false
        var waiters: [LifecycleWaiter] = []
    }

    public init(client: PfsLocalClient) {
        self.client = client
    }

    public static func connect(
        socketPath: String,
        attachRef: String,
        configuration: PfsLocalClient.Configuration = .init()
    ) async throws -> VolumeCore {
        let client = PfsLocalClient(socketPath: socketPath, configuration: configuration)
        let core = VolumeCore(client: client)
        try await core.resolve(attachRef: attachRef)
        return core
    }

    /// Binds this volume's connection to one attach incarnation and installs
    /// its root. A malformed root closes the client before any volume state
    /// exists.
    @discardableResult
    public func resolve(attachRef: String) async throws -> PfsResolvedVolume {
        let reply = try await client.resolve(attachRef: attachRef)
        do {
            guard reply.root == reply.rootAttr.item, reply.rootAttr.fileID == 1,
                  reply.rootAttr.kind == .directory, reply.rootAttr.parentFileID == 0 else {
                throw PfsLocalClientError.invalidFrame("invalid root attributes")
            }
            try validateOwningItem(reply.root)
            try validateFileAttributes(reply.rootAttr, allowingRoot: true)
        } catch {
            await client.close(error: error)
            throw error
        }
        let root = try daemonItem(for: reply.rootAttr, allowingRoot: true)
        publishedItems.insert(ObjectIdentifier(root))
        let resolved = PfsResolvedVolume(
            root: root,
            rootAttr: reply.rootAttr,
            volumeID: reply.volumeID,
            volumeName: reply.volumeName.isEmpty ? attachRef : reply.volumeName,
            capabilities: reply.capabilities
        )
        resolvedVolume = resolved
        traceConnection = await client.traceConnectionLabel
        return resolved
    }

    /// Establishes this connection's single event binding; see
    /// `PfsLocalClient.subscribeEvents`.
    public func subscribeEvents() async throws -> AsyncStream<PfsEvent> {
        try await client.subscribeEvents()
    }

    public func rootItem() throws -> PortableFSItem {
        try client.publicationGate.check()
        guard let root = resolvedVolume?.root else {
            throw PfsLocalClientError.unexpectedReply("volume has not been resolved")
        }
        return root
    }

    public func lookup(in directory: PortableFSItem, name: Data) async throws -> PfsLookupResult {
        var request = PfsLookupRequest()
        request.dir = try identity(for: directory).proto
        request.name = name
        let lease = try await client.requestResource(.lookup(request))
        let envelope = lease.envelope
        guard case let .lookupReply(reply)? = envelope.body else {
            await lease.complete(itemsPublished: false)
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        let item: PortableFSItem
        do {
            try validateParent(reply.attr, in: directory)
            item = try await adoptReplyItem(reply.attr, lease: lease)
        } catch {
            await lease.complete(itemsPublished: false)
            throw error
        }
        await lease.complete(itemsPublished: true)
        return PfsLookupResult(item: item, attr: reply.attr, canonicalName: name)
    }

    public func enumerate(
        directory: PortableFSItem,
        startingAt cookie: UInt64,
        wantAttributes: Bool,
        maxEntries: UInt32 = 256
    ) async throws -> PfsEnumerateResult {
        try await withDescriptorHandle(item: directory, mode: .read) { handle in
            var request = PfsEnumerateEntriesRequest()
            request.dir = try identity(for: directory).proto
            request.cookie = cookie
            request.maxEntries = max(1, maxEntries)
            request.wantAttrs = wantAttributes
            request.handle = handle
            let envelope = try await client.request(.enumerateEntries(request))
            guard case let .enumerateEntriesReply(reply)? = envelope.body else {
                throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
            }
            let entries = try reply.entries.map { entry in
                guard entry.attr.item == PfsItem(), entry.attr.parent == PfsItem(),
                      entry.attr.parentFileID == directory.fileID else {
                    throw PfsLocalClientError.invalidFrame("enumeration transferred an ownership handle or invalid parent")
                }
                try validateFileAttributes(entry.attr)
                return PfsDirectoryEntry(name: entry.name, attr: entry.attr, nextCookie: entry.cookie)
            }
            return PfsEnumerateResult(
                entries: entries,
                verifier: reply.dirVersion,
                nextCookie: reply.nextCookie
            )
        }
    }

    public func getattr(item: PortableFSItem) async throws -> PfsAttr {
        let objectID = ObjectIdentifier(item)
        return try await withDescriptorGate(for: objectID) {
            try await getattrLocked(item: item, objectID: objectID)
        }
    }

    private func getattrLocked(
        item: PortableFSItem,
        objectID: ObjectIdentifier
    ) async throws -> PfsAttr {
        var request = PfsGetAttrRequest()
        request.item = try identity(for: item).proto
        request.handle = openHandles[objectID]?.anyHandle ?? 0
        let envelope: PfsEnvelope
        do {
            envelope = try await client.request(.getAttr(request))
        } catch let error as PfsLocalClientError
            where error.posixErrno == ENOENT || error.posixErrno == ESTALE {
            // The frontend identity remains canonical until Reclaim even
            // after its last link disappears. Authorities may report that
            // retired backing inode as either ENOENT or ESTALE; FSKit's
            // pathname-visible result is consistently ENOENT. A surviving
            // hard-link alias succeeds here and therefore keeps the Item.
            throw PfsLocalClientError.daemon(errno: ENOENT, message: "item is no longer linked")
        }
        guard case let .getAttrReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        try validateAttributes(reply.attr, for: item)
        return reply.attr
    }

    public func setattr(item: PortableFSItem, attributes: PfsSetAttributes) async throws -> PfsAttr {
        let objectID = ObjectIdentifier(item)
        return try await withDescriptorGate(for: objectID) {
            try await setattrLocked(
                item: item,
                objectID: objectID,
                attributes: attributes
            )
        }
    }

    private func setattrLocked(
        item: PortableFSItem,
        objectID: ObjectIdentifier,
        attributes: PfsSetAttributes
    ) async throws -> PfsAttr {
        var request = PfsSetAttrRequest()
        request.item = try identity(for: item).proto
        // The authority truncates through the named description and refuses
        // one not open for writing. Without a write-capable description the
        // truncate is checked against the object instead, like truncate(2).
        request.handle = (attributes.size == nil
            ? openHandles[objectID]?.anyHandle
            : openHandles[objectID]?.writeHandle) ?? 0
        if let mode = attributes.mode { request.mode = mode }
        if let uid = attributes.uid { request.uid = uid }
        if let gid = attributes.gid { request.gid = gid }
        if let size = attributes.size { request.size = size }
        if let mtime = attributes.mtimeMilliseconds { request.mtimeMs = mtime }
        if let atime = attributes.atimeMilliseconds { request.atimeMs = atime }
        if let flags = attributes.flags {
            // setFlags is the intent; a zero word is a legal "clear
            // everything", so the bool must be set even when flags stays 0.
            request.setFlags = true
            request.flags = flags
        }

        let envelope = try await client.request(.setAttr(request))
        guard case let .setAttrReply(reply)? = envelope.body else {
            await stopForFailure()
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        do {
            try validateAttributes(reply.attr, for: item)
        } catch {
            await stopForFailure()
            throw error
        }
        return reply.attr
    }

    public func open(item: PortableFSItem, mode: PfsOpenMode) async throws {
        let objectID = ObjectIdentifier(item)
        try await withLifecycleGate(for: objectID) {
            try await openLocked(item: item, objectID: objectID, mode: mode)
        }
    }

    private func openLocked(
        item: PortableFSItem,
        objectID: ObjectIdentifier,
        mode: PfsOpenMode
    ) async throws {
        let identity = try identity(for: item)
        try await reconcileOpenHandleLocked(
            objectID: objectID,
            identity: identity,
            requestedMode: mode,
            origin: "open",
            fileID: item.fileID
        )
    }

    public func close(item: PortableFSItem, retainingModes: PfsOpenMode? = nil) async throws {
        if kernelCache?.deferCleanup(item, { [self] in
            do { try await self.close(item: item, retainingModes: retainingModes) }
            catch { await self.client.close(error: error) }
        }) == true { return }
        let objectID = ObjectIdentifier(item)
        try await withLifecycleGate(for: objectID) {
            try await closeLocked(
                item: item,
                objectID: objectID,
                retainingModes: retainingModes
            )
        }
    }

    private func closeLocked(
        item: PortableFSItem,
        objectID: ObjectIdentifier,
        retainingModes: PfsOpenMode?
    ) async throws {
        _ = try identity(for: item)
        guard openHandles[objectID] != nil else {
            return
        }
        // V3 final close can have waited behind I/O while a cache-state call
        // acquired a pin. Recheck at the actual descriptor-retirement boundary.
        let retireDescriptions = {
            if self.kernelCache?.deferCleanup(item, { [self] in
                do { try await self.close(item: item, retainingModes: retainingModes) }
                catch { await self.client.close(error: error) }
            }) == true { return true }
            // Closing never opens. A partially retained V2 description keeps
            // its original rights, including an open-unlinked capability.
            self.openHandles[objectID]?.retireDescriptions(notCarrying: retainingModes ?? .unspecified)
            self.kernelCache?.ownership(item, access: self.openHandles[objectID]?.heldAccess ?? .unspecified)
            return false
        }
        let deferred = kernelCache == nil ? retireDescriptions() : client.publicationGate.synchronized(retireDescriptions)
        guard !deferred else { return }
        try await closePendingDaemonHandles(objectID: objectID)
    }

    public func read(item: PortableFSItem, offset: UInt64, length: UInt32) async throws -> Data {
        try await withDescriptorHandle(item: item, mode: .read) { handle in
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
                let data = try await readChunk(
                    handle: handle,
                    offset: currentOffset,
                    length: UInt32(chunkLength)
                )
                output.append(data)
                if data.count < chunkLength {
                    break
                }
                remaining -= chunkLength
                currentOffset += UInt64(chunkLength)
            }
            return output
        }
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

    /// A write needs exactly write access, which an O_WRONLY or read/write
    /// description already holds. Demanding read access as well would OPEN a
    /// read description the write never uses: an extra authority round trip
    /// per O_WRONLY rewrite, and EACCES for a writable but unreadable (0200)
    /// file.
    @discardableResult
    public func write(item: PortableFSItem, offset: UInt64, data: Data) async throws -> (written: UInt32, attr: PfsAttr) {
        return try await withDescriptorHandle(item: item, mode: .write) { handle in
            if data.isEmpty {
                let result = try await writeChunk(handle: handle, offset: offset, data: data)
                try validateAttributes(result.attr, for: item)
                guard result.written == 0 else {
                    throw PfsLocalClientError.invalidFrame("nonzero count for an empty write")
                }
                return result
            }
            guard data.count <= Int(UInt32.max), offset <= UInt64.max - UInt64(data.count) else {
                throw PfsLocalClientError.daemon(errno: EOVERFLOW, message: "write range overflows")
            }
            var totalWritten = 0
            var lastSuccessfulChunk: (written: UInt32, attr: PfsAttr)?
            let chunkSize = ioChunkSize()
            while totalWritten < data.count {
                let end = min(data.count, totalWritten + chunkSize)
                let chunk = data.subdata(in: totalWritten..<end)
                let result: (written: UInt32, attr: PfsAttr)
                do {
                    result = try await writeChunk(handle: handle, offset: offset + UInt64(totalWritten), data: chunk)
                } catch {
                    // Earlier replies are durable. Returning their prefix never
                    // claims the failed (possibly uncertain) chunk succeeded.
                    if let lastSuccessfulChunk {
                        return (UInt32(totalWritten), lastSuccessfulChunk.attr)
                    }
                    throw error
                }
                do {
                    try validateAttributes(result.attr, for: item)
                } catch {
                    await stopForFailure()
                    throw error
                }
                guard result.written > 0, result.written <= chunk.count else {
                    await stopForFailure()
                    throw PfsLocalClientError.invalidFrame("invalid committed write count")
                }
                totalWritten += Int(result.written)
                lastSuccessfulChunk = result
                if result.written < chunk.count { break }
            }
            guard let lastSuccessfulChunk else {
                throw PfsLocalClientError.invalidFrame("write omitted committed state")
            }
            return (UInt32(totalWritten), lastSuccessfulChunk.attr)
        }
    }

    private func writeChunk(handle: UInt64, offset: UInt64, data: Data) async throws -> (written: UInt32, attr: PfsAttr) {
        var request = PfsWriteRequest()
        request.handle = handle
        request.offset = offset
        request.data = data
        let envelope = try await client.request(.write(request))
        guard case let .writeReply(reply)? = envelope.body else {
            if !data.isEmpty { await stopForFailure() }
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return (reply.written, reply.attr)
    }

    public func createFile(in directory: PortableFSItem, name: Data, mode: UInt32) async throws -> PfsCreateResult {
        var request = PfsCreateRequest()
        request.dir = try identity(for: directory).proto
        request.name = name
        request.mode = mode
        request.exclusive = true
        let lease = try await client.requestResource(.create(request))
        let envelope = lease.envelope
        guard case let .createReply(reply)? = envelope.body else {
            await stopForFailure()
            await lease.complete(itemsPublished: false)
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        guard reply.handle != 0 else {
            // Create's success contract transfers an open descriptor. Sending
            // accept_handles for zero would itself violate the disposition
            // contract; accepting only the item would publish a file whose
            // required open state was never installed. End the session.
            await stopForFailure()
            throw PfsLocalClientError.connectionClosed
        }
        let newItem: PortableFSItem
        do {
            try validateParent(reply.attr, in: directory)
            newItem = try await adoptReplyItem(
                reply.attr,
                lease: lease,
                terminalOnAbandon: true
            )
        } catch {
            await stopForFailure()
            throw error
        }
        openHandles[ObjectIdentifier(newItem)] = OpenState(
            readHandle: reply.handle,
            writeHandle: reply.handle,
            creationHandle: reply.handle
        )
        kernelCache?.ownership(newItem, access: .readWrite)
        lease.acceptHandles()
        await lease.complete(itemsPublished: true)
        return PfsCreateResult(item: newItem, attr: reply.attr, canonicalName: name)
    }

    public func mkdir(in directory: PortableFSItem, name: Data, mode: UInt32) async throws -> PfsCreateResult {
        var request = PfsMkdirRequest()
        request.dir = try identity(for: directory).proto
        request.name = name
        request.mode = mode
        let lease = try await client.requestResource(.mkdir(request))
        let envelope = lease.envelope
        guard case let .mkdirReply(reply)? = envelope.body else {
            await stopForFailure()
            await lease.complete(itemsPublished: false)
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        let item: PortableFSItem
        do {
            try validateParent(reply.attr, in: directory)
            item = try await adoptReplyItem(
                reply.attr,
                lease: lease,
                terminalOnAbandon: true
            )
        } catch {
            await stopForFailure()
            throw error
        }
        await lease.complete(itemsPublished: true)
        return PfsCreateResult(item: item, attr: reply.attr, canonicalName: name)
    }

    public func remove(item: PortableFSItem, named name: Data, from directory: PortableFSItem, isDirectory: Bool) async throws {
        try await pushDirtyData([item])
        try await removeAfterPush(item: item, named: name, from: directory, isDirectory: isDirectory)
    }

    func removeAfterPush(item: PortableFSItem, named name: Data, from directory: PortableFSItem, isDirectory: Bool) async throws {
        _ = try identity(for: item)
        var request = PfsRemoveRequest()
        request.dir = try identity(for: directory).proto
        request.name = name
        request.directory = isDirectory
        let envelope = try await client.request(.remove(request))
        guard case .removeReply? = envelope.body else {
            await stopForFailure()
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
    }

    @discardableResult
    public func rename(
        item: PortableFSItem,
        from sourceDirectory: PortableFSItem,
        sourceName: Data,
        to destinationDirectory: PortableFSItem,
        destinationName: Data,
        noReplace: Bool
    ) async throws -> Bool {
        try await pushDirtyData([item])
        return try await renameAfterPush(item: item, from: sourceDirectory, sourceName: sourceName,
                                         to: destinationDirectory, destinationName: destinationName, noReplace: noReplace)
    }

    func renameAfterPush(item: PortableFSItem, from sourceDirectory: PortableFSItem, sourceName: Data,
                         to destinationDirectory: PortableFSItem, destinationName: Data, noReplace: Bool) async throws -> Bool {
        let sourceIdentity = try identity(for: item)
        var request = PfsRenameRequest()
        request.fromDir = try identity(for: sourceDirectory).proto
        request.fromName = sourceName
        request.toDir = try identity(for: destinationDirectory).proto
        request.toName = destinationName
        request.noReplace = noReplace
        let envelope = try await client.request(.rename(request))
        guard case let .renameReply(reply)? = envelope.body else {
            await stopForFailure()
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        guard reply.newPostIdentity.count == 16,
              reply.newPostIdentity == sourceIdentity.stableIdentity,
              reply.oldPostIdentity.isEmpty || (
                reply.oldPostIdentity.count == 16
                    && reply.oldPostIdentity == sourceIdentity.stableIdentity
              ) else {
            await stopForFailure()
            throw PfsLocalClientError.connectionClosed
        }
        return !reply.oldPostIdentity.isEmpty
    }

    public func recordRenameReplacement(replacedItem: PortableFSItem) throws {
        // Rename-over removes one NAME, not necessarily the inode's last
        // link. The daemon owns the authoritative identity and link count:
        // another hard-link alias this mount never looked up may still
        // resolve to this same Item.
        // Keep the canonical object until FSKit's explicit reclaim boundary
        // and let getattr/lookup return the authority's actual nlink.
        _ = try identity(for: replacedItem)
    }

    public func symlink(in directory: PortableFSItem, name: Data, target: Data) async throws -> PfsCreateResult {
        var request = PfsSymlinkRequest()
        request.dir = try identity(for: directory).proto
        request.name = name
        request.target = target
        let lease = try await client.requestResource(.symlink(request))
        let envelope = lease.envelope
        guard case let .symlinkReply(reply)? = envelope.body else {
            await stopForFailure()
            await lease.complete(itemsPublished: false)
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        let item: PortableFSItem
        do {
            try validateParent(reply.attr, in: directory)
            item = try await adoptReplyItem(
                reply.attr,
                lease: lease,
                terminalOnAbandon: true
            )
        } catch {
            await stopForFailure()
            throw error
        }
        await lease.complete(itemsPublished: true)
        return PfsCreateResult(item: item, attr: reply.attr, canonicalName: name)
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

    public func hardLink(
        item: PortableFSItem,
        in directory: PortableFSItem,
        name: Data
    ) async throws -> PfsHardLinkResult {
        try await pushDirtyData([item])
        return try await hardLinkAfterPush(item: item, in: directory, name: name)
    }

    func hardLinkAfterPush(item: PortableFSItem, in directory: PortableFSItem, name: Data) async throws -> PfsHardLinkResult {
        var request = PfsHardLinkRequest()
        request.item = try identity(for: item).proto
        request.dir = try identity(for: directory).proto
        request.name = name
        let envelope = try await client.request(.hardLink(request))
        guard case let .hardLinkReply(reply)? = envelope.body else {
            await stopForFailure()
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        do {
            try validateAttributes(reply.attr, for: item)
        } catch {
            await stopForFailure()
            throw error
        }
        return PfsHardLinkResult(
            canonicalName: reply.name.isEmpty ? name : reply.name,
            attr: reply.attr
        )
    }

    public func xattrGet(item: PortableFSItem, name: String) async throws -> Data {
        let objectID = ObjectIdentifier(item)
        return try await withDescriptorGate(for: objectID) {
            try await xattrGetLocked(item: item, objectID: objectID, name: name)
        }
    }

    private func xattrGetLocked(
        item: PortableFSItem,
        objectID: ObjectIdentifier,
        name: String
    ) async throws -> Data {
        var request = PfsXattrGetRequest()
        request.item = try identity(for: item).proto
        request.name = name
        request.handle = openHandles[objectID]?.anyHandle ?? 0
        let envelope = try await client.request(.xattrGet(request))
        guard case let .xattrGetReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return reply.value
    }

    /// The fixed refusal for setting a user xattr. PortableFS user xattrs are
    /// readable and removable but never settable, and the refusal is local:
    /// no request is sent and nothing enters ordered publication. Precedence
    /// is fixed: a malformed request is EINVAL, which constructing `request`
    /// already decided before any item existed to consult; a reclaimed or
    /// foreign item is ESTALE; only a valid request on a live item reaches
    /// ENOTSUP, which the FSKit boundary maps to Darwin's EOPNOTSUPP so the
    /// VFS never falls back to an AppleDouble sidecar.
    public func refuseXattrSet(
        item: PortableFSItem,
        request: PfsXattrSetRequest
    ) throws -> Never {
        _ = try identity(for: item)
        throw PfsLocalClientError.daemon(
            errno: ENOTSUP,
            message: "PortableFS user xattrs are read-only"
        )
    }

    public func xattrList(item: PortableFSItem) async throws -> [String] {
        let objectID = ObjectIdentifier(item)
        return try await withDescriptorGate(for: objectID) {
            try await xattrListLocked(item: item, objectID: objectID)
        }
    }

    private func xattrListLocked(
        item: PortableFSItem,
        objectID: ObjectIdentifier
    ) async throws -> [String] {
        var request = PfsXattrListRequest()
        request.item = try identity(for: item).proto
        request.handle = openHandles[objectID]?.anyHandle ?? 0
        let envelope = try await client.request(.xattrList(request))
        guard case let .xattrListReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return reply.names
    }

    public func xattrRemove(item: PortableFSItem, name: String) async throws {
        let objectID = ObjectIdentifier(item)
        try await withDescriptorGate(for: objectID) {
            try await xattrRemoveLocked(item: item, objectID: objectID, name: name)
        }
    }

    private func xattrRemoveLocked(
        item: PortableFSItem,
        objectID: ObjectIdentifier,
        name: String
    ) async throws {
        var request = PfsXattrRemoveRequest()
        request.item = try identity(for: item).proto
        request.name = name
        request.handle = openHandles[objectID]?.anyHandle ?? 0
        let envelope = try await client.request(.xattrRemove(request))
        guard case .xattrRemoveReply? = envelope.body else {
            await stopForFailure()
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

    /// An explicit authority barrier over the authority's captured applied cut.
    /// Successful FSKit mutation replies are themselves the durability point.
    /// This call cannot cover kernel pages not yet delivered as callbacks or
    /// mutations not yet applied when the authority captures its cut. The caller
    /// or native framework must establish the required prior-work drain; native
    /// fsync/F_FULLFSYNC waiting and error propagation remain unproven. It does
    /// not withdraw kernel cache state. Authority failures surface to the
    /// caller rather than becoming local-only success.
    public func syncVolume() async throws {
        let envelope = try await client.request(.syncVolume(PfsSyncVolumeRequest()))
        guard case .syncVolumeReply? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
    }

    public func reclaim(item: PortableFSItem, nativeKernelCheck: Bool = false) async throws {
        let objectID = ObjectIdentifier(item)
        let identity = try identity(for: item)
        if retiringItems[identity] != nil {
            // Native reentry acknowledges the existing cleanup owner. Ordinary
            // core callers still wait for the exact retirement outcome.
            if nativeKernelCheck || kernelCache?.isPinned(item) == true { return }
            await waitForRetirement(identity)
            guard !stopped else { throw PfsLocalClientError.connectionClosed }
            return
        }
        if kernelCache?.deferCleanup(item, { [self] in
            do { try await self.reclaim(item: item, nativeKernelCheck: nativeKernelCheck) }
            catch { await self.client.close(error: error) }
        }) == true { return }
        // Detach even before waiting for an in-flight descriptor operation.
        // Otherwise a lookup could republish this object while reclaim queued.
        beginRetirement(item, identity: identity, objectID: objectID)
        kernelCache?.retiring(item, true)
        // Ownership cleanup must outlive caller cancellation, including while
        // waiting for the lifecycle gate. An unstructured task does not inherit
        // cancellation; awaiting its value still waits for the exact outcome.
        try await Task {
            try await completeRetirement(item, identity: identity, objectID: objectID, nativeKernelCheck: nativeKernelCheck)
        }.value
    }

    private func completeRetirement(
        _ item: PortableFSItem,
        identity: PfsItemIdentity,
        objectID: ObjectIdentifier,
        nativeKernelCheck: Bool
    ) async throws {
        var deferred = false
        defer { if !deferred { finishRetirement(identity: identity, objectID: objectID) } }
        do {
            try await withLifecycleGate(for: objectID) {
                await waitForSettlements(objectID: objectID)
                guard !stopped else { throw PfsLocalClientError.connectionClosed }
                // Settle every earlier lookup before checking FSKit's return
                // count. Retirement blocks new adoptions, and the publication
                // gate excludes concurrent framework replies and new pins.
                let prepareRetirement = { () -> (reclaim: Bool, deferred: Bool) in
                    if self.kernelCache?.deferCleanup(item, { [self] in
                        do {
                            try await self.completeRetirement(item, identity: identity, objectID: objectID,
                                                              nativeKernelCheck: nativeKernelCheck)
                        } catch { await self.client.close(error: error) }
                    }) == true {
                        return (false, true)
                    }
                    if nativeKernelCheck, #available(macOS 27, *) {
                        let retire = { self.retireReclaimedItem(item, objectID: objectID) }
                        let reclaimed = self.testingNativeReclaim?(item, retire) ?? item.tryReclaim(retire)
                        if !reclaimed {
                            self.itemsByIdentity[identity] = item
                            self.canonicalItemsByFileID[item.fileID, default: [:]][identity] = item
                            self.kernelCache?.retiring(item, false)
                            return (false, false)
                        }
                    } else {
                        self.kernelCache?.forget(item)
                    }
                    return (true, false)
                }
                let decision = kernelCache == nil ? prepareRetirement() : client.publicationGate.synchronized(prepareRetirement)
                deferred = decision.deferred
                guard decision.reclaim else { return }
                try await closeAllDaemonHandles(objectID: objectID)
                var request = PfsReclaimRequest()
                request.item = identity.proto
                let envelope = try await client.request(.reclaim(request))
                guard case .reclaimReply? = envelope.body else {
                    throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
                }
                retireReclaimedItem(item, objectID: objectID)
            }
        } catch {
            if error is PfsDispatchedReclaimError {
                await stopForFailure()
            } else if !stopped {
                if await client.isDetachingOrStopped {
                    // Whole-session cleanup owns remaining daemon resources.
                    retireReclaimedItem(item, objectID: objectID)
                } else {
                    // Even a confirmed Close can leave the accepted daemon item
                    // owned. A serving mount must not depend on another lookup
                    // to finish retirement after any pre-Reclaim failure.
                    await stopForFailure()
                }
            }
            if let error = error as? PfsDispatchedReclaimError { throw error.cause }
            throw error
        }
    }

    private func waitForRetirement(_ identity: PfsItemIdentity) async {
        while retiringItems[identity] != nil {
            await withCheckedContinuation { retirementWaiters[identity, default: []].append($0) }
        }
    }

    private func beginRetirement(_ item: PortableFSItem, identity: PfsItemIdentity, objectID: ObjectIdentifier) {
        retiringItems[identity] = objectID
        detachCanonicalItem(item)
    }

    private func detachCanonicalItem(_ item: PortableFSItem) {
        if itemsByIdentity[item.identity] === item { itemsByIdentity.removeValue(forKey: item.identity) }
        if canonicalItemsByFileID[item.fileID]?[item.identity] === item {
            canonicalItemsByFileID[item.fileID]?.removeValue(forKey: item.identity)
            if canonicalItemsByFileID[item.fileID]?.isEmpty == true {
                canonicalItemsByFileID.removeValue(forKey: item.fileID)
            }
        }
    }

    private func waitForSettlements(objectID: ObjectIdentifier) async {
        while provisionalItemReferences[objectID, default: 0] > 0 {
            await withCheckedContinuation { settlementWaiters[objectID, default: []].append($0) }
        }
    }

    private func finishRetirement(identity: PfsItemIdentity, objectID: ObjectIdentifier) {
        guard retiringItems[identity] == objectID else { return }
        retiringItems.removeValue(forKey: identity)
        let waiters = retirementWaiters.removeValue(forKey: identity) ?? []
        for waiter in waiters { waiter.resume() }
    }

    private func retireReclaimedItem(
        _ item: PortableFSItem,
        objectID: ObjectIdentifier
    ) {
        forgetObjectIdentity(objectID)
        itemsByObject.removeValue(forKey: objectID)
        publishedItems.remove(objectID)
        provisionalItemReferences.removeValue(forKey: objectID)
        let waiters = settlementWaiters.removeValue(forKey: objectID) ?? []
        for waiter in waiters { waiter.resume() }
        item.markReclaimed()
        kernelCache?.forget(item)
        detachCanonicalItem(item)
    }

    public func shutdown() async {
        await beginShutdown().value
    }

    /// A callback may be running on behalf of setCacheState. Fail publication
    /// and transport immediately, but let the one cleanup owner wait for the
    /// kernel call after this callback has returned its error.
    private func stopForFailure() async {
        let cleanup = beginShutdown()
        await client.close()
        if kernelCache == nil { await cleanup.value }
    }

    private func beginShutdown() -> Task<Void, Never> {
        if let shutdownTask { return shutdownTask }
        client.publicationGate.revoke(PfsLocalClientError.shutdown)
        stopped = true
        let cleanup = Task { [self] in
            await kernelCache?.withdraw(.revoke)
            await client.close()
            finishShutdown()
        }
        shutdownTask = cleanup
        return cleanup
    }

    private func finishShutdown() {
        for item in itemsByObject.values {
            item.markReclaimed()
            kernelCache?.forget(item)
        }
        itemsByIdentity.removeAll()
        canonicalItemsByFileID.removeAll()
        identitiesByObject.removeAll()
        objectIDsByItemID.removeAll()
        itemsByObject.removeAll()
        publishedItems.removeAll()
        provisionalItemReferences.removeAll()
        retiringItems.removeAll()
        let waiters = retirementWaiters.values.flatMap { $0 } + settlementWaiters.values.flatMap { $0 }
        retirementWaiters.removeAll()
        settlementWaiters.removeAll()
        for waiter in waiters { waiter.resume() }
        openHandles.removeAll()
    }

    // Direct callback tests cannot construct FSKit's kernel return counts.
    // Replace only that synchronous decision; retirement, close, IPC and
    // publication still follow the production path under the same gate.
    func testingNativeReclaimCheck(_ check: @escaping @Sendable (PortableFSItem, () -> Void) -> Bool) {
        testingNativeReclaim = check
    }

    func testingAdoptAttributes(_ attr: PfsAttr) throws -> PortableFSItem {
        try daemonItem(for: attr)
    }

    func testingDebugState() -> VolumeCoreDebugState {
        VolumeCoreDebugState(
            itemCount: itemsByIdentity.count,
            objectIdentityCount: identitiesByObject.count,
            publishedItemCount: publishedItems.count,
            provisionalItemCount: provisionalItemReferences.values.reduce(0, +),
            retiringItemCount: retiringItems.count,
            retirementWaiterCount: retirementWaiters.values.reduce(0) { $0 + $1.count },
            openHandleCount: openHandles.values.reduce(0) { $0 + $1.handleCount }
        )
    }

    /// Runs a complete descriptor operation under shared gate ownership. If
    /// the operation first needs a description for its access, it acquires
    /// that description exclusively and atomically downgrades to shared
    /// ownership before exposing the handle.
    private func withDescriptorHandle<T>(
        item: PortableFSItem,
        mode: PfsOpenMode,
        operation: (UInt64) async throws -> T
    ) async throws -> T {
        let objectID = ObjectIdentifier(item)
        try await acquireLifecycleGate(for: objectID, mode: .shared)
        if let handle = openHandles[objectID]?.handle(covering: mode) {
            defer { releaseLifecycleGate(for: objectID, mode: .shared) }
            return try await operation(handle)
        }
        releaseLifecycleGate(for: objectID, mode: .shared)

        try await acquireLifecycleGate(for: objectID, mode: .exclusive)
        let handle: UInt64
        do {
            handle = try await handleLocked(
                for: item,
                objectID: objectID,
                mode: mode
            )
            downgradeLifecycleGateToShared(for: objectID)
        } catch {
            releaseLifecycleGate(for: objectID, mode: .exclusive)
            throw error
        }
        defer { releaseLifecycleGate(for: objectID, mode: .shared) }
        return try await operation(handle)
    }

    private func handleLocked(
        for item: PortableFSItem,
        objectID: ObjectIdentifier,
        mode: PfsOpenMode
    ) async throws -> UInt64 {
        let identity = try identity(for: item)
        try await reconcileOpenHandleLocked(
            objectID: objectID,
            identity: identity,
            requestedMode: mode,
            origin: "io",
            fileID: item.fileID
        )
        guard let handle = openHandles[objectID]?.handle(covering: mode) else {
            throw PfsLocalClientError.unexpectedReply("open did not produce a handle")
        }
        return handle
    }

    /// Acquires only the access no held description grants, as one new
    /// description, while the object's lifecycle gate is held. No
    /// open/close/reclaim transition for this object can interleave across
    /// the daemon await below. A refused OPEN leaves every held description
    /// installed and usable.
    private func reconcileOpenHandleLocked(
        objectID: ObjectIdentifier,
        identity: PfsItemIdentity,
        requestedMode: PfsOpenMode,
        origin: StaticString,
        fileID: UInt64
    ) async throws {
        let held = openHandles[objectID] ?? OpenState()
        let missing = held.missing(requestedMode)
        // OPEN attribution for the measured LAN workload: whether an open or
        // I/O reused a held description, including CREATE's creation
        // description, or issued a real OPEN for missing access.
        client.trace.emit {
            PfsTraceRecord(.openDecision, connection: traceConnection, [
                "callback": PfsLocalClient.currentCallbackLabel,
                "origin": origin,
                "file": fileID,
                "requested": requestedMode.rawValue,
                "held": held.heldAccess.rawValue,
                "creation": held.creationHandle != nil,
                "opening": missing.rawValue,
            ])
        }
        guard missing != .unspecified else {
            return
        }
        let opened = try await openDaemonHandle(
            identity: identity,
            mode: missing
        )
        var state = openHandles[objectID] ?? OpenState()
        state.install(opened.handle, granting: missing)
        openHandles[objectID] = state
        if let item = itemsByObject[objectID] { kernelCache?.ownership(item, access: state.heldAccess) }
        opened.lease.acceptHandles()
        await opened.lease.complete(itemsPublished: true)
    }

    private func openDaemonHandle(
        identity: PfsItemIdentity,
        mode: PfsOpenMode
    ) async throws -> (handle: UInt64, lease: PfsResourceReplyLease) {
        var request = PfsOpenRequest()
        request.item = identity.proto
        request.mode = mode
        let lease = try await client.requestResource(.open(request))
        let envelope = lease.envelope
        guard case let .openReply(reply)? = envelope.body else {
            await lease.complete(itemsPublished: false)
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        guard reply.handle != 0 else {
            await client.close()
            throw PfsLocalClientError.connectionClosed
        }
        return (reply.handle, lease)
    }

    private struct DaemonCloseConfirmation {
        var terminalErrno: Int32?
    }

    /// A generic daemon error means the handle was not retired and must remain
    /// tracked. A CloseReply is a distinct, explicit retirement confirmation;
    /// its terminal errno is surfaced only after actor state forgets the now
    /// unusable descriptor.
    private func closeDaemonHandle(_ handle: UInt64) async throws -> DaemonCloseConfirmation {
        var request = PfsCloseRequest()
        request.handle = handle
        let envelope = try await client.request(.close(request))
        guard case let .closeReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        guard reply.retired else {
            throw PfsLocalClientError.unexpectedReply(
                "close reply did not confirm retirement for handle \(handle)"
            )
        }
        return DaemonCloseConfirmation(
            terminalErrno: reply.closeErrno == 0 ? nil : reply.closeErrno
        )
    }

    /// Closes every retired description in retirement order. A handle leaves
    /// actor state only after the daemon confirms that exact close; one that
    /// fails stays tracked for the next close or reclaim. Every handle gets
    /// its close attempt, and the first failure is surfaced afterwards.
    private func closePendingDaemonHandles(objectID: ObjectIdentifier) async throws {
        var firstFailure: Error?
        for handle in openHandles[objectID]?.pendingCloseHandles ?? [] {
            do {
                let confirmation = try await closeDaemonHandle(handle)
                openHandles[objectID]?.pendingCloseHandles.removeAll { $0 == handle }
                if let errno = confirmation.terminalErrno, firstFailure == nil {
                    firstFailure = PfsLocalClientError.daemon(
                        errno: errno,
                        message: "close retired handle \(handle) with a terminal error"
                    )
                }
            } catch {
                if firstFailure == nil { firstFailure = error }
            }
        }
        if openHandles[objectID]?.isEmpty == true {
            openHandles.removeValue(forKey: objectID)
        }
        if let firstFailure { throw firstFailure }
    }

    private func closeAllDaemonHandles(objectID: ObjectIdentifier) async throws {
        openHandles[objectID]?.retireAll()
        if let item = itemsByObject[objectID] { kernelCache?.ownership(item, access: .unspecified) }
        try await closePendingDaemonHandles(objectID: objectID)
    }

    /// Takes the exclusive side of one object's lifecycle gate. Descriptor
    /// operations take shared ownership, so they remain concurrent with each
    /// other while open/close/reclaim transitions wait for every in-flight RPC.
    private func withLifecycleGate<T>(
        for objectID: ObjectIdentifier,
        operation: () async throws -> T
    ) async throws -> T {
        try await acquireLifecycleGate(for: objectID, mode: .exclusive)
        defer { releaseLifecycleGate(for: objectID, mode: .exclusive) }
        return try await operation()
    }

    private func withDescriptorGate<T>(
        for objectID: ObjectIdentifier,
        operation: () async throws -> T
    ) async throws -> T {
        try await acquireLifecycleGate(for: objectID, mode: .shared)
        defer { releaseLifecycleGate(for: objectID, mode: .shared) }
        return try await operation()
    }

    private func acquireLifecycleGate(
        for objectID: ObjectIdentifier,
        mode: LifecycleGateMode
    ) async throws {
        try Task.checkCancellation()
        var state = lifecycleGates[objectID] ?? LifecycleGateState()
        let canAcquire: Bool
        switch mode {
        case .shared:
            // Do not bypass an already queued lifecycle transition.
            canAcquire = !state.exclusiveOwner && state.waiters.isEmpty
        case .exclusive:
            canAcquire = !state.exclusiveOwner
                && state.sharedOwners == 0
                && state.waiters.isEmpty
        }
        if canAcquire {
            switch mode {
            case .shared:
                state.sharedOwners += 1
            case .exclusive:
                state.exclusiveOwner = true
            }
            lifecycleGates[objectID] = state
            return
        }

        let waiterID = UUID()
        let acquired = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume(returning: false)
                    return
                }
                var current = lifecycleGates[objectID] ?? LifecycleGateState()
                current.waiters.append(
                    LifecycleWaiter(
                        id: waiterID,
                        mode: mode,
                        continuation: continuation
                    )
                )
                lifecycleGates[objectID] = current
            }
        } onCancel: {
            Task {
                await self.cancelLifecycleWaiter(
                    objectID: objectID,
                    waiterID: waiterID
                )
            }
        }
        guard acquired else {
            throw CancellationError()
        }
        if Task.isCancelled {
            // Ownership has already transferred from the prior operation.
            // Pass it to the next waiter before honoring cancellation.
            releaseLifecycleGate(for: objectID, mode: mode)
            throw CancellationError()
        }
    }

    private func cancelLifecycleWaiter(
        objectID: ObjectIdentifier,
        waiterID: UUID
    ) {
        guard var state = lifecycleGates[objectID],
              let index = state.waiters.firstIndex(where: { $0.id == waiterID }) else {
            return
        }
        let waiter = state.waiters.remove(at: index)
        lifecycleGates[objectID] = state
        wakeLifecycleWaiters(for: objectID)
        waiter.continuation.resume(returning: false)
    }

    private func releaseLifecycleGate(
        for objectID: ObjectIdentifier,
        mode: LifecycleGateMode
    ) {
        guard var state = lifecycleGates[objectID] else {
            return
        }
        switch mode {
        case .shared:
            precondition(state.sharedOwners > 0)
            state.sharedOwners -= 1
        case .exclusive:
            precondition(state.exclusiveOwner)
            state.exclusiveOwner = false
        }
        lifecycleGates[objectID] = state
        wakeLifecycleWaiters(for: objectID)
    }

    private func downgradeLifecycleGateToShared(for objectID: ObjectIdentifier) {
        guard var state = lifecycleGates[objectID] else {
            preconditionFailure("missing lifecycle gate during downgrade")
        }
        precondition(state.exclusiveOwner)
        precondition(state.sharedOwners == 0)
        state.exclusiveOwner = false
        state.sharedOwners = 1
        var ready: [LifecycleWaiter] = []
        while let next = state.waiters.first {
            guard case .shared = next.mode else {
                break
            }
            ready.append(state.waiters.removeFirst())
        }
        state.sharedOwners += ready.count
        lifecycleGates[objectID] = state
        for waiter in ready {
            waiter.continuation.resume(returning: true)
        }
    }

    private func wakeLifecycleWaiters(for objectID: ObjectIdentifier) {
        guard var state = lifecycleGates[objectID],
              !state.exclusiveOwner,
              state.sharedOwners == 0 else {
            return
        }
        guard let first = state.waiters.first else {
            lifecycleGates.removeValue(forKey: objectID)
            return
        }

        switch first.mode {
        case .exclusive:
            let waiter = state.waiters.removeFirst()
            state.exclusiveOwner = true
            lifecycleGates[objectID] = state
            waiter.continuation.resume(returning: true)
        case .shared:
            var ready: [LifecycleWaiter] = []
            while let next = state.waiters.first {
                guard case .shared = next.mode else {
                    break
                }
                ready.append(state.waiters.removeFirst())
            }
            state.sharedOwners += ready.count
            lifecycleGates[objectID] = state
            for waiter in ready {
                waiter.continuation.resume(returning: true)
            }
        }
    }

    // A malformed successful mutation reply is terminal: the applied result
    // cannot safely be published or retried. Non-mutating replies (including
    // zero-length writes) may fail just that callback, even on identity mismatch.
    private func validateFileAttributes(_ attr: PfsAttr, allowingRoot: Bool = false) throws {
        guard allowingRoot || attr.fileID != 1 else {
            throw PfsLocalClientError.invalidFrame("non-root item has the root file ID")
        }
        _ = try PfsFSKitMapping.itemIdentifier(from: attr.fileID)
        if attr.parentFileID != 0 { _ = try PfsFSKitMapping.itemIdentifier(from: attr.parentFileID) }
        guard PfsFSKitMapping.itemType(from: attr.kind) != .unknown else {
            throw PfsLocalClientError.invalidFrame("unknown item kind")
        }
    }

    private func validateAttributes(_ attr: PfsAttr, for item: PortableFSItem) throws {
        try validateFileAttributes(attr, allowingRoot: item === resolvedVolume?.root)
        guard PfsItemIdentity(attr.item) == item.identity,
              attr.fileID == item.fileID, attr.kind == item.kind else {
            throw PfsLocalClientError.invalidFrame("item attributes changed immutable identity")
        }
    }

    private func validateParent(_ attr: PfsAttr, in directory: PortableFSItem) throws {
        guard attr.parentFileID == directory.fileID else {
            throw PfsLocalClientError.invalidFrame("reply has an invalid parent file ID")
        }
    }

    /// An owning Item carries a positive ownership handle and generation and
    /// the authority's immutable 16-byte stable identity, which is never all
    /// zero. Non-owning enumeration entries carry an empty Item instead and
    /// never reach this check.
    private func validateOwningItem(_ item: PfsItem) throws {
        guard item.itemID > 0, item.itemGeneration > 0 else {
            throw PfsLocalClientError.invalidFrame("missing item ownership handle")
        }
        guard item.stableIdentity.count == 16,
              item.stableIdentity.contains(where: { $0 != 0 }) else {
            throw PfsLocalClientError.invalidFrame("owning item lacks its stable identity")
        }
    }

    private func daemonItem(for attr: PfsAttr, allowingRoot: Bool = false) throws -> PortableFSItem {
        try validateFileAttributes(attr, allowingRoot: allowingRoot)
        try validateOwningItem(attr.item)
        let identity = PfsItemIdentity(attr.item)
        for objectID in objectIDsByItemID[identity.itemID, default: []] {
            if let existing = itemsByObject[objectID], !existing.reclaimed,
               existing.identity != identity {
                throw PfsLocalClientError.invalidFrame("ownership handle reused by another identity")
            }
        }
        if let existing = itemsByIdentity[identity], !existing.reclaimed {
            try validateAttributes(attr, for: existing)
            return existing
        }
        // A file ID cannot denote two live inode incarnations. Retiring objects
        // are detached, allowing ordinary inode reuse after authority reclaim.
        for existing in canonicalItemsByFileID[attr.fileID, default: [:]].values where !existing.reclaimed {
            guard existing.identity.stableIdentity == identity.stableIdentity,
                  existing.kind == attr.kind else {
                throw PfsLocalClientError.invalidFrame("file ID reused by a live inode")
            }
        }
        let item = PortableFSItem(identity: identity, fileID: attr.fileID, kind: attr.kind)
        kernelCache?.retain(item)
        itemsByIdentity[identity] = item
        canonicalItemsByFileID[attr.fileID, default: [:]][identity] = item
        register(item: item, identity: identity)
        return item
    }

    private func adoptReplyItem(
        _ attr: PfsAttr,
        lease: PfsResourceReplyLease,
        terminalOnAbandon: Bool = false
    ) async throws -> PortableFSItem {
        let identity = PfsItemIdentity(attr.item)
        await waitForRetirement(identity)
        guard !stopped else { throw PfsLocalClientError.connectionClosed }
        let item = try daemonItem(for: attr)
        let objectID = ObjectIdentifier(item)
        provisionalItemReferences[objectID, default: 0] += 1
        lease.registerItemSettlement { [weak self, weak item] acceptedCount in
            guard let self, let item else { return }
            if acceptedCount == 0, terminalOnAbandon {
                await self.stopForFailure()
                return
            }
            await self.settleProvisionalItem(item: item, published: acceptedCount > 0)
        }
        return item
    }

    private func settleProvisionalItem(item: PortableFSItem, published: Bool) {
        let objectID = ObjectIdentifier(item)
        guard let references = provisionalItemReferences[objectID] else { return }
        let remaining = references - 1
        if remaining == 0 {
            provisionalItemReferences.removeValue(forKey: objectID)
            let waiters = settlementWaiters.removeValue(forKey: objectID) ?? []
            for waiter in waiters { waiter.resume() }
        } else {
            provisionalItemReferences[objectID] = remaining
        }
        if published, !item.reclaimed { publishedItems.insert(objectID) }
        guard remaining == 0, !publishedItems.contains(objectID),
              retiringItems[item.identity] != objectID,
              openHandles[objectID] == nil else { return }
        retireReclaimedItem(item, objectID: objectID)
    }

    private func identity(for item: PortableFSItem) throws -> PfsItemIdentity {
        let objectID = ObjectIdentifier(item)
        guard let identity = identitiesByObject[objectID] else {
            throw PfsLocalClientError.daemon(errno: ESTALE, message: "item was reclaimed")
        }
        return identity
    }

    private func register(item: PortableFSItem, identity: PfsItemIdentity) {
        let objectID = ObjectIdentifier(item)
        identitiesByObject[objectID] = identity
        objectIDsByItemID[identity.itemID, default: []].insert(objectID)
        itemsByObject[objectID] = item
    }

    private func forgetObjectIdentity(_ objectID: ObjectIdentifier) {
        guard let identity = identitiesByObject.removeValue(forKey: objectID) else { return }
        objectIDsByItemID[identity.itemID]?.remove(objectID)
        if objectIDsByItemID[identity.itemID]?.isEmpty == true {
            objectIDsByItemID.removeValue(forKey: identity.itemID)
        }
    }

    private func ioChunkSize() -> Int {
        let preferred = Int(resolvedVolume?.capabilities.preferredIoBytes ?? 0)
        let base = preferred > 0 ? preferred : Self.maximumIOChunkBytes
        return max(1, min(base, Self.maximumIOChunkBytes))
    }
}

extension PfsOpenMode {
    var grantsRead: Bool { self == .read || self == .readWrite }
    var grantsWrite: Bool { self == .write || self == .readWrite }

    init(read: Bool, write: Bool) {
        switch (read, write) {
        case (true, true): self = .readWrite
        case (true, false): self = .read
        case (false, true): self = .write
        case (false, false): self = .unspecified
        }
    }
}
