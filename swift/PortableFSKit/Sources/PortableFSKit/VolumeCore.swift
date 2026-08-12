import Foundation
import FSKit
@preconcurrency import Darwin

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
    public var resourceRequestID: UInt64
}

public struct PfsEnumerateResult: Sendable {
    public var entries: [PfsDirectoryEntry]
    public var verifier: UInt64
    public var nextCookie: UInt64
    /// pfslocal request whose provisional page resources produced `entries`.
    /// The FSKit adapter uses it to abandon a page suffix its packer declined.
    public var resourceRequestID: UInt64
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
    /// The extension always FORWARDS the intent: only the daemon knows whether
    /// this attach's authority persists flags, so it — not the mapping layer —
    /// is what answers ENOTSUP when it cannot.
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
    /// The raw resolve reply and validated terms of a strict-v3 attach whose
    /// declared cache policy exactly matches this frontend adapter. The FSKit
    /// adapter composes its coherence stack from these before the volume may
    /// serve; a different declared policy is never treated as a fallback.
    public private(set) var strictV3ResolveReply: PfsResolveReply?
    public private(set) var strictV3Contract: PfsMacOSV3LocalContract?
    private let supportedCachePolicies: Set<PfsMacOSCachePolicy>

    private var itemsByIdentity: [PfsItemIdentity: PortableFSItem] = [:]
    private var identitiesByObject: [ObjectIdentifier: PfsItemIdentity] = [:]
    private var itemsByObject: [ObjectIdentifier: PortableFSItem] = [:]
    private var deletedItemsByObject: [ObjectIdentifier: DeletedItemState] = [:]
    private var currentGenerationByItemID: [UInt64: UInt64] = [:]
    private var publishedItemIdentities: Set<PfsItemIdentity> = []
    private var provisionalItemReferences: [PfsItemIdentity: Int] = [:]
    private var openHandles: [ObjectIdentifier: OpenState] = [:]
    private var lifecycleGates: [ObjectIdentifier: LifecycleGateState] = [:]
    /// Items that exist only inside this process, for the macOS 26 repair
    /// scratch entry. FSKit's create callback must hand the kernel an `FSItem`,
    /// but the entry it names must never be known to the daemon, so these are
    /// deliberately absent from every identity table above. The only thing that
    /// can reach one is the kernel reference the create callback returned.
    private struct LocalRepairBindingKey: Hashable {
        let parentIdentity: Data
        let name: Data
    }

    private struct LocalRepairItemState {
        let item: PortableFSItem
        let binding: LocalRepairBindingKey
        var attributes: PfsAttr
        var xattrs: [String: Data] = [:]
    }

    private var localRepairItems: [ObjectIdentifier: LocalRepairItemState] = [:]
    /// The scratch create is a real kernel namespace transition even though it
    /// is not an authority mutation. A following unlink may resolve the name
    /// again before FSKit sends removeItem, so the local object needs one
    /// exact, process-local binding just like an ordinary filesystem object.
    private var localRepairBindings: [LocalRepairBindingKey: PortableFSItem] = [:]
    /// Minted downward through the high-half raw pfslocal identifier partition;
    /// `daemonItem(for:)` refuses a daemon item that lands in it before the
    /// object enters any identity table, so a synthetic identifier can never
    /// be confused with an authority item.
    private var nextLocalRepairItemID: UInt64 = UInt64.max - 1

    private struct OpenState: Sendable {
        var identity: PfsItemIdentity
        var handle: UInt64
        var mode: PfsOpenMode
        var isImplicit: Bool
        var attrSnapshot: PfsAttr?
        // Handles superseded by a successful mode upgrade remain owned here
        // until the daemon confirms each close. This prevents a failed close
        // from turning a live daemon descriptor into unreachable state.
        var pendingCloseHandles: [UInt64]
    }

    private struct DeletedItemState: Sendable {
        var identity: PfsItemIdentity
        var attrSnapshot: PfsAttr?
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

    public init(
        client: PfsLocalClient,
        supportedCachePolicies: Set<PfsMacOSCachePolicy> = [
            .synchronousVFSRepairV1,
            .synchronousVFSRepairV2,
        ]
    ) {
        self.client = client
        self.supportedCachePolicies = supportedCachePolicies
    }

    public static func connect(
        socketPath: String,
        attachRef: String,
        supportedCachePolicies: Set<PfsMacOSCachePolicy> = [
            .synchronousVFSRepairV1,
            .synchronousVFSRepairV2,
        ],
        configuration: PfsLocalClient.Configuration = .init()
    ) async throws -> VolumeCore {
        let client = PfsLocalClient(socketPath: socketPath, configuration: configuration)
        let core = VolumeCore(
            client: client,
            supportedCachePolicies: supportedCachePolicies
        )
        try await core.resolve(attachRef: attachRef)
        return core
    }

    @discardableResult
    public func resolve(attachRef: String) async throws -> PfsResolvedVolume {
        let reply = try await client.resolve(attachRef: attachRef)
        if reply.hasV3Coherence {
            // Cache-coherence behavior is a DECLARED policy carried by the
            // resolve contract, never an OS inference. Every frontend adapter
            // declares the exact named policies it implements. The macOS 26
            // adapter keeps both frozen compatibility revisions; the native
            // adapter declares only its native policy. A mismatch follows the
            // same close-first discipline as an unknown policy, so portablefsd
            // fails its authority session rather than waiting for a subscriber
            // that will never honor the promised repair contract.
            let contract: PfsMacOSV3LocalContract
            do {
                contract = try PfsLocalMacOSV3CoherenceTransport.parseContract(reply.v3Coherence)
            } catch {
                await client.close()
                if case PfsMacOSCoherenceError.invalidCachePolicy = error {
                    throw PfsLocalClientError.v3CoherenceIntegrationUnavailable
                }
                throw error
            }
            guard supportedCachePolicies.contains(contract.cachePolicy) else {
                await client.close()
                throw PfsLocalClientError.v3CoherenceIntegrationUnavailable
            }
            strictV3ResolveReply = reply
            strictV3Contract = contract
        }
        let root = try daemonItem(for: reply.root)
        publishedItemIdentities.insert(root.identity)
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

    /// Mints a process-local `FSItem` for a macOS 26 repair scratch entry.
    ///
    /// The identifier comes from the reserved top of the space that
    /// `PfsFSKitMapping.itemIdentifier(from:)` refuses for daemon items, so the
    /// kernel can never see one identifier standing for two different things.
    /// The item is registered in no identity table: `identity(for:)` will
    /// refuse it, which is the point — nothing can turn it into a pfslocal
    /// request.
    public func mintLocalRepairItem(
        parent: PortableFSItem,
        name: Data,
        mode: UInt32,
        uid: UInt32,
        gid: UInt32
    ) throws -> PortableFSItem {
        let binding = LocalRepairBindingKey(
            parentIdentity: parent.identity.stableIdentity,
            name: name
        )
        guard localRepairBindings[binding] == nil else {
            throw PfsLocalClientError.daemon(
                errno: EEXIST,
                message: "local repair binding already exists"
            )
        }
        guard nextLocalRepairItemID >= PfsFSKitMapping.localRepairIdentifierFloor else {
            throw PfsLocalClientError.daemon(
                errno: ENOSPC,
                message: "local repair identifier space exhausted"
            )
        }
        let identity = PfsItemIdentity(itemID: nextLocalRepairItemID, generation: 0)
        nextLocalRepairItemID -= 1
        let item = PortableFSItem(identity: identity)
        let nowMilliseconds = Int64(Date().timeIntervalSince1970 * 1_000)
        var attributes = PfsAttr()
        attributes.item = identity.proto
        attributes.parent = parent.identity.proto
        attributes.kind = .file
        attributes.mode = mode
        attributes.nlink = 1
        attributes.uid = uid
        attributes.gid = gid
        attributes.flags = 0
        attributes.size = 0
        attributes.allocSize = 0
        attributes.atimeMs = nowMilliseconds
        attributes.mtimeMs = nowMilliseconds
        attributes.ctimeMs = nowMilliseconds
        attributes.birthtimeMs = nowMilliseconds
        localRepairItems[ObjectIdentifier(item)] = LocalRepairItemState(
            item: item,
            binding: binding,
            attributes: attributes
        )
        localRepairBindings[binding] = item
        return item
    }

    public func isLocalRepairItem(_ item: PortableFSItem) -> Bool {
        localRepairItems[ObjectIdentifier(item)] != nil
    }

    public func localRepairAttributes(_ item: PortableFSItem) -> PfsAttr? {
        localRepairItems[ObjectIdentifier(item)]?.attributes
    }

    public func localRepairItem(
        in parent: PortableFSItem,
        named name: Data
    ) -> PortableFSItem? {
        localRepairBindings[
            LocalRepairBindingKey(
                parentIdentity: parent.identity.stableIdentity,
                name: name
            )
        ]
    }

    /// Returns `nil` only when `item` is not a live synthetic repair item.
    /// A live item with no value returns `.some(nil)`; the distinction keeps a
    /// missing local xattr from accidentally falling through to the daemon.
    public func localRepairXattr(
        named name: String,
        of item: PortableFSItem
    ) -> Data?? {
        guard let state = localRepairItems[ObjectIdentifier(item)] else {
            return nil
        }
        return .some(state.xattrs[name])
    }

    public func localRepairXattrs(of item: PortableFSItem) -> [String]? {
        guard let state = localRepairItems[ObjectIdentifier(item)] else {
            return nil
        }
        return state.xattrs.keys.sorted()
    }

    /// Applies one normal xattr policy to the process-local scratch object.
    /// `false` means the item is not local; every local outcome either applies
    /// or throws the same POSIX error an authority-backed object would.
    public func updateLocalRepairXattr(
        named name: String,
        value: Data?,
        on item: PortableFSItem,
        createOnly: Bool,
        replaceOnly: Bool,
        remove: Bool
    ) throws -> Bool {
        let key = ObjectIdentifier(item)
        guard var state = localRepairItems[key] else { return false }
        let exists = state.xattrs[name] != nil
        if remove {
            guard exists else {
                throw PfsLocalClientError.daemon(errno: ENOATTR, message: "xattr missing")
            }
            state.xattrs.removeValue(forKey: name)
        } else {
            if createOnly && exists {
                throw PfsLocalClientError.daemon(errno: EEXIST, message: "xattr exists")
            }
            if replaceOnly && !exists {
                throw PfsLocalClientError.daemon(errno: ENOATTR, message: "xattr missing")
            }
            state.xattrs[name] = value ?? Data()
        }
        localRepairItems[key] = state
        return true
    }

    public func releaseLocalRepairItem(_ item: PortableFSItem) {
        if let state = localRepairItems.removeValue(forKey: ObjectIdentifier(item)) {
            if localRepairBindings[state.binding] === item {
                localRepairBindings.removeValue(forKey: state.binding)
            }
            state.item.markReclaimed()
        }
    }

    /// Retires only the process-local namespace coordinate for a synthetic
    /// repair item. `removeItem` is not the end of the item's vnode lifetime:
    /// FSKit may still deliver getattr/open/close/reclaim while unlinkat(2) is
    /// completing. Keeping the object classified locally until the repair
    /// lease releases prevents that teardown tail from entering the closed
    /// authority publication gate.
    public func retireLocalRepairBinding(_ item: PortableFSItem) {
        guard let state = localRepairItems[ObjectIdentifier(item)],
              localRepairBindings[state.binding] === item else {
            return
        }
        localRepairBindings.removeValue(forKey: state.binding)
    }

    public func localRepairItemCount() -> Int { localRepairItems.count }

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
        let lease = try await client.requestResource(.lookup(request))
        let envelope = lease.envelope
        guard case let .lookupReply(reply)? = envelope.body else {
            await lease.complete(itemsPublished: false)
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        let item: PortableFSItem
        do {
            item = try adoptReplyItem(reply.attr.item, lease: lease)
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
            var request = PfsEnumerateRequest()
            request.dir = try identity(for: directory).proto
            request.cookie = cookie
            request.maxEntries = max(1, maxEntries)
            request.wantAttrs = wantAttributes
            request.handle = handle
            let lease = try await client.requestResource(.enumerate(request))
            let envelope = lease.envelope
            guard case let .enumerateReply(reply)? = envelope.body else {
                await lease.complete(itemsPublished: false)
                throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
            }

            let entries = reply.entries.map { entry in
                PfsDirectoryEntry(
                    name: entry.name,
                    attr: entry.attr,
                    nextCookie: entry.cookie,
                    resourceRequestID: envelope.requestID
                )
            }
            // A typed direct caller receives raw directory metadata, not
            // canonical FSItems. Default to accepting no reply items; the
            // FSKit adapter overwrites this with its exact packed prefix before
            // the outer publication boundary settles.
            lease.acceptItemPrefix(0)
            await lease.complete(itemsPublished: true)
            return PfsEnumerateResult(
                entries: entries,
                verifier: reply.dirVersion,
                nextCookie: reply.nextCookie,
                resourceRequestID: envelope.requestID
            )
        }
    }

    /// Adopts only directory entries FSKit's packer actually accepted. Raw
    /// Enumerate pages stay outside the canonical item tables until this call,
    /// so an unpacked suffix cannot leave stale local identities after its
    /// daemon-side provisional resources are abandoned.
    func adoptEnumeratedItems(
        _ entries: [PfsDirectoryEntry]
    ) throws -> [PortableFSItem] {
        // A direct core.enumerate has already sent prefix 0, so its raw metadata
        // is observational only. Adoption is valid solely inside the adapter's
        // still-live outer publication collector, before that exact reply's
        // disposition is emitted.
        for requestID in Set(entries.map(\.resourceRequestID)) {
            guard client.canAdoptResourceReply(requestID) else {
                throw PfsLocalClientError.invalidFrame(
                    "enumeration item adoption requires an unsettled resource reply"
                )
            }
        }
        // Validate the whole batch before mutating any canonical table.
        for entry in entries {
            guard entry.attr.item.itemID > 0,
                  entry.attr.item.itemID < PfsFSKitMapping.localRepairIdentifierFloor else {
                throw PfsLocalClientError.daemon(
                    errno: EOVERFLOW,
                    message: "daemon item identifier enters the local repair partition"
                )
            }
        }
        var adopted: [PortableFSItem] = []
        adopted.reserveCapacity(entries.count)
        var byRequest: [UInt64: [(PfsItemIdentity, PortableFSItem)]] = [:]
        for entry in entries {
            let (item, identity) = try adoptProvisionalDaemonItem(
                for: entry.attr.item
            )
            adopted.append(item)
            byRequest[entry.resourceRequestID, default: []].append((identity, item))
        }
        for (requestID, items) in byRequest {
            client.registerResourceItemSettlement(targetRequestID: requestID) {
                [weak self] acceptedCount in
                guard let self else { return }
                for (index, owned) in items.enumerated() {
                    await self.settleProvisionalItem(
                        identity: owned.0,
                        item: owned.1,
                        published: index < Int(acceptedCount)
                    )
                }
            }
        }
        return adopted
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
        if let deleted = deletedItemsByObject[objectID] {
            guard openHandles[objectID] != nil else {
                throw PfsLocalClientError.daemon(errno: ENOENT, message: "item was unlinked")
            }
            // A retained descriptor is the native FSKit object lifetime.
            // Never answer fstat from the deletion snapshot: writes and
            // metadata changes after unlink would make it stale.
            _ = deleted
        }

        var request = PfsGetAttrRequest()
        request.item = try identity(for: item).proto
        request.handle = openHandles[objectID]?.handle ?? 0
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
        _ = try self.daemonItem(for: reply.attr.item)
        rememberAttrSnapshot(reply.attr, for: objectID)
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
        request.handle = openHandles[objectID]?.handle ?? 0
        if let mode = attributes.mode { request.mode = mode }
        if let uid = attributes.uid { request.uid = uid }
        if let gid = attributes.gid { request.gid = gid }
        if let size = attributes.size { request.size = size }
        if let mtime = attributes.mtimeMilliseconds { request.mtimeMs = mtime }
        if let atime = attributes.atimeMilliseconds { request.atimeMs = atime }
        if let flags = attributes.flags {
            // The forwarding invariant, at the boundary that actually sends
            // the frame: `set_flags`/`flags` are APPENDED fields, so a daemon
            // built before them discards both and applies the rest of the
            // setattr as if the flags change had never been asked for. Only an
            // affirmative `flagsUnderstood` in this attach's resolve reply
            // proves the daemon reads them; anything else — including the
            // absent field an old daemon leaves at false — is refused here
            // rather than turned into a successful no-op.
            //
            // The check is COMPREHENSION, never `flagsSupported`: that field
            // is about the authority's durable storage, and a machine-local
            // graft in the same namespace needs no authority feature to make
            // chflags(2) stick. Whether THIS object can take a flag word is
            // the daemon's call, per target, answered as an errno.
            guard resolvedVolume?.capabilities.flagsUnderstood == true else {
                throw PfsLocalClientError.daemon(
                    errno: ENOTSUP,
                    message: "this PortableFS daemon does not understand BSD file flags"
                )
            }
            // setFlags is the intent; a zero word is a legal "clear
            // everything", so the bool must be set even when flags stays 0.
            request.setFlags = true
            request.flags = flags
        }

        let envelope = try await client.request(.setAttr(request))
        guard case let .setAttrReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        _ = try self.daemonItem(for: reply.attr.item)
        rememberAttrSnapshot(reply.attr, for: objectID)
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
        try await reconcileOpenHandleLocked(
            objectID: objectID,
            identity: identity,
            requestedMode: mode,
            implicit: false,
            attrSnapshot: attrSnapshot
        )
    }

    public func close(item: PortableFSItem, retainingModes: PfsOpenMode? = nil) async throws {
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
        let identity = try identity(for: item)
        guard let state = openHandles[objectID] else {
            return
        }

        let retainedMode = retainingModes ?? .unspecified
        if retainedMode == .unspecified {
            try await closeAllDaemonHandles(objectID: objectID)
            return
        }

        // FSKit reports the modes that remain live, not a request to replace
        // the backing descriptor. A broader descriptor already covers that
        // retained access and, critically, may be the only remaining
        // capability for an unlinked or rename-replaced object.
        if Self.mode(state.mode, covers: retainedMode) {
            try await closePendingDaemonHandles(objectID: objectID)
            return
        }

        let opened = try await openDaemonHandle(
            identity: identity,
            mode: retainedMode
        )
        var replacement = OpenState(
            identity: identity,
            handle: opened.handle,
            mode: retainedMode,
            isImplicit: state.isImplicit,
            attrSnapshot: state.attrSnapshot,
            pendingCloseHandles: state.pendingCloseHandles
        )
        replacement.pendingCloseHandles.append(state.handle)
        openHandles[objectID] = replacement
        opened.lease.acceptHandles()
        await opened.lease.complete(itemsPublished: true)
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

    @discardableResult
    public func write(item: PortableFSItem, offset: UInt64, data: Data) async throws -> (written: UInt32, attr: PfsAttr) {
        let objectID = ObjectIdentifier(item)
        return try await withDescriptorHandle(item: item, mode: .readWrite) { handle in
            if data.isEmpty {
                let result = try await writeChunk(handle: handle, offset: offset, data: data)
                rememberAttrSnapshot(result.attr, for: objectID)
                return result
            }

            // ── COMMITTED PROGRESS OUTRANKS THE ERROR THAT FOLLOWED IT ──────
            //
            // One framework write callback becomes SEVERAL daemon requests, and
            // every one of them is separately acknowledged: by the time chunk k
            // fails, chunks 0..<k are already in the mount's stream WAL (or at
            // the authority) and are as durable as anything this stack ever
            // promises. Throwing here discarded that count and the adapter
            // replied `(0, error)` — telling the kernel that nothing at all was
            // written about bytes that are on media.
            //
            // That is a lie in the direction POSIX is least forgiving of, and
            // the daemon already refuses to tell it on its own half of the same
            // boundary: "A host short write reports both a count and an error.
            // The count is committed progress and outranks the error for exactly
            // the reason a post-commit failure does: reporting zero invites a
            // retry that duplicates an append." (portablefsd/ops.go, attach.write).
            // The two ends of one wire must not disagree about what a partially
            // completed write looks like.
            //
            // So a failure that arrives with committed bytes behind it is
            // reported as a SHORT WRITE, not as a failure. Nothing is swallowed:
            // the kernel reissues the remainder as a fresh callback, that
            // callback starts at totalWritten == 0, and whatever is still wrong
            // surfaces there as the error it is — plus at the next fsync,
            // synchronize or unmount barrier, which are the drain barriers this
            // mount's durability contract is actually written about. An error is
            // thrown from here only when NOTHING committed, which is the one
            // case where the error is the whole truth.
            var totalWritten = 0
            var currentOffset = offset
            var latestAttr: PfsAttr?
            let chunkSize = ioChunkSize()

            let fallbackAttr = openHandles[objectID]?.attrSnapshot ?? PfsAttr()
            func committed() -> (written: UInt32, attr: PfsAttr) {
                (UInt32(clamping: totalWritten), latestAttr ?? fallbackAttr)
            }

            while totalWritten < data.count {
                let end = min(data.count, totalWritten + chunkSize)
                let chunk = data.subdata(in: totalWritten..<end)
                let result: (written: UInt32, attr: PfsAttr)
                do {
                    result = try await writeChunk(handle: handle, offset: currentOffset, data: chunk)
                } catch {
                    if totalWritten > 0 {
                        return committed()
                    }
                    throw error
                }
                latestAttr = result.attr
                rememberAttrSnapshot(result.attr, for: objectID)
                let written = Int(result.written)
                if written <= 0 {
                    // A non-empty chunk that committed nothing and reported no
                    // errno. The daemon refuses to produce this outcome
                    // (attach.write answers EIO for it), so reaching here means
                    // the invariant broke — but whatever earlier chunks
                    // committed is still committed.
                    if totalWritten > 0 {
                        return committed()
                    }
                    throw PfsLocalClientError.daemon(
                        errno: EIO,
                        message: "daemon write made no progress"
                    )
                }
                totalWritten += written
                currentOffset += UInt64(written)
                if written < chunk.count {
                    break
                }
            }
            return committed()
        }
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
        let lease = try await client.requestResource(.create(request))
        let envelope = lease.envelope
        guard case let .createReply(reply)? = envelope.body else {
            await lease.complete(itemsPublished: false)
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        guard reply.handle != 0 else {
            // Create's success contract transfers an open descriptor. Sending
            // accept_handles for zero would itself violate minor 12; accepting
            // only the item would publish a file whose required open state was
            // never installed. Retire the ownership epoch instead.
            await client.close()
            throw PfsLocalClientError.connectionClosed
        }
        let newItem: PortableFSItem
        do {
            newItem = try adoptReplyItem(
                reply.attr.item,
                lease: lease,
                terminalOnAbandon: true
            )
        } catch {
            // The namespace mutation is already durable at the daemon. A
            // frontend that cannot map its successful post-apply reply cannot
            // honestly publish or retry it, so strict mode fails terminally.
            await client.close()
            throw PfsLocalClientError.connectionClosed
        }
        openHandles[ObjectIdentifier(newItem)] = OpenState(
            identity: PfsItemIdentity(reply.attr.item),
            handle: reply.handle,
            mode: .readWrite,
            isImplicit: false,
            attrSnapshot: reply.attr,
            pendingCloseHandles: []
        )
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
            await lease.complete(itemsPublished: false)
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        let item: PortableFSItem
        do {
            item = try adoptReplyItem(
                reply.attr.item,
                lease: lease,
                terminalOnAbandon: true
            )
        } catch {
            await client.close()
            throw PfsLocalClientError.connectionClosed
        }
        await lease.complete(itemsPublished: true)
        return PfsCreateResult(item: item, attr: reply.attr, canonicalName: name)
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
        // Rename-over removes one NAME, not necessarily the inode's last
        // link. The daemon owns the authoritative identity and link count:
        // a peer-only hard-link alias may still resolve to this same Item.
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
            await lease.complete(itemsPublished: false)
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        let item: PortableFSItem
        do {
            item = try adoptReplyItem(
                reply.attr.item,
                lease: lease,
                terminalOnAbandon: true
            )
        } catch {
            await client.close()
            throw PfsLocalClientError.connectionClosed
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
        var request = PfsHardLinkRequest()
        request.item = try identity(for: item).proto
        request.dir = try identity(for: directory).proto
        request.name = name
        let envelope = try await client.request(.hardLink(request))
        guard case let .hardLinkReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
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
        request.handle = openHandles[objectID]?.handle ?? 0
        let envelope = try await client.request(.xattrGet(request))
        guard case let .xattrGetReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return reply.value
    }

    public func xattrSet(item: PortableFSItem, name: String, value: Data, createOnly: Bool, replaceOnly: Bool) async throws {
        let objectID = ObjectIdentifier(item)
        try await withDescriptorGate(for: objectID) {
            try await xattrSetLocked(
                item: item,
                objectID: objectID,
                name: name,
                value: value,
                createOnly: createOnly,
                replaceOnly: replaceOnly
            )
        }
    }

    /// Validate a set-xattr callback before it enters publication admission.
    ///
    /// A production XFS attach negotiates xattr-set as unsupported. That
    /// verdict is independent of a coherence repair and must therefore reach
    /// FSKit before an ordered callback can be refused by a closed PREPARE
    /// gate. The same helper is reused by the forwarding path so item/name/
    /// mode validation cannot drift between preflight and execution.
    func preflightXattrSet(
        item: PortableFSItem,
        name: String,
        createOnly: Bool,
        replaceOnly: Bool
    ) throws {
        _ = try validatedXattrSetIdentity(
            item: item,
            name: name,
            createOnly: createOnly,
            replaceOnly: replaceOnly
        )
        guard resolvedVolume?.capabilities.xattrSetSupported == true else {
            throw PfsLocalClientError.daemon(
                errno: ENOTSUP,
                message: "xattr set is not supported by this daemon"
            )
        }
    }

    private func xattrSetLocked(
        item: PortableFSItem,
        objectID: ObjectIdentifier,
        name: String,
        value: Data,
        createOnly: Bool,
        replaceOnly: Bool
    ) async throws {
        let itemIdentity = try validatedXattrSetIdentity(
            item: item,
            name: name,
            createOnly: createOnly,
            replaceOnly: replaceOnly
        )
        guard resolvedVolume?.capabilities.xattrSetSupported == true else {
            throw PfsLocalClientError.daemon(
                errno: ENOTSUP,
                message: "xattr set is not supported by this daemon"
            )
        }
        var request = PfsXattrSetRequest()
        request.item = itemIdentity.proto
        request.name = name
        request.value = value
        request.createOnly = createOnly
        request.replaceOnly = replaceOnly
        request.handle = openHandles[objectID]?.handle ?? 0
        let envelope = try await client.request(.xattrSet(request))
        guard case .xattrSetReply? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
    }

    private func validatedXattrSetIdentity(
        item: PortableFSItem,
        name: String,
        createOnly: Bool,
        replaceOnly: Bool
    ) throws -> PfsItemIdentity {
        // Validate request grammar before resolving the item, then consult the
        // negotiated forwarding capability. This pins the public precedence:
        // malformed request (EINVAL), reclaimed/foreign item (ESTALE), valid
        // unsupported set (ENOTSUP, mapped to Darwin EOPNOTSUPP).
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
        return try identity(for: item)
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
        request.handle = openHandles[objectID]?.handle ?? 0
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
        request.handle = openHandles[objectID]?.handle ?? 0
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

    /// The v3 authority durability barrier. There is no client or daemon
    /// write-back tail: filesystem mutations are synchronous authority calls
    /// against raw XFS. Success here means the authority applied every prior
    /// operation in its order and completed its `syncfs` cut. Cache-visible
    /// mutations use their own two-phase repair protocol; this call does not
    /// invent an additional macOS cache-revocation boundary. There is no
    /// degraded local-only success: an unreachable, slow, or fenced authority
    /// fails the barrier and surfaces to the kernel caller.
    public func syncVolume() async throws {
        let envelope = try await client.request(.syncVolume(PfsSyncVolumeRequest()))
        guard case .syncVolumeReply? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
    }

    public func fsync(item: PortableFSItem) async throws {
        let objectID = ObjectIdentifier(item)
        try await withDescriptorGate(for: objectID) {
            try await fsyncLocked(item: item, objectID: objectID)
        }
    }

    private func fsyncLocked(
        item: PortableFSItem,
        objectID: ObjectIdentifier
    ) async throws {
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
        try await withLifecycleGate(for: objectID) {
            try await reclaimLocked(item: item, objectID: objectID)
        }
    }

    private func reclaimLocked(
        item: PortableFSItem,
        objectID: ObjectIdentifier
    ) async throws {
        let identity = try identity(for: item)

        if openHandles[objectID] != nil {
            try await closeAllDaemonHandles(objectID: objectID)
        }
        var request = PfsReclaimRequest()
        request.item = identity.proto
        let envelope = try await client.request(.reclaim(request))
        guard case .reclaimReply? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }

        retireReclaimedItem(item, identity: identity, objectID: objectID)
    }

    /// Retires only this frontend's FSItem after a macOS 26 cache-actuator
    /// unlink. The authority binding still exists and must not receive a real
    /// Reclaim: the next lookup is expected to publish it again. A kernel
    /// reclaim means no open descriptor can remain; fail closed if local
    /// handle bookkeeping disproves that invariant.
    public func reclaimLocalRepairSource(item: PortableFSItem) throws {
        let objectID = ObjectIdentifier(item)
        let identity = try identity(for: item)
        guard openHandles[objectID] == nil else {
            throw PfsLocalClientError.daemon(
                errno: EIO,
                message: "repair-source reclaim encountered a live daemon handle"
            )
        }
        retireReclaimedItem(item, identity: identity, objectID: objectID)
    }

    private func retireReclaimedItem(
        _ item: PortableFSItem,
        identity: PfsItemIdentity,
        objectID: ObjectIdentifier
    ) {
        identitiesByObject.removeValue(forKey: objectID)
        itemsByObject.removeValue(forKey: objectID)
        deletedItemsByObject.removeValue(forKey: objectID)
        item.markReclaimed()
        if let canonical = itemsByIdentity[identity], canonical === item {
            itemsByIdentity.removeValue(forKey: identity)
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
        for state in localRepairItems.values {
            state.item.markReclaimed()
        }
        localRepairItems.removeAll()
        localRepairBindings.removeAll()
    }

    func testingAdoptItem(identity: PfsItemIdentity) -> PortableFSItem {
        item(for: identity.proto)
    }

    func testingAdoptDaemonItem(identity: PfsItemIdentity) throws -> PortableFSItem {
        try daemonItem(for: identity.proto)
    }

    func testingDebugState() -> VolumeCoreDebugState {
        VolumeCoreDebugState(
            itemCount: itemsByIdentity.count,
            objectIdentityCount: identitiesByObject.count + deletedItemsByObject.count,
            generationCount: currentGenerationByItemID.count,
            openHandleCount: openHandles.values.reduce(into: 0) { count, state in
                count += 1 + state.pendingCloseHandles.count
            }
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

    /// Runs a complete descriptor operation under shared gate ownership. If
    /// the operation first needs to open or upgrade a descriptor, it performs
    /// that transition exclusively and atomically downgrades to shared
    /// ownership before exposing the handle.
    private func withDescriptorHandle<T>(
        item: PortableFSItem,
        mode: PfsOpenMode,
        operation: (UInt64) async throws -> T
    ) async throws -> T {
        let objectID = ObjectIdentifier(item)
        try await acquireLifecycleGate(for: objectID, mode: .shared)
        if let state = openHandles[objectID], Self.mode(state.mode, covers: mode) {
            defer { releaseLifecycleGate(for: objectID, mode: .shared) }
            return try await operation(state.handle)
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
        try await reconcileOpenHandleLocked(
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

    /// Reconciles one object's descriptor state while its lifecycle gate is
    /// held. No open/close/reclaim transition for this object can interleave
    /// across the daemon awaits below.
    private func reconcileOpenHandleLocked(
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
            let opened = try await openDaemonHandle(
                identity: identity,
                mode: targetMode
            )
            var replacement = OpenState(
                identity: identity,
                handle: opened.handle,
                mode: targetMode,
                isImplicit: implicit && state.isImplicit,
                attrSnapshot: state.attrSnapshot ?? attrSnapshot,
                pendingCloseHandles: state.pendingCloseHandles
            )
            replacement.pendingCloseHandles.append(state.handle)
            openHandles[objectID] = replacement
            opened.lease.acceptHandles()
            await opened.lease.complete(itemsPublished: true)
            try await closePendingDaemonHandles(objectID: objectID)
            return
        }

        let opened = try await openDaemonHandle(
            identity: identity,
            mode: requestedMode
        )
        openHandles[objectID] = OpenState(
            identity: identity,
            handle: opened.handle,
            mode: requestedMode,
            isImplicit: implicit,
            attrSnapshot: attrSnapshot,
            pendingCloseHandles: []
        )
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

    /// Closes superseded descriptors in creation order. A handle leaves actor
    /// state only after the daemon confirms that exact close.
    private func closePendingDaemonHandles(objectID: ObjectIdentifier) async throws {
        while let handle = openHandles[objectID]?.pendingCloseHandles.first {
            let confirmation = try await closeDaemonHandle(handle)
            if var current = openHandles[objectID],
               let index = current.pendingCloseHandles.firstIndex(of: handle) {
                current.pendingCloseHandles.remove(at: index)
                openHandles[objectID] = current
            }
            if let errno = confirmation.terminalErrno {
                throw PfsLocalClientError.daemon(
                    errno: errno,
                    message: "close retired handle \(handle) with a terminal error"
                )
            }
        }
    }

    /// Drains superseded descriptors before the primary descriptor so a
    /// failure always leaves every still-live handle represented in state.
    private func closeAllDaemonHandles(objectID: ObjectIdentifier) async throws {
        try await closePendingDaemonHandles(objectID: objectID)
        guard let state = openHandles[objectID] else {
            return
        }
        let confirmation = try await closeDaemonHandle(state.handle)
        if let current = openHandles[objectID],
           current.handle == state.handle,
           current.pendingCloseHandles.isEmpty {
            openHandles.removeValue(forKey: objectID)
        }
        if let errno = confirmation.terminalErrno {
            throw PfsLocalClientError.daemon(
                errno: errno,
                message: "close retired handle \(state.handle) with a terminal error"
            )
        }
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

    /// The single ingestion boundary for every daemon-originated object. A
    /// reserved-range item must fail before it can enter the canonical tables
    /// or reach an FSKit callback; checking only while mapping attributes is
    /// too late because lookup/create return the `FSItem` itself.
    private func daemonItem(for proto: PfsItem) throws -> PortableFSItem {
        guard proto.itemID > 0,
              proto.itemID < PfsFSKitMapping.localRepairIdentifierFloor else {
            throw PfsLocalClientError.daemon(
                errno: EOVERFLOW,
                message: "daemon item identifier enters the local repair partition"
            )
        }
        return item(for: proto)
    }

    /// Installs a reply item provisionally. The canonical object may be needed
    /// to construct the framework result, but it becomes durable actor state
    /// only if that callback publishes the item. Multiple concurrent replies
    /// share one canonical object and independent provisional references, so
    /// abandoning one can never remove an item another already published.
    private func adoptProvisionalDaemonItem(
        for proto: PfsItem
    ) throws -> (PortableFSItem, PfsItemIdentity) {
        guard proto.itemID > 0,
              proto.itemID < PfsFSKitMapping.localRepairIdentifierFloor else {
            throw PfsLocalClientError.daemon(
                errno: EOVERFLOW,
                message: "daemon item identifier enters the local repair partition"
            )
        }
        let identity = PfsItemIdentity(proto)
        if itemsByIdentity[identity] != nil,
           provisionalItemReferences[identity] == nil {
            // Canonical state that predates this provisional reply already has
            // an owner (root, a prior callback, or a live kernel item).
            publishedItemIdentities.insert(identity)
        }
        let item = item(for: proto)
        provisionalItemReferences[identity, default: 0] += 1
        return (item, identity)
    }

    private func adoptReplyItem(
        _ proto: PfsItem,
        lease: PfsResourceReplyLease,
        terminalOnAbandon: Bool = false
    ) throws -> PortableFSItem {
        let (item, identity) = try adoptProvisionalDaemonItem(for: proto)
        lease.registerItemSettlement { [weak self, weak item] acceptedCount in
            guard let self, let item else { return }
            if acceptedCount == 0, terminalOnAbandon {
                await self.shutdown()
                return
            }
            await self.settleProvisionalItem(
                identity: identity,
                item: item,
                published: acceptedCount > 0
            )
        }
        return item
    }

    private func settleProvisionalItem(
        identity: PfsItemIdentity,
        item: PortableFSItem,
        published: Bool
    ) {
        let remaining = max(0, (provisionalItemReferences[identity] ?? 1) - 1)
        if remaining == 0 {
            provisionalItemReferences.removeValue(forKey: identity)
        } else {
            provisionalItemReferences[identity] = remaining
        }
        if published {
            publishedItemIdentities.insert(identity)
            return
        }
        guard remaining == 0,
              !publishedItemIdentities.contains(identity),
              itemsByIdentity[identity] === item,
              openHandles[ObjectIdentifier(item)] == nil,
              deletedItemsByObject[ObjectIdentifier(item)] == nil else {
            return
        }
        forgetKnownItems(for: identity)
        pruneGenerationIfUnused(itemID: identity.itemID)
    }

    /// Internal fixture adoption is deliberately separate from daemon
    /// ingestion so tests can model stale/reclaimed generations directly.
    private func item(for proto: PfsItem) -> PortableFSItem {
        let identity = PfsItemIdentity(proto)
        if let currentGeneration = currentGenerationByItemID[identity.itemID],
           currentGeneration != identity.generation {
            let oldIdentity = PfsItemIdentity(
                itemID: identity.itemID,
                generation: currentGeneration,
                stableIdentity: identity.stableIdentity
            )
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
        publishedItemIdentities.remove(identity)
        provisionalItemReferences.removeValue(forKey: identity)
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
