import Foundation

/// One exact authority visibility target after strict wire validation.
///
/// A namespace target names only `(parent_identity, name)`. It does not claim
/// that the mount cached a positive or negative result; the frontend derives
/// that fact from the exact bindings it published to its own kernel.
public enum PfsMacOSVisibilityTarget: Sendable, Equatable {
    case namespace(parentIdentity: PfsMacOSStableIdentity, name: Data)
    case data(identity: PfsMacOSStableIdentity, size: UInt64)
    case attributes(identity: PfsMacOSStableIdentity)
}

/// This mount's own map of every published namespace coordinate to the local
/// facts a macOS 26 repair needs: which stable item hangs there, and what inode
/// number THIS kernel projected for it. A reverse index preserves every alias
/// of a hard-linked item.
///
/// The invariant that makes the map sufficient is a negative one: the kernel
/// cannot hold a cache entry for a binding this extension never returned, so an
/// identity with no entry here has nothing stale to purge. Callers must
/// therefore record an entry on exactly the callbacks that publish a binding
/// and forget it when the binding goes away — otherwise "unknown" stops meaning
/// "uncached" and the skip below stops being sound.
public actor PfsMacOSNamespaceIndex {
    public struct Entry: Sendable, Equatable {
        public let parentIdentity: PfsMacOSStableIdentity
        public let name: Data
        /// `st_ino` as this mount projects it — the value an `fstat` through
        /// this mount returns, which the authority cannot know.
        public let vfsFileID: UInt64

        public init(parentIdentity: PfsMacOSStableIdentity, name: Data, vfsFileID: UInt64) {
            self.parentIdentity = parentIdentity
            self.name = name
            self.vfsFileID = vfsFileID
        }
    }

    public struct Binding: Sendable, Equatable {
        public let identity: PfsMacOSStableIdentity
        public let entry: Entry

        public init(identity: PfsMacOSStableIdentity, entry: Entry) {
            self.identity = identity
            self.entry = entry
        }
    }

    /// Bounds the parent walk so a corrupt or cyclic map cannot spin.
    public static let maximumDepth = 512

    public let rootIdentity: PfsMacOSStableIdentity
    private struct BindingKey: Hashable {
        let parentIdentity: PfsMacOSStableIdentity
        let name: Data
    }

    /// Coordinates, not identities, are primary. A file can have several
    /// hard-link aliases and every alias the extension published remains a
    /// distinct kernel-cache obligation.
    private var bindings: [BindingKey: Binding] = [:]
    private var keysByIdentity: [PfsMacOSStableIdentity: Set<BindingKey>] = [:]

    public init(rootIdentity: PfsMacOSStableIdentity) {
        self.rootIdentity = rootIdentity
    }

    public func record(identity: PfsMacOSStableIdentity, entry: Entry) {
        guard identity != rootIdentity else { return }
        let key = BindingKey(parentIdentity: entry.parentIdentity, name: entry.name)
        if let prior = bindings.updateValue(
            Binding(identity: identity, entry: entry),
            forKey: key
        ), prior.identity != identity {
            keysByIdentity[prior.identity]?.remove(key)
            if keysByIdentity[prior.identity]?.isEmpty == true {
                keysByIdentity.removeValue(forKey: prior.identity)
            }
        }
        keysByIdentity[identity, default: []].insert(key)
    }

    public func forget(identity: PfsMacOSStableIdentity) {
        guard let keys = keysByIdentity.removeValue(forKey: identity) else { return }
        for key in keys where bindings[key]?.identity == identity {
            bindings.removeValue(forKey: key)
        }
    }

    public func forget(parentIdentity: PfsMacOSStableIdentity, name: Data) {
        let key = BindingKey(parentIdentity: parentIdentity, name: name)
        guard let prior = bindings.removeValue(forKey: key) else { return }
        keysByIdentity[prior.identity]?.remove(key)
        if keysByIdentity[prior.identity]?.isEmpty == true {
            keysByIdentity.removeValue(forKey: prior.identity)
        }
    }

    public func entry(for identity: PfsMacOSStableIdentity) -> Entry? {
        entries(for: identity).first
    }

    public func vfsFileID(for identity: PfsMacOSStableIdentity) -> UInt64? {
        entry(for: identity)?.vfsFileID
    }

    public func entries(for identity: PfsMacOSStableIdentity) -> [Entry] {
        guard let keys = keysByIdentity[identity] else { return [] }
        return keys.compactMap { bindings[$0]?.entry }.sorted(by: Self.entryOrder)
    }

    public func binding(
        parentIdentity: PfsMacOSStableIdentity,
        name: Data
    ) -> Binding? {
        bindings[BindingKey(parentIdentity: parentIdentity, name: name)]
    }

    public func count() -> Int { bindings.count }

    /// The mount-relative path for `identity`, or `nil` when this mount holds
    /// no chain of bindings reaching the root — which is exactly the case in
    /// which it holds no cache entry to repair.
    public func path(for identity: PfsMacOSStableIdentity) throws -> PfsMacOSRelativePath? {
        if identity == rootIdentity {
            return try PfsMacOSRelativePath(components: [])
        }
        var components: [Data] = []
        var current = identity
        var seen: Set<PfsMacOSStableIdentity> = [identity]
        while current != rootIdentity {
            guard components.count < Self.maximumDepth else {
                throw PfsMacOSCoherenceError.namespaceCycle
            }
            guard let entry = entry(for: current) else { return nil }
            components.append(entry.name)
            current = entry.parentIdentity
            guard seen.insert(current).inserted || current == rootIdentity else {
                throw PfsMacOSCoherenceError.namespaceCycle
            }
        }
        return try PfsMacOSRelativePath(components: components.reversed())
    }

    public func path(
        parentIdentity: PfsMacOSStableIdentity,
        name: Data
    ) throws -> PfsMacOSRelativePath? {
        guard let parent = try path(for: parentIdentity) else { return nil }
        return try PfsMacOSRelativePath(components: parent.components + [name])
    }

    private static func entryOrder(_ lhs: Entry, _ rhs: Entry) -> Bool {
        if lhs.parentIdentity.bytes != rhs.parentIdentity.bytes {
            return lhs.parentIdentity.bytes.lexicographicallyPrecedes(rhs.parentIdentity.bytes)
        }
        return lhs.name.lexicographicallyPrecedes(rhs.name)
    }
}

/// Tracks kernel objects with live open state independently from namespace
/// aliases. Unlink removes a coordinate from `PfsMacOSNamespaceIndex`; it must
/// not remove the object from this index until FSKit closes/reclaims it.
public actor PfsMacOSLiveObjectIndex {
    private struct IndexedObject {
        let reference: PfsMacOSLiveObjectReference
        let ordinal: UInt64
    }

    private var objectsByIdentity: [
        PfsMacOSStableIdentity: [ObjectIdentifier: IndexedObject]
    ] = [:]
    private var identityByObject: [ObjectIdentifier: PfsMacOSStableIdentity] = [:]
    private var nextOrdinal: UInt64 = 1

    public init() {}

    /// Records the current open-object state. Repeated calls for the same
    /// `PortableFSItem` update in place; FSKit's retaining-modes close callback
    /// decides when `forget` is appropriate.
    public func record(
        item: PortableFSItem,
        vfsFileID: UInt64
    ) throws {
        let identity = try PfsMacOSStableIdentity(item.identity.stableIdentity)
        let objectID = ObjectIdentifier(item)
        if let priorIdentity = identityByObject[objectID], priorIdentity != identity {
            objectsByIdentity[priorIdentity]?.removeValue(forKey: objectID)
            if objectsByIdentity[priorIdentity]?.isEmpty == true {
                objectsByIdentity.removeValue(forKey: priorIdentity)
            }
        }
        let ordinal = objectsByIdentity[identity]?[objectID]?.ordinal ?? nextOrdinal
        if objectsByIdentity[identity]?[objectID] == nil {
            nextOrdinal += 1
        }
        objectsByIdentity[identity, default: [:]][objectID] = IndexedObject(
            reference: .init(item: item, vfsFileID: vfsFileID),
            ordinal: ordinal
        )
        identityByObject[objectID] = identity
    }

    public func forget(item: PortableFSItem) {
        let objectID = ObjectIdentifier(item)
        guard let identity = identityByObject.removeValue(forKey: objectID) else { return }
        objectsByIdentity[identity]?.removeValue(forKey: objectID)
        if objectsByIdentity[identity]?.isEmpty == true {
            objectsByIdentity.removeValue(forKey: identity)
        }
    }

    public func objects(
        for identity: PfsMacOSStableIdentity
    ) -> [PfsMacOSLiveObjectReference] {
        (objectsByIdentity[identity]?.values ?? [:].values)
            .sorted { $0.ordinal < $1.ordinal }
            .map(\.reference)
    }

    public func count() -> Int { identityByObject.count }
}

/// Turns exact authority targets into the local repair plans the macOS 26
/// backend can actuate.
///
/// Every derivation that the authority cannot perform happens here: the path
/// comes from the index's parent chain, and `expectedVFSFileID` comes from the
/// inode number this mount recorded when it published the binding. Namespace
/// polarity is derived here: a known coordinate is a positive eviction; an
/// otherwise known parent needs a negative-cache purge.
public struct PfsMacOSRepairPlanner: Sendable {
    public let index: PfsMacOSNamespaceIndex
    public let liveObjects: PfsMacOSLiveObjectIndex

    public init(
        index: PfsMacOSNamespaceIndex,
        liveObjects: PfsMacOSLiveObjectIndex = PfsMacOSLiveObjectIndex()
    ) {
        self.index = index
        self.liveObjects = liveObjects
    }

    public func repairs(
        for targets: [PfsMacOSVisibilityTarget]
    ) async throws -> [PfsMacOSCacheRepair] {
        var repairs: [PfsMacOSCacheRepair] = []
        for target in targets {
            switch target {
            case let .namespace(parentIdentity, name):
                if let binding = await index.binding(
                    parentIdentity: parentIdentity,
                    name: name
                ), let path = try await index.path(
                    parentIdentity: parentIdentity,
                    name: name
                ) {
                    repairs.append(
                        .evictBinding(
                            path: path,
                            parentIdentity: parentIdentity,
                            itemIdentity: binding.identity
                        )
                    )
                    continue
                }
                guard let parent = try await index.path(for: parentIdentity) else { continue }
                repairs.append(
                    .purgeNegative(
                        parent: parent,
                        parentIdentity: parentIdentity,
                        name: name
                    )
                )
            case let .data(identity, size):
                var repairedByPath = false
                for entry in await index.entries(for: identity) {
                    guard let path = try await index.path(
                        parentIdentity: entry.parentIdentity,
                        name: entry.name
                    ) else { continue }
                    repairs.append(
                        .invalidateData(
                            path: path,
                            parentIdentity: entry.parentIdentity,
                            itemIdentity: identity,
                            expectedVFSFileID: entry.vfsFileID,
                            authoritativeSize: size
                        )
                    )
                    repairedByPath = true
                    break
                }
                if !repairedByPath {
                    for object in await liveObjects.objects(for: identity) {
                        repairs.append(
                            .invalidateDataObject(
                                object: object,
                                itemIdentity: identity,
                                authoritativeSize: size
                            )
                        )
                    }
                }
            case let .attributes(identity):
                let start = repairs.count
                for entry in await index.entries(for: identity) {
                    guard let path = try await index.path(
                        parentIdentity: entry.parentIdentity,
                        name: entry.name
                    ) else { continue }
                    repairs.append(
                        .evictBinding(
                            path: path,
                            parentIdentity: entry.parentIdentity,
                            itemIdentity: identity
                        )
                    )
                }
                if repairs.count == start {
                    for object in await liveObjects.objects(for: identity) {
                        repairs.append(
                            .invalidateAttributesObject(
                                object: object,
                                itemIdentity: identity
                            )
                        )
                    }
                }
            }
        }
        return repairs
    }
}

/// Prototype coherence terms used by the offline enforcement tests. These are
/// inputs to a future exact attach encoder, not an `AttachRequest` mirror: a
/// conforming encoder would send the wire `STRICT` profile, map `coherenceProfile`
/// to a supported `NamespaceRepair`, and also supply replay slots and the route
/// revision. No such production encoder exists today.
public struct PfsMacOSCoherenceAttachParameters: Sendable, Equatable {
    /// The local repair implementation the frontend proposes. Its raw value is
    /// not an authority wire field.
    public let coherenceProfile: PfsMacOSCachePolicy
    /// How many name bindings this mount can hold before it must forget one.
    /// The authority needs it to bound the repair set it may have to send.
    public let cachedNameCapacity: UInt64
    /// The client's own bound on how long it will spend actuating one barrier
    /// before failing closed. Zero means the client offers no bound, which the
    /// authority must treat as unacceptable rather than unlimited.
    public let repairBudgetMillis: UInt32

    public init(
        coherenceProfile: PfsMacOSCachePolicy,
        cachedNameCapacity: UInt64,
        repairBudgetMillis: UInt32
    ) {
        self.coherenceProfile = coherenceProfile
        self.cachedNameCapacity = cachedNameCapacity
        self.repairBudgetMillis = repairBudgetMillis
    }

    public var offersBoundedRepair: Bool { repairBudgetMillis > 0 }
}

/// Evidence that one exact kernel mount is gone, as `DetachRequest` carries it.
/// It is evidence, not an assertion: `observation` is the raw mount-table
/// reading the client took, and `component` names what took it, so the
/// authority can decide whether it believes the proof rather than trusting a
/// boolean the client set.
public struct PfsMacOSMountAbsenceProof: Sendable, Equatable {
    public let observedUnixNanos: Int64
    public let observation: Data
    public let component: String

    public init(observedUnixNanos: Int64, observation: Data, component: String) {
        self.observedUnixNanos = observedUnixNanos
        self.observation = observation
        self.component = component
    }

    /// A proof with no observation bytes proves nothing.
    public var isWellFormed: Bool {
        observedUnixNanos > 0 && !observation.isEmpty && !component.isEmpty
    }
}
