import Foundation
import os

private let pfsNamespaceLogger = Logger(
    subsystem: "dev.portablefs.fskit",
    category: "PfsMacOSNamespaceIndex"
)

/// One exact authority visibility target after strict wire validation.
///
/// A namespace target names only `(parent_identity, name)`. It does not claim
/// that the mount cached a positive or negative result; the frontend derives
/// that fact from the exact bindings it published to its own kernel.
public enum PfsMacOSVisibilityTarget: Sendable, Equatable {
    case namespace(parentIdentity: PfsMacOSStableIdentity, name: Data)
    /// Namespace coordinate whose exact post-mutation owner is attested by the
    /// authority. This is stronger than dependency/related-target metadata.
    case namespacePost(
        parentIdentity: PfsMacOSStableIdentity,
        name: Data,
        identity: PfsMacOSStableIdentity
    )
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
/// and forget it when an authority mutation targets the binding. Only a
/// data-only cache invalidation may move the coordinate into a distinct repair-
/// locator set, because authority still owns that exact name-to-identity
/// binding. Ordinary namespace polarity sees the locator as absent, and the
/// next namespace target discards it before COMPLETE repair planning.
public actor PfsMacOSNamespaceIndex {
    public struct Entry: Sendable, Equatable {
        public let parentIdentity: PfsMacOSStableIdentity
        public let name: Data
        /// `st_ino` as this mount projects it — the value an `fstat` through
        /// this mount returns, which the authority cannot know.
        public let vfsFileID: UInt64
        /// Immutable type returned with the callback that published this exact
        /// binding. It selects unlink versus rmdir for cache-only eviction.
        public let itemKind: PfsMacOSCachedItemKind

        public init(
            parentIdentity: PfsMacOSStableIdentity,
            name: Data,
            vfsFileID: UInt64,
            itemKind: PfsMacOSCachedItemKind = .file
        ) {
            self.parentIdentity = parentIdentity
            self.name = name
            self.vfsFileID = vfsFileID
            self.itemKind = itemKind
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

    /// An unforgeable reservation for one namespace mutation. Capacity and
    /// source-identity checks happen when the reservation is created, before
    /// the authority mutation is dispatched. Committing a valid reservation
    /// after authority success is deliberately nonthrowing.
    public struct RecordReservation: Sendable {
        fileprivate let id: UUID
        fileprivate let key: BindingKey
        fileprivate let consumesCapacity: Bool
    }

    public struct ForgetReservation: Sendable {
        fileprivate let id: UUID
        fileprivate let key: BindingKey
    }

    public struct MoveReservation: Sendable {
        fileprivate let id: UUID
        fileprivate let sourceKey: BindingKey
        fileprivate let destinationKey: BindingKey
        fileprivate let source: Binding
    }

    /// Bounds the parent walk so a corrupt or cyclic map cannot spin.
    public static let maximumDepth = 512

    public let rootIdentity: PfsMacOSStableIdentity
    fileprivate struct BindingKey: Hashable {
        let parentIdentity: PfsMacOSStableIdentity
        let name: Data
    }

    /// Coordinates, not identities, are primary. A file can have several
    /// hard-link aliases and every alias the extension published remains a
    /// distinct kernel-cache obligation.
    private var bindings: [BindingKey: Binding] = [:]
    private var keysByIdentity: [PfsMacOSStableIdentity: Set<BindingKey>] = [:]
    /// A source coordinate removed only by an authenticated cache actuator.
    /// It is not a published positive binding, but remains a safe pathname for
    /// a rapid successor repair while the kernel retains the source vnode.
    private var repairLocators: [BindingKey: Binding] = [:]
    private var locatorKeysByIdentity: [PfsMacOSStableIdentity: Set<BindingKey>] = [:]
    private var reservedKeys: [BindingKey: UUID] = [:]
    private var reservedCapacity = 0
    private var reservationWaiters: [BindingKey: [CheckedContinuation<Void, Never>]] = [:]

    public init(rootIdentity: PfsMacOSStableIdentity) {
        self.rootIdentity = rootIdentity
    }

    @discardableResult
    public func record(
        identity: PfsMacOSStableIdentity,
        entry: Entry,
        capacity: Int = .max
    ) async -> Bool {
        let key = BindingKey(parentIdentity: entry.parentIdentity, name: entry.name)
        await waitUntilUnreserved([key])
        let consumesCapacity = bindings[key] == nil && repairLocators[key] == nil
        if consumesCapacity, bindings.count + repairLocators.count >= capacity {
            return false
        }
        recordImmediately(identity: identity, entry: entry)
        return true
    }

    private func recordImmediately(identity: PfsMacOSStableIdentity, entry: Entry) {
        guard identity != rootIdentity else { return }
        let key = BindingKey(parentIdentity: entry.parentIdentity, name: entry.name)
        // Authority lookup has republished current truth at this coordinate;
        // the prior data-repair locator is no longer needed.
        forgetRepairLocatorImmediately(key)
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

    public func forget(identity: PfsMacOSStableIdentity) async {
        while true {
            let bindingKeys = keysByIdentity[identity] ?? []
            let locatorKeys = locatorKeysByIdentity[identity] ?? []
            let keys = bindingKeys.union(locatorKeys)
            await waitUntilUnreserved(Array(keys))
            if bindingKeys == (keysByIdentity[identity] ?? []),
               locatorKeys == (locatorKeysByIdentity[identity] ?? []) {
                break
            }
        }
        for key in keysByIdentity.removeValue(forKey: identity) ?? []
            where bindings[key]?.identity == identity {
            bindings.removeValue(forKey: key)
        }
        for key in locatorKeysByIdentity.removeValue(forKey: identity) ?? []
            where repairLocators[key]?.identity == identity {
            repairLocators.removeValue(forKey: key)
        }
    }

    public func forget(parentIdentity: PfsMacOSStableIdentity, name: Data) async {
        let key = BindingKey(parentIdentity: parentIdentity, name: name)
        await waitUntilUnreserved([key])
        forgetImmediately(key)
    }

    private func forgetImmediately(_ key: BindingKey) {
        if let prior = bindings.removeValue(forKey: key) {
            keysByIdentity[prior.identity]?.remove(key)
            if keysByIdentity[prior.identity]?.isEmpty == true {
                keysByIdentity.removeValue(forKey: prior.identity)
            }
        }
        forgetRepairLocatorImmediately(key)
    }

    private func forgetRepairLocatorImmediately(_ key: BindingKey) {
        guard let prior = repairLocators.removeValue(forKey: key) else { return }
        locatorKeysByIdentity[prior.identity]?.remove(key)
        if locatorKeysByIdentity[prior.identity]?.isEmpty == true {
            locatorKeysByIdentity.removeValue(forKey: prior.identity)
        }
    }

    /// Discards only a data-repair locator while leaving any currently
    /// published binding at the coordinate intact. Every namespace-target
    /// event invalidates the locator because authority may have changed the
    /// name-to-identity binding since the data-only invalidation retained it.
    public func forgetRepairLocator(
        parentIdentity: PfsMacOSStableIdentity,
        name: Data
    ) async {
        let key = BindingKey(parentIdentity: parentIdentity, name: name)
        await waitUntilUnreserved([key])
        forgetRepairLocatorImmediately(key)
    }

    /// Moves one published binding into the conservative locator set after an
    /// authenticated data-only cache invalidation removes the kernel's name.
    /// Authority still owns this exact binding; a rapid data/attribute
    /// successor may safely address the same path until a namespace event.
    public func retainDataRepairLocator(
        parentIdentity: PfsMacOSStableIdentity,
        name: Data,
        expectedIdentity: PfsMacOSStableIdentity
    ) async throws {
        let key = BindingKey(parentIdentity: parentIdentity, name: name)
        await waitUntilUnreserved([key])
        if let existing = repairLocators[key] {
            guard existing.identity == expectedIdentity else {
                throw PfsMacOSCoherenceError.cachedTargetUnrepresentable
            }
            return
        }
        guard let binding = bindings[key], binding.identity == expectedIdentity else {
            throw PfsMacOSCoherenceError.cachedTargetUnrepresentable
        }
        bindings.removeValue(forKey: key)
        keysByIdentity[binding.identity]?.remove(key)
        if keysByIdentity[binding.identity]?.isEmpty == true {
            keysByIdentity.removeValue(forKey: binding.identity)
        }
        repairLocators[key] = binding
        locatorKeysByIdentity[binding.identity, default: []].insert(key)
    }

    /// Moves one published coordinate after a successful local rename while
    /// preserving immutable item kind and this mount's projected inode. A
    /// rename reply carries no fresh attributes, so re-deriving either fact
    /// would require an unnecessary authority round trip.
    public func move(
        parentIdentity: PfsMacOSStableIdentity,
        name: Data,
        toParentIdentity: PfsMacOSStableIdentity,
        toName: Data,
        expectedIdentity: PfsMacOSStableIdentity
    ) async throws {
        let sourceKey = BindingKey(parentIdentity: parentIdentity, name: name)
        let destinationKey = BindingKey(parentIdentity: toParentIdentity, name: toName)
        await waitUntilUnreserved([sourceKey, destinationKey])
        guard let source = bindings[sourceKey], source.identity == expectedIdentity else {
            throw PfsMacOSCoherenceError.cachedTargetUnrepresentable
        }
        moveImmediately(sourceKey: sourceKey, destinationKey: destinationKey, source: source)
    }

    private func moveImmediately(
        sourceKey: BindingKey,
        destinationKey: BindingKey,
        source: Binding
    ) {
        forgetRepairLocatorImmediately(sourceKey)
        forgetRepairLocatorImmediately(destinationKey)
        if sourceKey == destinationKey { return }
        // POSIX rename is a no-op when both names are hard links to the same
        // inode. Keep both exact cache obligations in that case.
        if bindings[destinationKey]?.identity == source.identity { return }

        bindings.removeValue(forKey: sourceKey)
        keysByIdentity[source.identity]?.remove(sourceKey)
        if let replaced = bindings.removeValue(forKey: destinationKey) {
            keysByIdentity[replaced.identity]?.remove(destinationKey)
            if keysByIdentity[replaced.identity]?.isEmpty == true {
                keysByIdentity.removeValue(forKey: replaced.identity)
            }
        }
        let moved = Binding(
            identity: source.identity,
            entry: Entry(
                parentIdentity: destinationKey.parentIdentity,
                name: destinationKey.name,
                vfsFileID: source.entry.vfsFileID,
                itemKind: source.entry.itemKind
            )
        )
        bindings[destinationKey] = moved
        keysByIdentity[source.identity, default: []].insert(destinationKey)
    }

    public func reserveRecord(
        parentIdentity: PfsMacOSStableIdentity,
        name: Data,
        capacity: Int
    ) throws -> RecordReservation? {
        let key = BindingKey(parentIdentity: parentIdentity, name: name)
        guard reservedKeys[key] == nil else {
            pfsNamespaceLogger.error("record reservation collided with an in-flight local mutation")
            throw PfsLocalClientError.publicationAdmissionBusy
        }
        let consumesCapacity = bindings[key] == nil && repairLocators[key] == nil
        if consumesCapacity,
           bindings.count + repairLocators.count + reservedCapacity >= capacity {
            return nil
        }
        let id = UUID()
        reservedKeys[key] = id
        if consumesCapacity { reservedCapacity += 1 }
        return RecordReservation(id: id, key: key, consumesCapacity: consumesCapacity)
    }

    public func commitRecord(
        _ reservation: RecordReservation,
        identity: PfsMacOSStableIdentity,
        entry: Entry
    ) {
        release(reservation.id, keys: [reservation.key], consumesCapacity: reservation.consumesCapacity)
        recordImmediately(identity: identity, entry: entry)
    }

    public func reserveForget(
        parentIdentity: PfsMacOSStableIdentity,
        name: Data,
        expectedIdentity: PfsMacOSStableIdentity
    ) throws -> ForgetReservation {
        let key = BindingKey(parentIdentity: parentIdentity, name: name)
        guard reservedKeys[key] == nil else {
            pfsNamespaceLogger.error("forget reservation collided with an in-flight local mutation")
            throw PfsLocalClientError.publicationAdmissionBusy
        }
        guard bindings[key]?.identity == expectedIdentity else {
            throw PfsMacOSCoherenceError.cachedTargetUnrepresentable
        }
        let id = UUID()
        reservedKeys[key] = id
        return ForgetReservation(id: id, key: key)
    }

    public func commitForget(_ reservation: ForgetReservation) {
        release(reservation.id, keys: [reservation.key], consumesCapacity: false)
        forgetImmediately(reservation.key)
    }

    public func reserveMove(
        parentIdentity: PfsMacOSStableIdentity,
        name: Data,
        toParentIdentity: PfsMacOSStableIdentity,
        toName: Data,
        expectedIdentity: PfsMacOSStableIdentity
    ) throws -> MoveReservation {
        let sourceKey = BindingKey(parentIdentity: parentIdentity, name: name)
        let destinationKey = BindingKey(parentIdentity: toParentIdentity, name: toName)
        guard reservedKeys[sourceKey] == nil, reservedKeys[destinationKey] == nil else {
            pfsNamespaceLogger.error("move reservation collided with an in-flight local mutation")
            throw PfsLocalClientError.publicationAdmissionBusy
        }
        guard let source = bindings[sourceKey], source.identity == expectedIdentity else {
            throw PfsMacOSCoherenceError.cachedTargetUnrepresentable
        }
        let id = UUID()
        reservedKeys[sourceKey] = id
        reservedKeys[destinationKey] = id
        return MoveReservation(
            id: id,
            sourceKey: sourceKey,
            destinationKey: destinationKey,
            source: source
        )
    }

    public func commitMove(_ reservation: MoveReservation) {
        release(
            reservation.id,
            keys: [reservation.sourceKey, reservation.destinationKey],
            consumesCapacity: false
        )
        moveImmediately(
            sourceKey: reservation.sourceKey,
            destinationKey: reservation.destinationKey,
            source: reservation.source
        )
    }

    public func cancel(_ reservation: RecordReservation) {
        release(reservation.id, keys: [reservation.key], consumesCapacity: reservation.consumesCapacity)
    }

    public func cancel(_ reservation: ForgetReservation) {
        release(reservation.id, keys: [reservation.key], consumesCapacity: false)
    }

    public func cancel(_ reservation: MoveReservation) {
        release(
            reservation.id,
            keys: [reservation.sourceKey, reservation.destinationKey],
            consumesCapacity: false
        )
    }

    private func waitUntilUnreserved(_ keys: [BindingKey]) async {
        while let key = keys.first(where: { reservedKeys[$0] != nil }) {
            await withCheckedContinuation { continuation in
                reservationWaiters[key, default: []].append(continuation)
            }
        }
    }

    private func release(_ id: UUID, keys: [BindingKey], consumesCapacity: Bool) {
        if consumesCapacity, reservedCapacity > 0 { reservedCapacity -= 1 }
        var waiters: [CheckedContinuation<Void, Never>] = []
        for key in Set(keys) where reservedKeys[key] == id {
            reservedKeys.removeValue(forKey: key)
            waiters.append(contentsOf: reservationWaiters.removeValue(forKey: key) ?? [])
        }
        for waiter in waiters { waiter.resume() }
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

    public func repairLocatorEntries(for identity: PfsMacOSStableIdentity) -> [Entry] {
        guard let keys = locatorKeysByIdentity[identity] else { return [] }
        return keys.compactMap { repairLocators[$0]?.entry }.sorted(by: Self.entryOrder)
    }

    public func binding(
        parentIdentity: PfsMacOSStableIdentity,
        name: Data
    ) -> Binding? {
        bindings[BindingKey(parentIdentity: parentIdentity, name: name)]
    }

    public func repairLocator(
        parentIdentity: PfsMacOSStableIdentity,
        name: Data
    ) -> Binding? {
        repairLocators[BindingKey(parentIdentity: parentIdentity, name: name)]
    }

    public func bindingOrRepairLocator(
        parentIdentity: PfsMacOSStableIdentity,
        name: Data
    ) -> Binding? {
        let key = BindingKey(parentIdentity: parentIdentity, name: name)
        return bindings[key] ?? repairLocators[key]
    }

    public func count() -> Int { bindings.count + repairLocators.count }

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

    /// Path reconstruction reserved for an exact identity repair fallback.
    /// Published bindings are preferred at every hop; a repair locator is used
    /// only where no published coordinate remains.
    public func repairPath(
        for identity: PfsMacOSStableIdentity
    ) throws -> PfsMacOSRelativePath? {
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
            let entry = entry(for: current) ?? repairLocatorEntries(for: current).first
            guard let entry else { return nil }
            components.append(entry.name)
            current = entry.parentIdentity
            guard seen.insert(current).inserted || current == rootIdentity else {
                throw PfsMacOSCoherenceError.namespaceCycle
            }
        }
        return try PfsMacOSRelativePath(components: components.reversed())
    }

    public func repairPath(
        parentIdentity: PfsMacOSStableIdentity,
        name: Data
    ) throws -> PfsMacOSRelativePath? {
        guard let parent = try repairPath(for: parentIdentity) else { return nil }
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
    public struct Reservation: Sendable {
        fileprivate let id: UUID
    }

    private struct IndexedObject {
        let reference: PfsMacOSLiveObjectReference
        let ordinal: UInt64
    }

    private var objectsByIdentity: [
        PfsMacOSStableIdentity: [ObjectIdentifier: IndexedObject]
    ] = [:]
    private var identityByObject: [ObjectIdentifier: PfsMacOSStableIdentity] = [:]
    private var itemKindsByIdentity: [PfsMacOSStableIdentity: PfsMacOSCachedItemKind] = [:]
    private var nextOrdinal: UInt64 = 1
    private var reservations: Set<UUID> = []

    public init() {}

    /// Atomically records or updates one exact FSItem. Capacity applies only to
    /// a newly indexed object; reopening the same vnode is idempotent even when
    /// the index is full.
    @discardableResult
    public func record(
        item: PortableFSItem,
        vfsFileID: UInt64,
        itemKind: PfsMacOSCachedItemKind? = nil,
        capacity: Int = .max
    ) throws -> Bool {
        let identity = try PfsMacOSStableIdentity(item.identity.stableIdentity)
        let objectID = ObjectIdentifier(item)
        if identityByObject[objectID] == nil,
           identityByObject.count + reservations.count >= capacity {
            return false
        }
        recordImmediately(
            item: item,
            identity: identity,
            vfsFileID: vfsFileID,
            itemKind: itemKind
        )
        return true
    }

    private func recordImmediately(
        item: PortableFSItem,
        identity: PfsMacOSStableIdentity,
        vfsFileID: UInt64,
        itemKind: PfsMacOSCachedItemKind? = nil
    ) {
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
        if let itemKind { itemKindsByIdentity[identity] = itemKind }
        objectsByIdentity[identity, default: [:]][objectID] = IndexedObject(
            reference: .init(
                item: item,
                vfsFileID: vfsFileID,
                itemKind: itemKind ?? itemKindsByIdentity[identity]
            ),
            ordinal: ordinal
        )
        identityByObject[objectID] = identity
    }

    public func recordItemKind(
        identity: PfsMacOSStableIdentity,
        itemKind: PfsMacOSCachedItemKind
    ) {
        itemKindsByIdentity[identity] = itemKind
        guard var objects = objectsByIdentity[identity] else { return }
        for (objectID, indexed) in objects {
            objects[objectID] = IndexedObject(
                reference: .init(
                    item: indexed.reference.item,
                    vfsFileID: indexed.reference.vfsFileID,
                    itemKind: itemKind
                ),
                ordinal: indexed.ordinal
            )
        }
        objectsByIdentity[identity] = objects
    }

    public func reserve(capacity: Int) -> Reservation? {
        guard identityByObject.count + reservations.count < capacity else { return nil }
        let reservation = Reservation(id: UUID())
        reservations.insert(reservation.id)
        return reservation
    }

    public func commit(
        _ reservation: Reservation,
        item: PortableFSItem,
        identity: PfsMacOSStableIdentity,
        vfsFileID: UInt64,
        itemKind: PfsMacOSCachedItemKind? = nil
    ) {
        reservations.remove(reservation.id)
        recordImmediately(
            item: item,
            identity: identity,
            vfsFileID: vfsFileID,
            itemKind: itemKind
        )
    }

    public func cancel(_ reservation: Reservation) {
        reservations.remove(reservation.id)
    }

    public func forget(item: PortableFSItem) {
        let objectID = ObjectIdentifier(item)
        guard let identity = identityByObject.removeValue(forKey: objectID) else { return }
        objectsByIdentity[identity]?.removeValue(forKey: objectID)
        if objectsByIdentity[identity]?.isEmpty == true {
            objectsByIdentity.removeValue(forKey: identity)
            itemKindsByIdentity.removeValue(forKey: identity)
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
        for targets: [PfsMacOSVisibilityTarget],
        authorityNamespaceTruthChanged: Bool = false
    ) async throws -> [PfsMacOSCacheRepair] {
        // Normalize the authority's obligation set before deriving any local
        // action. Target order is not semantics, duplicate targets are
        // idempotent, and two authoritative sizes for one identity are a
        // malformed event rather than an invitation to run two truncates.
        var namespaceTargets: Set<PfsMacOSNamespaceCoordinate> = []
        var namespacePostBindings: [
            PfsMacOSNamespaceCoordinate: PfsMacOSStableIdentity
        ] = [:]
        var attributeTargets: Set<PfsMacOSStableIdentity> = []
        var dataTargets: [PfsMacOSStableIdentity: UInt64] = [:]
        for target in targets {
            switch target {
            case let .namespace(parentIdentity, name):
                namespaceTargets.insert(.init(parentIdentity: parentIdentity, name: name))
            case let .namespacePost(parentIdentity, name, identity):
                let coordinate = PfsMacOSNamespaceCoordinate(
                    parentIdentity: parentIdentity,
                    name: name
                )
                if let prior = namespacePostBindings[coordinate], prior != identity {
                    throw PfsMacOSCoherenceError.invalidVisibilityTarget
                }
                namespaceTargets.insert(coordinate)
                namespacePostBindings[coordinate] = identity
            case let .attributes(identity):
                attributeTargets.insert(identity)
            case let .data(identity, size):
                if let prior = dataTargets[identity], prior != size {
                    throw PfsMacOSCoherenceError.invalidVisibilityTarget
                }
                dataTargets[identity] = size
            }
        }

        // A locator exists only because a prior data-only invalidation left the
        // authority name-to-identity binding unchanged. Observing a namespace
        // target at COMPLETE ends that proof: the coordinate may now be absent,
        // replaced, or moved. Discard the locator before deriving any action in
        // that event so data/attribute targets cannot reuse stale pathname
        // provenance. Removing it early is conservative if later repair fails;
        // a strict mount fences instead of reviving an unattested coordinate.
        if authorityNamespaceTruthChanged {
            for coordinate in namespaceTargets {
                await index.forgetRepairLocator(
                    parentIdentity: coordinate.parentIdentity,
                    name: coordinate.name
                )
            }
        }

        // One coordinate gets at most one mounted-VFS transaction. A stronger
        // action includes every cache transition of a weaker one:
        // data invalidation > positive eviction > negative purge.
        var pathActions: [PfsMacOSNamespaceCoordinate: PfsMacOSCacheRepair] = [:]
        for coordinate in namespaceTargets.sorted(by: Self.coordinateOrder) {
            if let binding = await index.binding(
                parentIdentity: coordinate.parentIdentity,
                name: coordinate.name
            ) {
                guard let path = try await index.path(
                    parentIdentity: coordinate.parentIdentity,
                    name: coordinate.name
                ) else {
                    throw PfsMacOSCoherenceError.cachedTargetUnrepresentable
                }
                Self.retain(
                    .evictBinding(
                        path: path,
                        parentIdentity: coordinate.parentIdentity,
                        itemIdentity: binding.identity,
                        itemKind: binding.entry.itemKind
                    ),
                    at: coordinate,
                    in: &pathActions
                )
                continue
            }
            if let parent = try await index.path(for: coordinate.parentIdentity) {
                Self.retain(
                    .purgeNegative(
                        parent: parent,
                        parentIdentity: coordinate.parentIdentity,
                        name: coordinate.name
                    ),
                    at: coordinate,
                    in: &pathActions
                )
                continue
            }
            // An unknown parent means this mount never published a name in it
            // only when neither local index retains the parent. A retained but
            // unpathable object may still own a kernel cache entry; ACKing an
            // empty repair would silently bless stale state.
            let retainedParentEntry = await index.entry(for: coordinate.parentIdentity)
            let retainedParentObjects = await liveObjects.objects(for: coordinate.parentIdentity)
            if retainedParentEntry != nil || !retainedParentObjects.isEmpty {
                throw PfsMacOSCoherenceError.cachedTargetUnrepresentable
            }
        }

        var objectRepairs: [PfsMacOSCacheRepair] = []
        var objectRepairKeys: Set<PfsMacOSRepairPlannerKey> = []
        var dataRefreshedIdentities: Set<PfsMacOSStableIdentity> = []
        for identity in dataTargets.keys.sorted(by: Self.identityOrder) {
            guard let size = dataTargets[identity] else { continue }
            let publishedEntries = await index.entries(for: identity)
            let usesRepairLocator = publishedEntries.isEmpty
            let entries = usesRepairLocator
                ? await index.repairLocatorEntries(for: identity)
                : publishedEntries
            var pathRepair: (PfsMacOSNamespaceCoordinate, PfsMacOSCacheRepair)?
            for entry in entries {
                guard entry.itemKind == .file else {
                    throw PfsMacOSCoherenceError.invalidVisibilityTarget
                }
                let path = usesRepairLocator
                    ? try await index.repairPath(
                        parentIdentity: entry.parentIdentity,
                        name: entry.name
                    )
                    : try await index.path(
                        parentIdentity: entry.parentIdentity,
                        name: entry.name
                    )
                guard let path else { continue }
                pathRepair = (
                    .init(parentIdentity: entry.parentIdentity, name: entry.name),
                    .invalidateData(
                        path: path,
                        parentIdentity: entry.parentIdentity,
                        itemIdentity: identity,
                        expectedVFSFileID: entry.vfsFileID,
                        authoritativeSize: size
                    )
                )
                break
            }
            if pathRepair == nil,
               let reference = (await liveObjects.objects(for: identity)).first(where: {
                   $0.itemKind == .file
               }),
               let coordinate = namespacePostBindings
                   .filter({ $0.value == identity })
                   .map(\.key)
                   .sorted(by: Self.coordinateOrder)
                   .first,
               let path = try await index.path(
                   parentIdentity: coordinate.parentIdentity,
                   name: coordinate.name
               ) {
                pathRepair = (
                    coordinate,
                    .invalidateData(
                        path: path,
                        parentIdentity: coordinate.parentIdentity,
                        itemIdentity: identity,
                        expectedVFSFileID: reference.vfsFileID,
                        authoritativeSize: size
                    )
                )
            }
            if let (coordinate, repair) = pathRepair {
                Self.retain(repair, at: coordinate, in: &pathActions)
                dataRefreshedIdentities.insert(identity)
                continue
            }
            let objects = await liveObjects.objects(for: identity)
            if !objects.isEmpty {
                for object in objects {
                    let repair = PfsMacOSCacheRepair.invalidateDataObject(
                        object: object,
                        itemIdentity: identity,
                        authoritativeSize: size
                    )
                    if objectRepairKeys.insert(repair.plannerKey).inserted {
                        objectRepairs.append(repair)
                    }
                }
                continue
            }
            if !entries.isEmpty {
                throw PfsMacOSCoherenceError.cachedTargetUnrepresentable
            }
        }

        // Every retained pathname action refreshes its parent through FSKit.
        // Attribute groups are selected deepest-first; only a group actually
        // retained here can cover its parent. This avoids both the original
        // parent-getattr deadlock and phantom coverage from a provisional group
        // that was later removed.
        var refreshedDirectories = Set(pathActions.keys.map(\.parentIdentity))
        var attributePlans: [PfsMacOSAttributeRepairPlan] = []
        for identity in attributeTargets {
            let publishedEntries = await index.entries(for: identity)
            let usesRepairLocator = publishedEntries.isEmpty
            let entries = usesRepairLocator
                ? await index.repairLocatorEntries(for: identity)
                : publishedEntries
            if !entries.isEmpty {
                var candidates: [(PfsMacOSNamespaceCoordinate, PfsMacOSCacheRepair)] = []
                var maximumDepth = 0
                for entry in entries {
                    let path = usesRepairLocator
                        ? try await index.repairPath(
                            parentIdentity: entry.parentIdentity,
                            name: entry.name
                        )
                        : try await index.path(
                            parentIdentity: entry.parentIdentity,
                            name: entry.name
                        )
                    guard let path else {
                        throw PfsMacOSCoherenceError.cachedTargetUnrepresentable
                    }
                    maximumDepth = max(maximumDepth, path.components.count)
                    candidates.append((
                        .init(parentIdentity: entry.parentIdentity, name: entry.name),
                        .refreshAttributes(
                            path: path,
                            parentIdentity: entry.parentIdentity,
                            itemIdentity: identity,
                            expectedVFSFileID: entry.vfsFileID,
                            itemKind: entry.itemKind
                        )
                    ))
                }
                attributePlans.append(.init(
                    identity: identity,
                    depth: maximumDepth,
                    pathRepairs: candidates,
                    objectRepairs: []
                ))
                continue
            }
            let postCoordinates = namespacePostBindings
                .filter { $0.value == identity }
                .map(\.key)
                .sorted(by: Self.coordinateOrder)
            if !postCoordinates.isEmpty,
               let reference = (await liveObjects.objects(for: identity)).first(where: {
                   $0.itemKind != nil
               }),
               let itemKind = reference.itemKind {
                var candidates: [(PfsMacOSNamespaceCoordinate, PfsMacOSCacheRepair)] = []
                var maximumDepth = 0
                for coordinate in postCoordinates {
                    guard let path = try await index.path(
                        parentIdentity: coordinate.parentIdentity,
                        name: coordinate.name
                    ) else {
                        throw PfsMacOSCoherenceError.cachedTargetUnrepresentable
                    }
                    maximumDepth = max(maximumDepth, path.components.count)
                    candidates.append((
                        coordinate,
                        .refreshAttributes(
                            path: path,
                            parentIdentity: coordinate.parentIdentity,
                            itemIdentity: identity,
                            expectedVFSFileID: reference.vfsFileID,
                            itemKind: itemKind
                        )
                    ))
                }
                attributePlans.append(.init(
                    identity: identity,
                    depth: maximumDepth,
                    pathRepairs: candidates,
                    objectRepairs: []
                ))
                continue
            }
            let repairs = await liveObjects.objects(for: identity).map {
                PfsMacOSCacheRepair.invalidateAttributesObject(
                    object: $0,
                    itemIdentity: identity
                )
            }
            if repairs.isEmpty, identity == index.rootIdentity {
                // FSKit always publishes and may cache the root, but macOS 26
                // has neither a parent pathname nor a native object revocation
                // API for it. ACKing an empty repair would bless stale attrs.
                throw PfsMacOSCoherenceError.cachedTargetUnrepresentable
            }
            if !repairs.isEmpty {
                attributePlans.append(.init(
                    identity: identity,
                    depth: -1,
                    pathRepairs: [],
                    objectRepairs: repairs
                ))
            }
        }
        attributePlans.sort(by: Self.attributePlanOrder)
        for plan in attributePlans {
            if refreshedDirectories.contains(plan.identity)
                || dataRefreshedIdentities.contains(plan.identity) {
                continue
            }
            for (coordinate, repair) in plan.pathRepairs {
                Self.retain(repair, at: coordinate, in: &pathActions)
                refreshedDirectories.insert(coordinate.parentIdentity)
            }
            for repair in plan.objectRepairs
                where objectRepairKeys.insert(repair.plannerKey).inserted {
                objectRepairs.append(repair)
            }
        }

        return pathActions
            .map { ($0.key, $0.value) }
            .sorted(by: Self.pathActionOrder)
            .map(\.1) + objectRepairs
    }

    private static func retain(
        _ repair: PfsMacOSCacheRepair,
        at coordinate: PfsMacOSNamespaceCoordinate,
        in actions: inout [PfsMacOSNamespaceCoordinate: PfsMacOSCacheRepair]
    ) {
        guard let existing = actions[coordinate] else {
            actions[coordinate] = repair
            return
        }
        if repair.strength > existing.strength {
            actions[coordinate] = repair
        }
    }

    private static func identityOrder(
        _ lhs: PfsMacOSStableIdentity,
        _ rhs: PfsMacOSStableIdentity
    ) -> Bool {
        lhs.bytes.lexicographicallyPrecedes(rhs.bytes)
    }

    private static func coordinateOrder(
        _ lhs: PfsMacOSNamespaceCoordinate,
        _ rhs: PfsMacOSNamespaceCoordinate
    ) -> Bool {
        if lhs.parentIdentity != rhs.parentIdentity {
            return identityOrder(lhs.parentIdentity, rhs.parentIdentity)
        }
        return lhs.name.lexicographicallyPrecedes(rhs.name)
    }

    private static func attributePlanOrder(
        _ lhs: PfsMacOSAttributeRepairPlan,
        _ rhs: PfsMacOSAttributeRepairPlan
    ) -> Bool {
        if lhs.depth != rhs.depth { return lhs.depth > rhs.depth }
        return identityOrder(lhs.identity, rhs.identity)
    }

    private static func pathActionOrder(
        _ lhs: (PfsMacOSNamespaceCoordinate, PfsMacOSCacheRepair),
        _ rhs: (PfsMacOSNamespaceCoordinate, PfsMacOSCacheRepair)
    ) -> Bool {
        let lhsDepth = lhs.1.pathDepth
        let rhsDepth = rhs.1.pathDepth
        if lhsDepth != rhsDepth { return lhsDepth > rhsDepth }
        return coordinateOrder(lhs.0, rhs.0)
    }
}

private struct PfsMacOSAttributeRepairPlan {
    let identity: PfsMacOSStableIdentity
    let depth: Int
    let pathRepairs: [(PfsMacOSNamespaceCoordinate, PfsMacOSCacheRepair)]
    let objectRepairs: [PfsMacOSCacheRepair]
}

/// Exact local actuation identity used only to collapse obligations that
/// authority target shapes intentionally repeat (for example unlink's
/// namespace target plus the removed item's attribute target). A key includes
/// every operand that can change what the actuator does; two merely related
/// repairs never compare equal.
private enum PfsMacOSRepairPlannerKey: Hashable {
    case purgeNegative(PfsMacOSRelativePath, PfsMacOSStableIdentity, Data)
    case evictBinding(
        PfsMacOSRelativePath,
        PfsMacOSStableIdentity,
        PfsMacOSStableIdentity,
        PfsMacOSCachedItemKind
    )
    case refreshAttributes(
        PfsMacOSRelativePath,
        PfsMacOSStableIdentity,
        PfsMacOSStableIdentity,
        UInt64,
        PfsMacOSCachedItemKind
    )
    case invalidateData(
        PfsMacOSRelativePath,
        PfsMacOSStableIdentity,
        PfsMacOSStableIdentity,
        UInt64,
        UInt64
    )
    case invalidateDataObject(
        ObjectIdentifier,
        UInt64,
        PfsMacOSStableIdentity,
        UInt64
    )
    case invalidateAttributesObject(
        ObjectIdentifier,
        UInt64,
        PfsMacOSStableIdentity
    )
}

private extension PfsMacOSCacheRepair {
    var strength: Int {
        switch self {
        case .purgeNegative: 1
        case .evictBinding, .refreshAttributes: 2
        case .invalidateData: 3
        case .invalidateDataObject, .invalidateAttributesObject: 0
        }
    }

    var pathDepth: Int {
        switch self {
        case let .purgeNegative(parent, _, _):
            parent.components.count + 1
        case let .evictBinding(path, _, _, _),
             let .refreshAttributes(path, _, _, _, _),
             let .invalidateData(path, _, _, _, _):
            path.components.count
        case .invalidateDataObject, .invalidateAttributesObject:
            -1
        }
    }

    var plannerKey: PfsMacOSRepairPlannerKey {
        switch self {
        case let .purgeNegative(parent, parentIdentity, name):
            return .purgeNegative(parent, parentIdentity, name)
        case let .evictBinding(path, parentIdentity, itemIdentity, itemKind):
            return .evictBinding(path, parentIdentity, itemIdentity, itemKind)
        case let .refreshAttributes(
            path,
            parentIdentity,
            itemIdentity,
            expectedVFSFileID,
            itemKind
        ):
            return .refreshAttributes(
                path,
                parentIdentity,
                itemIdentity,
                expectedVFSFileID,
                itemKind
            )
        case let .invalidateData(
            path,
            parentIdentity,
            itemIdentity,
            expectedVFSFileID,
            authoritativeSize
        ):
            return .invalidateData(
                path,
                parentIdentity,
                itemIdentity,
                expectedVFSFileID,
                authoritativeSize
            )
        case let .invalidateDataObject(object, itemIdentity, authoritativeSize):
            return .invalidateDataObject(
                ObjectIdentifier(object.item),
                object.vfsFileID,
                itemIdentity,
                authoritativeSize
            )
        case let .invalidateAttributesObject(object, itemIdentity):
            return .invalidateAttributesObject(
                ObjectIdentifier(object.item),
                object.vfsFileID,
                itemIdentity
            )
        }
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
