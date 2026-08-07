import Foundation

/// The enforcement half of repair provenance.
///
/// `PfsMacOS26RepairAuthenticator` mints an unguessable operand; this registry
/// is what makes that operand mean something. It is simultaneously
///
/// - the `PfsMacOS26RepairArmer` the backend arms a plan with, and
/// - the `PfsMacOS26RepairGate` the FSKit adapter asks about every reserved
///   name it is handed.
///
/// Both halves are methods on one actor, so "is this callback authorized?" and
/// "mark it consumed" are a single, indivisible actor step. There is no
/// wall-clock component anywhere: an authorization exists between `arm` and
/// `finish`/`cancel` and at no other time.
public actor PfsMacOS26RepairArmRegistry: PfsMacOS26RepairArmer, PfsMacOS26RepairGate {
    /// Every repair kind the macOS 26 compatibility policy actuates, including
    /// `.dataInvalidation`.
    ///
    /// `.dataInvalidation` is a declared owner decision, not an oversight. Its
    /// truncate callback carries an `FSItem` and a size but no name, so it can
    /// never ride the operand HMAC; it is authorized instead through the armed
    /// transaction's source-removed window with the tightest binding the
    /// platform offers: item stable identity, authority epoch and barrier
    /// sequence (bound into the armed plan's authenticated operand), the exact
    /// authoritative post-repair size, and consumption that exists only after
    /// the exact source-removal callback and before event release — never a
    /// wall-clock window.
    ///
    /// The residual race is exact and bounded: a process that, during the
    /// repair window, already holds the vnode and truncates it to exactly the
    /// authoritative post-state size has that metadata-only effect coalesced
    /// with the repair — the file was about to hold precisely that size, and
    /// XFS already does. A truncate to any other size, on any other item, or
    /// outside the window is never swallowed. This coalescing is the
    /// reason macOS 26 is a declared compatibility policy rather than the exact
    /// contract; no workload-dependent percentage is assigned. macOS 27's
    /// native cache API closes the provenance window.
    public static let defaultSupportedKinds: Set<PfsMacOS26RepairKind> = [
        .negativeScratch,
        .positiveEviction,
        .dataInvalidation,
        .attributeRefresh
    ]

    private struct TraversalCoordinate: Sendable, Hashable {
        let parentIdentity: Data
        let name: Data
    }

    private struct Transaction {
        struct LocalScratchOwnership: Sendable {
            let item: PortableFSItem
            let retireBinding: @Sendable (PortableFSItem) async -> Void
        }

        let plan: PfsMacOS26RepairPlan
        let required: [PfsMacOS26RepairCallback]
        let traversalCoordinates: Set<TraversalCoordinate>
        let traversalItemIdentities: Set<Data>
        var consumed: [PfsMacOS26RepairCallback] = []
        /// Exact-size truncates swallowed during this repair window. The
        /// actuator's own truncate is the first; a racing identical truncate
        /// is coalesced rather than double-applied.
        var truncateConsumptions = 0
        var attributeRefreshConsumptions = 0
        /// Callback completeness has been checked, but event-scoped source
        /// item ownership remains live until the COMPLETE barrier resumes.
        var validated = false
        /// The negative repair's synthetic vnode is owned by the whole event,
        /// not by its namespace binding. The binding disappears at remove;
        /// this ownership survives until release/cancel so every exit retires
        /// the name. The core retains vnode classification independently until
        /// FSKit's actual reclaim callback.
        var localScratch: LocalScratchOwnership?

        /// The exact kernel-only source removal has completed and the held-file
        /// descriptor may now drive the authenticated truncate callback.
        var dataRepairActive: Bool {
            plan.kind == .dataInvalidation
                && consumed.contains(.removeSource)
        }
    }

    private let authenticator: PfsMacOS26RepairAuthenticator
    private let supportedKinds: Set<PfsMacOS26RepairKind>
    private let namespaceIndex: PfsMacOSNamespaceIndex?
    private var armed: [Data: Transaction] = [:]
    /// The one plan whose mounted-VFS syscall is currently executing. All
    /// plans are pre-armed to validate traversal before surgery begins, but
    /// nameless callbacks shared by hard-link aliases must be credited only to
    /// the sequentially active operand rather than dictionary iteration order.
    private var activeOperand: Data?

    public init(
        authenticator: PfsMacOS26RepairAuthenticator,
        supportedKinds: Set<PfsMacOS26RepairKind> = defaultSupportedKinds,
        namespaceIndex: PfsMacOSNamespaceIndex? = nil
    ) {
        self.authenticator = authenticator
        self.supportedKinds = supportedKinds
        self.namespaceIndex = namespaceIndex
    }

    public func armedOperandCount() -> Int { armed.count }

    /// The callbacks this operand may still legally produce, in order. Empty
    /// for an operand that is not armed.
    public func pendingCallbacks(operand: Data) -> [PfsMacOS26RepairCallback] {
        guard let transaction = armed[operand] else { return [] }
        return Array(transaction.required.dropFirst(transaction.consumed.count))
    }

    // MARK: - Armer

    public func arm(_ plan: PfsMacOS26RepairPlan) async throws -> any PfsMacOS26RepairArmLease {
        guard supportedKinds.contains(plan.kind) else {
            throw PfsMacOSCoherenceError.repairKindUnsupported(plan.kind)
        }
        guard let operand = plan.operand,
              PfsMacOS26RepairAuthenticator.isReserved(operand) else {
            throw PfsMacOSCoherenceError.invalidRepairOperand
        }
        if plan.kind == .dataInvalidation {
            // The nameless half of the plan needs both coordinates to decide
            // "swallow or refuse" per truncate; a plan without them could arm
            // a window nothing can ever close.
            guard plan.expectedVFSFileID != nil, plan.authoritativeSize != nil else {
                throw PfsMacOSCoherenceError.invalidRepairOperand
            }
        }
        if plan.kind == .attributeRefresh, plan.expectedVFSFileID == nil {
            throw PfsMacOSCoherenceError.invalidRepairOperand
        }
        // The plan is not trusted just because it arrived through the backend.
        // Authenticating it here is what makes a forged or replayed plan
        // unable to open a window in the user's namespace.
        guard authenticator.validate(
            operand: operand,
            epoch: plan.epoch,
            sequence: plan.sequence,
            step: plan.step,
            kind: plan.kind,
            parentIdentity: plan.parentIdentity,
            itemIdentity: plan.itemIdentity,
            sourceName: plan.authenticatedSourceName
        ) else {
            throw PfsMacOSCoherenceError.invalidRepairOperand
        }
        guard armed[operand] == nil else { throw PfsMacOSCoherenceError.repairAlreadyArmed }
        let traversal = try await resolveTraversalCoordinates(for: plan)
        armed[operand] = Transaction(
            plan: plan,
            required: plan.requiredCallbacks,
            traversalCoordinates: traversal.coordinates,
            traversalItemIdentities: traversal.itemIdentities
        )
        return Lease(registry: self, operand: operand)
    }

    private func resolveTraversalCoordinates(
        for plan: PfsMacOS26RepairPlan
    ) async throws -> (
        coordinates: Set<TraversalCoordinate>,
        itemIdentities: Set<Data>
    ) {
        guard let namespaceIndex else { return ([], []) }
        let components: ArraySlice<Data>
        switch plan.kind {
        case .negativeScratch:
            components = plan.path.components[...]
        case .positiveEviction, .dataInvalidation, .attributeRefresh:
            components = plan.path.components.dropLast()
        }
        var current = namespaceIndex.rootIdentity
        var coordinates: Set<TraversalCoordinate> = []
        var itemIdentities: Set<Data> = [current.bytes]
        for name in components {
            guard let binding = await namespaceIndex.bindingOrRepairLocator(
                parentIdentity: current,
                name: name
            ) else {
                throw PfsMacOSCoherenceError.cachedTargetUnrepresentable
            }
            coordinates.insert(TraversalCoordinate(
                parentIdentity: current.bytes,
                name: name
            ))
            current = binding.identity
            itemIdentities.insert(current.bytes)
        }
        guard current == plan.parentIdentity else {
            throw PfsMacOSCoherenceError.cachedTargetUnrepresentable
        }
        return (coordinates, itemIdentities)
    }

    fileprivate func activate(operand: Data) throws {
        guard activeOperand == nil,
              let transaction = armed[operand],
              !transaction.validated else {
            throw PfsMacOSCoherenceError.repairCallbackOutOfOrder
        }
        activeOperand = operand
    }

    // MARK: - Gate

    public func consume(
        callback: PfsMacOS26RepairCallback,
        operand: Data,
        parentIdentity: Data?
    ) async throws {
        guard var transaction = armed[operand] else {
            throw PfsMacOSCoherenceError.repairNotArmed
        }
        // The HMAC binds the plan's parent identity; the callback must present
        // the same one. A same-basename callback arriving from a different
        // directory is someone else's file, whatever its name claims.
        guard parentIdentity == transaction.plan.parentIdentity.bytes else {
            throw PfsMacOSCoherenceError.invalidRepairOperand
        }
        if transaction.consumed.contains(callback) {
            throw PfsMacOSCoherenceError.repairAlreadyConsumed
        }
        guard transaction.consumed.count < transaction.required.count,
              transaction.required[transaction.consumed.count] == callback else {
            throw PfsMacOSCoherenceError.repairCallbackOutOfOrder
        }
        transaction.consumed.append(callback)
        armed[operand] = transaction
    }

    public func adoptLocalRepairScratch(
        operand: Data,
        item: PortableFSItem,
        retireBinding: @escaping @Sendable (PortableFSItem) async -> Void
    ) async throws {
        guard var transaction = armed[operand] else {
            throw PfsMacOSCoherenceError.repairNotArmed
        }
        guard transaction.plan.kind == .negativeScratch,
              transaction.consumed == [.createScratch],
              transaction.localScratch == nil,
              !transaction.validated else {
            throw PfsMacOSCoherenceError.repairCallbackOutOfOrder
        }
        transaction.localScratch = Transaction.LocalScratchOwnership(
            item: item,
            retireBinding: retireBinding
        )
        armed[operand] = transaction
    }

    public func isArmedRepairSource(
        parentIdentity: Data,
        name: Data
    ) -> Bool {
        armed.values.contains { transaction in
            transaction.plan.kind != .negativeScratch
                && transaction.plan.parentIdentity.bytes == parentIdentity
                && transaction.plan.authenticatedSourceName == name
                && !transaction.consumed.contains(.removeSource)
        }
    }

    public func isArmedRepairTraversal(
        parentIdentity: Data,
        name: Data
    ) -> Bool {
        let coordinate = TraversalCoordinate(
            parentIdentity: parentIdentity,
            name: name
        )
        return armed.values.contains { transaction in
            transaction.traversalCoordinates.contains(coordinate)
        }
    }

    public func isArmedRepairTraversalItem(itemIdentity: Data) -> Bool {
        armed.values.contains { transaction in
            transaction.traversalItemIdentities.contains(itemIdentity)
        }
    }

    /// Whether an `openItem` callback can still belong to the actuator's source
    /// acquisition. FSKit exposes no caller or repair token on open, so the
    /// exact source vnode is treated as repair-owned only until removeSource is
    /// consumed. A later open must take ordinary publication admission rather
    /// than inheriting teardown ownership for the rest of the lease.
    public func isArmedRepairSourceOpenItem(itemIdentity: Data) -> Bool {
        armed.values.contains { transaction in
            transaction.plan.kind != .negativeScratch
                && transaction.plan.itemIdentity.bytes == itemIdentity
                && !transaction.consumed.contains(.removeSource)
        }
    }

    public func isArmedRepairSourceItem(itemIdentity: Data) -> Bool {
        armed.values.contains { transaction in
            transaction.plan.kind != .negativeScratch
                && transaction.plan.itemIdentity.bytes == itemIdentity
                // Source-name ownership ends when removeSource is consumed,
                // but source-VNODE ownership lasts until the actuator syscall
                // has returned and its lease finishes. FSKit may issue
                // getattr/xattr/close/reclaim callbacks after removeItem has
                // replied but before unlinkat(2) returns. Dropping this bit at
                // mutation consumption parks that teardown tail behind the
                // COMPLETE barrier that is waiting for unlinkat: a cycle.
        }
    }

    public func isArmedRepairParentItem(itemIdentity: Data) -> Bool {
        armed.values.contains { transaction in
            transaction.plan.parentIdentity.bytes == itemIdentity
        }
    }

    public func consumeArmedSourceRemoval(
        parentIdentity: Data,
        name: Data,
        item: PortableFSItem
    ) throws -> PfsMacOS26ArmedSourceRemovalDisposition? {
        let matches = armed.filter { _, transaction in
            (transaction.plan.kind == .positiveEviction
                || transaction.plan.kind == .dataInvalidation)
                && transaction.plan.parentIdentity.bytes == parentIdentity
                && transaction.plan.authenticatedSourceName == name
                && transaction.plan.itemIdentity.bytes == item.identity.stableIdentity
        }
        guard !matches.isEmpty else { return nil }
        guard matches.count == 1, let match = matches.first else {
            throw PfsMacOSCoherenceError.invalidRepairOperand
        }
        let operand = match.key
        var transaction = match.value
        guard transaction.consumed.count < transaction.required.count,
              transaction.required[transaction.consumed.count] == .removeSource else {
            throw PfsMacOSCoherenceError.repairCallbackOutOfOrder
        }
        transaction.consumed.append(.removeSource)
        armed[operand] = transaction
        switch transaction.plan.kind {
        case .positiveEviction:
            return .positiveEviction
        case .dataInvalidation:
            return .dataInvalidation
        case .negativeScratch, .attributeRefresh:
            // The match predicate above excludes both kinds.
            throw PfsMacOSCoherenceError.invalidRepairOperand
        }
    }

    public func isArmedTruncateItem(itemIdentity: Data) -> Bool {
        armed.values.contains { transaction in
            transaction.plan.kind == .dataInvalidation
                && transaction.dataRepairActive
                && transaction.plan.itemIdentity.bytes == itemIdentity
        }
    }

    public func isArmedAttributeRefreshItem(itemIdentity: Data) -> Bool {
        if let activeOperand {
            guard let transaction = armed[activeOperand] else { return false }
            return transaction.plan.kind == .attributeRefresh
                && transaction.plan.itemIdentity.bytes == itemIdentity
        }
        return armed.values.filter { transaction in
            transaction.plan.kind == .attributeRefresh
                && transaction.plan.itemIdentity.bytes == itemIdentity
        }.count == 1
    }

    public func consumeArmedAttributeRefresh(
        itemIdentity: Data
    ) -> PfsMacOS26ArmedAttributeRefreshConsumption? {
        let matchingOperands = armed.compactMap { operand, transaction in
            transaction.plan.kind == .attributeRefresh
                && transaction.plan.itemIdentity.bytes == itemIdentity
                && transaction.plan.expectedVFSFileID != nil
                ? operand
                : nil
        }
        let operand: Data
        if let activeOperand {
            guard matchingOperands.contains(activeOperand) else { return nil }
            operand = activeOperand
        } else {
            // Standalone one-plan users predate explicit actuation. Preserve
            // that safe case, but refuse ambiguous same-inode aliases rather
            // than choosing a dictionary entry nondeterministically.
            guard matchingOperands.count == 1, let only = matchingOperands.first else {
                return nil
            }
            operand = only
        }
        guard var transaction = armed[operand],
              let expectedVFSFileID = transaction.plan.expectedVFSFileID else {
            return nil
        }
        // FSKit carries no caller or repair token on setattr. Keep all mode-only
        // callbacks on the exact active item local for this syscall window so
        // an indistinguishable user request cannot consume a single slot and
        // park fchmod behind this barrier.
        transaction.attributeRefreshConsumptions += 1
        armed[operand] = transaction
        return .init(expectedVFSFileID: expectedVFSFileID)
    }

    public func consumeArmedTruncate(
        itemIdentity: Data,
        size: UInt64
    ) -> PfsMacOS26ArmedTruncateConsumption? {
        // Barriers actuate repairs one plan at a time, so at most one live
        // data-repair window can name this identity; iteration order is
        // irrelevant for a match that must be exact on every coordinate.
        for (operand, var transaction) in armed {
            guard transaction.plan.kind == .dataInvalidation,
                  transaction.dataRepairActive,
                  transaction.plan.itemIdentity.bytes == itemIdentity,
                  transaction.plan.authoritativeSize == size,
                  let expectedVFSFileID = transaction.plan.expectedVFSFileID else {
                continue
            }
            transaction.truncateConsumptions += 1
            armed[operand] = transaction
            return PfsMacOS26ArmedTruncateConsumption(
                expectedVFSFileID: expectedVFSFileID,
                size: size
            )
        }
        return nil
    }

    // MARK: - Lease body

    fileprivate func validate(operand: Data) async throws {
        guard var transaction = armed[operand] else {
            throw PfsMacOSCoherenceError.repairNotArmed
        }
        guard activeOperand == nil || activeOperand == operand else {
            throw PfsMacOSCoherenceError.repairCallbackOutOfOrder
        }
        let namespaceComplete = transaction.consumed == transaction.required
            || transaction.plan.kind == .positiveEviction
                && transaction.consumed.isEmpty
        guard namespaceComplete,
              transaction.plan.kind != .dataInvalidation
                || transaction.truncateConsumptions > 0,
              transaction.plan.kind != .attributeRefresh
                || transaction.attributeRefreshConsumptions > 0 else {
            throw PfsMacOSCoherenceError.repairCallbackOutOfOrder
        }
        // The actuator intentionally accepts ENOENT for a positive eviction:
        // the kernel has already proved the cached name absent and emits no
        // remove callback. Retire the old attested coordinate here as well as
        // in OperationsAdapter's callback path, before the barrier resumes.
        // The operation is idempotent when the callback already forgot it.
        if transaction.plan.kind == .positiveEviction {
            if let name = transaction.plan.authenticatedSourceName,
               let namespaceIndex {
                await namespaceIndex.forget(
                    parentIdentity: transaction.plan.parentIdentity,
                    name: name
                )
            }
        }
        transaction.validated = true
        armed[operand] = transaction
        if activeOperand == operand { activeOperand = nil }
    }

    fileprivate func release(operand: Data) async throws {
        guard let transaction = armed[operand] else {
            throw PfsMacOSCoherenceError.repairNotArmed
        }
        guard transaction.validated else {
            throw PfsMacOSCoherenceError.repairCallbackOutOfOrder
        }
        armed.removeValue(forKey: operand)
        if let scratch = transaction.localScratch {
            await scratch.retireBinding(scratch.item)
        }
    }

    fileprivate func cancel(operand: Data) async {
        guard let transaction = armed.removeValue(forKey: operand) else { return }
        if activeOperand == operand { activeOperand = nil }
        if let scratch = transaction.localScratch {
            await scratch.retireBinding(scratch.item)
        }
    }

    private struct Lease: PfsMacOS26RepairArmLease {
        let registry: PfsMacOS26RepairArmRegistry
        let operand: Data

        func activate() async throws { try await registry.activate(operand: operand) }
        func validate() async throws { try await registry.validate(operand: operand) }
        func release() async throws { try await registry.release(operand: operand) }
        func cancel() async { await registry.cancel(operand: operand) }
    }
}
