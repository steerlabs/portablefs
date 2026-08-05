import Foundation

/// A namespace transaction that moved a user's name to the hidden operand and
/// then failed to put it back. Recording it is the only honest outcome: the
/// mount can no longer describe its own namespace, so it must stop.
public struct PfsMacOS26TornRepair: Sendable, Equatable {
    public let sequence: UInt64
    public let step: UInt32
    public let kind: PfsMacOS26RepairKind
    /// The reserved name the user's file is stranded under.
    public let hiddenName: Data
    /// The user-namespace name it was renamed away from.
    public let sourceName: Data?
}

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
    /// transaction's isolation window with the tightest binding the platform
    /// offers: item stable identity, authority epoch and barrier sequence
    /// (bound into the armed plan's authenticated operand), the exact
    /// authoritative post-repair size, and consumption that exists only while
    /// the hidden-rename isolation transaction holds the file at its
    /// authenticated hidden name — never a wall-clock window.
    ///
    /// The residual race is exact and bounded: a process that, during the
    /// isolation window, addresses the hidden operand and truncates it to
    /// exactly the authoritative post-state size has that metadata-only effect
    /// coalesced with the repair — the file was about to hold precisely that
    /// size, and XFS already does. A truncate to any other size, on any other
    /// item, or outside the window is never swallowed. This coalescing is the
    /// reason the macOS 26 policy is a declared "~98%" compatibility policy
    /// rather than the exact contract; macOS 27's native cache API closes it.
    public static let defaultSupportedKinds: Set<PfsMacOS26RepairKind> = [
        .negativeScratch,
        .positiveEviction,
        .dataInvalidation
    ]

    private struct Transaction {
        let plan: PfsMacOS26RepairPlan
        let required: [PfsMacOS26RepairCallback]
        var consumed: [PfsMacOS26RepairCallback] = []
        var rolledBack = false
        /// The item the isolating rename parked at the hidden operand. Only a
        /// data-invalidation transaction records it, and only while isolation
        /// is live may a reserved-name lookup be answered with it.
        var isolatedItem: PortableFSItem?
        /// Exact-size truncates swallowed during this isolation window. The
        /// actuator's own truncate is the first; a racing identical truncate
        /// is coalesced rather than double-applied.
        var truncateConsumptions = 0

        /// The user's name is parked at the hidden operand: after the
        /// isolating rename, before removal or rollback.
        var isolationActive: Bool {
            consumed.contains(.renameIntoOperand)
                && !consumed.contains(.removeOperand)
                && !rolledBack
        }
    }

    private let authenticator: PfsMacOS26RepairAuthenticator
    private let supportedKinds: Set<PfsMacOS26RepairKind>
    private var armed: [Data: Transaction] = [:]
    private var torn: [PfsMacOS26TornRepair] = []

    public init(
        authenticator: PfsMacOS26RepairAuthenticator,
        supportedKinds: Set<PfsMacOS26RepairKind> = defaultSupportedKinds
    ) {
        self.authenticator = authenticator
        self.supportedKinds = supportedKinds
    }

    /// Sealed means a transaction tore. Nothing is ever armed again.
    public var isSealed: Bool { !torn.isEmpty }
    public func tornRepairs() -> [PfsMacOS26TornRepair] { torn }
    public func armedOperandCount() -> Int { armed.count }

    /// The callbacks this operand may still legally produce, in order. Empty
    /// for an operand that is not armed.
    public func pendingCallbacks(operand: Data) -> [PfsMacOS26RepairCallback] {
        guard let transaction = armed[operand] else { return [] }
        return Array(transaction.required.dropFirst(transaction.consumed.count))
    }

    // MARK: - Armer

    public func arm(_ plan: PfsMacOS26RepairPlan) async throws -> any PfsMacOS26RepairArmLease {
        guard torn.isEmpty else { throw PfsMacOSCoherenceError.repairRegistrySealed }
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
        armed[operand] = Transaction(plan: plan, required: plan.requiredCallbacks)
        return Lease(registry: self, operand: operand)
    }

    // MARK: - Gate

    public func consume(
        callback: PfsMacOS26RepairCallback,
        operand: Data,
        sourceName: Data?,
        parentIdentity: Data?,
        item: PortableFSItem?
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
        if callback == .rollbackRename {
            // Authorized only while the user's name is actually parked at the
            // operand: after the isolating rename, before the removal.
            guard transaction.consumed.contains(.renameIntoOperand),
                  !transaction.consumed.contains(.removeOperand),
                  !transaction.rolledBack else {
                throw PfsMacOSCoherenceError.repairCallbackOutOfOrder
            }
            guard sourceName == transaction.plan.authenticatedSourceName else {
                throw PfsMacOSCoherenceError.invalidRepairOperand
            }
            transaction.rolledBack = true
            transaction.isolatedItem = nil
            armed[operand] = transaction
            return
        }
        guard !transaction.rolledBack else {
            throw PfsMacOSCoherenceError.repairCallbackOutOfOrder
        }
        if transaction.consumed.contains(callback) {
            throw PfsMacOSCoherenceError.repairAlreadyConsumed
        }
        guard transaction.consumed.count < transaction.required.count,
              transaction.required[transaction.consumed.count] == callback else {
            throw PfsMacOSCoherenceError.repairCallbackOutOfOrder
        }
        if callback == .renameIntoOperand {
            guard sourceName == transaction.plan.authenticatedSourceName else {
                throw PfsMacOSCoherenceError.invalidRepairOperand
            }
            if transaction.plan.kind == .dataInvalidation {
                // The isolation window answers exactly one object. Without the
                // item, a later reserved lookup or armed truncate would have
                // nothing provable to bind to.
                guard let item else { throw PfsMacOSCoherenceError.invalidRepairOperand }
                transaction.isolatedItem = item
            }
        }
        if callback == .removeOperand, transaction.plan.kind == .dataInvalidation {
            // Removal ends the isolation window. Admitting it before the armed
            // truncate was consumed would let the plan's data half be silently
            // skipped while its namespace half completes.
            guard transaction.truncateConsumptions > 0 else {
                throw PfsMacOSCoherenceError.repairCallbackOutOfOrder
            }
            transaction.isolatedItem = nil
        }
        transaction.consumed.append(callback)
        armed[operand] = transaction
    }

    public func isolatedRepairItem(operand: Data) -> PortableFSItem? {
        guard let transaction = armed[operand],
              transaction.plan.kind == .dataInvalidation,
              transaction.isolationActive else {
            return nil
        }
        return transaction.isolatedItem
    }

    public func isArmedTruncateItem(itemIdentity: Data) -> Bool {
        armed.values.contains { transaction in
            transaction.plan.kind == .dataInvalidation
                && transaction.isolationActive
                && transaction.plan.itemIdentity.bytes == itemIdentity
        }
    }

    public func consumeArmedTruncate(
        itemIdentity: Data,
        size: UInt64
    ) -> PfsMacOS26ArmedTruncateConsumption? {
        // Barriers actuate repairs one plan at a time, so at most one live
        // isolation window can name this identity; iteration order is
        // irrelevant for a match that must be exact on every coordinate.
        for (operand, var transaction) in armed {
            guard transaction.plan.kind == .dataInvalidation,
                  transaction.isolationActive,
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

    fileprivate func finish(operand: Data) throws {
        guard let transaction = armed.removeValue(forKey: operand) else {
            throw PfsMacOSCoherenceError.repairNotArmed
        }
        guard !transaction.rolledBack,
              transaction.consumed == transaction.required,
              transaction.plan.kind != .dataInvalidation
                || transaction.truncateConsumptions > 0 else {
            recordTearIfNeeded(transaction, operand: operand)
            throw PfsMacOSCoherenceError.repairTransactionTorn(
                hiddenName: String(decoding: operand, as: UTF8.self),
                rolledBack: transaction.rolledBack
            )
        }
    }

    fileprivate func cancel(operand: Data) {
        guard let transaction = armed.removeValue(forKey: operand) else { return }
        recordTearIfNeeded(transaction, operand: operand)
    }

    /// A transaction is torn exactly when it moved the user's name to the
    /// operand and neither removed it nor put it back. Every other partial
    /// state left the user namespace untouched.
    private func recordTearIfNeeded(_ transaction: Transaction, operand: Data) {
        guard transaction.consumed.contains(.renameIntoOperand),
              !transaction.consumed.contains(.removeOperand),
              !transaction.rolledBack else {
            return
        }
        torn.append(
            PfsMacOS26TornRepair(
                sequence: transaction.plan.sequence,
                step: transaction.plan.step,
                kind: transaction.plan.kind,
                hiddenName: operand,
                sourceName: transaction.plan.authenticatedSourceName
            )
        )
    }

    private struct Lease: PfsMacOS26RepairArmLease {
        let registry: PfsMacOS26RepairArmRegistry
        let operand: Data

        func finish() async throws { try await registry.finish(operand: operand) }
        func cancel() async { await registry.cancel(operand: operand) }
    }
}
