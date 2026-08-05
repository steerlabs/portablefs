import CryptoKit
import Foundation
@preconcurrency import Darwin

/// Cache-coherence behavior is an attach contract, not an inference from an OS
/// version. A client and authority must agree on one exact policy before the
/// mount becomes visible.
public enum PfsMacOSCachePolicy: String, Sendable, CaseIterable {
    /// macOS 26: synchronous, authenticated VFS operations drive the kernel's
    /// cache transitions before the authority mutation is acknowledged.
    case synchronousVFSRepairV1 = "macos26-synchronous-vfs-repair-v1"

    /// macOS 27+: synchronous kernel cache revocation through Apple's native
    /// FSKit API. The Xcode 26 SDK intentionally has no implementation.
    case nativeFSKitRevocationV1 = "fskit-native-revocation-v1"
}

public enum PfsMacOSCoherenceError: Error, Equatable, CustomStringConvertible {
    case missingV3CoherenceContract
    case invalidAuthorityProtocolMajor(UInt32)
    case invalidEpochLength(Int)
    case invalidSecretLength(Int)
    case invalidSessionIDLength(Int)
    case invalidStableIdentityLength(Int)
    case invalidCachePolicy(String)
    case invalidRepairBudget(UInt64)
    case repairDeadlineExceeded(
        sequence: UInt64,
        phase: PfsMacOSVisibilityPhase,
        budgetMillis: UInt64
    )
    case livenessDeadlineExceeded(UInt64)
    case livenessSessionMismatch
    case initialCursorMustBeComplete
    case invalidPathComponent
    case invalidSequence(UInt64)
    case invalidVisibilityPhase(Int)
    case invalidVisibilityScope(Int)
    case invalidVisibilityTarget
    case invalidRoutesChange
    case routesChangeRequiresRemount
    case sequenceGap(expected: UInt64, received: UInt64)
    case epochChanged
    case invalidRepairOperand
    case unsupportedRepair
    case nativeRevocationUnavailable
    case transportClosed
    case posix(operation: String, errno: Int32)
    /// The adapter has no unforgeable provenance channel for at least one
    /// FSKit callback this repair kind requires, so it refuses to arm it.
    case repairKindUnsupported(PfsMacOS26RepairKind)
    /// A reserved-namespace callback arrived with no live armed transaction.
    case repairNotArmed
    case repairAlreadyArmed
    /// One-shot consumption already happened for this exact callback.
    case repairAlreadyConsumed
    /// The callback is part of the plan but not the next one it declared.
    case repairCallbackOutOfOrder
    /// A namespace transaction moved the user's name to the hidden operand and
    /// then failed. `rolledBack` says whether the local namespace was restored.
    case repairTransactionTorn(hiddenName: String, rolledBack: Bool)
    /// A torn transaction permanently seals the registry: this mount can no
    /// longer prove its own namespace state, so it runs no further surgery.
    case repairRegistrySealed
    /// An identity mapping does not reach the mount root.
    case namespaceCycle

    public var description: String {
        switch self {
        case .missingV3CoherenceContract:
            return "resolved v3 attach omitted its coherence contract"
        case let .invalidAuthorityProtocolMajor(major):
            return "unsupported authority protocol major \(major)"
        case let .invalidEpochLength(length):
            return "authority epoch has \(length) bytes; expected 16"
        case let .invalidSecretLength(length):
            return "repair secret has \(length) bytes; expected 32"
        case let .invalidSessionIDLength(length):
            return "mount session identifier has \(length) bytes; expected 16"
        case let .invalidStableIdentityLength(length):
            return "stable item identity has \(length) bytes; expected 16"
        case let .invalidCachePolicy(policy):
            return "unsupported macOS cache policy \(policy)"
        case let .invalidRepairBudget(budget):
            return "invalid macOS repair budget \(budget) milliseconds"
        case let .repairDeadlineExceeded(sequence, phase, budget):
            return "macOS visibility repair \(sequence)/\(phase) exceeded \(budget) milliseconds"
        case let .livenessDeadlineExceeded(budget):
            return "strict-v3 liveness round trip exceeded \(budget) milliseconds"
        case .livenessSessionMismatch:
            return "strict-v3 liveness reply changed the resolved authority session"
        case .initialCursorMustBeComplete:
            return "initial visibility cursor must be COMPLETE"
        case .invalidPathComponent:
            return "repair path contains an invalid component"
        case let .invalidSequence(sequence):
            return "repair sequence \(sequence) is invalid"
        case let .invalidVisibilityPhase(phase):
            return "unsupported visibility phase \(phase)"
        case let .invalidVisibilityScope(scope):
            return "unsupported visibility scope \(scope)"
        case .invalidVisibilityTarget:
            return "visibility target has fields outside its declared scope"
        case .invalidRoutesChange:
            return "visibility route change has an invalid shape"
        case .routesChangeRequiresRemount:
            return "visibility route change requires this mount to fail closed and remount"
        case let .sequenceGap(expected, received):
            return "repair sequence gap: expected \(expected), received \(received)"
        case .epochChanged:
            return "coherence event belongs to a different authority epoch"
        case .invalidRepairOperand:
            return "repair operand is not authenticated for this mount session"
        case .unsupportedRepair:
            return "repair cannot be represented by this cache policy"
        case .nativeRevocationUnavailable:
            return "the selected SDK has no native FSKit cache-revocation implementation"
        case .transportClosed:
            return "coherence transport closed before the barrier completed"
        case let .posix(operation, code):
            return "\(operation) failed with errno \(code)"
        case let .repairKindUnsupported(kind):
            return "repair kind \(kind) has no unforgeable provenance channel in this adapter"
        case .repairNotArmed:
            return "reserved repair namespace touched without an armed transaction"
        case .repairAlreadyArmed:
            return "repair operand is already armed"
        case .repairAlreadyConsumed:
            return "repair callback was already consumed once"
        case .repairCallbackOutOfOrder:
            return "repair callback arrived out of the order the plan declared"
        case let .repairTransactionTorn(hiddenName, rolledBack):
            return rolledBack
                ? "repair transaction failed and was rolled back from \(hiddenName)"
                : "repair transaction is torn: a name is stranded at \(hiddenName)"
        case .repairRegistrySealed:
            return "repair registry is sealed after a torn transaction"
        case .namespaceCycle:
            return "identity mapping does not reach the mount root"
        }
    }
}

/// Stable XFS identity supplied by the authority's visibility contract. It is
/// distinct from both an epoch-local item capability and the numeric inode ID
/// projected by a particular FSKit mount.
public struct PfsMacOSStableIdentity: Sendable, Equatable, Hashable {
    public let bytes: Data

    public init(_ bytes: Data) throws {
        guard bytes.count == 16 else {
            throw PfsMacOSCoherenceError.invalidStableIdentityLength(bytes.count)
        }
        self.bytes = bytes
    }

    public static let zero = try! PfsMacOSStableIdentity(Data(repeating: 0, count: 16))
}

/// A path relative to the already-attested mount root. Components are bytes so
/// the repair protocol does not accidentally narrow filesystem names to Unicode.
public struct PfsMacOSRelativePath: Sendable, Equatable, Hashable {
    public let components: [Data]

    public init(components: [Data]) throws {
        for component in components {
            guard !component.isEmpty,
                  component != Data(".".utf8),
                  component != Data("..".utf8),
                  !component.contains(0),
                  !component.contains(UInt8(ascii: "/")) else {
                throw PfsMacOSCoherenceError.invalidPathComponent
            }
        }
        self.components = components
    }

    public var parent: PfsMacOSRelativePath? {
        guard !components.isEmpty else { return nil }
        return try? PfsMacOSRelativePath(components: Array(components.dropLast()))
    }

    public var name: Data? { components.last }
}

/// One still-live FSKit object that may outlast every namespace alias.
///
/// This is deliberately an object reference, not another path projection. An
/// open file that has been unlinked on every mount still owns a kernel vnode,
/// and a native FSKit revoker must address that vnode directly after a remote
/// write or attribute change.
public struct PfsMacOSLiveObjectReference: @unchecked Sendable, Equatable {
    public let item: PortableFSItem
    /// `st_ino` as projected by this exact mount.
    public let vfsFileID: UInt64

    public init(item: PortableFSItem, vfsFileID: UInt64) {
        self.item = item
        self.vfsFileID = vfsFileID
    }

    public static func == (
        lhs: PfsMacOSLiveObjectReference,
        rhs: PfsMacOSLiveObjectReference
    ) -> Bool {
        lhs.item === rhs.item && lhs.vfsFileID == rhs.vfsFileID
    }
}

public enum PfsMacOSCacheRepair: Sendable, Equatable {
    /// Purges negative name-cache entries in `parent` by creating and removing
    /// an authenticated synthetic child.
    ///
    /// `PortableFSVolume` consumes the matching `createItem` and `removeItem`
    /// callbacks against `PfsMacOS26RepairArmRegistry` and returns without
    /// issuing any pfslocal request, so neither call reaches the authority.
    /// With no registry installed — the production configuration today — the
    /// same two callbacks are refused with EPERM instead.
    /// `name` is retained even though the macOS 26 synthetic actuator cannot
    /// address a negative dentry directly. The native macOS 27 adapter must
    /// not lose this coordinate before its live-kernel proof establishes what
    /// parent revocation does to that exact child.
    case purgeNegative(
        parent: PfsMacOSRelativePath,
        parentIdentity: PfsMacOSStableIdentity,
        name: Data
    )

    /// Purges a positive binding and its cached attributes by renaming it to an
    /// authenticated synthetic name and removing that name locally. A later
    /// lookup fetches the authority's current binding.
    case evictBinding(
        path: PfsMacOSRelativePath,
        parentIdentity: PfsMacOSStableIdentity,
        itemIdentity: PfsMacOSStableIdentity
    )

    /// Purges cached data and size for the same authoritative item. The
    /// actuator performs an unconditional ftruncate followed by an invalidating
    /// shared mapping. A conditional size check is incorrect on macOS 26: stat
    /// metadata and readable EOF can disagree.
    case invalidateData(
        path: PfsMacOSRelativePath,
        parentIdentity: PfsMacOSStableIdentity,
        itemIdentity: PfsMacOSStableIdentity,
        expectedVFSFileID: UInt64,
        authoritativeSize: UInt64
    )

    /// Native macOS 27+ revocation for a live vnode with no remaining path.
    /// macOS 26 has no safe representation and must fail this repair closed.
    case invalidateDataObject(
        object: PfsMacOSLiveObjectReference,
        itemIdentity: PfsMacOSStableIdentity,
        authoritativeSize: UInt64
    )

    /// Native macOS 27+ attribute revocation for an open-but-unlinked vnode.
    /// This must never be silently replaced by an empty repair list.
    case invalidateAttributesObject(
        object: PfsMacOSLiveObjectReference,
        itemIdentity: PfsMacOSStableIdentity
    )
}

public enum PfsMacOSVisibilityPhase: UInt8, Sendable, Equatable {
    /// Close callback publication admission and drain callbacks admitted before
    /// this barrier. No XFS mutation has happened yet.
    case prepare = 1
    /// Repair the post-mutation kernel state, then reopen callback admission.
    case complete = 2
}

/// Identifies the exact admitted mutation callback that owns the authority
/// operation. Publication barriers use this ticket—not a path heuristic—to
/// avoid waiting on the initiator while it waits for the authority reply.
public struct PfsMacOSMutationInitiator: Sendable, Equatable, Hashable {
    public let sessionID: Data
    public let replaySlot: UInt32
    public let mutationSequence: UInt64
    /// The pfslocal logical callback ID for this mount's own mutation. Peer
    /// events carry nil. This is the exact publication lease the callback
    /// barrier exempts at PREPARE and waits for at source COMPLETE.
    public let localOperationID: UInt64?

    public init(
        sessionID: Data,
        replaySlot: UInt32,
        mutationSequence: UInt64,
        localOperationID: UInt64? = nil
    ) throws {
        guard sessionID.count == 16 else {
            throw PfsMacOSCoherenceError.invalidSessionIDLength(sessionID.count)
        }
        guard mutationSequence > 0 else {
            throw PfsMacOSCoherenceError.invalidSequence(mutationSequence)
        }
        if let localOperationID, localOperationID == 0 {
            throw PfsMacOSCoherenceError.invalidSequence(0)
        }
        self.sessionID = sessionID
        self.replaySlot = replaySlot
        self.mutationSequence = mutationSequence
        self.localOperationID = localOperationID
    }
}

/// Every event describes the complete client-side work required for one
/// authority mutation. Peer COMPLETE acknowledgements precede the mutation
/// reply. The source COMPLETE is delivered too, but is acknowledged only after
/// the ordinary initiating callback publishes; the next mutation waits for it.
public struct PfsMacOSCoherenceEvent: Sendable, Equatable {
    public let epoch: Data
    public let sequence: UInt64
    public let phase: PfsMacOSVisibilityPhase
    public let initiator: PfsMacOSMutationInitiator
    public let repairs: [PfsMacOSCacheRepair]

    public init(
        epoch: Data,
        sequence: UInt64,
        phase: PfsMacOSVisibilityPhase,
        initiator: PfsMacOSMutationInitiator,
        repairs: [PfsMacOSCacheRepair]
    ) throws {
        guard epoch.count == 16 else {
            throw PfsMacOSCoherenceError.invalidEpochLength(epoch.count)
        }
        guard sequence > 0 else {
            throw PfsMacOSCoherenceError.invalidSequence(sequence)
        }
        self.epoch = epoch
        self.sequence = sequence
        self.phase = phase
        self.initiator = initiator
        self.repairs = repairs
    }
}

public struct PfsMacOSVisibilityCursor: Sendable, Equatable {
    public let sequence: UInt64
    public let phase: PfsMacOSVisibilityPhase

    public init(sequence: UInt64, phase: PfsMacOSVisibilityPhase) {
        self.sequence = sequence
        self.phase = phase
    }
}

public protocol PfsMacOSCoherenceBackend: Sendable {
    var policy: PfsMacOSCachePolicy { get }
    func repair(_ event: PfsMacOSCoherenceEvent) async throws
}

/// Transport deliberately separates event delivery, cumulative acknowledgement,
/// and terminal failure. A dropped connection, frozen actuator, cancellation, or
/// failed syscall has no path to an acknowledgement.
public protocol PfsMacOSCoherenceTransport: Sendable {
    func nextEvent() async throws -> PfsMacOSCoherenceEvent?
    func acknowledge(epoch: Data, cursor: PfsMacOSVisibilityCursor) async throws
    func failClosed(epoch: Data, cursor: PfsMacOSVisibilityCursor?, reason: String) async
}

/// Resolves one operation/watchdog race without making the caller wait for a
/// repair backend that ignored cancellation. The losing repair task remains
/// cancelled and cannot advance the cursor because `consumeEvent` checks
/// cancellation after the backend returns and before touching its ledger.
final class PfsMacOSDeadlineRace: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Void, Error>?
    private var waiters: [CheckedContinuation<Void, Error>] = []

    func wait() async throws {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            if let result {
                lock.unlock()
                continuation.resume(with: result)
                return
            }
            waiters.append(continuation)
            lock.unlock()
        }
    }

    func resolve(_ result: Result<Void, Error>) {
        lock.lock()
        guard self.result == nil else {
            lock.unlock()
            return
        }
        self.result = result
        let waiters = waiters
        self.waiters.removeAll()
        lock.unlock()
        for waiter in waiters {
            waiter.resume(with: result)
        }
    }
}

/// Runs one strict mount's ordered visibility barrier.
public actor PfsMacOSCoherenceRunner {
    public let epoch: Data
    public let policy: PfsMacOSCachePolicy

    private let backend: any PfsMacOSCoherenceBackend
    private let transport: any PfsMacOSCoherenceTransport
    private let repairBudgetMillis: UInt64?
    private let repairBudget: Duration?
    /// The last cursor whose local repair actually ran to completion. This is
    /// the exactly-once ledger: it is written BEFORE the authority
    /// acknowledgment, so a lost, refused, or cancelled ack can only ever cost
    /// a repeated ack — never a second run of namespace surgery.
    private var lastCompletedCursor: PfsMacOSVisibilityCursor?
    /// The last cursor the transport confirmed it delivered to the authority.
    /// It exists for reporting and for `failClosed`; ordering never uses it.
    private var lastAcknowledgedCursor: PfsMacOSVisibilityCursor?
    private var terminal = false

    public init(
        epoch: Data,
        initialAcknowledgedCursor: PfsMacOSVisibilityCursor? = nil,
        repairBudgetMillis: UInt64? = nil,
        backend: any PfsMacOSCoherenceBackend,
        transport: any PfsMacOSCoherenceTransport
    ) throws {
        guard epoch.count == 16 else {
            throw PfsMacOSCoherenceError.invalidEpochLength(epoch.count)
        }
        if let repairBudgetMillis {
            guard repairBudgetMillis > 0,
                  repairBudgetMillis <= UInt64(Int64.max) else {
                throw PfsMacOSCoherenceError.invalidRepairBudget(repairBudgetMillis)
            }
        }
        self.epoch = epoch
        self.policy = backend.policy
        self.repairBudgetMillis = repairBudgetMillis
        self.repairBudget = repairBudgetMillis.map {
            .milliseconds(Int64($0))
        }
        self.lastCompletedCursor = initialAcknowledgedCursor
        self.lastAcknowledgedCursor = initialAcknowledgedCursor
        self.backend = backend
        self.transport = transport
    }

    public func run() async throws {
        guard !terminal else { throw PfsMacOSCoherenceError.transportClosed }
        do {
            while let event = try await transport.nextEvent() {
                try Task.checkCancellation()
                try await consume(event)
            }
            throw PfsMacOSCoherenceError.transportClosed
        } catch {
            if !terminal {
                terminal = true
                await transport.failClosed(
                    epoch: epoch,
                    cursor: lastAcknowledgedCursor,
                    reason: String(describing: error)
                )
            }
            throw error
        }
    }

    public func consume(_ event: PfsMacOSCoherenceEvent) async throws {
        guard let repairBudget, let repairBudgetMillis else {
            try await consumeEvent(event)
            return
        }

        let race = PfsMacOSDeadlineRace()
        let operation = Task {
            do {
                try await self.consumeEvent(event)
                race.resolve(.success(()))
            } catch {
                race.resolve(.failure(error))
            }
        }
        let watchdog = Task {
            do {
                try await Task.sleep(for: repairBudget)
                operation.cancel()
                race.resolve(.failure(PfsMacOSCoherenceError.repairDeadlineExceeded(
                    sequence: event.sequence,
                    phase: event.phase,
                    budgetMillis: repairBudgetMillis
                )))
            } catch {
                // The operation or caller won the race and cancelled the timer.
            }
        }

        do {
            try await withTaskCancellationHandler {
                try await race.wait()
            } onCancel: {
                operation.cancel()
                watchdog.cancel()
                race.resolve(.failure(CancellationError()))
            }
            watchdog.cancel()
        } catch {
            operation.cancel()
            watchdog.cancel()
            if case PfsMacOSCoherenceError.repairDeadlineExceeded = error {
                terminal = true
                await transport.failClosed(
                    epoch: epoch,
                    cursor: lastAcknowledgedCursor,
                    reason: String(describing: error)
                )
            }
            throw error
        }
    }

    private func consumeEvent(_ event: PfsMacOSCoherenceEvent) async throws {
        guard !terminal else { throw PfsMacOSCoherenceError.transportClosed }
        guard event.epoch == epoch else { throw PfsMacOSCoherenceError.epochChanged }

        let cursor = PfsMacOSVisibilityCursor(sequence: event.sequence, phase: event.phase)
        if cursor == lastCompletedCursor {
            // The repair already ran to completion locally. Whether or not the
            // authority ever saw the ack, rerunning namespace surgery here
            // would be a second, differently-nonced set of real VFS mutations
            // against the user's namespace. Re-ack only.
            try await transport.acknowledge(epoch: epoch, cursor: cursor)
            lastAcknowledgedCursor = cursor
            return
        }

        var validSuccessor = false
        let minimumExpectedSequence: UInt64
        if let lastCompletedCursor {
            switch lastCompletedCursor.phase {
            case .prepare:
                validSuccessor = cursor.phase == .complete
                    && cursor.sequence == lastCompletedCursor.sequence
                minimumExpectedSequence = lastCompletedCursor.sequence
            case .complete:
                validSuccessor = cursor.phase == .prepare
                    && cursor.sequence > lastCompletedCursor.sequence
                minimumExpectedSequence = lastCompletedCursor.sequence == UInt64.max
                    ? UInt64.max
                    : lastCompletedCursor.sequence + 1
            }
        } else {
            // Fresh genesis has no positive sequence. A participant is included
            // only in barriers whose footprint may intersect its cache, so its
            // first observed authority sequence may already be sparse.
            validSuccessor = cursor.phase == .prepare && cursor.sequence > 0
            minimumExpectedSequence = 1
        }
        guard validSuccessor else {
            throw PfsMacOSCoherenceError.sequenceGap(
                expected: minimumExpectedSequence,
                received: event.sequence
            )
        }

        try Task.checkCancellation()
        try await backend.repair(event)
        // Ordering is the whole fix: the local ledger advances the instant the
        // surgery is done and before anything can fail on the wire.
        lastCompletedCursor = cursor
        try Task.checkCancellation()
        try await transport.acknowledge(epoch: epoch, cursor: cursor)
        lastAcknowledgedCursor = cursor
    }

    public func acknowledgedCursor() -> PfsMacOSVisibilityCursor? { lastAcknowledgedCursor }

    /// The exactly-once ledger. A cursor at or below this has had its local
    /// repair performed; the authority may or may not know it yet.
    public func completedCursor() -> PfsMacOSVisibilityCursor? { lastCompletedCursor }
}

/// The PREPARE phase must close ordinary cache-producing callback admission,
/// wait for already admitted callbacks to publish, and keep the gate closed
/// through COMPLETE. Implementations must exclude the one initiating callback
/// identified by the authority contract or a source-mount mutation deadlocks.
public protocol PfsMacOSCallbackPublicationBarrier: Sendable {
    func prepare(_ event: PfsMacOSCoherenceEvent) async throws
    /// For a peer mutation, reopen only after every requested repair has
    /// completed. For this mount's own mutation, wait until the exact callback
    /// named by `event.initiator` has published its ordinary FSKit reply, then
    /// reopen. The authority deliberately defers that source COMPLETE so it
    /// never asks FSKit to perform nested VFS surgery behind the callback.
    func resume(_ event: PfsMacOSCoherenceEvent) async throws
}

/// A future macOS 27 implementation supplies this interface with the SDK's
/// native synchronous revoke API. Keeping the interface independent of those
/// symbols lets Xcode 26 compile without pretending the API exists.
public protocol PfsFSKitNativeCacheRevoker: Sendable {
    func revoke(_ repair: PfsMacOSCacheRepair) async throws
}

public struct PfsNativeFSKitCoherenceBackend: PfsMacOSCoherenceBackend {
    public let policy = PfsMacOSCachePolicy.nativeFSKitRevocationV1
    private let localAuthoritySessionID: Data
    private let revoker: any PfsFSKitNativeCacheRevoker
    private let publicationBarrier: any PfsMacOSCallbackPublicationBarrier

    public init(
        localAuthoritySessionID: Data,
        revoker: any PfsFSKitNativeCacheRevoker,
        publicationBarrier: any PfsMacOSCallbackPublicationBarrier
    ) throws {
        guard localAuthoritySessionID.count == 16 else {
            throw PfsMacOSCoherenceError.invalidSessionIDLength(localAuthoritySessionID.count)
        }
        self.localAuthoritySessionID = localAuthoritySessionID
        self.revoker = revoker
        self.publicationBarrier = publicationBarrier
    }

    public func repair(_ event: PfsMacOSCoherenceEvent) async throws {
        switch event.phase {
        case .prepare:
            try await publicationBarrier.prepare(event)
        case .complete:
            // The source's normal FSKit callback is its cache transition. A
            // nested revocation can be serialized behind that callback and
            // deadlock. Its deferred COMPLETE waits for callback publication
            // in `resume` instead.
            if event.initiator.sessionID != localAuthoritySessionID {
                for repair in event.repairs {
                    try Task.checkCancellation()
                    try await revoker.revoke(repair)
                }
            }
            try await publicationBarrier.resume(event)
        }
    }
}

public enum PfsMacOS26RepairKind: UInt8, Sendable, Equatable, CaseIterable {
    case negativeScratch = 1
    case positiveEviction = 2
    case dataInvalidation = 3
}

/// The exact NAME-CARRYING FSKit callbacks one repair plan consumes, in the
/// order the actuator's syscalls produce them. Arming a plan authorizes this
/// list and nothing else, which is what lets the adapter answer "swallow or
/// refuse?" per callback rather than per transaction.
///
/// Only callbacks that carry the reserved operand name belong here: the name
/// is the channel the HMAC rides. The data-invalidation open and truncate
/// carry an `FSItem` and no name, so they are structurally impossible to
/// consume through this list; they are authorized instead through the armed
/// transaction's isolation window (`PfsMacOS26RepairGate.consumeArmedTruncate`
/// and `isolatedRepairItem`), which exists only between the isolating rename
/// and the removal of the hidden name. A callback case that the adapter could
/// never present would make a declared plan unexecutable, so no such case
/// exists.
public enum PfsMacOS26RepairCallback: UInt8, Sendable, Equatable, Hashable, CaseIterable {
    /// `createItem(named: operand)` for the negative-cache scratch entry.
    case createScratch = 1
    /// `renameItem(source -> operand)`.
    case renameIntoOperand = 2
    /// `removeItem(named: operand)`.
    case removeOperand = 5
    /// `renameItem(operand -> source)`. Never required; authorized only while
    /// the transaction has moved the user's name and has not yet removed it,
    /// so a failed step can restore the local namespace it disturbed.
    case rollbackRename = 6
}

/// One authority-sequenced, mount-session-authenticated local repair operation.
/// `operand` is a legal single directory-entry name for the two namespace
/// repairs. Data invalidation is authenticated through this same plan but has no
/// visible name operand.
public struct PfsMacOS26RepairPlan: Sendable, Equatable {
    public let epoch: Data
    public let sequence: UInt64
    public let step: UInt32
    public let kind: PfsMacOS26RepairKind
    public let path: PfsMacOSRelativePath
    public let parentIdentity: PfsMacOSStableIdentity
    public let itemIdentity: PfsMacOSStableIdentity
    public let expectedVFSFileID: UInt64?
    public let authoritativeSize: UInt64?
    public let operand: Data?

    /// The user-namespace name the operand's HMAC is bound to, or `nil` for a
    /// scratch create that has no source. Validation must use exactly this.
    public var authenticatedSourceName: Data? {
        switch kind {
        case .negativeScratch:
            return nil
        case .positiveEviction, .dataInvalidation:
            return path.name
        }
    }

    /// The ordered name-carrying callbacks the actuator's syscalls will
    /// produce. `finish()` requires every one of them to have been consumed
    /// exactly once. Data invalidation's open and truncate carry no name and
    /// are therefore authorized through the isolation window instead: the
    /// gate refuses to consume `removeOperand` for a data plan until the
    /// armed truncate has actually been consumed, so the nameless half cannot
    /// be silently skipped.
    public var requiredCallbacks: [PfsMacOS26RepairCallback] {
        switch kind {
        case .negativeScratch:
            return [.createScratch, .removeOperand]
        case .positiveEviction, .dataInvalidation:
            return [.renameIntoOperand, .removeOperand]
        }
    }
}

/// Arms the FSKit adapter before the external VFS actuator issues a syscall.
/// Implementations must consume each plan once and must reject every reserved
/// operand that was not armed and authenticated.
public protocol PfsMacOS26RepairArmLease: Sendable {
    /// Confirms that every callback belonging to the armed transaction was
    /// consumed locally. A partial create/rename transaction is a failure.
    func finish() async throws
    /// Revokes the transaction on every non-success exit, including task
    /// cancellation after arming but before the actuator starts.
    func cancel() async
}

/// The exact provenance one consumed armed truncate hands back to the
/// adapter, so the swallowed `setAttributes(size:)` can synthesize a truthful
/// local reply without a daemon round trip.
public struct PfsMacOS26ArmedTruncateConsumption: Sendable, Equatable {
    public let expectedVFSFileID: UInt64
    public let size: UInt64

    public init(expectedVFSFileID: UInt64, size: UInt64) {
        self.expectedVFSFileID = expectedVFSFileID
        self.size = size
    }
}

/// The FSKit-callback side of the same one-shot authorization. `arm` publishes
/// a transaction; the adapter asks this to decide, per callback, whether a
/// reserved-namespace operation is that transaction's next step (consume it
/// locally) or anything else at all (refuse and never forward it).
public protocol PfsMacOS26RepairGate: Sendable {
    /// Atomically consumes the authorization for exactly one callback.
    ///
    /// - Parameter operand: the reserved name the callback names.
    /// - Parameter sourceName: for the two rename callbacks, the user-namespace
    ///   name on the other side of the rename; `nil` otherwise.
    /// - Parameter parentIdentity: the stable identity of the directory the
    ///   callback operates in, exactly as the adapter's directory item carries
    ///   it. The HMAC binds the plan's parent; consumption re-checks it here so
    ///   a same-basename operation in a different directory can never be
    ///   swallowed.
    /// - Parameter item: for `renameIntoOperand`, the FSKit item being moved to
    ///   the hidden operand. A data-invalidation transaction records it as the
    ///   one object its isolation window may answer for; other kinds ignore it.
    ///
    /// Throws — and consumes nothing — for an unarmed operand, a repeated
    /// callback, an out-of-order callback, a mismatched source name, or a
    /// mismatched parent.
    func consume(
        callback: PfsMacOS26RepairCallback,
        operand: Data,
        sourceName: Data?,
        parentIdentity: Data?,
        item: PortableFSItem?
    ) async throws

    /// The one item a live data-invalidation isolation window may answer a
    /// reserved-name lookup for, or `nil` when `operand` names no armed
    /// transaction whose user name is currently parked at the hidden operand.
    func isolatedRepairItem(operand: Data) async -> PortableFSItem?

    /// True while a data-invalidation isolation window is live for exactly
    /// this stable item identity. The adapter uses it to route the actuator's
    /// own nameless re-entrant callbacks (open/close on the isolated file)
    /// around ordinary publication admission.
    func isArmedTruncateItem(itemIdentity: Data) async -> Bool

    /// Consumes an armed truncate: a size-only `setAttributes` whose item
    /// stable identity and requested size exactly match a live isolation
    /// window's authoritative post-state. Returns `nil` — and consumes
    /// nothing — for anything else; the adapter forwards those unchanged.
    func consumeArmedTruncate(
        itemIdentity: Data,
        size: UInt64
    ) async -> PfsMacOS26ArmedTruncateConsumption?
}

public protocol PfsMacOS26RepairArmer: Sendable {
    func arm(_ plan: PfsMacOS26RepairPlan) async throws -> any PfsMacOS26RepairArmLease
}

public protocol PfsMacOS26RepairActuator: Sendable {
    func apply(_ plan: PfsMacOS26RepairPlan) async throws
}

public struct PfsMacOS26RepairAuthenticator: Sendable {
    public static let reservedPrefix = Data(".portablefs-v3-r1-".utf8)
    private static let version: UInt8 = 1
    private static let tagBytes = 16

    public let mountSessionID: UUID
    private let key: SymmetricKey

    public init(mountSessionID: UUID, secret: Data) throws {
        guard secret.count == 32 else {
            throw PfsMacOSCoherenceError.invalidSecretLength(secret.count)
        }
        self.mountSessionID = mountSessionID
        self.key = SymmetricKey(data: secret)
    }

    public static func isReserved(_ name: Data) -> Bool {
        name.starts(with: reservedPrefix)
    }

    public func makeOperand(
        epoch: Data,
        sequence: UInt64,
        step: UInt32,
        kind: PfsMacOS26RepairKind,
        parentIdentity: PfsMacOSStableIdentity,
        itemIdentity: PfsMacOSStableIdentity,
        sourceName: Data?
    ) throws -> Data {
        guard epoch.count == 16 else {
            throw PfsMacOSCoherenceError.invalidEpochLength(epoch.count)
        }
        guard sequence > 0 else {
            throw PfsMacOSCoherenceError.invalidSequence(sequence)
        }
        var nonceGenerator = SystemRandomNumberGenerator()
        let nonce = UInt64.random(in: UInt64.min...UInt64.max, using: &nonceGenerator)
        var operandBody = Data([Self.version, kind.rawValue])
        operandBody.appendBigEndian(sequence)
        operandBody.appendBigEndian(step)
        operandBody.appendBigEndian(nonce)
        let signed = signedContext(
            operandBody: operandBody,
            epoch: epoch,
            parentIdentity: parentIdentity,
            itemIdentity: itemIdentity,
            sourceName: sourceName
        )
        let tag = HMAC<SHA256>.authenticationCode(for: signed, using: key)
        operandBody.append(contentsOf: tag.prefix(Self.tagBytes))
        return Self.reservedPrefix + operandBody.hexEncodedData()
    }

    public func validate(
        operand: Data,
        epoch: Data,
        sequence: UInt64,
        step: UInt32,
        kind: PfsMacOS26RepairKind,
        parentIdentity: PfsMacOSStableIdentity,
        itemIdentity: PfsMacOSStableIdentity,
        sourceName: Data?
    ) -> Bool {
        guard operand.starts(with: Self.reservedPrefix),
              let decoded = Data(hexEncoded: operand.dropFirst(Self.reservedPrefix.count)),
              decoded.count == 2 + 8 + 4 + 8 + Self.tagBytes else {
            return false
        }
        let operandBody = Data(decoded.dropLast(Self.tagBytes))
        let suppliedTag = decoded.suffix(Self.tagBytes)
        let signed = signedContext(
            operandBody: operandBody,
            epoch: epoch,
            parentIdentity: parentIdentity,
            itemIdentity: itemIdentity,
            sourceName: sourceName
        )
        let fullTag = HMAC<SHA256>.authenticationCode(for: signed, using: key)
        guard Self.constantTimeEqual(Data(fullTag.prefix(Self.tagBytes)), Data(suppliedTag)) else { return false }

        var cursor = PfsMacOSByteCursor(operandBody)
        guard cursor.readUInt8() == Self.version,
              cursor.readUInt8() == kind.rawValue,
              cursor.readUInt64() == sequence,
              cursor.readUInt32() == step else {
            return false
        }
        _ = cursor.readUInt64() // nonce
        return cursor.isAtEnd
    }

    private func signedContext(
        operandBody: Data,
        epoch: Data,
        parentIdentity: PfsMacOSStableIdentity,
        itemIdentity: PfsMacOSStableIdentity,
        sourceName: Data?
    ) -> Data {
        var signed = Data("portablefs-macos26-repair-v1".utf8)
        signed.append(contentsOf: operandBody)
        signed.append(contentsOf: epoch)
        signed.appendUUID(mountSessionID)
        signed.append(contentsOf: parentIdentity.bytes)
        signed.append(contentsOf: itemIdentity.bytes)
        signed.append(contentsOf: SHA256.hash(data: sourceName ?? Data()))
        return signed
    }

    private static func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
        guard left.count == right.count else { return false }
        var difference: UInt8 = 0
        for (lhs, rhs) in zip(left, right) { difference |= lhs ^ rhs }
        return difference == 0
    }
}

/// macOS 26 backend. Each plan is authenticated, armed in the FSKit adapter,
/// then executed through the mounted VFS. Returning from `repair` is the local
/// visibility barrier; the runner sends the authority ACK only afterward.
public struct PfsMacOS26CoherenceBackend: PfsMacOSCoherenceBackend {
    public let policy = PfsMacOSCachePolicy.synchronousVFSRepairV1
    private let localAuthoritySessionID: Data
    private let authenticator: PfsMacOS26RepairAuthenticator
    private let armer: any PfsMacOS26RepairArmer
    private let actuator: any PfsMacOS26RepairActuator
    private let publicationBarrier: any PfsMacOSCallbackPublicationBarrier

    public init(
        localAuthoritySessionID: Data,
        authenticator: PfsMacOS26RepairAuthenticator,
        armer: any PfsMacOS26RepairArmer,
        actuator: any PfsMacOS26RepairActuator,
        publicationBarrier: any PfsMacOSCallbackPublicationBarrier
    ) throws {
        guard localAuthoritySessionID.count == 16 else {
            throw PfsMacOSCoherenceError.invalidSessionIDLength(localAuthoritySessionID.count)
        }
        self.localAuthoritySessionID = localAuthoritySessionID
        self.authenticator = authenticator
        self.armer = armer
        self.actuator = actuator
        self.publicationBarrier = publicationBarrier
    }

    public func repair(_ event: PfsMacOSCoherenceEvent) async throws {
        if event.phase == .prepare {
            try await publicationBarrier.prepare(event)
            return
        }
        if event.initiator.sessionID != localAuthoritySessionID {
            for (index, repair) in event.repairs.enumerated() {
                try Task.checkCancellation()
                let plan = try makePlan(event: event, step: UInt32(index), repair: repair)
                let lease = try await armer.arm(plan)
                do {
                    try Task.checkCancellation()
                    try await actuator.apply(plan)
                    try await lease.finish()
                } catch {
                    await lease.cancel()
                    throw error
                }
            }
        }
        try await publicationBarrier.resume(event)
    }

    private func makePlan(
        event: PfsMacOSCoherenceEvent,
        step: UInt32,
        repair: PfsMacOSCacheRepair
    ) throws -> PfsMacOS26RepairPlan {
        switch repair {
        case let .purgeNegative(parent, parentIdentity, _):
            let operand = try authenticator.makeOperand(
                epoch: event.epoch,
                sequence: event.sequence,
                step: step,
                kind: .negativeScratch,
                parentIdentity: parentIdentity,
                itemIdentity: .zero,
                sourceName: nil
            )
            return PfsMacOS26RepairPlan(
                epoch: event.epoch,
                sequence: event.sequence,
                step: step,
                kind: .negativeScratch,
                path: parent,
                parentIdentity: parentIdentity,
                itemIdentity: .zero,
                expectedVFSFileID: nil,
                authoritativeSize: nil,
                operand: operand
            )
        case let .evictBinding(path, parentIdentity, itemIdentity):
            guard let name = path.name else { throw PfsMacOSCoherenceError.invalidPathComponent }
            let operand = try authenticator.makeOperand(
                epoch: event.epoch,
                sequence: event.sequence,
                step: step,
                kind: .positiveEviction,
                parentIdentity: parentIdentity,
                itemIdentity: itemIdentity,
                sourceName: name
            )
            return PfsMacOS26RepairPlan(
                epoch: event.epoch,
                sequence: event.sequence,
                step: step,
                kind: .positiveEviction,
                path: path,
                parentIdentity: parentIdentity,
                itemIdentity: itemIdentity,
                expectedVFSFileID: nil,
                authoritativeSize: nil,
                operand: operand
            )
        case let .invalidateData(path, parentIdentity, itemIdentity, expectedVFSFileID, authoritativeSize):
            guard let name = path.name else { throw PfsMacOSCoherenceError.invalidPathComponent }
            let operand = try authenticator.makeOperand(
                epoch: event.epoch,
                sequence: event.sequence,
                step: step,
                kind: .dataInvalidation,
                parentIdentity: parentIdentity,
                itemIdentity: itemIdentity,
                sourceName: name
            )
            return PfsMacOS26RepairPlan(
                epoch: event.epoch,
                sequence: event.sequence,
                step: step,
                kind: .dataInvalidation,
                path: path,
                parentIdentity: parentIdentity,
                itemIdentity: itemIdentity,
                expectedVFSFileID: expectedVFSFileID,
                authoritativeSize: authoritativeSize,
                operand: operand
            )
        case .invalidateDataObject, .invalidateAttributesObject:
            // VFS pathname surgery cannot name an object after its final link
            // disappeared. Only the native macOS 27+ object API can repair it.
            throw PfsMacOSCoherenceError.unsupportedRepair
        }
    }
}

/// POSIX actuator rooted at a pre-opened, independently attested mount
/// descriptor. It never resolves absolute paths and refuses symlink traversal.
/// The descriptor is duplicated and owned by this object.
public final class PfsMacOS26POSIXActuator: PfsMacOS26RepairActuator, @unchecked Sendable {
    private let rootFileDescriptor: Int32

    public init(rootFileDescriptor: Int32) throws {
        let duplicated = fcntl(rootFileDescriptor, F_DUPFD_CLOEXEC, 0)
        guard duplicated >= 0 else {
            throw PfsMacOSCoherenceError.posix(operation: "dup mount root", errno: errno)
        }
        self.rootFileDescriptor = duplicated
    }

    deinit { close(rootFileDescriptor) }

    public func apply(_ plan: PfsMacOS26RepairPlan) async throws {
        try Task.checkCancellation()
        switch plan.kind {
        case .negativeScratch:
            guard let operand = plan.operand else { throw PfsMacOSCoherenceError.invalidRepairOperand }
            let parentFD = try openDirectory(plan.path)
            defer { close(parentFD) }
            let scratchFD = try operand.withPOSIXName { name in
                openat(parentFD, name, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0o600)
            }
            guard scratchFD >= 0 else {
                throw PfsMacOSCoherenceError.posix(operation: "create repair scratch", errno: errno)
            }
            close(scratchFD)
            let unlinked = try operand.withPOSIXName { name in unlinkat(parentFD, name, 0) }
            guard unlinked == 0 else {
                throw PfsMacOSCoherenceError.posix(operation: "remove repair scratch", errno: errno)
            }

        case .positiveEviction:
            guard let parent = plan.path.parent,
                  let source = plan.path.name,
                  let operand = plan.operand else {
                throw PfsMacOSCoherenceError.invalidPathComponent
            }
            let parentFD = try openDirectory(parent)
            defer { close(parentFD) }
            let renamed = try source.withPOSIXName { sourceName in
                try operand.withPOSIXName { destinationName in
                    renameat(parentFD, sourceName, parentFD, destinationName)
                }
            }
            guard renamed == 0 else {
                throw PfsMacOSCoherenceError.posix(operation: "evict cached binding", errno: errno)
            }
            try Self.afterIsolating(parentFD: parentFD, source: source, operand: operand) {
                let unlinked = try operand.withPOSIXName { name in unlinkat(parentFD, name, 0) }
                guard unlinked == 0 else {
                    throw PfsMacOSCoherenceError.posix(operation: "remove evicted binding", errno: errno)
                }
            }

        case .dataInvalidation:
            guard let parent = plan.path.parent,
                  let name = plan.path.name,
                  let operand = plan.operand,
                  let expectedVFSFileID = plan.expectedVFSFileID,
                  let size = plan.authoritativeSize,
                  size <= UInt64(off_t.max) else {
                throw PfsMacOSCoherenceError.invalidPathComponent
            }
            let parentFD = try openDirectory(parent)
            defer { close(parentFD) }
            let renamed = try name.withPOSIXName { sourceName in
                try operand.withPOSIXName { destinationName in
                    renameat(parentFD, sourceName, parentFD, destinationName)
                }
            }
            guard renamed == 0 else {
                throw PfsMacOSCoherenceError.posix(operation: "isolate data repair target", errno: errno)
            }
            try Self.afterIsolating(parentFD: parentFD, source: name, operand: operand) {
                let fileFD = try operand.withPOSIXName { component in
                    openat(parentFD, component, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
                }
                guard fileFD >= 0 else {
                    throw PfsMacOSCoherenceError.posix(operation: "open data repair target", errno: errno)
                }
                defer { close(fileFD) }
                var status = stat()
                guard fstat(fileFD, &status) == 0 else {
                    throw PfsMacOSCoherenceError.posix(operation: "stat data repair target", errno: errno)
                }
                guard status.st_ino == expectedVFSFileID else {
                    throw PfsMacOSCoherenceError.invalidRepairOperand
                }
                // Unconditional by design. On macOS 26, fstat may already report
                // the new length while stale cached pages still expose the old EOF.
                guard ftruncate(fileFD, off_t(size)) == 0 else {
                    throw PfsMacOSCoherenceError.posix(operation: "truncate data repair target", errno: errno)
                }
                let windows = try PfsMacOS26MappingWindows(fileSize: size)
                for window in windows {
                    try Task.checkCancellation()
                    let address = mmap(nil, window.length, PROT_READ, MAP_SHARED, fileFD, off_t(window.offset))
                    guard address != MAP_FAILED else {
                        throw PfsMacOSCoherenceError.posix(operation: "map data repair target", errno: errno)
                    }
                    let syncResult = msync(address, window.length, MS_INVALIDATE)
                    let syncErrno = errno
                    let unmapResult = munmap(address, window.length)
                    guard syncResult == 0 else {
                        throw PfsMacOSCoherenceError.posix(operation: "invalidate data repair target", errno: syncErrno)
                    }
                    guard unmapResult == 0 else {
                        throw PfsMacOSCoherenceError.posix(operation: "unmap data repair target", errno: errno)
                    }
                }
                let unlinked = try operand.withPOSIXName { component in unlinkat(parentFD, component, 0) }
                guard unlinked == 0 else {
                    throw PfsMacOSCoherenceError.posix(operation: "remove data repair target", errno: errno)
                }
            }
        }
    }

    /// Runs the part of a namespace transaction that executes while the user's
    /// name is parked at the hidden operand.
    ///
    /// Between the isolating rename and the removal there is exactly one state
    /// in which a failure would strand a user's file under a name nothing else
    /// knows: this closure's throw path. Rolling the rename back is the only
    /// operation that returns the local namespace to what it was before the
    /// repair began; it is not error recovery, because the original error is
    /// re-thrown either way and the caller still fails closed. If the rollback
    /// also fails, the thrown error names the stranded operand so the failure
    /// is reported rather than silently left in the directory.
    private static func afterIsolating(
        parentFD: Int32,
        source: Data,
        operand: Data,
        _ body: () throws -> Void
    ) throws {
        do {
            try body()
        } catch {
            let restored = (try? operand.withPOSIXName { hidden in
                try source.withPOSIXName { original in
                    renameat(parentFD, hidden, parentFD, original)
                }
            }) == 0
            if restored {
                throw error
            }
            throw PfsMacOSCoherenceError.repairTransactionTorn(
                hiddenName: String(decoding: operand, as: UTF8.self),
                rolledBack: false
            )
        }
    }

    private func openDirectory(_ path: PfsMacOSRelativePath) throws -> Int32 {
        var current = fcntl(rootFileDescriptor, F_DUPFD_CLOEXEC, 0)
        guard current >= 0 else {
            throw PfsMacOSCoherenceError.posix(operation: "dup repair root", errno: errno)
        }
        for component in path.components {
            let next = try component.withPOSIXName { name in
                openat(current, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            }
            if next < 0 {
                let code = errno
                close(current)
                throw PfsMacOSCoherenceError.posix(operation: "open repair directory", errno: code)
            }
            close(current)
            current = next
        }
        return current
    }
}

/// Lazy, bounded mmap plan. Window boundaries are page-aligned and arithmetic
/// remains in UInt64 until the bounded length is converted to Int. A sparse
/// multi-terabyte file therefore consumes one fixed-size virtual mapping at a
/// time rather than one address range proportional to file size.
public struct PfsMacOS26MappingWindows: Sendable, Sequence {
    public struct Window: Sendable, Equatable {
        public let offset: UInt64
        public let length: Int
    }

    public static let defaultMaximumWindowBytes: UInt64 = 256 * 1024 * 1024
    public let fileSize: UInt64
    public let maximumWindowBytes: UInt64
    public let count: UInt64

    public init(
        fileSize: UInt64,
        maximumWindowBytes: UInt64 = defaultMaximumWindowBytes,
        pageSize: UInt64 = UInt64(getpagesize())
    ) throws {
        guard pageSize > 0,
              maximumWindowBytes > 0,
              maximumWindowBytes <= UInt64(Int.max),
              maximumWindowBytes.isMultiple(of: pageSize) else {
            throw PfsMacOSCoherenceError.unsupportedRepair
        }
        self.fileSize = fileSize
        self.maximumWindowBytes = maximumWindowBytes
        self.count = fileSize == 0 ? 0 : 1 + ((fileSize - 1) / maximumWindowBytes)
    }

    public func makeIterator() -> Iterator {
        Iterator(fileSize: fileSize, maximumWindowBytes: maximumWindowBytes)
    }

    public struct Iterator: IteratorProtocol {
        private let fileSize: UInt64
        private let maximumWindowBytes: UInt64
        private var offset: UInt64 = 0

        fileprivate init(fileSize: UInt64, maximumWindowBytes: UInt64) {
            self.fileSize = fileSize
            self.maximumWindowBytes = maximumWindowBytes
        }

        public mutating func next() -> Window? {
            guard offset < fileSize else { return nil }
            let remaining = fileSize - offset
            let length = Swift.min(remaining, maximumWindowBytes)
            let window = Window(offset: offset, length: Int(length))
            offset += length
            return window
        }
    }
}

private struct PfsMacOSByteCursor {
    private let data: Data
    private var offset = 0

    init(_ data: Data) { self.data = data }
    var isAtEnd: Bool { offset == data.count }

    mutating func read(_ count: Int) -> Data? {
        guard count >= 0, offset <= data.count - count else { return nil }
        defer { offset += count }
        return data.subdata(in: offset..<(offset + count))
    }

    mutating func readUInt8() -> UInt8? { read(1)?.first }
    mutating func readUInt32() -> UInt32? { readInteger() }
    mutating func readUInt64() -> UInt64? { readInteger() }

    private mutating func readInteger<T: FixedWidthInteger>() -> T? {
        guard let bytes = read(MemoryLayout<T>.size) else { return nil }
        return bytes.reduce(T.zero) { ($0 << 8) | T($1) }
    }
}

private extension Data {
    mutating func appendBigEndian<T: FixedWidthInteger>(_ value: T) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
    }

    mutating func appendUUID(_ value: UUID) {
        var uuid = value.uuid
        Swift.withUnsafeBytes(of: &uuid) { append(contentsOf: $0) }
    }

    func hexEncodedData() -> Data {
        let alphabet = Array("0123456789abcdef".utf8)
        var result = Data()
        result.reserveCapacity(count * 2)
        for byte in self {
            result.append(alphabet[Int(byte >> 4)])
            result.append(alphabet[Int(byte & 0x0f)])
        }
        return result
    }

    init?<Bytes: Collection>(hexEncoded bytes: Bytes) where Bytes.Element == UInt8 {
        guard bytes.count.isMultiple(of: 2) else { return nil }
        var output = Data()
        output.reserveCapacity(bytes.count / 2)
        var iterator = bytes.makeIterator()
        while let highByte = iterator.next(), let lowByte = iterator.next() {
            func nibble(_ byte: UInt8) -> UInt8? {
                switch byte {
                case UInt8(ascii: "0")...UInt8(ascii: "9"): return byte - UInt8(ascii: "0")
                case UInt8(ascii: "a")...UInt8(ascii: "f"): return byte - UInt8(ascii: "a") + 10
                default: return nil
                }
            }
            guard let high = nibble(highByte), let low = nibble(lowByte) else { return nil }
            output.append((high << 4) | low)
        }
        self = output
    }

    func withPOSIXName<T>(_ body: (UnsafePointer<CChar>) throws -> T) throws -> T {
        guard !isEmpty, !contains(0), !contains(UInt8(ascii: "/")) else {
            throw PfsMacOSCoherenceError.invalidPathComponent
        }
        var terminated = [UInt8](self)
        terminated.append(0)
        return try terminated.withUnsafeBufferPointer { buffer in
            try buffer.baseAddress!.withMemoryRebound(to: CChar.self, capacity: buffer.count) {
                try body($0)
            }
        }
    }
}
