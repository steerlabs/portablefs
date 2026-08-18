import CryptoKit
import Foundation
import OSLog
@preconcurrency import Darwin

/// Cache-coherence behavior is an attach contract, not an inference from an OS
/// version. A client and authority must agree on one exact policy before the
/// mount becomes visible.
public enum PfsMacOSCachePolicy: String, Sendable, CaseIterable {
    /// macOS 26: synchronous, authenticated VFS operations drive the kernel's
    /// cache transitions before the authority mutation is acknowledged.
    case synchronousVFSRepairV1 = "macos26-synchronous-vfs-repair-v1"

    /// macOS 26 corrected boundary: a classified authority pre-apply
    /// interruption is surfaced as ECANCELED, never a kernel-restartable
    /// result. The callback must release FSKit's namespace lane before the
    /// nested VFS repair can run.
    case synchronousVFSRepairV2 = "macos26-synchronous-vfs-repair-v2"

    /// macOS 27+: synchronous kernel cache revocation through Apple's native
    /// FSKit API. The Xcode 26 SDK intentionally has no implementation.
    case nativeFSKitRevocationV1 = "fskit-native-revocation-v1"
}

public enum PfsMacOSCoherenceError: Error, Equatable, CustomStringConvertible {
    case missingV3CoherenceContract
    case invalidAuthorityProtocolMajor(UInt32)
    /// Authority v6 requires synchronous typed source-state installation and
    /// exact namespace, attribute, and data peer repair. Neither the macOS 26
    /// Operations API nor the checked-in macOS 27 probes supply that complete
    /// primitive set, so accepting it would be a silent compatibility mode.
    case exactVNextFSKitUnavailable(UInt32)
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
    case sourceVisibilityEventForbidden
    case invalidRoutesChange
    case routesChangeRequiresRemount
    case sequenceGap(expected: UInt64, received: UInt64)
    case eventIdentityMismatch(UInt64)
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
    /// An identity mapping does not reach the mount root.
    case namespaceCycle
    /// The mount demonstrably cached a target but retained no safe pathname or
    /// native object operation capable of repairing it.
    case cachedTargetUnrepresentable

    public var description: String {
        switch self {
        case .missingV3CoherenceContract:
            return "resolved v3 attach omitted its coherence contract"
        case let .invalidAuthorityProtocolMajor(major):
            return "unsupported authority protocol major \(major)"
        case let .exactVNextFSKitUnavailable(major):
            return "authority protocol \(major) requires unavailable exact FSKit post-state and repair primitives"
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
        case .sourceVisibilityEventForbidden:
            return "source filesystem visibility events are forbidden"
        case .invalidRoutesChange:
            return "visibility route change has an invalid shape"
        case .routesChangeRequiresRemount:
            return "visibility route change requires this mount to fail closed and remount"
        case let .sequenceGap(expected, received):
            return "repair sequence gap: expected \(expected), received \(received)"
        case let .eventIdentityMismatch(sequence):
            return "visibility event \(sequence) changed its mutation identity"
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
        case .namespaceCycle:
            return "identity mapping does not reach the mount root"
        case .cachedTargetUnrepresentable:
            return "a cached visibility target has no representable local repair"
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

/// One exact child-name cache coordinate. Parent identity is part of the key:
/// basenames alone are never a coherence scope because the same name in two
/// directories is unrelated state.
public struct PfsMacOSNamespaceCoordinate: Sendable, Equatable, Hashable {
    public let parentIdentity: PfsMacOSStableIdentity
    public let name: Data

    public init(parentIdentity: PfsMacOSStableIdentity, name: Data) {
        self.parentIdentity = parentIdentity
        self.name = name
    }
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
    /// Immutable kind learned when this vnode was published in a namespace.
    public let itemKind: PfsMacOSCachedItemKind?

    public init(
        item: PortableFSItem,
        vfsFileID: UInt64,
        itemKind: PfsMacOSCachedItemKind? = nil
    ) {
        self.item = item
        self.vfsFileID = vfsFileID
        self.itemKind = itemKind
    }

    public static func == (
        lhs: PfsMacOSLiveObjectReference,
        rhs: PfsMacOSLiveObjectReference
    ) -> Bool {
        lhs.item === rhs.item && lhs.vfsFileID == rhs.vfsFileID && lhs.itemKind == rhs.itemKind
    }
}

public enum PfsMacOSCacheRepair: Sendable, Equatable {
    /// Purges negative name-cache entries in `parent` by creating and removing
    /// an authenticated synthetic child.
    ///
    /// `PortableFSVolume` consumes the matching `createItem` and `removeItem`
    /// callbacks against `PfsMacOS26RepairArmRegistry` and returns without
    /// issuing any pfslocal request, so neither call reaches the authority.
    /// With no registry installed, the same two callbacks are refused with
    /// EPERM instead. Production installs the registry and actuator together
    /// or fails the mount closed.
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
        itemIdentity: PfsMacOSStableIdentity,
        itemKind: PfsMacOSCachedItemKind
    )

    /// Forces an exact retained vnode through FSKit setAttributes without
    /// mutating authority truth; the adapter replies with a full authoritative
    /// getattr snapshot so macOS replaces its attribute cache.
    case refreshAttributes(
        path: PfsMacOSRelativePath,
        parentIdentity: PfsMacOSStableIdentity,
        itemIdentity: PfsMacOSStableIdentity,
        expectedVFSFileID: UInt64,
        itemKind: PfsMacOSCachedItemKind
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

/// Identifies the authority mutation which produced a peer repair event.
public struct PfsMacOSMutationInitiator: Sendable, Equatable, Hashable {
    public let sessionID: Data
    public let replaySlot: UInt32
    public let mutationSequence: UInt64
    public init(
        sessionID: Data,
        replaySlot: UInt32,
        mutationSequence: UInt64
    ) throws {
        guard sessionID.count == 16 else {
            throw PfsMacOSCoherenceError.invalidSessionIDLength(sessionID.count)
        }
        guard mutationSequence > 0 else {
            throw PfsMacOSCoherenceError.invalidSequence(mutationSequence)
        }
        self.sessionID = sessionID
        self.replaySlot = replaySlot
        self.mutationSequence = mutationSequence
    }
}

/// Every event describes the complete client-side work required for one
/// authority mutation. COMPLETE acknowledgements follow peer kernel repair.
public struct PfsMacOSCoherenceEvent: Sendable, Equatable {
    public let epoch: Data
    public let sequence: UInt64
    public let phase: PfsMacOSVisibilityPhase
    public let initiator: PfsMacOSMutationInitiator
    /// Canonical immutable authority event bytes, captured before mutable local
    /// indexes derive repair operands. Duplicate-cursor validation uses this
    /// identity rather than comparing repairs that the first repair may change.
    public let authorityPayloadIdentity: Data
    public let repairs: [PfsMacOSCacheRepair]

    public init(
        epoch: Data,
        sequence: UInt64,
        phase: PfsMacOSVisibilityPhase,
        initiator: PfsMacOSMutationInitiator,
        authorityPayloadIdentity: Data = Data(),
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
        self.authorityPayloadIdentity = authorityPayloadIdentity
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
    /// Liveness-only feedback sampled after local COMPLETE repair and before
    /// its exact authority acknowledgement. Safety never depends on this bit.
    func orderedAdmissionContended(for event: PfsMacOSCoherenceEvent) async -> Bool
    /// Called only after the authority has accepted this event's exact cursor.
    /// A backend may use this edge to release work that was safe to park after
    /// local repair but not before the distributed barrier actually advanced.
    func acknowledged(_ event: PfsMacOSCoherenceEvent) async
}

/// Transport deliberately separates event delivery, cumulative acknowledgement,
/// and terminal failure. A dropped connection, frozen actuator, cancellation, or
/// failed syscall has no path to an acknowledgement.
public extension PfsMacOSCoherenceBackend {
    func orderedAdmissionContended(for event: PfsMacOSCoherenceEvent) async -> Bool { false }
}

public protocol PfsMacOSCoherenceTransport: Sendable {
    func nextEvent() async throws -> PfsMacOSCoherenceEvent?
    func acknowledge(epoch: Data, cursor: PfsMacOSVisibilityCursor) async throws
    func acknowledge(
        epoch: Data,
        cursor: PfsMacOSVisibilityCursor,
        orderedAdmissionContended: Bool
    ) async throws
    func failClosed(epoch: Data, cursor: PfsMacOSVisibilityCursor?, reason: String) async
}

public extension PfsMacOSCoherenceTransport {
    func acknowledge(
        epoch: Data,
        cursor: PfsMacOSVisibilityCursor,
        orderedAdmissionContended: Bool
    ) async throws {
        try await acknowledge(epoch: epoch, cursor: cursor)
    }
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
    /// Immutable authority mutation identity retained beside the local cursor.
    /// Repair operands are derived through mutable local indexes and may decode
    /// differently when the same wire event is replayed after local surgery;
    /// they are deliberately not part of duplicate identity.
    private var lastCompletedInitiator: PfsMacOSMutationInitiator?
    private var lastCompletedPayloadIdentity: Data?
    /// COMPLETE must name the same mutation that PREPARE admitted. In
    /// particular, changing source/peer identity between phases could either
    /// skip peer repair or skip source publication waiting.
    private var preparedInitiator: PfsMacOSMutationInitiator?
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
            guard let expectedInitiator = lastCompletedInitiator,
                  let expectedPayloadIdentity = lastCompletedPayloadIdentity,
                  event.initiator == expectedInitiator,
                  event.authorityPayloadIdentity == expectedPayloadIdentity else {
                throw PfsMacOSCoherenceError.eventIdentityMismatch(event.sequence)
            }
            let contended = await backend.orderedAdmissionContended(for: event)
            try await transport.acknowledge(
                epoch: epoch,
                cursor: cursor,
                orderedAdmissionContended: contended
            )
            lastAcknowledgedCursor = cursor
            await backend.acknowledged(event)
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
        if event.phase == .complete, event.initiator != preparedInitiator {
            throw PfsMacOSCoherenceError.eventIdentityMismatch(event.sequence)
        }

        try Task.checkCancellation()
        try await backend.repair(event)
        // Ordering is the whole fix: the local ledger advances the instant the
        // surgery is done and before anything can fail on the wire.
        lastCompletedCursor = cursor
        lastCompletedInitiator = event.initiator
        lastCompletedPayloadIdentity = event.authorityPayloadIdentity
        switch event.phase {
        case .prepare:
            preparedInitiator = event.initiator
        case .complete:
            preparedInitiator = nil
        }
        try Task.checkCancellation()
        let contended = await backend.orderedAdmissionContended(for: event)
        try await transport.acknowledge(
            epoch: epoch,
            cursor: cursor,
            orderedAdmissionContended: contended
        )
        lastAcknowledgedCursor = cursor
        await backend.acknowledged(event)
    }

    public func acknowledgedCursor() -> PfsMacOSVisibilityCursor? { lastAcknowledgedCursor }

    /// The exactly-once ledger. A cursor at or below this has had its local
    /// repair performed; the authority may or may not know it yet.
    public func completedCursor() -> PfsMacOSVisibilityCursor? { lastCompletedCursor }
}

/// Peer PREPARE closes ordinary cache-producing callback admission, waits for
/// already admitted callbacks to publish, and keeps the gate closed through
/// COMPLETE acknowledgement. Source mutations use their callback-owned
/// publication gate and never enter this event stream.
public protocol PfsMacOSCallbackPublicationBarrier: Sendable {
    func prepare(_ event: PfsMacOSCoherenceEvent) async throws
    /// Reopen only after every requested peer repair has completed.
    func resume(_ event: PfsMacOSCoherenceEvent) async throws
    /// Returns true only when this exact peer COMPLETE repair refused at least
    /// one ordered callback before acknowledgement.
    func orderedAdmissionContended(for event: PfsMacOSCoherenceEvent) async -> Bool
    /// Opens admission only after the authority accepted COMPLETE. Between
    /// local repair completion and this edge, overlapping callbacks may park:
    /// no further mounted-VFS work is needed, but mutation order is still held.
    func acknowledged(_ event: PfsMacOSCoherenceEvent) async
}

public extension PfsMacOSCallbackPublicationBarrier {
    func orderedAdmissionContended(for event: PfsMacOSCoherenceEvent) async -> Bool { false }
}

/// SDK-independent mirror of the three cache requests introduced by macOS 27
/// `FSVolume.DataCacheHandler`. Keeping this decision outside the SDK adapter
/// makes the no-write-back rule testable by the stable Xcode lane.
public enum PfsFSKitNativeDataCacheRequest: Sendable, Equatable, CaseIterable {
    case none
    case read
    case readWrite
}

/// The complete set of cache grants PortableFS can return. `writeBack` is
/// deliberately unrepresentable: a successful PortableFS write cannot leave
/// its only dirty copy in the client kernel after returning to the caller.
public enum PfsFSKitNativeDataCacheGrant: Sendable, Equatable {
    case noCache
    case readCache
    case writeThrough
}

public enum PfsFSKitNativeDataCachePolicy {
    public static func grant(
        for request: PfsFSKitNativeDataCacheRequest
    ) -> PfsFSKitNativeDataCacheGrant {
        switch request {
        case .none:
            .noCache
        case .read:
            .readCache
        case .readWrite:
            .writeThrough
        }
    }
}

/// One exact data target that Apple's documented SDK-27 cache API can address.
/// The linked form still needs the adapter's retained live-object index to
/// resolve its stable identity to the exact FSItem before touching the kernel.
public enum PfsFSKitNativeDataInvalidation: Sendable, Equatable {
    case linked(
        path: PfsMacOSRelativePath,
        parentIdentity: PfsMacOSStableIdentity,
        itemIdentity: PfsMacOSStableIdentity,
        expectedVFSFileID: UInt64,
        authoritativeSize: UInt64
    )
    case object(
        reference: PfsMacOSLiveObjectReference,
        itemIdentity: PfsMacOSStableIdentity,
        authoritativeSize: UInt64
    )
}

/// Implemented by the SDK-27 target with synchronous `setCacheState`. It has
/// no namespace or attribute method because Apple's published API does not
/// promise those transitions.
public protocol PfsFSKitNativeDataCacheInvalidator: Sendable {
    func invalidate(_ target: PfsFSKitNativeDataInvalidation) async throws
}

/// Single-assignment bridge used while constructing a native FSKit volume.
/// The authority transport and repair runner are prepared before FSKit can see
/// the volume; the concrete SDK-27 invalidator is then installed on that exact
/// volume before the runner starts. A missing or duplicate installation is a
/// terminal integration error, never a reason to acknowledge an event.
public actor PfsFSKitNativeDataCacheInvalidatorSlot:
    PfsFSKitNativeDataCacheInvalidator
{
    private var invalidator: (any PfsFSKitNativeDataCacheInvalidator)?

    public init() {}

    public func install(
        _ invalidator: any PfsFSKitNativeDataCacheInvalidator
    ) throws {
        guard self.invalidator == nil else {
            throw PfsMacOSCoherenceError.nativeRevocationUnavailable
        }
        self.invalidator = invalidator
    }

    public func invalidate(
        _ target: PfsFSKitNativeDataInvalidation
    ) async throws {
        guard let invalidator else {
            throw PfsMacOSCoherenceError.nativeRevocationUnavailable
        }
        try await invalidator.invalidate(target)
    }
}

/// The currently documented subset of the native cache-revocation policy.
/// Unsupported repair families fail before the backend resumes publication;
/// live-kernel qualification may extend this only after proving an SDK-backed
/// operation with the required semantics.
public struct PfsFSKitDocumentedNativeCacheRevoker: PfsFSKitNativeCacheRevoker {
    private let invalidator: any PfsFSKitNativeDataCacheInvalidator

    public init(invalidator: any PfsFSKitNativeDataCacheInvalidator) {
        self.invalidator = invalidator
    }

    public func revoke(_ repair: PfsMacOSCacheRepair) async throws {
        switch repair {
        case let .invalidateData(
            path,
            parentIdentity,
            itemIdentity,
            expectedVFSFileID,
            authoritativeSize
        ):
            try await invalidator.invalidate(.linked(
                path: path,
                parentIdentity: parentIdentity,
                itemIdentity: itemIdentity,
                expectedVFSFileID: expectedVFSFileID,
                authoritativeSize: authoritativeSize
            ))
        case let .invalidateDataObject(object, itemIdentity, authoritativeSize):
            try await invalidator.invalidate(.object(
                reference: object,
                itemIdentity: itemIdentity,
                authoritativeSize: authoritativeSize
            ))
        case .purgeNegative, .evictBinding, .refreshAttributes,
             .invalidateAttributesObject:
            throw PfsMacOSCoherenceError.unsupportedRepair
        }
    }
}

/// A macOS 27 implementation supplies this interface with the SDK's native
/// synchronous cache API. Keeping the interface independent of those symbols
/// lets Xcode 26 compile the ordering and refusal tests without pretending the
/// SDK implementation exists.
public protocol PfsFSKitNativeCacheRevoker: Sendable {
    func revoke(_ repair: PfsMacOSCacheRepair) async throws
}

public struct PfsNativeFSKitCoherenceBackend: PfsMacOSCoherenceBackend {
    public let policy = PfsMacOSCachePolicy.nativeFSKitRevocationV1
    private let revoker: any PfsFSKitNativeCacheRevoker
    private let publicationBarrier: any PfsMacOSCallbackPublicationBarrier

    public init(
        revoker: any PfsFSKitNativeCacheRevoker,
        publicationBarrier: any PfsMacOSCallbackPublicationBarrier
    ) throws {
        self.revoker = revoker
        self.publicationBarrier = publicationBarrier
    }

    public func repair(_ event: PfsMacOSCoherenceEvent) async throws {
        switch event.phase {
        case .prepare:
            try await publicationBarrier.prepare(event)
        case .complete:
            for repair in event.repairs {
                try Task.checkCancellation()
                try await revoker.revoke(repair)
            }
            try await publicationBarrier.resume(event)
        }
    }

    public func orderedAdmissionContended(
        for event: PfsMacOSCoherenceEvent
    ) async -> Bool {
        await publicationBarrier.orderedAdmissionContended(for: event)
    }

    public func acknowledged(_ event: PfsMacOSCoherenceEvent) async {
        await publicationBarrier.acknowledged(event)
    }
}

public enum PfsMacOS26RepairKind: UInt8, Sendable, Equatable, CaseIterable {
    case negativeScratch = 1
    case positiveEviction = 2
    case dataInvalidation = 3
    case attributeRefresh = 4
}

/// Immutable item type recorded at the exact callback that published a
/// binding. The macOS 26 actuator needs this local fact before its only
/// `unlinkat(2)`: Darwin requires `AT_REMOVEDIR` for directories and rejects
/// that flag for files and symlinks. Unknown wire kinds are never guessed.
public enum PfsMacOSCachedItemKind: UInt8, Sendable, Equatable, Hashable, CaseIterable {
    case file = 1
    case directory = 2
    case symlink = 3

    public init(_ kind: PfsItemKind) throws {
        switch kind {
        case .file:
            self = .file
        case .directory:
            self = .directory
        case .symlink:
            self = .symlink
        case .unspecified, .UNRECOGNIZED:
            throw PfsMacOSCoherenceError.invalidRepairOperand
        }
    }

    var daemonWireValue: String {
        switch self {
        case .file: "file"
        case .directory: "directory"
        case .symlink: "symlink"
        }
    }
}

/// The exact reserved-name FSKit callbacks a scratch repair consumes, in the
/// order the actuator's syscalls produce them. Arming a plan authorizes this
/// list and nothing else, which is what lets the adapter answer "swallow or
/// refuse?" per callback rather than per transaction.
///
/// Positive and data repair never move a user name into the reserved namespace:
/// they consume an exact authenticated source removal through
/// `consumeArmedSourceRemoval`. A callback case that production cannot emit is
/// deliberately absent from this privileged surface.
public enum PfsMacOS26RepairCallback: UInt8, Sendable, Equatable, Hashable, CaseIterable {
    /// `createItem(named: operand)` for the negative-cache scratch entry.
    case createScratch = 1
    /// `removeItem(named: operand)`.
    case removeOperand = 5
    /// Removes the exact authenticated user-visible source binding from the
    /// macOS kernel only. Authority truth is untouched; a later lookup
    /// republishes that binding from XFS.
    case removeSource = 7
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

    /// Item type authenticated inside the operand. Keeping the behavior-changing
    /// bit in the signed body means the gate's existing plan validation also
    /// validates the daemon's unlink-versus-rmdir choice.
    public var itemKind: PfsMacOSCachedItemKind? {
        guard let operand else { return nil }
        return PfsMacOS26RepairAuthenticator.authenticatedItemKind(in: operand)
    }

    /// The user-namespace name the operand's HMAC is bound to, or `nil` for a
    /// scratch create that has no source. Validation must use exactly this.
    public var authenticatedSourceName: Data? {
        switch kind {
        case .negativeScratch:
            return nil
        case .positiveEviction, .dataInvalidation, .attributeRefresh:
            return path.name
        }
    }

    /// The ordered name-carrying callbacks the actuator's syscalls will
    /// produce. `finish()` requires every one of them to have been consumed
    /// exactly once. Positive and data repair consume `.removeSource` through
    /// the exact coordinate-and-object gate instead.
    public var requiredCallbacks: [PfsMacOS26RepairCallback] {
        switch kind {
        case .negativeScratch:
            return [.createScratch, .removeOperand]
        case .positiveEviction, .dataInvalidation:
            return [.removeSource]
        case .attributeRefresh:
            return []
        }
    }
}

/// Arms the FSKit adapter before the external VFS actuator issues a syscall.
/// Implementations must consume each plan once and must reject every reserved
/// operand that was not armed and authenticated.
public protocol PfsMacOS26RepairArmLease: Sendable {
    /// Selects this pre-armed plan as the one mounted-VFS syscall currently
    /// executing. The production registry uses this to bind nameless callbacks
    /// to one hard-link alias even when several plans share an item identity.
    func activate() async throws
    /// Confirms that every callback belonging to the armed plan was consumed,
    /// but deliberately keeps source-item ownership armed. FSKit can deliver
    /// teardown for an earlier syscall while a later plan in the same COMPLETE
    /// event is running.
    func validate() async throws
    /// Ends repair ownership only after the COMPLETE publication barrier has
    /// resumed. This is the event boundary, not an individual syscall return.
    func release() async throws
    /// Revokes the transaction on every non-success exit, including task
    /// cancellation after arming but before the actuator starts.
    func cancel() async
}

public extension PfsMacOS26RepairArmLease {
    /// Legacy/mock leases that do not multiplex a production registry have no
    /// actuation selection state. The production lease overrides this method.
    func activate() async throws {}

    /// Convenience for a standalone plan outside the multi-plan backend.
    func finish() async throws {
        do {
            try await validate()
            try await release()
        } catch {
            await cancel()
            throw error
        }
    }
}

/// The exact identity attestation an armed attribute-refresh callback hands
/// back to the adapter. The adapter verifies its post-apply authoritative
/// getattr before returning that complete snapshot to FSKit.
public struct PfsMacOS26ArmedAttributeRefreshConsumption: Sendable, Equatable {
    public let expectedVFSFileID: UInt64

    public init(expectedVFSFileID: UInt64) {
        self.expectedVFSFileID = expectedVFSFileID
    }
}

public struct PfsMacOS26ArmedTruncateConsumption: Sendable, Equatable {
    public let expectedVFSFileID: UInt64
    public let size: UInt64

    public init(expectedVFSFileID: UInt64, size: UInt64) {
        self.expectedVFSFileID = expectedVFSFileID
        self.size = size
    }
}

/// What authority truth says about the exact user-visible name removed only
/// from this Mac's kernel cache. A positive eviction accompanies a namespace
/// target and does not preserve an attested binding of this item at that
/// coordinate. A data invalidation leaves the authority binding intact and may
/// retain that coordinate solely as a bounded locator for an already-retained
/// vnode.
public enum PfsMacOS26ArmedSourceRemovalDisposition: Sendable, Equatable {
    case positiveEviction
    case dataInvalidation
}

/// The FSKit-callback side of the same one-shot authorization. `arm` publishes
/// a transaction; the adapter asks this to decide, per callback, whether a
/// reserved-namespace operation is that transaction's next step (consume it
/// locally) or anything else at all (refuse and never forward it).
public protocol PfsMacOS26RepairGate: Sendable {
    /// Atomically consumes the authorization for exactly one callback.
    ///
    /// - Parameter operand: the reserved name the callback names.
    /// - Parameter parentIdentity: the stable identity of the directory the
    ///   callback operates in, exactly as the adapter's directory item carries
    ///   it. The HMAC binds the plan's parent; consumption re-checks it here so
    ///   a same-basename operation in a different directory can never be
    ///   swallowed.
    /// Throws — and consumes nothing — for an unarmed operand, a repeated
    /// callback, an out-of-order callback, or a mismatched parent.
    func consume(
        callback: PfsMacOS26RepairCallback,
        operand: Data,
        parentIdentity: Data?
    ) async throws

    /// Gives the armed negative repair ownership of the process-local scratch
    /// object minted for its consumed create callback. Name removal and vnode
    /// reclamation are distinct: the adapter retires the binding at remove,
    /// and lease release/cancellation guarantees the binding is retired on
    /// every partial path. The object itself remains locally classified until
    /// FSKit emits reclaim; mount shutdown deterministically clears any vnode
    /// the kernel retained without reclaiming first.
    func adoptLocalRepairScratch(
        operand: Data,
        item: PortableFSItem,
        retireBinding: @escaping @Sendable (PortableFSItem) async -> Void
    ) async throws

    /// True while an armed positive/data repair is about to resolve its exact
    /// user-visible source coordinate. unlinkat(2) performs this lookup before
    /// it emits the exact source-removal callback, so the lookup is repair-owned.
    func isArmedRepairSource(
        parentIdentity: Data,
        name: Data
    ) async -> Bool

    /// True for one exact ancestor coordinate captured from the namespace
    /// index when the event was armed. The daemon must traverse these names to
    /// reach the final repaired parent; without this authorization its own
    /// path lookup would wait behind the COMPLETE barrier it is servicing.
    func isArmedRepairTraversal(
        parentIdentity: Data,
        name: Data
    ) async -> Bool

    /// True for an exact directory item reached through one of the armed
    /// ancestor coordinates above. FSKit may emit open/getattr/close for each
    /// directory vnode while the daemon walks to the repaired parent; those
    /// item-only callbacks need the same provenance as the named lookup.
    func isArmedRepairTraversalItem(itemIdentity: Data) async -> Bool

    /// True while an armed positive/data repair is resolving the exact source
    /// object named by its authenticated plan. FSKit asks for that object's
    /// attributes after the source-name lookup and before it emits the remove
    /// callback. That getattr is therefore part of path resolution, even
    /// though it carries only an item and no name.
    func isArmedRepairSourceItem(itemIdentity: Data) async -> Bool

    /// Narrow open-only source exemption. Once removeSource is consumed, a new
    /// open takes ordinary publication admission while teardown callbacks keep
    /// using `isArmedRepairSourceItem` through lease release.
    func isArmedRepairSourceOpenItem(itemIdentity: Data) async -> Bool

    /// True while an event-scoped plan is traversing its exact parent
    /// directory. The daemon actuator opens relative parent components before
    /// it can issue the child cache operation; FSKit may surface the final
    /// parent open/getattr/close while that same coordinate is closed.
    func isArmedRepairParentItem(itemIdentity: Data) async -> Bool

    /// Atomically consumes a kernel-only unlink for the exact authenticated
    /// source coordinate and stable object identity. Returns `nil` when no
    /// armed plan names that source, so ordinary user unlinks continue to the
    /// authority unchanged. The disposition says whether authority truth still
    /// owns this exact coordinate after the cache-only unlink.
    func consumeArmedSourceRemoval(
        parentIdentity: Data,
        name: Data,
        item: PortableFSItem
    ) async throws -> PfsMacOS26ArmedSourceRemovalDisposition?

    /// True after the exact source removal of a data repair and until its event
    /// lease ends. The adapter uses it to route the actuator's held-descriptor
    /// truncate callbacks around ordinary publication admission.
    func isArmedTruncateItem(itemIdentity: Data) async -> Bool

    /// True only for the exact item of an armed attribute-refresh syscall.
    func isArmedAttributeRefreshItem(itemIdentity: Data) async -> Bool

    /// Consumes a nameless mode-only callback for the authenticated exact item.
    /// More than one callback may be coalesced because FSKit exposes no caller
    /// or repair token with which to distinguish the actuator's existing-mode
    /// `fchmod` from a racing user request.
    func consumeArmedAttributeRefresh(
        itemIdentity: Data
    ) async -> PfsMacOS26ArmedAttributeRefreshConsumption?

    /// Consumes an armed truncate: a size-only `setAttributes` whose item
    /// stable identity and requested size exactly match a live data repair's
    /// authoritative post-state. Returns `nil` — and consumes
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
    private static let version: UInt8 = 2
    private static let tagBytes = 16
    private static let operandBodyBytes = 3 + 8 + 4 + 8

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
        sourceName: Data?,
        itemKind: PfsMacOSCachedItemKind? = nil
    ) throws -> Data {
        guard epoch.count == 16 else {
            throw PfsMacOSCoherenceError.invalidEpochLength(epoch.count)
        }
        guard sequence > 0 else {
            throw PfsMacOSCoherenceError.invalidSequence(sequence)
        }
        var nonceGenerator = SystemRandomNumberGenerator()
        let nonce = UInt64.random(in: UInt64.min...UInt64.max, using: &nonceGenerator)
        let authenticatedItemKind: UInt8
        switch kind {
        case .negativeScratch:
            guard itemKind == nil else {
                throw PfsMacOSCoherenceError.invalidRepairOperand
            }
            authenticatedItemKind = 0
        case .positiveEviction:
            // File remains the default for source compatibility with focused
            // callers that predate typed directory eviction. Production plans
            // always pass the exact indexed kind explicitly.
            authenticatedItemKind = (itemKind ?? .file).rawValue
        case .dataInvalidation:
            guard itemKind == nil || itemKind == .file else {
                throw PfsMacOSCoherenceError.invalidRepairOperand
            }
            authenticatedItemKind = PfsMacOSCachedItemKind.file.rawValue
        case .attributeRefresh:
            guard let itemKind else {
                throw PfsMacOSCoherenceError.invalidRepairOperand
            }
            authenticatedItemKind = itemKind.rawValue
        }
        var operandBody = Data([Self.version, kind.rawValue, authenticatedItemKind])
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
              decoded.count == Self.operandBodyBytes + Self.tagBytes else {
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
              let authenticatedItemKind = cursor.readUInt8(),
              cursor.readUInt64() == sequence,
              cursor.readUInt32() == step else {
            return false
        }
        switch kind {
        case .negativeScratch:
            guard authenticatedItemKind == 0 else { return false }
        case .positiveEviction, .attributeRefresh:
            guard PfsMacOSCachedItemKind(rawValue: authenticatedItemKind) != nil else {
                return false
            }
        case .dataInvalidation:
            guard authenticatedItemKind == PfsMacOSCachedItemKind.file.rawValue else {
                return false
            }
        }
        _ = cursor.readUInt64() // nonce
        return cursor.isAtEnd
    }

    /// Reads the item kind from the signed operand body. Callers use this only
    /// after the arm registry has authenticated the complete operand.
    public static func authenticatedItemKind(in operand: Data) -> PfsMacOSCachedItemKind? {
        guard operand.starts(with: reservedPrefix),
              let decoded = Data(hexEncoded: operand.dropFirst(reservedPrefix.count)),
              decoded.count == operandBodyBytes + tagBytes else {
            return nil
        }
        var cursor = PfsMacOSByteCursor(Data(decoded.dropLast(tagBytes)))
        guard cursor.readUInt8() == version,
              let repairRaw = cursor.readUInt8(),
              let repairKind = PfsMacOS26RepairKind(rawValue: repairRaw),
              let itemRaw = cursor.readUInt8() else {
            return nil
        }
        switch repairKind {
        case .negativeScratch:
            return nil
        case .positiveEviction, .attributeRefresh:
            return PfsMacOSCachedItemKind(rawValue: itemRaw)
        case .dataInvalidation:
            return itemRaw == PfsMacOSCachedItemKind.file.rawValue ? .file : nil
        }
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
    private static let signposter = OSSignposter(
        subsystem: "dev.portablefs.fskit",
        category: "MacOS26RepairActuation"
    )

    public let policy: PfsMacOSCachePolicy
    private let authenticator: PfsMacOS26RepairAuthenticator
    private let armer: any PfsMacOS26RepairArmer
    private let actuator: any PfsMacOS26RepairActuator
    private let publicationBarrier: any PfsMacOSCallbackPublicationBarrier

    public init(
        policy: PfsMacOSCachePolicy = .synchronousVFSRepairV1,
        authenticator: PfsMacOS26RepairAuthenticator,
        armer: any PfsMacOS26RepairArmer,
        actuator: any PfsMacOS26RepairActuator,
        publicationBarrier: any PfsMacOSCallbackPublicationBarrier
    ) throws {
        guard policy == .synchronousVFSRepairV1 || policy == .synchronousVFSRepairV2 else {
            throw PfsMacOSCoherenceError.unsupportedRepair
        }
        self.policy = policy
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
        // Validate the complete repair set before the first mounted-VFS
        // mutation. A later native-only/object repair must fail macOS 26
        // closed without leaving earlier pathname surgery partially run.
        let plans = try makePlans(event: event)
        let actuationStarted = DispatchTime.now().uptimeNanoseconds
        if Self.signposter.isEnabled {
            Self.signposter.emitEvent(
                "RepairActuation",
                "edge=begin sequence=\(event.sequence) plans=\(plans.count) repairs=\(event.repairs.count)"
            )
        }
        var leases: [any PfsMacOS26RepairArmLease] = []
        do {
                // Arm and resolve the exact traversal coordinates for the
                // whole event before the first cache mutation changes the
                // local namespace index. This also proves every plan is
                // executable before any mounted-VFS surgery begins.
            for plan in plans {
                try Task.checkCancellation()
                leases.append(try await armer.arm(plan))
            }
            for (plan, lease) in zip(plans, leases) {
                try Task.checkCancellation()
                try await lease.activate()
                try await actuator.apply(plan)
                try await lease.validate()
            }
                // Keep every completed plan armed while the event barrier
                // resumes: FSKit may emit a prior unlink's close/reclaim tail
                // after unlinkat has returned and while the next plan runs.
            try await publicationBarrier.resume(event)
            for lease in leases {
                try await lease.release()
            }
            if Self.signposter.isEnabled {
                let now = DispatchTime.now().uptimeNanoseconds
                let elapsed = now < actuationStarted
                    ? 0
                    : (now - actuationStarted) / 1_000
                Self.signposter.emitEvent(
                    "RepairActuation",
                    "edge=end sequence=\(event.sequence) duration_us=\(elapsed) plans=\(plans.count)"
                )
            }
        } catch {
            for lease in leases {
                await lease.cancel()
            }
            if Self.signposter.isEnabled {
                let now = DispatchTime.now().uptimeNanoseconds
                let elapsed = now < actuationStarted
                    ? 0
                    : (now - actuationStarted) / 1_000
                let nsError = error as NSError
                Self.signposter.emitEvent(
                    "RepairActuation",
                    "edge=failed sequence=\(event.sequence) duration_us=\(elapsed) plans=\(plans.count) domain=\(nsError.domain, privacy: .public) code=\(nsError.code)"
                )
            }
            throw error
        }
    }

    public func orderedAdmissionContended(
        for event: PfsMacOSCoherenceEvent
    ) async -> Bool {
        await publicationBarrier.orderedAdmissionContended(for: event)
    }

    public func acknowledged(_ event: PfsMacOSCoherenceEvent) async {
        await publicationBarrier.acknowledged(event)
    }

    /// A negative-cache purge is a parent-directory transaction: one sibling
    /// create+unlink invalidates every negative name cached in that directory.
    /// PREPARE still receives the complete repair list and therefore closes all
    /// exact callback scopes; only the redundant mounted-VFS actuations collapse.
    private func makePlans(
        event: PfsMacOSCoherenceEvent
    ) throws -> [PfsMacOS26RepairPlan] {
        let candidates = try event.repairs.enumerated().map { index, repair in
            try makePlan(event: event, step: UInt32(index), repair: repair)
        }
        var plans: [PfsMacOS26RepairPlan] = []
        var negativeParents: [PfsMacOSStableIdentity: PfsMacOSRelativePath] = [:]
        for plan in candidates {
            if plan.kind == .negativeScratch {
                if let recordedParent = negativeParents[plan.parentIdentity] {
                    guard recordedParent == plan.path else {
                        throw PfsMacOSCoherenceError.invalidRepairOperand
                    }
                    continue
                }
                negativeParents[plan.parentIdentity] = plan.path
            }
            plans.append(plan)
        }
        return plans
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
        case let .evictBinding(path, parentIdentity, itemIdentity, itemKind):
            guard let name = path.name else { throw PfsMacOSCoherenceError.invalidPathComponent }
            let operand = try authenticator.makeOperand(
                epoch: event.epoch,
                sequence: event.sequence,
                step: step,
                kind: .positiveEviction,
                parentIdentity: parentIdentity,
                itemIdentity: itemIdentity,
                sourceName: name,
                itemKind: itemKind
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
        case let .refreshAttributes(
            path,
            parentIdentity,
            itemIdentity,
            expectedVFSFileID,
            itemKind
        ):
            guard let name = path.name else {
                throw PfsMacOSCoherenceError.invalidPathComponent
            }
            let operand = try authenticator.makeOperand(
                epoch: event.epoch,
                sequence: event.sequence,
                step: step,
                kind: .attributeRefresh,
                parentIdentity: parentIdentity,
                itemIdentity: itemIdentity,
                sourceName: name,
                itemKind: itemKind
            )
            return PfsMacOS26RepairPlan(
                epoch: event.epoch,
                sequence: event.sequence,
                step: step,
                kind: .attributeRefresh,
                path: path,
                parentIdentity: parentIdentity,
                itemIdentity: itemIdentity,
                expectedVFSFileID: expectedVFSFileID,
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
                  plan.operand != nil,
                  let itemKind = plan.itemKind else {
                throw PfsMacOSCoherenceError.invalidPathComponent
            }
            let parentFD = try openDirectory(parent)
            defer { close(parentFD) }
            let removalFlags: Int32 = itemKind == .directory ? AT_REMOVEDIR : 0
            let unlinked = try source.withPOSIXName { sourceName in
                unlinkat(parentFD, sourceName, removalFlags)
            }
            guard unlinked == 0 || errno == ENOENT else {
                throw PfsMacOSCoherenceError.posix(operation: "evict cached binding", errno: errno)
            }

        case .attributeRefresh:
            guard let parent = plan.path.parent,
                  let name = plan.path.name,
                  let itemKind = plan.itemKind,
                  itemKind != .symlink,
                  let expectedVFSFileID = plan.expectedVFSFileID else {
                throw PfsMacOSCoherenceError.invalidRepairOperand
            }
            let parentFD = try openDirectory(parent)
            defer { close(parentFD) }
            let flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW
                | (itemKind == .directory ? O_DIRECTORY : 0)
            let itemFD = try name.withPOSIXName { component in
                openat(parentFD, component, flags)
            }
            guard itemFD >= 0 else {
                throw PfsMacOSCoherenceError.posix(operation: "open attribute repair source", errno: errno)
            }
            defer { close(itemFD) }
            var status = stat()
            guard fstat(itemFD, &status) == 0 else {
                throw PfsMacOSCoherenceError.posix(operation: "stat attribute repair source", errno: errno)
            }
            guard status.st_ino == expectedVFSFileID else {
                throw PfsMacOSCoherenceError.invalidRepairOperand
            }
            let permissions = mode_t(status.st_mode) & mode_t(0o7777)
            guard fchmod(itemFD, permissions) == 0 else {
                throw PfsMacOSCoherenceError.posix(operation: "refresh cached attributes", errno: errno)
            }

        case .dataInvalidation:
            guard let parent = plan.path.parent,
                  let name = plan.path.name,
                  plan.operand != nil,
                  plan.itemKind == .file,
                  let expectedVFSFileID = plan.expectedVFSFileID,
                  let size = plan.authoritativeSize,
                  size <= UInt64(off_t.max) else {
                throw PfsMacOSCoherenceError.invalidPathComponent
            }
            let parentFD = try openDirectory(parent)
            defer { close(parentFD) }
            let fileFD = try name.withPOSIXName { component in
                openat(parentFD, component, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
            }
            guard fileFD >= 0 else {
                throw PfsMacOSCoherenceError.posix(operation: "open data repair source", errno: errno)
            }
            defer { close(fileFD) }
            var status = stat()
            guard fstat(fileFD, &status) == 0 else {
                throw PfsMacOSCoherenceError.posix(operation: "stat data repair source", errno: errno)
            }
            guard status.st_ino == expectedVFSFileID else {
                throw PfsMacOSCoherenceError.invalidRepairOperand
            }
            let unlinked = try name.withPOSIXName { component in unlinkat(parentFD, component, 0) }
            guard unlinked == 0 else {
                throw PfsMacOSCoherenceError.posix(operation: "evict data repair source", errno: errno)
            }
            // Unconditional by design. On macOS 26 fstat may already report
            // the new length while stale cached pages still expose the old EOF.
            guard ftruncate(fileFD, off_t(size)) == 0 else {
                throw PfsMacOSCoherenceError.posix(operation: "truncate data repair source", errno: errno)
            }
            let windows = try PfsMacOS26MappingWindows(fileSize: size)
            for window in windows {
                try Task.checkCancellation()
                let address = mmap(nil, window.length, PROT_READ, MAP_SHARED, fileFD, off_t(window.offset))
                guard address != MAP_FAILED else {
                    throw PfsMacOSCoherenceError.posix(operation: "map data repair source", errno: errno)
                }
                let syncResult = msync(address, window.length, MS_INVALIDATE)
                let syncErrno = errno
                let unmapResult = munmap(address, window.length)
                guard syncResult == 0 else {
                    throw PfsMacOSCoherenceError.posix(operation: "invalidate data repair source", errno: syncErrno)
                }
                guard unmapResult == 0 else {
                    throw PfsMacOSCoherenceError.posix(operation: "unmap data repair source", errno: errno)
                }
            }
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
