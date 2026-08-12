import Foundation
import OSLog
@preconcurrency import Darwin
@preconcurrency import Dispatch

// MARK: - Callback admission

/// One typed cache-publication selector. Namespace coordinates are exact;
/// directory selectors cover whole-directory snapshots and parent-locking
/// namespace mutations; item selectors cover attributes/data for one stable
/// authority object.
public enum PfsMacOSAdmissionSelector: Sendable, Equatable, Hashable {
    case namespace(PfsMacOSNamespaceCoordinate)
    case directory(PfsMacOSStableIdentity)
    case item(PfsMacOSStableIdentity)
    /// This callback can submit an authority-ordered mutation. macOS 26 FSKit
    /// can withhold synthetic-repair callbacks behind one such callback even
    /// when paths differ. This selector therefore overlaps every active repair;
    /// local PREPARE releases it and the callback-serialized authority refuses
    /// the mutation definite-preapply instead of leaving it parked.
    case orderedMutation

    fileprivate func overlaps(_ other: Self) -> Bool {
        switch (self, other) {
        case let (.namespace(lhs), .namespace(rhs)):
            lhs == rhs
        case let (.directory(parent), .namespace(coordinate)),
             let (.namespace(coordinate), .directory(parent)):
            parent == coordinate.parentIdentity
        case let (.directory(lhs), .directory(rhs)):
            lhs == rhs
        case let (.item(lhs), .item(rhs)):
            lhs == rhs
        case (.orderedMutation, .orderedMutation):
            true
        default:
            false
        }
    }
}

/// Immutable scope declared before an FSKit callback enters publication
/// admission. Empty or malformed callback descriptions are represented by
/// `conservative`, which overlaps every repair instead of silently opening a
/// coherence hole.
public struct PfsMacOSCallbackScope: Sendable, Equatable {
    fileprivate let selectors: Set<PfsMacOSAdmissionSelector>
    fileprivate let isConservative: Bool

    public static let conservative = PfsMacOSCallbackScope(
        selectors: [], isConservative: true
    )

    public init(selectors: Set<PfsMacOSAdmissionSelector>) {
        self.selectors = selectors
        isConservative = selectors.isEmpty
    }

    fileprivate init(
        selectors: Set<PfsMacOSAdmissionSelector>,
        isConservative: Bool
    ) {
        self.selectors = selectors
        self.isConservative = isConservative
    }

    static func conservative(orderedMutation: Bool) -> Self {
        PfsMacOSCallbackScope(
            selectors: orderedMutation ? [.orderedMutation] : [],
            isConservative: true
        )
    }

    fileprivate func overlaps(_ other: Self) -> Bool {
        if isConservative || other.isConservative { return true }
        for selector in selectors {
            if other.selectors.contains(where: selector.overlaps) { return true }
        }
        return false
    }

    /// Declared before admission so every authority-ordered callback overlaps
    /// every repair. PREPARE can then close future requests and drain the
    /// callback's exact outcome before the nested actuator enters FSKit.
    var canSubmitOrderedMutation: Bool {
        selectors.contains(.orderedMutation)
    }

    var diagnosticSummary: String {
        var namespaceCount = 0
        var directoryCount = 0
        var itemCount = 0
        for selector in selectors {
            switch selector {
            case .namespace:
                namespaceCount += 1
            case .directory:
                directoryCount += 1
            case .item:
                itemCount += 1
            case .orderedMutation:
                break
            }
        }
        return "conservative=\(isConservative) ordered=\(canSubmitOrderedMutation) namespace=\(namespaceCount) directory=\(directoryCount) item=\(itemCount)"
    }

}

/// The immutable source-phase classification of one ordered request.
///
/// A distinct callback is safe for the macOS 26 pipelined source exception
/// only when it has issued ordered requests and nothing else.  The verdict is
/// captured under the ticket lock at the same instant this request commits to
/// dispatch; deriving it later would race an ordinary request's history and
/// let the frontend and authority make opposite PREPARE-drain decisions.
public struct PfsMacOSOrderedMutationSubmission: Sendable, Equatable {
    public let sourcePhaseQueueable: Bool
}

/// Synchronous accounting for an FSKit upcall before its asynchronous callback
/// task can be scheduled. A reservation grants no request permission; it only
/// lets PREPARE include every callback whose framework ingress won the same
/// lock-linearized cut.
final class PfsMacOSCallbackIngressReservation: @unchecked Sendable {
    let ticket: PfsMacOSAdmittedCallbackTicket
    let scope: PfsMacOSCallbackScope

    init(ticket: PfsMacOSAdmittedCallbackTicket, scope: PfsMacOSCallbackScope) {
        self.ticket = ticket
        self.scope = scope
    }
}

private final class PfsMacOSCallbackIngressRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private let admissionRefusal: PfsLocalClientError
    private var nextDiagnosticTicketID: UInt64 = 1
    private var pending: [ObjectIdentifier: PfsMacOSCallbackIngressReservation] = [:]

    init(admissionRefusal: PfsLocalClientError) {
        self.admissionRefusal = admissionRefusal
    }

    func reserve(
        scope: PfsMacOSCallbackScope,
        callbackKind: String,
        ingressUptimeNanoseconds: UInt64
    ) -> PfsMacOSCallbackIngressReservation {
        lock.lock()
        let diagnosticID = allocateDiagnosticIDLocked()
        let ticket = PfsMacOSAdmittedCallbackTicket(
            scope: scope,
            admissionRefusal: admissionRefusal,
            diagnosticID: diagnosticID,
            callbackKind: callbackKind,
            ingressUptimeNanoseconds: ingressUptimeNanoseconds
        )
        let reservation = PfsMacOSCallbackIngressReservation(
            ticket: ticket,
            scope: scope
        )
        pending[ObjectIdentifier(reservation)] = reservation
        lock.unlock()
        return reservation
    }

    func makeTicket(
        scope: PfsMacOSCallbackScope,
        callbackKind: String,
        ingressUptimeNanoseconds: UInt64
    ) -> PfsMacOSAdmittedCallbackTicket {
        lock.lock()
        let diagnosticID = allocateDiagnosticIDLocked()
        lock.unlock()
        return PfsMacOSAdmittedCallbackTicket(
            scope: scope,
            admissionRefusal: admissionRefusal,
            diagnosticID: diagnosticID,
            callbackKind: callbackKind,
            ingressUptimeNanoseconds: ingressUptimeNanoseconds
        )
    }

    func takePending() -> [PfsMacOSCallbackIngressReservation] {
        lock.lock()
        let reservations = Array(pending.values)
        pending.removeAll(keepingCapacity: true)
        lock.unlock()
        return reservations
    }

    @discardableResult
    func remove(_ reservation: PfsMacOSCallbackIngressReservation) -> Bool {
        lock.lock()
        let removed = pending.removeValue(forKey: ObjectIdentifier(reservation)) != nil
        lock.unlock()
        return removed
    }

    func count() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return pending.count
    }

    private func allocateDiagnosticIDLocked() -> UInt64 {
        let diagnosticID = nextDiagnosticTicketID
        nextDiagnosticTicketID = diagnosticID == UInt64.max ? 1 : diagnosticID + 1
        return diagnosticID
    }
}

/// One ordinary cache-producing FSKit callback, from admission until its
/// reply crosses the framework publication boundary.
///
/// The ticket is the barrier's unit of accounting and the pfslocal client's
/// reporting channel: `PfsLocalClient` stamps the callback's logical operation
/// ID onto the current task's ticket the moment it allocates one, which is
/// what lets a PREPARE barrier exempt exactly the initiating callback rather
/// than guessing from paths.
public final class PfsMacOSAdmittedCallbackTicket: @unchecked Sendable {
    private static let signposter = OSSignposter(
        subsystem: "dev.portablefs.fskit",
        category: "MacOSV3Admission"
    )

    private enum OrderedSubmissionAttempt {
        case submitted(PfsMacOSOrderedMutationSubmission)
        case parked
        case revoked
    }

    private enum OrdinarySubmissionAttempt {
        case submitted(UInt64)
        case parked
        case revoked
    }

    private struct OrdinaryRequest {
        var cancel: (@Sendable () -> Void)?
    }

    private let lock = NSLock()
    private let scope: PfsMacOSCallbackScope
    private let admissionRefusal: PfsLocalClientError
    let diagnosticID: UInt64
    let callbackKind: String
    let ingressUptimeNanoseconds: UInt64
    private var operationID: UInt64?
    private var published = false
    private var orderedMutationsInFlight = 0
    private var orderedMutationEverSubmitted = false
    private var ordinaryRequestEverSubmitted = false
    private var futureRequestsRevoked = false
    /// v2 PREPARE closes new request admission but lets already-issued reads
    /// publish naturally. Terminal failure flips this back to false and invokes
    /// every installed cancellation so teardown still cannot hang.
    private var ordinaryRequestsDrainNaturally = false
    /// A source PREPARE has already identified this ticket as work that is
    /// authority-ordered after the initiating callback (or as a callback that
    /// has not issued any request at all). Existing ordered requests may drain
    /// at the authority, but no later request from the callback may cross the
    /// source's deferred COMPLETE boundary.
    private var futureRequestsParkedForSource = false
    private var ordinaryRequestsInFlight = 0
    private var nextOrdinaryRequestID: UInt64 = 1
    private var ordinaryRequests: [UInt64: OrdinaryRequest] = [:]
    private var sourceParkWaiters: [UUID: CheckedContinuation<Bool, Never>] = [:]
    private var ordinaryAdmissionWaiters: [UUID: CheckedContinuation<Bool, Never>] = [:]
    private var crossed = false
    private var publicationWaiters: [UUID: CheckedContinuation<Bool, Never>] = [:]

    public init(
        scope: PfsMacOSCallbackScope = .conservative,
        admissionRefusal: PfsLocalClientError = .publicationAdmissionClosed,
        diagnosticID: UInt64 = 0,
        callbackKind: String = "unspecified",
        ingressUptimeNanoseconds: UInt64 = 0
    ) {
        self.scope = scope
        self.admissionRefusal = admissionRefusal
        self.diagnosticID = diagnosticID
        self.callbackKind = callbackKind
        self.ingressUptimeNanoseconds = ingressUptimeNanoseconds
    }

    func admissionRefusalError() -> PfsLocalClientError { admissionRefusal }

    /// Focused drain-test observation. Request admission itself remains the
    /// authority; this avoids probing it by accidentally submitting work.
    func hasClosedFutureRequests() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return futureRequestsRevoked
    }

    /// Whether this callback can publish a value touched by one repair. An
    /// undeclared callback is deliberately conservative. This predicate is
    /// used both for callbacks arriving after PREPARE and, critically, for
    /// the already-admitted drain: crossing unrelated callbacks was the
    /// source of unnecessary application-visible conflicts during a disjoint
    /// peer storm.
    func intersects(_ repairScope: PfsMacOSCallbackScope) -> Bool {
        scope.overlaps(repairScope)
    }

    /// Records the pfslocal logical operation ID for the callback's current
    /// publication attempt. Most callbacks own one ID, but a daemon retraction
    /// transparently reissues the whole operation with a fresh collector and a
    /// fresh ID. Replacing the prior attempt here is what lets the source
    /// PREPARE/COMPLETE pair exempt and await the surviving attempt rather than
    /// an already-acknowledged one.
    public func noteOperationID(_ id: UInt64) {
        lock.lock()
        operationID = id
        lock.unlock()
        if Self.signposter.isEnabled {
            Self.signposter.emitEvent(
                "OperationAssigned",
                "ticket=\(self.diagnosticID) kind=\(self.callbackKind, privacy: .public)"
            )
        }
    }

    func currentOperationID() -> UInt64? {
        lock.lock()
        defer { lock.unlock() }
        return operationID
    }

    /// Marks an authority-ordered mutation of this callback in flight. The
    /// callback-serialized authority gives it an exact pre/post-apply outcome;
    /// PREPARE waits through framework publication before repair begins.
    @discardableResult
    public func orderedMutationSubmitted() -> Bool {
        orderedMutationSubmission() != nil
    }

    /// Non-waiting test/helper form of production ordered admission.  The
    /// returned token belongs to this exact request and must be stamped on its
    /// pfslocal envelope; it is not a callback-wide value that may be sampled
    /// later.
    public func orderedMutationSubmission() -> PfsMacOSOrderedMutationSubmission? {
        lock.lock()
        if futureRequestsRevoked || futureRequestsParkedForSource {
            lock.unlock()
            return nil
        }
        let submission = PfsMacOSOrderedMutationSubmission(
            sourcePhaseQueueable: !ordinaryRequestEverSubmitted
        )
        orderedMutationEverSubmitted = true
        orderedMutationsInFlight += 1
        lock.unlock()
        return submission
    }

    /// Production request admission. A callback that was already inside FSKit
    /// when its own mount's PREPARE arrived is parked rather than failed if it
    /// had not exposed any request yet. The synchronous helper above remains a
    /// precise non-waiting probe for focused tests.
    public func orderedMutationSubmittedWhenPermitted() async throws -> Bool {
        try await orderedMutationSubmissionWhenPermitted() != nil
    }

    /// Commits one ordered request and atomically captures whether the
    /// authority may queue this distinct callback through its own source phase.
    /// Once any ordinary request has entered the ticket, every later ordered
    /// submission is conservatively nonqueueable even after that request has
    /// settled.
    public func orderedMutationSubmissionWhenPermitted() async throws
        -> PfsMacOSOrderedMutationSubmission? {
        while true {
            try Task.checkCancellation()
            switch trySubmitOrderedMutation() {
            case let .submitted(submission):
                return submission
            case .revoked:
                return nil
            case .parked:
                try await waitForSourceParkToEnd()
            }
        }
    }

    private func trySubmitOrderedMutation() -> OrderedSubmissionAttempt {
        lock.lock()
        defer { lock.unlock() }
        if futureRequestsRevoked {
            return .revoked
        }
        if !futureRequestsParkedForSource {
            let submission = PfsMacOSOrderedMutationSubmission(
                sourcePhaseQueueable: !ordinaryRequestEverSubmitted
            )
            orderedMutationEverSubmitted = true
            orderedMutationsInFlight += 1
            return .submitted(submission)
        }
        return .parked
    }

    /// Frozen-v1/terminal admission closure. A future ordered request is
    /// refused before it can reach the authority and ordinary reads already in
    /// flight are canceled locally. The v2 PREPARE path deliberately uses
    /// `closeFutureRequestsForNaturalDrain` instead, because its exact audience
    /// may finish and publish without being crossed by the peer mutation.
    ///
    /// Cancellation callbacks are invoked outside the ticket lock. Installing
    /// one after revocation invokes it immediately, so PREPARE and request
    /// enqueue have one total order with no check-then-register gap.
    func revokeFutureRequests() {
        lock.lock()
        futureRequestsRevoked = true
        futureRequestsParkedForSource = false
        ordinaryRequestsDrainNaturally = false
        if ordinaryRequestsInFlight > 0, !orderedMutationEverSubmitted {
            crossed = true
        }
        let cancellations = ordinaryRequests.values.compactMap(\.cancel)
        let parkWaiters = Array(sourceParkWaiters.values)
        sourceParkWaiters.removeAll()
        let ordinaryWaiters = Array(ordinaryAdmissionWaiters.values)
        ordinaryAdmissionWaiters.removeAll()
        lock.unlock()
        for cancel in cancellations {
            cancel()
        }
        for waiter in parkWaiters {
            waiter.resume(returning: true)
        }
        for waiter in ordinaryWaiters {
            waiter.resume(returning: true)
        }
    }

    /// v2 PREPARE admission closure. The authority has separated callbacks
    /// already in the exact PREPARE audience from reads that arrive afterward,
    /// so an issued ordinary request can finish and publish without crossing
    /// the mutation. Canceling it here both lost a valid local read and raced a
    /// successful resource-bearing reply into unreachable ownership.
    func closeFutureRequestsForNaturalDrain() {
        lock.lock()
        futureRequestsRevoked = true
        futureRequestsParkedForSource = false
        ordinaryRequestsDrainNaturally = true
        let parkWaiters = Array(sourceParkWaiters.values)
        sourceParkWaiters.removeAll()
        let ordinaryWaiters = Array(ordinaryAdmissionWaiters.values)
        ordinaryAdmissionWaiters.removeAll()
        lock.unlock()
        for waiter in parkWaiters {
            waiter.resume(returning: true)
        }
        for waiter in ordinaryWaiters {
            waiter.resume(returning: true)
        }
    }

    enum LocalSourcePrepareDisposition: Equatable {
        case initiatingOperation
        case parkedPristine
        case parkedDistinctOrderedOperation
        case parkedOrderedIdentityPending
        case mustRevokeAndDrain
    }

    /// Atomically classifies an already-admitted callback at a source PREPARE.
    ///
    /// Operation-ID *ordering* is deliberately not used here. A higher-ID read
    /// can execute before the initiating mutation and still carry stale data.
    /// Equality identifies the one initiating callback; beyond that, only two
    /// histories are safe to preserve:
    ///
    /// - no request of any kind has ever been submitted, so the callback cannot
    ///   hold an authority result or cache value; or
    /// - it has submitted ordered mutations under a different logical operation
    ///   and no ordinary request. The authority serializes that distinct
    ///   frontend operation after the source callback and holds it until the
    ///   deferred COMPLETE is acknowledged.
    ///
    /// Both classes have their *future* requests parked through exact COMPLETE
    /// acknowledgement. Anything that has submitted an ordinary request stays
    /// in the exact drain audience; v2 lets that issued request finish
    /// naturally while closing all future requests on the ticket.
    func prepareForLocalSource(
        initiatingOperationID: UInt64
    ) -> LocalSourcePrepareDisposition {
        lock.lock()
        defer { lock.unlock() }
        if operationID == initiatingOperationID {
            return .initiatingOperation
        }
        guard !futureRequestsRevoked, !ordinaryRequestEverSubmitted else {
            return .mustRevokeAndDrain
        }
        if orderedMutationEverSubmitted, operationID == nil {
            // Request admission won the ticket lock, so this exact request is
            // already committed to dispatch even though collector stamping has
            // not run yet. It cannot be the source initiator (that event names a
            // request already stamped and observed by the daemon); the strict
            // connection's next operation ID is therefore necessarily distinct.
            // Park later requests, but let this committed dispatch finish
            // acquiring its identity and queue behind the source at authority.
            futureRequestsParkedForSource = true
            return .parkedOrderedIdentityPending
        }
        if !orderedMutationEverSubmitted, operationID == nil {
            futureRequestsParkedForSource = true
            return .parkedPristine
        }
        if orderedMutationEverSubmitted, operationID != nil {
            futureRequestsParkedForSource = true
            return .parkedDistinctOrderedOperation
        }
        // A submitted ordered request without an identity is malformed once no
        // dispatch commit is in progress. Keep the conservative failure path.
        return .mustRevokeAndDrain
    }

    func releaseSourcePark() {
        lock.lock()
        futureRequestsParkedForSource = false
        let waiters = Array(sourceParkWaiters.values)
        sourceParkWaiters.removeAll()
        let ordinaryWaiters = Array(ordinaryAdmissionWaiters.values)
        ordinaryAdmissionWaiters.removeAll()
        lock.unlock()
        for waiter in waiters {
            waiter.resume(returning: true)
        }
        for waiter in ordinaryWaiters {
            waiter.resume(returning: true)
        }
    }

    public func orderedMutationSettled() {
        lock.lock()
        orderedMutationsInFlight -= 1
        let ordinaryWaiters: [CheckedContinuation<Bool, Never>]
        if orderedMutationsInFlight == 0 {
            ordinaryWaiters = Array(ordinaryAdmissionWaiters.values)
            ordinaryAdmissionWaiters.removeAll()
        } else {
            ordinaryWaiters = []
        }
        lock.unlock()
        for waiter in ordinaryWaiters {
            waiter.resume(returning: true)
        }
    }

    /// Once this callback has dispatched an ordered mutation, no local
    /// cancellation or timeout may synthesize a retryable outcome for any of
    /// its remaining requests. The authority may already have applied the
    /// mutation; the callback must drain its exact result or fail the mount as
    /// uncertain.
    public func hasSubmittedOrderedMutation() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return orderedMutationEverSubmitted
    }

    /// Marks an ordinary (non-mutating) request of this callback in flight.
    /// The authority parks a read on a barrier-affected coordinate until every
    /// strict mount has acknowledged PREPARE, so a drain that waited for this
    /// callback would wait on the very acknowledgment it is blocking — the
    /// read-side twin of the two-writer deadlock. The drain releases it; what
    /// keeps that sound is `markCrossedIfExposedReadsWereReleased` below.
    @discardableResult
    public func ordinaryRequestSubmitted() -> UInt64? {
        lock.lock()
        if futureRequestsRevoked || ordinaryRequestMustWaitLocked() {
            lock.unlock()
            return nil
        }
        guard nextOrdinaryRequestID != UInt64.max else {
            lock.unlock()
            return nil
        }
        let requestID = nextOrdinaryRequestID
        nextOrdinaryRequestID += 1
        ordinaryRequestEverSubmitted = true
        ordinaryRequests[requestID] = OrdinaryRequest()
        ordinaryRequestsInFlight += 1
        lock.unlock()
        return requestID
    }

    public func ordinaryRequestSubmittedWhenPermitted() async throws -> UInt64? {
        while true {
            try Task.checkCancellation()
            switch trySubmitOrdinaryRequest() {
            case let .submitted(requestID):
                return requestID
            case .revoked:
                return nil
            case .parked:
                try await waitForOrdinaryAdmission()
            }
        }
    }

    private func trySubmitOrdinaryRequest() -> OrdinarySubmissionAttempt {
        lock.lock()
        defer { lock.unlock() }
        if futureRequestsRevoked {
            return .revoked
        }
        if !ordinaryRequestMustWaitLocked() {
            guard nextOrdinaryRequestID != UInt64.max else {
                return .revoked
            }
            let requestID = nextOrdinaryRequestID
            nextOrdinaryRequestID += 1
            ordinaryRequestEverSubmitted = true
            ordinaryRequests[requestID] = OrdinaryRequest()
            ordinaryRequestsInFlight += 1
            return .submitted(requestID)
        }
        return .parked
    }

    /// An ordered-only request's queueability proof remains true until its
    /// exact outcome settles. Letting an ordinary request from the same ticket
    /// dispatch concurrently would retroactively turn the callback mixed after
    /// the authority had already accepted the proof. Production waits; the
    /// synchronous helper conservatively refuses until the ordered request is
    /// no longer in flight.
    private func ordinaryRequestMustWaitLocked() -> Bool {
        futureRequestsParkedForSource
            || (!ordinaryRequestEverSubmitted && orderedMutationsInFlight > 0)
    }

    public func installOrdinaryRequestCancellation(
        _ requestID: UInt64,
        cancel: @escaping @Sendable () -> Void
    ) {
        lock.lock()
        guard ordinaryRequests[requestID] != nil else {
            lock.unlock()
            return
        }
        if futureRequestsRevoked && !ordinaryRequestsDrainNaturally {
            lock.unlock()
            cancel()
            return
        }
        ordinaryRequests[requestID]?.cancel = cancel
        lock.unlock()
    }

    public func ordinaryRequestSettled(_ requestID: UInt64) {
        lock.lock()
        if ordinaryRequests.removeValue(forKey: requestID) != nil {
            ordinaryRequestsInFlight -= 1
        }
        lock.unlock()
    }

    /// Test helper for the conservative release verdict applied when PREPARE
    /// revokes an ordinary request.
    public func markCrossedIfExposedReadsWereReleased() {
        lock.lock()
        if !published, !orderedMutationEverSubmitted,
           orderedMutationsInFlight == 0, ordinaryRequestsInFlight > 0 {
            crossed = true
        }
        lock.unlock()
    }

    public func isCrossed() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return crossed
    }

    @discardableResult
    func markPublished() -> Bool {
        lock.lock()
        guard !published else {
            lock.unlock()
            return false
        }
        published = true
        let waiters = Array(publicationWaiters.values)
        publicationWaiters.removeAll()
        lock.unlock()
        for waiter in waiters {
            waiter.resume(returning: true)
        }
        return true
    }

    func waitUntilPublished() async throws {
        let waiterID = UUID()
        let didPublish = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                lock.lock()
                if published {
                    lock.unlock()
                    continuation.resume(returning: true)
                    return
                }
                if Task.isCancelled {
                    lock.unlock()
                    continuation.resume(returning: false)
                    return
                }
                publicationWaiters[waiterID] = continuation
                lock.unlock()
            }
        } onCancel: {
            self.cancelPublicationWaiter(waiterID)
        }
        guard didPublish else { throw CancellationError() }
        try Task.checkCancellation()
    }

    private func cancelPublicationWaiter(_ id: UUID) {
        lock.lock()
        let waiter = publicationWaiters.removeValue(forKey: id)
        lock.unlock()
        waiter?.resume(returning: false)
    }

    private func waitForSourceParkToEnd() async throws {
        let waiterID = UUID()
        let didWake = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                lock.lock()
                if !futureRequestsParkedForSource || futureRequestsRevoked {
                    lock.unlock()
                    continuation.resume(returning: true)
                    return
                }
                if Task.isCancelled {
                    lock.unlock()
                    continuation.resume(returning: false)
                    return
                }
                sourceParkWaiters[waiterID] = continuation
                lock.unlock()
            }
        } onCancel: {
            self.cancelSourceParkWaiter(waiterID)
        }
        guard didWake else { throw CancellationError() }
        try Task.checkCancellation()
    }

    private func cancelSourceParkWaiter(_ id: UUID) {
        lock.lock()
        let waiter = sourceParkWaiters.removeValue(forKey: id)
        lock.unlock()
        waiter?.resume(returning: false)
    }

    private func waitForOrdinaryAdmission() async throws {
        let waiterID = UUID()
        let didWake = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                lock.lock()
                if !ordinaryRequestMustWaitLocked() || futureRequestsRevoked {
                    lock.unlock()
                    continuation.resume(returning: true)
                    return
                }
                if Task.isCancelled {
                    lock.unlock()
                    continuation.resume(returning: false)
                    return
                }
                ordinaryAdmissionWaiters[waiterID] = continuation
                lock.unlock()
            }
        } onCancel: {
            self.cancelOrdinaryAdmissionWaiter(waiterID)
        }
        guard didWake else { throw CancellationError() }
        try Task.checkCancellation()
    }

    private func cancelOrdinaryAdmissionWaiter(_ id: UUID) {
        lock.lock()
        let waiter = ordinaryAdmissionWaiters.removeValue(forKey: id)
        lock.unlock()
        waiter?.resume(returning: false)
    }

    func pendingOrdinaryAdmissionWaiterCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return ordinaryAdmissionWaiters.count
    }


}

/// Task-local bridge from the FSKit callback that admitted itself to the
/// pfslocal client that allocates its logical operation ID. Task locals flow
/// across actor hops within one task, so the client sees exactly the callback
/// it is working for and no other.
public enum PfsMacOSCallbackAdmission {
    @TaskLocal public static var ticket: PfsMacOSAdmittedCallbackTicket?
}

/// The production `PfsMacOSCallbackPublicationBarrier`.
///
/// PREPARE closes publication only for callbacks whose typed selectors overlap
/// the repair and drains only overlapping already-admitted callbacks,
/// exempting the exact initiating operation. While mounted-VFS repair may still
/// be needed, an overlapping callback is refused immediately so it releases
/// FSKit's callback lane. Once local repair is complete, overlapping callbacks
/// may safely park, but they are admitted only after the authority accepts the
/// exact COMPLETE cursor. Authenticated actuator callbacks bypass admission.
public actor PfsMacOSFSKitPublicationBarrier: PfsMacOSCallbackPublicationBarrier {
    private enum AdmissionState {
        case open
        case repairActive
        case awaitingAuthorityAcknowledgement
    }

    private struct AdmissionWaiter {
        let continuation: CheckedContinuation<Void, Error>
    }

    private let localAuthoritySessionID: Data
    private let admissionRefusal: PfsLocalClientError
    private let allowsLocalSourcePipelining: Bool
    private nonisolated let ingressRegistry: PfsMacOSCallbackIngressRegistry
    private var admissionState = AdmissionState.open
    private var terminal: Error?
    private var admitted: [ObjectIdentifier: PfsMacOSAdmittedCallbackTicket] = [:]
    private var sourceParkedTickets: [ObjectIdentifier: PfsMacOSAdmittedCallbackTicket] = [:]
    private var admissionWaiters: [UUID: AdmissionWaiter] = [:]
    /// Exact cache coordinates touched by the current repair. They scope the
    /// PREPARE drain and post-PREPARE refusal. Namespace mutators declare a
    /// whole-parent selector in addition to their exact child coordinate: live
    /// macOS 26 testing proved that a distinct child mutation in the same
    /// parent can park behind the barrier while holding the callback lane the
    /// synthetic repair needs. Unrelated item reads and other parents remain
    /// live.
    private var closedRepairScope: PfsMacOSCallbackScope?
    /// A source mount never actuates its own COMPLETE: its initiating VFS
    /// callback already performed the local cache transition. Once that exact
    /// callback publishes, callbacks can park without blocking repair, but they
    /// cannot be admitted while the authority still holds mutation order.
    private var localInitiatorAwaitingPublication: UInt64?
    private var activeEpoch: Data?
    private var activeSequence: UInt64?
    // Diagnostic counters for callbacks that had to release FSKit execution
    // capacity during one peer repair. They never influence admission or ACK.
    private var refusedOrderedCallbacks: UInt64 = 0
    private var refusedOtherCallbacks: UInt64 = 0
    private var prepareUptimeNanoseconds: UInt64?
    private var completeUptimeNanoseconds: UInt64?
    private let signposter = OSSignposter(
        subsystem: "dev.portablefs.fskit",
        category: "MacOSV3Admission"
    )

    public init(
        localAuthoritySessionID: Data,
        policy: PfsMacOSCachePolicy = .synchronousVFSRepairV2
    ) throws {
        guard localAuthoritySessionID.count == 16 else {
            throw PfsMacOSCoherenceError.invalidSessionIDLength(localAuthoritySessionID.count)
        }
        let admissionRefusal: PfsLocalClientError
        let allowsLocalSourcePipelining: Bool
        switch policy {
        case .synchronousVFSRepairV1:
            admissionRefusal = .publicationAdmissionBusy
            allowsLocalSourcePipelining = false
        case .synchronousVFSRepairV2:
            admissionRefusal = .publicationAdmissionClosed
            allowsLocalSourcePipelining = true
        case .nativeFSKitRevocationV1:
            admissionRefusal = .publicationAdmissionClosed
            allowsLocalSourcePipelining = false
        }
        self.admissionRefusal = admissionRefusal
        self.allowsLocalSourcePipelining = allowsLocalSourcePipelining
        ingressRegistry = PfsMacOSCallbackIngressRegistry(
            admissionRefusal: admissionRefusal
        )
        self.localAuthoritySessionID = localAuthoritySessionID
    }

    /// Admits an undeclared callback conservatively. While PREPARE is active it
    /// is refused immediately rather than parked.
    public func admit() async throws -> PfsMacOSAdmittedCallbackTicket {
        try await admit(scope: .conservative)
    }

    /// Records callback ingress synchronously, before the callback's cooperative
    /// task can lose a scheduler race to PREPARE. The reservation is accounting,
    /// not permission to issue requests; the actor resolves that permission only
    /// after capability preflight and authenticated repair exemption checks.
    nonisolated func reserveCallbackIngress(
        scope: PfsMacOSCallbackScope,
        callbackKind: String,
        ingressUptimeNanoseconds: UInt64
    ) -> PfsMacOSCallbackIngressReservation {
        ingressRegistry.reserve(
            scope: scope,
            callbackKind: callbackKind,
            ingressUptimeNanoseconds: ingressUptimeNanoseconds
        )
    }

    /// Resolves a synchronous ingress reservation against the actor's current
    /// phase. A reservation adopted by PREPARE keeps its pre-cut ticket; a
    /// post-cut reservation follows the ordinary refuse/park/disjoint rules.
    func resolveAdmission(
        for reservation: PfsMacOSCallbackIngressReservation,
        exemptFromAdmission: Bool
    ) async throws -> PfsMacOSAdmittedCallbackTicket? {
        let ticket = reservation.ticket
        let key = ObjectIdentifier(ticket)
        let wasPending = ingressRegistry.remove(reservation)
        if exemptFromAdmission {
            admitted.removeValue(forKey: key)
            sourceParkedTickets.removeValue(forKey: key)
            return nil
        }
        if admitted[key] != nil {
            return ticket
        }
        guard wasPending else {
            if let terminal { throw terminal }
            throw PfsMacOSCoherenceError.transportClosed
        }
        return try await admitExisting(ticket, scope: reservation.scope)
    }

    /// Finalizes every reservation only after its FSKit reply closure returns.
    /// PREPARE may already have adopted the ticket, so removal and publication
    /// remain actor-serialized with the existing admitted-ticket ledger.
    func callbackReplyReturned(
        _ reservation: PfsMacOSCallbackIngressReservation
    ) {
        ingressRegistry.remove(reservation)
        published(reservation.ticket)
    }

    func pendingIngressReservationCount() -> Int {
        ingressRegistry.count()
    }

    /// An overlapping callback after PREPARE is refused definite-preapply. It
    /// must release FSKit's pathname/namespace lane before the nested repair
    /// actuator can enter that same coordinate. After local repair is done it
    /// parks instead: authority acknowledgement uses no FSKit callback lane.
    public func admit(
        scope: PfsMacOSCallbackScope,
        callbackKind: String = "unspecified",
        ingressUptimeNanoseconds: UInt64 = 0
    ) async throws -> PfsMacOSAdmittedCallbackTicket {
        let ticket = ingressRegistry.makeTicket(
            scope: scope,
            callbackKind: callbackKind,
            ingressUptimeNanoseconds: ingressUptimeNanoseconds
        )
        return try await admitExisting(ticket, scope: scope)
    }

    private func admitExisting(
        _ ticket: PfsMacOSAdmittedCallbackTicket,
        scope: PfsMacOSCallbackScope
    ) async throws -> PfsMacOSAdmittedCallbackTicket {
        while true {
            try Task.checkCancellation()
            if let terminal { throw terminal }
            let overlaps = scope.overlaps(closedRepairScope ?? .conservative)
            switch admissionState {
            case .open:
                try Task.checkCancellation()
                return admitImmediately(ticket)
            case .repairActive where overlaps:
                if scope.canSubmitOrderedMutation {
                    if refusedOrderedCallbacks < UInt64.max {
                        refusedOrderedCallbacks += 1
                    }
                } else if refusedOtherCallbacks < UInt64.max {
                    refusedOtherCallbacks += 1
                }
                if signposter.isEnabled {
                    let now = DispatchTime.now().uptimeNanoseconds
                    let ingress = ticket.ingressUptimeNanoseconds
                    let delay = ingress == 0 || now < ingress
                        ? 0
                        : (now - ingress) / 1_000
                    signposter.emitEvent(
                        "CallbackRefused",
                        "ticket=\(ticket.diagnosticID) kind=\(ticket.callbackKind, privacy: .public) sequence=\(self.activeSequence ?? 0) state=repair-active ordered=\(scope.canSubmitOrderedMutation) ingress_to_refusal_us=\(delay) scope=\(scope.diagnosticSummary, privacy: .public)"
                    )
                }
                throw admissionRefusal
            case .awaitingAuthorityAcknowledgement where overlaps:
                let waiterID = UUID()
                try await withTaskCancellationHandler {
                    try await withCheckedThrowingContinuation {
                        (continuation: CheckedContinuation<Void, Error>) in
                        if Task.isCancelled {
                            continuation.resume(throwing: CancellationError())
                            return
                        }
                        admissionWaiters[waiterID] = AdmissionWaiter(
                            continuation: continuation
                        )
                    }
                } onCancel: {
                    Task { await self.cancelAdmissionWaiter(waiterID) }
                }
                // ACK and cancellation may wake together. Re-check cancellation
                // and the current gate state before installing the reserved
                // ticket, so cancellation cannot leak it into the next drain.
                continue
            case .repairActive, .awaitingAuthorityAcknowledgement:
                try Task.checkCancellation()
                return admitImmediately(ticket)
            }
        }
    }

    private func admitImmediately(
        _ ticket: PfsMacOSAdmittedCallbackTicket
    ) -> PfsMacOSAdmittedCallbackTicket {
        admitted[ObjectIdentifier(ticket)] = ticket
        return ticket
    }

    private func cancelAdmissionWaiter(_ id: UUID) {
        guard let waiter = admissionWaiters.removeValue(forKey: id) else { return }
        waiter.continuation.resume(throwing: CancellationError())
    }

    private static func repairScope(
        of repairs: [PfsMacOSCacheRepair]
    ) -> PfsMacOSCallbackScope {
        var selectors: Set<PfsMacOSAdmissionSelector> = []
        // Every repair is an authority ordering barrier. Ordered callbacks are
        // volume-global for progress on macOS 26, independent of cache scope.
        selectors.insert(.orderedMutation)
        for repair in repairs {
            switch repair {
            case let .purgeNegative(_, parentIdentity, name):
                selectors.insert(.namespace(PfsMacOSNamespaceCoordinate(
                    parentIdentity: parentIdentity, name: name
                )))
                selectors.insert(.item(parentIdentity))
            case let .evictBinding(path, parentIdentity, itemIdentity, _),
                 let .refreshAttributes(path, parentIdentity, itemIdentity, _, _):
                guard let name = path.name else { return .conservative }
                selectors.insert(.namespace(PfsMacOSNamespaceCoordinate(
                    parentIdentity: parentIdentity, name: name
                )))
                selectors.insert(.item(parentIdentity))
                selectors.insert(.item(itemIdentity))
            case let .invalidateData(path, parentIdentity, itemIdentity, _, _):
                guard let name = path.name else { return .conservative }
                selectors.insert(.namespace(PfsMacOSNamespaceCoordinate(
                    parentIdentity: parentIdentity, name: name
                )))
                selectors.insert(.item(parentIdentity))
                selectors.insert(.item(itemIdentity))
            case let .invalidateDataObject(_, itemIdentity, _):
                selectors.insert(.item(itemIdentity))
            case let .invalidateAttributesObject(_, itemIdentity):
                selectors.insert(.item(itemIdentity))
            }
        }
        return PfsMacOSCallbackScope(selectors: selectors)
    }

    /// Marks the callback's reply as having crossed the framework publication
    /// boundary. This — not the async method's return — is the drain point
    /// PREPARE waits for.
    public func published(_ ticket: PfsMacOSAdmittedCallbackTicket) {
        let key = ObjectIdentifier(ticket)
        admitted.removeValue(forKey: key)
        sourceParkedTickets.removeValue(forKey: key)
        guard ticket.markPublished() else { return }
        if signposter.isEnabled {
            let now = DispatchTime.now().uptimeNanoseconds
            let ingress = ticket.ingressUptimeNanoseconds
            let elapsed = ingress == 0 || now < ingress ? 0 : (now - ingress) / 1_000
            signposter.emitEvent(
                "CallbackPublished",
                "ticket=\(ticket.diagnosticID) kind=\(ticket.callbackKind, privacy: .public) sequence=\(self.activeSequence ?? 0) ingress_to_publish_us=\(elapsed)"
            )
        }
        guard terminal == nil else { return }
        if let operationID = localInitiatorAwaitingPublication,
           ticket.currentOperationID() == operationID {
            // The source callback's reply is the source mount's local cache
            // transition. COMPLETE carries no local actuator work, so newer
            // overlapping callbacks may park without closing an FSKit repair
            // cycle. They still cannot reach the authority before its exact
            // COMPLETE acknowledgement releases mutation order.
            admissionState = .awaitingAuthorityAcknowledgement
        }
    }

    public func admittedCallbackCount() -> Int { admitted.count }
    func pendingAdmissionWaiterCount() -> Int { admissionWaiters.count }
    func refusedCallbackCounts() -> (ordered: UInt64, other: UInt64) {
        (refusedOrderedCallbacks, refusedOtherCallbacks)
    }
    public func isAdmissionClosed() -> Bool {
        if case .open = admissionState { return false }
        return true
    }

    public func prepare(_ event: PfsMacOSCoherenceEvent) async throws {
        if let terminal { throw terminal }
        // This lock-linearized cut is before PREPARE's first suspension. Every
        // framework upcall that arrived first becomes an ordinary admitted
        // ticket; every later upcall resolves against the closed actor state.
        let ingressReservations = ingressRegistry.takePending()
        for reservation in ingressReservations {
            admitted[ObjectIdentifier(reservation.ticket)] = reservation.ticket
        }
        refusedOrderedCallbacks = 0
        refusedOtherCallbacks = 0
        activeEpoch = event.epoch
        activeSequence = event.sequence
        prepareUptimeNanoseconds = DispatchTime.now().uptimeNanoseconds
        completeUptimeNanoseconds = nil
        let repairScope = Self.repairScope(of: event.repairs)
        closedRepairScope = repairScope
        let isLocalInitiator = event.initiator.sessionID == localAuthoritySessionID
        if signposter.isEnabled {
            signposter.emitEvent(
                "VisibilityPhase",
                "edge=prepare sequence=\(event.sequence) local=\(isLocalInitiator) adopted_ingress=\(ingressReservations.count) repairs=\(event.repairs.count) scope=\(repairScope.diagnosticSummary, privacy: .public)"
            )
        }
        // A peer COMPLETE may need authenticated mounted-VFS surgery, so peer
        // PREPARE closes new overlapping admission and drains the callbacks in
        // its exact audience before reusing FSKit's actuator lane. Under v2 an
        // already-issued ordinary request finishes naturally; frozen v1 still
        // revokes it. A source event never actuates its own mount:
        // the initiating callback is the cache transition. New overlapping
        // callbacks can therefore park from PREPARE onward without creating a
        // repair cycle, and must remain parked through exact COMPLETE ACK.
        admissionState = isLocalInitiator
            ? .awaitingAuthorityAcknowledgement
            : .repairActive
        let exemptOperationID = isLocalInitiator
            ? event.initiator.localOperationID
            : nil
        if let exemptOperationID {
            localInitiatorAwaitingPublication = exemptOperationID
        }
        // Snapshot before waiting: callbacks admitted later are held at the
        // gate and are not this barrier's obligation. The initiating callback
        // must not be waited on — it is waiting for the authority reply that
        // this very barrier gates — and its operation ID was stamped when its
        // mutation request was sent, strictly before the authority could have
        // begun this barrier.
        //
        // The drain waits for bounded local publication after request admission
        // closes. In v2, already-issued ordinary requests in this PREPARE's
        // audience finish and publish naturally; frozen v1/terminal paths
        // revoke them. In either case the framework reply must return before
        // the actuator can safely reuse the same FSKit lane.
        let drain = admitted.values.filter { ticket in
            let intersects = ticket.intersects(repairScope)
            guard intersects else { return false }
            if let exemptOperationID, isLocalInitiator,
               allowsLocalSourcePipelining {
                switch ticket.prepareForLocalSource(
                    initiatingOperationID: exemptOperationID
                ) {
                case .initiatingOperation:
                    return false
                case .parkedPristine, .parkedDistinctOrderedOperation,
                     .parkedOrderedIdentityPending:
                    sourceParkedTickets[ObjectIdentifier(ticket)] = ticket
                    return false
                case .mustRevokeAndDrain:
                    break
                }
            } else if let exemptOperationID,
                      ticket.currentOperationID() == exemptOperationID {
                // Frozen v1 (and profiles without the v2 pipelined contract)
                // retain exact-initiator-only exemption.
                return false
            }
            if allowsLocalSourcePipelining {
                ticket.closeFutureRequestsForNaturalDrain()
            } else {
                ticket.revokeFutureRequests()
            }
            return true
        }
        for ticket in drain {
            try await ticket.waitUntilPublished()
            try Task.checkCancellation()
            if let terminal { throw terminal }
        }
        if signposter.isEnabled {
            signposter.emitEvent(
                "VisibilityPhase",
                "edge=prepare-drained sequence=\(event.sequence) drained=\(drain.count)"
            )
        }
    }

    public func resume(_ event: PfsMacOSCoherenceEvent) async throws {
        if let terminal { throw terminal }
        let completeNow = DispatchTime.now().uptimeNanoseconds
        completeUptimeNanoseconds = completeNow
        if signposter.isEnabled {
            let prepare = prepareUptimeNanoseconds ?? completeNow
            let elapsed = completeNow < prepare ? 0 : (completeNow - prepare) / 1_000
            signposter.emitEvent(
                "VisibilityPhase",
                "edge=complete sequence=\(event.sequence) local=\(event.initiator.sessionID == self.localAuthoritySessionID) prepare_to_complete_us=\(elapsed) repairs=\(event.repairs.count)"
            )
        }
        if event.initiator.sessionID == localAuthoritySessionID,
           let operationID = event.initiator.localOperationID {
            // The deferred source COMPLETE: acknowledged only after the exact
            // initiating callback published its ordinary FSKit reply. If no
            // admitted ticket carries the ID, the callback has already
            // published — a ticket leaves `admitted` only through `published`,
            // and the daemon names only operations it observed on a request.
            if let ticket = admitted.values.first(
                where: { $0.currentOperationID() == operationID }
            ) {
                try await ticket.waitUntilPublished()
                try Task.checkCancellation()
                if let terminal { throw terminal }
            }
            if localInitiatorAwaitingPublication == operationID {
                localInitiatorAwaitingPublication = nil
            }
        }
        // Local repair is complete, so an overlapping callback no longer has
        // to fail in order to release FSKit's actuator lane. It parks until the
        // runner reports that the authority accepted this COMPLETE cursor.
        admissionState = .awaitingAuthorityAcknowledgement
        if signposter.isEnabled {
            signposter.emitEvent(
                "VisibilityPhase",
                "edge=complete-local-finished sequence=\(event.sequence)"
            )
        }
    }

    public func orderedAdmissionContended(
        for event: PfsMacOSCoherenceEvent
    ) async -> Bool {
        guard allowsLocalSourcePipelining,
              event.phase == .complete,
              event.initiator.sessionID != localAuthoritySessionID,
              event.epoch == activeEpoch,
              event.sequence == activeSequence else {
            return false
        }
        return refusedOrderedCallbacks != 0
    }

    public func acknowledged(_ event: PfsMacOSCoherenceEvent) async {
        guard let expectedEpoch = activeEpoch,
              let expectedSequence = activeSequence,
              event.phase == .complete,
              event.epoch == expectedEpoch,
              event.sequence == expectedSequence else {
            return
        }
        let now = DispatchTime.now().uptimeNanoseconds
        let prepare = prepareUptimeNanoseconds ?? now
        let complete = completeUptimeNanoseconds ?? now
        let prepareToComplete = complete < prepare ? 0 : (complete - prepare) / 1_000
        let completeToAck = now < complete ? 0 : (now - complete) / 1_000
        if refusedOrderedCallbacks != 0 || refusedOtherCallbacks != 0 {
            pfsClientLogger.notice(
                "macOS 26 visibility sequence \(event.sequence, privacy: .public) refused \(self.refusedOrderedCallbacks, privacy: .public) ordered and \(self.refusedOtherCallbacks, privacy: .public) other overlapping callbacks before COMPLETE ACK; prepare_to_complete_us=\(prepareToComplete) complete_to_ack_us=\(completeToAck)"
            )
        }
        if signposter.isEnabled {
            signposter.emitEvent(
                "VisibilityPhase",
                "edge=ack-open sequence=\(event.sequence) prepare_to_complete_us=\(prepareToComplete) complete_to_ack_us=\(completeToAck) parked=\(self.sourceParkedTickets.count) waiters=\(self.admissionWaiters.count)"
            )
        }
        admissionState = .open
        closedRepairScope = nil
        activeEpoch = nil
        activeSequence = nil
        prepareUptimeNanoseconds = nil
        completeUptimeNanoseconds = nil
        localInitiatorAwaitingPublication = nil
        let parkedTickets = Array(sourceParkedTickets.values)
        sourceParkedTickets.removeAll()
        for ticket in parkedTickets {
            ticket.releaseSourcePark()
        }

        // Wake parked callbacks only. Each one re-enters `admit`, checks task
        // cancellation, and then mints its ticket. Returning tickets directly
        // here would leak an admitted-but-never-published ticket when ACK races
        // task cancellation.
        let waiters = Array(admissionWaiters.values)
        admissionWaiters.removeAll()
        for waiter in waiters {
            waiter.continuation.resume()
        }
    }

    /// Terminal failure: the coherence session is over. Every waiting and
    /// future admission throws instead of hanging on a gate nobody will ever
    /// reopen; the pfslocal client is closed by the transport on the same
    /// path, so the refusals here are the ordering guarantee, not the only
    /// defense.
    public func fail(_ error: Error) {
        guard terminal == nil else { return }
        terminal = error
        admissionState = .open
        closedRepairScope = nil
        localInitiatorAwaitingPublication = nil
        activeEpoch = nil
        activeSequence = nil
        prepareUptimeNanoseconds = nil
        completeUptimeNanoseconds = nil
        let parkedTickets = Array(sourceParkedTickets.values)
        sourceParkedTickets.removeAll()
        var terminalTickets = admitted
        for ticket in parkedTickets {
            terminalTickets[ObjectIdentifier(ticket)] = ticket
        }
        for ticket in terminalTickets.values {
            ticket.revokeFutureRequests()
        }
        let waiters = Array(admissionWaiters.values)
        admissionWaiters.removeAll()
        for waiter in waiters {
            waiter.continuation.resume(throwing: error)
        }
    }
}

// MARK: - Deferred mount-root actuator

/// A `PfsMacOS26RepairActuator` whose mount-root descriptor arrives after
/// construction. The coherence stack is composed at resolve time, before FSKit
/// has mounted anything; the kernel mount that repairs must be actuated
/// through exists only later. Until a root is installed every apply fails
/// closed — the barrier reports the cursor blocked rather than acknowledging a
/// repair that never touched the kernel.
public final class PfsMacOS26DeferredMountActuator: PfsMacOS26RepairActuator, @unchecked Sendable {
    private let lock = NSLock()
    private var inner: PfsMacOS26POSIXActuator?
    private var locator: (@Sendable () throws -> Int32)?

    public init(locator: (@Sendable () throws -> Int32)? = nil) {
        self.locator = locator
    }

    public var isInstalled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return inner != nil
    }

    /// Installs the attested mount-root descriptor. The descriptor is
    /// duplicated by the POSIX actuator; the caller keeps ownership of `fd`.
    public func installRoot(fileDescriptor: Int32) throws {
        let actuator = try PfsMacOS26POSIXActuator(rootFileDescriptor: fileDescriptor)
        lock.lock()
        if inner == nil {
            inner = actuator
        }
        lock.unlock()
    }

    public func apply(_ plan: PfsMacOS26RepairPlan) async throws {
        let actuator = try resolveActuator()
        try await actuator.apply(plan)
    }

    private func resolveActuator() throws -> PfsMacOS26POSIXActuator {
        lock.lock()
        let installed = inner
        let locate = installed == nil ? locator : nil
        lock.unlock()
        if let installed {
            return installed
        }
        if let locate {
            let fd = try locate()
            defer { close(fd) }
            try installRoot(fileDescriptor: fd)
            lock.lock()
            let resolved = inner
            lock.unlock()
            if let resolved {
                return resolved
            }
        }
        throw PfsMacOSCoherenceError.posix(operation: "locate repair mount root", errno: ENXIO)
    }
}

// MARK: - Composed strict-v3 volume coherence

/// Shared state required by the callback adapter for any strict macOS cache
/// policy. The macOS 26 and macOS 27 backends differ only in how COMPLETE
/// repairs reach the kernel; namespace tracking, live-object ownership,
/// publication admission, capacities, and terminal lifecycle stay common.
public protocol PfsMacOSV3CoherenceContext: AnyObject, Sendable {
    var contract: PfsMacOSV3LocalContract? { get }
    var namespaceIndex: PfsMacOSNamespaceIndex { get }
    var liveObjects: PfsMacOSLiveObjectIndex { get }
    var barrier: PfsMacOSFSKitPublicationBarrier { get }
    var namespaceCapacity: Int { get }
    var liveObjectCapacity: Int { get }

    func shutdown()
}

/// Everything the macOS 26 compatibility cache policy installs into one strict
/// FSKit volume: the namespace and live-object indexes the planner derives
/// repairs from, the callback publication barrier, the repair gate, and the
/// running coherence session. Constructed only when the resolve contract's
/// cache policy names a supported macOS 26 synchronous-VFS repair version —
/// the policy is a
/// declared selection, never an inference.
public final class PfsMacOSV3VolumeCoherence:
    PfsMacOSV3CoherenceContext,
    @unchecked Sendable
{
    /// Default hard bound for exact records. Bindings past the bound fail the
    /// publishing callback closed; records are never dropped by silent LRU,
    /// because a dropped record is a kernel cache entry this mount can no
    /// longer prove absent.
    public static let defaultNamespaceCapacity = 1 << 22
    public static let defaultLiveObjectCapacity = 1 << 20

    public let contract: PfsMacOSV3LocalContract?
    public let namespaceIndex: PfsMacOSNamespaceIndex
    public let liveObjects: PfsMacOSLiveObjectIndex
    public let barrier: PfsMacOSFSKitPublicationBarrier
    public let repairGate: any PfsMacOS26RepairGate
    public let namespaceCapacity: Int
    public let liveObjectCapacity: Int
    let mountActuator: PfsMacOS26DeferredMountActuator?

    private let lock = NSLock()
    private var runnerTask: Task<Void, Never>?
    private var actuatorInstallInFlight = false

    public init(
        contract: PfsMacOSV3LocalContract?,
        namespaceIndex: PfsMacOSNamespaceIndex,
        liveObjects: PfsMacOSLiveObjectIndex,
        barrier: PfsMacOSFSKitPublicationBarrier,
        repairGate: any PfsMacOS26RepairGate,
        mountActuator: PfsMacOS26DeferredMountActuator? = nil,
        namespaceCapacity: Int = PfsMacOSV3VolumeCoherence.defaultNamespaceCapacity,
        liveObjectCapacity: Int = PfsMacOSV3VolumeCoherence.defaultLiveObjectCapacity
    ) {
        self.contract = contract
        self.namespaceIndex = namespaceIndex
        self.liveObjects = liveObjects
        self.barrier = barrier
        self.repairGate = repairGate
        self.mountActuator = mountActuator
        self.namespaceCapacity = namespaceCapacity
        self.liveObjectCapacity = liveObjectCapacity
    }

    func adoptRunnerTask(_ task: Task<Void, Never>) {
        lock.lock()
        runnerTask = task
        lock.unlock()
    }

    /// Attempts to bind the deferred actuator to the live kernel mount.
    /// Triggered from ordinary serving rather than the mount callback because
    /// the kernel's mount-table entry exists only after mounting completes; a
    /// failed attempt retries at the next served callback until the mount
    /// appears. Failure stays loud at repair time, not here: an uninstalled
    /// actuator fails every repair closed.
    func scheduleActuatorInstall(_ locate: @escaping @Sendable () throws -> Int32) {
        lock.lock()
        guard !actuatorInstallInFlight, let mountActuator, !mountActuator.isInstalled else {
            lock.unlock()
            return
        }
        actuatorInstallInFlight = true
        lock.unlock()
        Task.detached { [weak self] in
            defer { self?.finishActuatorInstallAttempt() }
            guard let fd = try? locate() else { return }
            defer { close(fd) }
            try? mountActuator.installRoot(fileDescriptor: fd)
        }
    }

    private nonisolated func finishActuatorInstallAttempt() {
        lock.lock()
        actuatorInstallInFlight = false
        lock.unlock()
    }

    public func shutdown() {
        lock.lock()
        let task = runnerTask
        runnerTask = nil
        lock.unlock()
        task?.cancel()
    }

    /// Composes the full strict-v3 stack for a `VolumeCore` whose resolve
    /// carried the macOS 26 compatibility policy: indexes, transport bound to
    /// the exact resolved UDS connection (one connection, no reconnect,
    /// liveness pulse at one third of the repair budget — all enforced by the
    /// transport itself), arm registry, publication barrier, backend, and the
    /// running coherence session. Throws — with the client already closed by
    /// the caller's fail-closed discipline — when any strict term is invalid.
    static func compose(
        client: PfsLocalClient,
        resolved: PfsResolveReply,
        rootItem: PortableFSItem,
        contract: PfsMacOSV3LocalContract,
        daemonActuation: (socketPath: String, attachRef: String)? = nil
    ) async throws -> PfsMacOSV3VolumeCoherence {
        let rootIdentity = try PfsMacOSStableIdentity(resolved.root.stableIdentity)
        guard rootItem.identity.stableIdentity == rootIdentity.bytes else {
            throw PfsMacOSCoherenceError.invalidVisibilityTarget
        }
        let namespaceIndex = PfsMacOSNamespaceIndex(rootIdentity: rootIdentity)
        let liveObjects = PfsMacOSLiveObjectIndex()
        let rootVFSFileID = try PfsFSKitMapping.itemIdentifier(
            from: rootItem.identity.itemID
        ).rawValue
        guard try await liveObjects.record(
            item: rootItem,
            vfsFileID: rootVFSFileID,
            itemKind: .directory,
            capacity: defaultLiveObjectCapacity
        ) else {
            throw PfsLocalClientError.daemon(
                errno: EIO,
                message: "strict-v3 root live-object index is at capacity"
            )
        }
        let planner = PfsMacOSRepairPlanner(index: namespaceIndex, liveObjects: liveObjects)
        let transport = try await PfsLocalMacOSV3CoherenceTransport.connect(
            client: client,
            resolved: resolved,
            planner: planner
        )

        // The repair secret authenticates only this mount incarnation's own
        // operands to itself; it is minted here and never leaves the process.
        var generator = SystemRandomNumberGenerator()
        var secret = Data(capacity: 32)
        for _ in 0..<4 {
            var word = UInt64.random(in: UInt64.min...UInt64.max, using: &generator)
            withUnsafeBytes(of: &word) { secret.append(contentsOf: $0) }
        }
        let authenticator = try PfsMacOS26RepairAuthenticator(
            mountSessionID: UUID(),
            secret: secret
        )
        let registry = PfsMacOS26RepairArmRegistry(
            authenticator: authenticator,
            namespaceIndex: namespaceIndex
        )
        let barrier = try PfsMacOSFSKitPublicationBarrier(
            localAuthoritySessionID: contract.sessionID,
            policy: contract.cachePolicy
        )
        // The repair syscalls are ISSUED by portablefsd, not this extension:
        // the sandbox forbids the extension write-class VFS operations on its
        // own mount, so the daemon performs the motion and this process
        // authenticates the resulting kernel callbacks through the armed
        // registry. A daemon-backed mount must not also install the unused
        // in-process actuator: that actuator retains a duplicate root vnode
        // for its lifetime and made every otherwise-clean unmount answer
        // EBUSY. When no daemon channel is supplied (offline tests), the
        // in-process deferred actuator remains the backend's actuator.
        let repairActuator: any PfsMacOS26RepairActuator
        let mountActuator: PfsMacOS26DeferredMountActuator?
        if let daemonActuation {
            repairActuator = PfsMacOS26DaemonActuator(
                socketPath: daemonActuation.socketPath,
                attachRef: daemonActuation.attachRef
            )
            mountActuator = nil
        } else {
            let actuator = PfsMacOS26DeferredMountActuator()
            repairActuator = actuator
            mountActuator = actuator
        }
        let backend = try PfsMacOS26CoherenceBackend(
            policy: contract.cachePolicy,
            localAuthoritySessionID: contract.sessionID,
            authenticator: authenticator,
            armer: registry,
            actuator: repairActuator,
            publicationBarrier: barrier
        )
        let runner = try await transport.makeRunner(backend: backend)

        let coherence = PfsMacOSV3VolumeCoherence(
            contract: contract,
            namespaceIndex: namespaceIndex,
            liveObjects: liveObjects,
            barrier: barrier,
            repairGate: registry,
            mountActuator: mountActuator
        )
        coherence.adoptRunnerTask(Task(priority: .userInitiated) {
            do {
                try await runner.run()
            } catch {
                // The runner has already reported the blocked cursor and
                // closed the pfslocal client. Failing the barrier is what
                // stops admission-gated callbacks from hanging on a gate
                // nobody will reopen.
                await barrier.fail(error)
            }
            withExtendedLifetime(transport) {}
        })
        return coherence
    }
}

/// Native FSKit coherence context. Construction prepares the exact authority
/// subscription and runner but deliberately does not start it. The SDK-27
/// adapter must first bind `invalidatorSlot` to the same `FSVolume` instance
/// that it returns to FSKit, then call `start()`. This removes the otherwise
/// unavoidable initialization race between the first visibility event and the
/// kernel cache driver becoming addressable.
public final class PfsMacOSV3NativeVolumeCoherence:
    PfsMacOSV3CoherenceContext,
    @unchecked Sendable
{
    public static let defaultNamespaceCapacity =
        PfsMacOSV3VolumeCoherence.defaultNamespaceCapacity
    public static let defaultLiveObjectCapacity =
        PfsMacOSV3VolumeCoherence.defaultLiveObjectCapacity

    public let contract: PfsMacOSV3LocalContract?
    public let namespaceIndex: PfsMacOSNamespaceIndex
    public let liveObjects: PfsMacOSLiveObjectIndex
    public let barrier: PfsMacOSFSKitPublicationBarrier
    public let namespaceCapacity: Int
    public let liveObjectCapacity: Int
    public let invalidatorSlot: PfsFSKitNativeDataCacheInvalidatorSlot

    private let lock = NSLock()
    private var runner: PfsMacOSCoherenceRunner?
    private var transport: PfsLocalMacOSV3CoherenceTransport?
    private var runnerTask: Task<Void, Never>?

    private init(
        contract: PfsMacOSV3LocalContract,
        namespaceIndex: PfsMacOSNamespaceIndex,
        liveObjects: PfsMacOSLiveObjectIndex,
        barrier: PfsMacOSFSKitPublicationBarrier,
        invalidatorSlot: PfsFSKitNativeDataCacheInvalidatorSlot,
        runner: PfsMacOSCoherenceRunner,
        transport: PfsLocalMacOSV3CoherenceTransport,
        namespaceCapacity: Int,
        liveObjectCapacity: Int
    ) {
        self.contract = contract
        self.namespaceIndex = namespaceIndex
        self.liveObjects = liveObjects
        self.barrier = barrier
        self.invalidatorSlot = invalidatorSlot
        self.runner = runner
        self.transport = transport
        self.namespaceCapacity = namespaceCapacity
        self.liveObjectCapacity = liveObjectCapacity
    }

    public static func prepare(
        client: PfsLocalClient,
        resolved: PfsResolveReply,
        rootItem: PortableFSItem,
        contract: PfsMacOSV3LocalContract,
        namespaceCapacity: Int = defaultNamespaceCapacity,
        liveObjectCapacity: Int = defaultLiveObjectCapacity
    ) async throws -> PfsMacOSV3NativeVolumeCoherence {
        guard contract.cachePolicy == .nativeFSKitRevocationV1 else {
            throw PfsMacOSCoherenceError.unsupportedRepair
        }
        let rootIdentity = try PfsMacOSStableIdentity(
            resolved.root.stableIdentity
        )
        guard rootItem.identity.stableIdentity == rootIdentity.bytes else {
            throw PfsMacOSCoherenceError.invalidVisibilityTarget
        }

        let namespaceIndex = PfsMacOSNamespaceIndex(
            rootIdentity: rootIdentity
        )
        let liveObjects = PfsMacOSLiveObjectIndex()
        let rootVFSFileID = try PfsFSKitMapping.itemIdentifier(
            from: rootItem.identity.itemID
        ).rawValue
        guard try await liveObjects.record(
            item: rootItem,
            vfsFileID: rootVFSFileID,
            itemKind: .directory,
            capacity: liveObjectCapacity
        ) else {
            throw PfsLocalClientError.daemon(
                errno: EIO,
                message: "strict-v3 native root live-object index is at capacity"
            )
        }

        let planner = PfsMacOSRepairPlanner(
            index: namespaceIndex,
            liveObjects: liveObjects
        )
        let transport = try await PfsLocalMacOSV3CoherenceTransport.connect(
            client: client,
            resolved: resolved,
            planner: planner
        )
        let barrier = try PfsMacOSFSKitPublicationBarrier(
            localAuthoritySessionID: contract.sessionID,
            policy: contract.cachePolicy
        )
        let invalidatorSlot = PfsFSKitNativeDataCacheInvalidatorSlot()
        let revoker = PfsFSKitDocumentedNativeCacheRevoker(
            invalidator: invalidatorSlot
        )
        let backend = try PfsNativeFSKitCoherenceBackend(
            localAuthoritySessionID: contract.sessionID,
            revoker: revoker,
            publicationBarrier: barrier
        )
        let runner = try await transport.makeRunner(backend: backend)

        return PfsMacOSV3NativeVolumeCoherence(
            contract: contract,
            namespaceIndex: namespaceIndex,
            liveObjects: liveObjects,
            barrier: barrier,
            invalidatorSlot: invalidatorSlot,
            runner: runner,
            transport: transport,
            namespaceCapacity: namespaceCapacity,
            liveObjectCapacity: liveObjectCapacity
        )
    }

    public func start() throws {
        lock.lock()
        guard runnerTask == nil,
              let runner,
              let transport else {
            lock.unlock()
            throw PfsMacOSCoherenceError.nativeRevocationUnavailable
        }
        self.runner = nil
        self.transport = nil
        let barrier = self.barrier
        let task = Task(priority: .userInitiated) {
            do {
                try await runner.run()
            } catch {
                await barrier.fail(error)
            }
            withExtendedLifetime(transport) {}
        }
        runnerTask = task
        lock.unlock()
    }

    public func shutdown() {
        lock.lock()
        let task = runnerTask
        runnerTask = nil
        runner = nil
        transport = nil
        lock.unlock()
        task?.cancel()
    }
}
