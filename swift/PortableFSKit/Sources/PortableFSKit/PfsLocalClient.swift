import Foundation
import os
@preconcurrency import Darwin

/// Transport-layer diagnostics. Terminal events are logged at the layer that
/// caused them; a closed session connection is the mount's death, and the
/// cause must reach the unified log with the error public.
let pfsClientLogger = Logger(subsystem: "dev.portablefs.fskit", category: "PfsLocalClient")

/// The one event stream of a resolved connection. Buffering is unbounded
/// because the daemon emits only rare attach-state transitions and dropping a
/// terminal one would leave a degraded or detaching mount serving.
private final class PfsEventSink: @unchecked Sendable {
    let stream: AsyncStream<PfsEvent>
    private let lock = NSLock()
    private var continuation: AsyncStream<PfsEvent>.Continuation?

    init() {
        var captured: AsyncStream<PfsEvent>.Continuation?
        stream = AsyncStream(PfsEvent.self, bufferingPolicy: .unbounded) { continuation in
            captured = continuation
        }
        continuation = captured
    }

    func yield(_ event: PfsEvent) {
        lock.lock()
        let continuation = continuation
        lock.unlock()
        continuation?.yield(event)
    }

    func finish() {
        lock.lock()
        let continuation = continuation
        self.continuation = nil
        lock.unlock()
        continuation?.finish()
    }
}

private final class PfsConnection: @unchecked Sendable {
    let id = UUID()
    let socket: PfsAsyncSocket
    let writer: PfsOrderedEnvelopeWriter
    var nextOperationID: UInt64 = 1
    /// The per-request reply bound the daemon announced in HelloReply. It is
    /// a property of the peer, not of this process: a compiled-in constant
    /// could not see the daemon's own budgets and would expire ahead of them.
    /// Zero only while Hello itself is in flight, which the configured
    /// handshake deadline bounds.
    var requestDeadlineNanoseconds: UInt64 = 0

    init(socket: PfsAsyncSocket) {
        self.socket = socket
        self.writer = PfsOrderedEnvelopeWriter { envelope in
            try await socket.write(envelope)
        }
    }
}

final class PfsEnvelopeWriteReceipt: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Void, Error>?
    private var continuations: [CheckedContinuation<Void, Error>] = []

    func wait() async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            lock.lock()
            if let result {
                lock.unlock()
                continuation.resume(with: result)
                return
            }
            continuations.append(continuation)
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
        let continuations = continuations
        self.continuations.removeAll(keepingCapacity: false)
        lock.unlock()
        for continuation in continuations {
            continuation.resume(with: result)
        }
    }
}

private struct PfsQueuedEnvelopeWrite: @unchecked Sendable {
    var envelope: PfsEnvelope
    var receipt: PfsEnvelopeWriteReceipt
}

/// Requests carry nonzero, strictly increasing IDs and stay in one FIFO lane.
/// The publication lane carries only the request-ID-zero PublicationAck and
/// ResourceReplyDisposition frames, which the daemon consumes on its serial
/// reader without request admission.
enum PfsEnvelopeWriteLane {
    case request
    case publication
}

private struct PfsEnvelopeWriteQueue {
    private var storage: [PfsQueuedEnvelopeWrite?] = []
    private var head = 0

    mutating func append(_ write: PfsQueuedEnvelopeWrite) {
        storage.append(write)
    }

    mutating func popFirst() -> PfsQueuedEnvelopeWrite? {
        guard head < storage.count, let write = storage[head] else {
            return nil
        }
        // Release each frame and receipt as soon as it leaves the queue. The
        // backing allocation may remain at its peak capacity, but live
        // payload memory is bounded by the actual backlog.
        storage[head] = nil
        head += 1
        if head == storage.count {
            storage.removeAll(keepingCapacity: true)
            head = 0
        } else if head >= 1024, head * 2 >= storage.count {
            storage.removeFirst(head)
            head = 0
        }
        return write
    }

    mutating func removeAll() -> [PfsQueuedEnvelopeWrite] {
        let pending = storage[head...].compactMap { $0 }
        storage.removeAll(keepingCapacity: false)
        head = 0
        return pending
    }
}

/// One lock-linearized writer owns every frame for a connection. Ordinary
/// requests retain strict FIFO order. Publication acknowledgements use a
/// control lane so a callback can release its daemon holds before a large
/// request burst reaches the daemon's admission bound. The control lane is
/// checked only between complete frame writes, so bytes never interleave.
///
/// A single drain task performs writes and consumed slots release their payload
/// immediately, avoiding both concurrent stream writes and an unbounded
/// dependency/retention chain under sustained load.
final class PfsOrderedEnvelopeWriter: @unchecked Sendable {
    private let write: @Sendable (PfsEnvelope) async throws -> Void
    private let lock = NSLock()
    private var requestQueue = PfsEnvelopeWriteQueue()
    private var publicationQueue = PfsEnvelopeWriteQueue()
    private var draining = false
    private var terminalError: Error?

    init(write: @escaping @Sendable (PfsEnvelope) async throws -> Void) {
        self.write = write
    }

    func enqueue(
        _ envelope: PfsEnvelope,
        lane: PfsEnvelopeWriteLane = .request
    ) -> PfsEnvelopeWriteReceipt {
        let receipt = PfsEnvelopeWriteReceipt()
        var startDrain = false

        lock.lock()
        if let terminalError {
            lock.unlock()
            receipt.resolve(.failure(terminalError))
        } else {
            let queued = PfsQueuedEnvelopeWrite(
                envelope: envelope,
                receipt: receipt
            )
            switch lane {
            case .request:
                requestQueue.append(queued)
            case .publication:
                publicationQueue.append(queued)
            }
            if !draining {
                draining = true
                startDrain = true
            }
            lock.unlock()
        }

        if startDrain {
            Task.detached(priority: .userInitiated) {
                await self.drain()
            }
        }
        return receipt
    }

    func testingFailWrites() {
        let error = PfsLocalClientError.connectionClosed
        for write in terminate(with: error) {
            write.receipt.resolve(.failure(error))
        }
    }

    private func drain() async {
        while true {
            guard let queued = dequeue() else {
                return
            }

            do {
                try await write(queued.envelope)
                queued.receipt.resolve(.success(()))
            } catch {
                let pending = terminate(with: error)
                queued.receipt.resolve(.failure(error))
                for write in pending {
                    write.receipt.resolve(.failure(error))
                }
                return
            }
        }
    }

    private func dequeue() -> PfsQueuedEnvelopeWrite? {
        lock.lock()
        defer { lock.unlock() }
        if let publication = publicationQueue.popFirst() {
            return publication
        }
        if let request = requestQueue.popFirst() {
            return request
        }
        draining = false
        return nil
    }

    private func terminate(with error: Error) -> [PfsQueuedEnvelopeWrite] {
        lock.lock()
        defer { lock.unlock() }
        terminalError = error
        let pending = publicationQueue.removeAll() + requestQueue.removeAll()
        draining = false
        return pending
    }
}

private struct PfsPendingRequest: Sendable {
    var continuation: CheckedContinuation<PfsEnvelope, Error>
    var timeoutTask: Task<Void, Never>?
    var publicationCollector: PfsPublicationCollector?
    var orderedMutation: Bool
    var exactLifecycleOutcome: Bool
    var connectionID: UUID

    /// Once a callback dispatched an authority-ordered mutation, no local
    /// timeout or cancellation may synthesize a retryable outcome for any of
    /// its requests: the authority may already have applied the mutation.
    var requiresExactOutcome: Bool {
        exactLifecycleOutcome
            || orderedMutation
            || publicationCollector?.hasSubmittedOrderedMutation == true
    }
}

private struct PfsPublicationTicket: Sendable {
    var connection: PfsConnection
    var operationID: UInt64
    var semanticCommit: PfsPublicationSemanticCommit
    // The write receipts of every request that carried this operation's ID.
    // The acknowledgement is gated on them: the ack travels the priority
    // publication lane, which dequeues ahead of the request lane, so an ack
    // enqueued while a stamped request is still queued would reach the daemon
    // before the request that creates the operation — a protocol violation
    // the daemon answers by closing the whole connection. A fast
    // cancellation produced exactly that ordering.
    var stampedWrites: [PfsEnvelopeWriteReceipt]
}

private struct PfsResourceReplyTicket: Sendable {
    var connection: PfsConnection
    var targetRequestID: UInt64
    var acceptHandles: Bool
    var itemCount: UInt32
    var acceptedItemCount: UInt32
    var settleLocalItems: (@Sendable (UInt32) async -> Void)?
}

private struct PfsBoundaryTickets: Sendable {
    var publications: [PfsPublicationTicket]
    var resources: [PfsResourceReplyTicket]
}

/// One FSKit callback's publication unit: its lazily allocated operation ID,
/// the provisional resources its replies delivered, and whether it dispatched
/// an ordered mutation. A client has exactly one established connection, so
/// every stamp and verdict of a callback belongs to that connection.
private final class PfsPublicationCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var connection: PfsConnection?
    private var operationID: UInt64?
    private var orderedMutationSubmitted = false
    private var stampedWrites: [PfsEnvelopeWriteReceipt] = []
    private struct ResourceReplyState {
        var connection: PfsConnection
        var targetRequestID: UInt64
        var itemCount: UInt32
        var acceptHandles = false
        var selectedItemCount: UInt32?
        var settleLocalItems: (@Sendable (UInt32) async -> Void)?
    }
    private var resources: [UInt64: ResourceReplyState] = [:]

    /// Binds this callback's operation ID and RECORDS THE ACKNOWLEDGEMENT
    /// OBLIGATION IN THE SAME STEP.
    ///
    /// The daemon creates its logical operation the instant it sees this
    /// operation ID on a request, and from that moment only a PublicationAck
    /// for that ID can retire it. The obligation is therefore incurred when
    /// the ID is stamped, not when a reply comes back: an operation whose
    /// reply was never observed (cancelled, timed out, or never delivered)
    /// would otherwise stay pinned in the daemon's publication set forever,
    /// holding its source coordinates and refusing clean unmount on a healthy
    /// connection. Acknowledging such an operation is the stronger statement:
    /// a reply that was never observed installed nothing.
    func bind(
        to connection: PfsConnection,
        allocating candidate: UInt64
    ) -> (id: UInt64, isNew: Bool) {
        lock.lock()
        defer { lock.unlock() }
        if let operationID {
            return (operationID, false)
        }
        self.connection = connection
        operationID = candidate
        return (candidate, true)
    }

    /// The operation ID a nonpublishing continuation of this callback must
    /// carry, if a publishing request already allocated one.
    var existingOperationID: UInt64? {
        lock.lock()
        defer { lock.unlock() }
        return operationID
    }

    func noteOrderedMutation() {
        lock.lock()
        orderedMutationSubmitted = true
        lock.unlock()
    }

    var hasSubmittedOrderedMutation: Bool {
        lock.lock()
        defer { lock.unlock() }
        return orderedMutationSubmitted
    }

    /// Records the ownership obligation at the same point the resource-bearing
    /// reply is accepted for delivery. Socket delivery is not ownership: the
    /// callback may still be canceled or rejected at its final framework
    /// publication boundary, so the daemon keeps the handle provisional until
    /// `completeBoundary` sends exactly one disposition.
    func appendResourceReply(
        connection: PfsConnection,
        targetRequestID: UInt64,
        itemIDs: [UInt64]
    ) {
        lock.lock()
        resources[targetRequestID] = ResourceReplyState(
            connection: connection,
            targetRequestID: targetRequestID,
            itemCount: UInt32(clamping: itemIDs.count)
        )
        lock.unlock()
    }

    func acceptResourceReply(targetRequestID: UInt64) {
        lock.lock()
        if var resource = resources[targetRequestID] {
            resource.acceptHandles = true
            resources[targetRequestID] = resource
        }
        lock.unlock()
    }

    func acceptResourceItemPrefix(targetRequestID: UInt64, count: UInt32) {
        lock.lock()
        if var resource = resources[targetRequestID] {
            resource.selectedItemCount = min(count, resource.itemCount)
            resources[targetRequestID] = resource
        }
        lock.unlock()
    }

    func registerLocalItemSettlement(
        targetRequestID: UInt64,
        settle: @escaping @Sendable (UInt32) async -> Void
    ) {
        lock.lock()
        if var resource = resources[targetRequestID] {
            resource.settleLocalItems = settle
            resources[targetRequestID] = resource
        }
        lock.unlock()
    }

    func snapshot(itemsPublished: Bool) -> PfsBoundaryTickets {
        lock.lock()
        var publications: [PfsPublicationTicket] = []
        if let operationID, let connection {
            publications.append(PfsPublicationTicket(
                connection: connection,
                operationID: operationID,
                semanticCommit: itemsPublished ? .published : .notPublished,
                stampedWrites: stampedWrites
            ))
        }
        let resources = resources.values.map { resource in
            let acceptedItemCount = itemsPublished
                ? (resource.selectedItemCount ?? resource.itemCount)
                : 0
            return PfsResourceReplyTicket(
                connection: resource.connection,
                targetRequestID: resource.targetRequestID,
                acceptHandles: resource.acceptHandles,
                itemCount: resource.itemCount,
                acceptedItemCount: acceptedItemCount,
                settleLocalItems: resource.settleLocalItems
            )
        }
        lock.unlock()
        return PfsBoundaryTickets(
            publications: publications,
            resources: resources
        )
    }

    /// Records the write receipt of a request stamped with this operation's
    /// ID. The acknowledgement must not be enqueued until every stamped
    /// request's frame has left the writer; see `PfsPublicationTicket`.
    func noteStampedWrite(_ receipt: PfsEnvelopeWriteReceipt) {
        lock.lock()
        stampedWrites.append(receipt)
        lock.unlock()
    }
}

private enum PfsPublicationContext {
    @TaskLocal static var collector: PfsPublicationCollector?
}

struct PfsResourceReplyLease: @unchecked Sendable {
    let envelope: PfsEnvelope
    private let collector: PfsPublicationCollector
    private let completion: PfsOneShotResourceCompletion?

    fileprivate init(
        envelope: PfsEnvelope,
        collector: PfsPublicationCollector,
        completion: (@Sendable (Bool) async -> Void)?
    ) {
        self.envelope = envelope
        self.collector = collector
        self.completion = completion.map(PfsOneShotResourceCompletion.init)
    }

    func acceptHandles() {
        collector.acceptResourceReply(targetRequestID: envelope.requestID)
    }

    func registerItemSettlement(
        _ settle: @escaping @Sendable (UInt32) async -> Void
    ) {
        collector.registerLocalItemSettlement(
            targetRequestID: envelope.requestID,
            settle: settle
        )
    }

    func complete(itemsPublished: Bool) async {
        guard let operation = completion?.take() else { return }
        await operation(itemsPublished)
    }
}

/// A resource lease is a value so it can move across actor boundaries, but its
/// settlement is not a value operation: the wire contract permits exactly one
/// disposition for a successful resource-bearing reply. Copies therefore share
/// this lock-backed once token. An accidental second completion is a no-op
/// instead of emitting a duplicate disposition that would correctly terminate
/// the daemon connection.
private final class PfsOneShotResourceCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var operation: (@Sendable (Bool) async -> Void)?

    init(_ operation: @escaping @Sendable (Bool) async -> Void) {
        self.operation = operation
    }

    func take() -> (@Sendable (Bool) async -> Void)? {
        lock.lock()
        let operation = self.operation
        self.operation = nil
        lock.unlock()
        return operation
    }
}

/// Returns nil for an ordinary reply and the provisional item IDs for a
/// resource-bearing reply. Open has no item ID but still returns an empty list:
/// its daemon handle needs a final disposition. Metadata-only enumeration
/// transfers no resources.
private func pfsReplyResourceItemIDs(
    _ body: PfsEnvelope.OneOf_Body?
) -> [UInt64]? {
    switch body {
    case .openReply:
        return []
    case let .createReply(reply):
        return [reply.attr.item.itemID]
    case let .lookupReply(reply):
        return [reply.attr.item.itemID]
    case let .mkdirReply(reply):
        return [reply.attr.item.itemID]
    case let .symlinkReply(reply):
        return [reply.attr.item.itemID]
    default:
        return nil
    }
}

/// Whether this successful resource-bearing reply actually conveyed a daemon
/// handle. Item ownership is independent: Lookup/Mkdir/Symlink never
/// carry handles, and a malformed zero-handle Open/Create must never make the
/// raw request API send `accept_handles = true`.
private func pfsReplyHasHandle(_ body: PfsEnvelope.OneOf_Body?) -> Bool {
    switch body {
    case let .openReply(reply):
        return reply.handle != 0
    case let .createReply(reply):
        return reply.handle != 0
    default:
        return false
    }
}

/// Exactly the pfslocal replies that can publish namespace, metadata, xattr,
/// or content state into a frontend cache. Operation IDs are allocated only
/// for these requests. Nonpublishing requests use ID zero, so an open/statfs
/// request at the start of a callback cannot consume an ID before the first
/// cache publication that the daemon needs to gate.
private func pfsRequestPublishes(
    _ body: PfsEnvelope.OneOf_Body
) -> Bool {
    switch body {
    case .lookup, .enumerateEntries, .getAttr, .setAttr, .read, .write,
         .create, .mkdir, .remove, .rename, .symlink, .readlink,
         .hardLink, .xattrGet, .xattrList, .xattrRemove:
        return true
    default:
        return false
    }
}

/// The requests that can apply an authority mutation. Once one is dispatched
/// its exact outcome is state: a local timeout or cancellation cannot prove
/// whether the authority applied it.
func pfsRequestIsOrderedMutation(
    _ body: PfsEnvelope.OneOf_Body
) -> Bool {
    switch body {
    case .setAttr, .write, .create, .mkdir, .remove, .rename,
         .symlink, .hardLink, .xattrRemove:
        return true
    default:
        return false
    }
}

/// Lifecycle retirements apply no mutation, but their exact reply is
/// still state: dropping a successful Close/Reclaim response leaves VolumeCore
/// believing it owns a resource the daemon already retired. Once dispatched,
/// caller cancellation must therefore wait for the daemon's idempotent verdict.
private func pfsRequestRequiresExactLifecycleOutcome(
    _ body: PfsEnvelope.OneOf_Body
) -> Bool {
    switch body {
    case .close, .reclaim:
        return true
    default:
        return false
    }
}

/// Only the transport can distinguish a rejected pre-dispatch request from a
/// failed Reclaim whose daemon ownership may already have been retired.
struct PfsDispatchedReclaimError: Error {
    let cause: Error
}

/// Async pfslocal client for length-prefixed protobuf over a Unix domain socket.
///
/// One client is one pfslocal session: exactly one connection that completes
/// one Hello and then one Resolve, which binds it permanently to one attach
/// incarnation. Requests are multiplexed over that stream with strictly
/// increasing request IDs and replies may arrive out of order. Only the
/// initial connection may be retried, and only for failures to reach the
/// peer; once Hello has succeeded, loss of the connection is terminal for the
/// client. A bound frontend never reconnects or re-resolves into a successor
/// session, so no request, publication or event can migrate across
/// connections.
public actor PfsLocalClient {
    public static let protocolMajor: UInt32 = 2
    public static let protocolMinor: UInt32 = 0

    public struct Configuration: Sendable {
        public var maxFrameLength: Int
        /// Attempts to reach the daemon socket before the session exists.
        public var maxConnectAttempts: Int
        public var connectRetryBaseDelayNanoseconds: UInt64
        public var connectRetryMaxDelayNanoseconds: UInt64
        /// Bounds the Hello exchange only. Every later request uses the
        /// deadline the daemon announces in HelloReply.
        public var handshakeDeadlineNanoseconds: UInt64
        /// Connection role label. It authenticates nothing; the daemon uses
        /// it only to tell the shipping frontend from control self-probes.
        public var clientName: String
        public var clientVersion: String

        public init(
            maxFrameLength: Int = PfsFrameCodec.defaultMaxFrameLength,
            maxConnectAttempts: Int = 5,
            connectRetryBaseDelayNanoseconds: UInt64 = 50_000_000,
            connectRetryMaxDelayNanoseconds: UInt64 = 1_000_000_000,
            handshakeDeadlineNanoseconds: UInt64 = 60_000_000_000,
            clientName: String = "portablefskit",
            clientVersion: String = "1"
        ) {
            self.maxFrameLength = maxFrameLength
            self.maxConnectAttempts = maxConnectAttempts
            self.connectRetryBaseDelayNanoseconds = connectRetryBaseDelayNanoseconds
            self.connectRetryMaxDelayNanoseconds = connectRetryMaxDelayNanoseconds
            self.handshakeDeadlineNanoseconds = handshakeDeadlineNanoseconds
            self.clientName = clientName
            self.clientVersion = clientVersion
        }
    }

    private let socketPathProvider: @Sendable () async throws -> String
    private let configuration: Configuration
    /// The first protocol defect any connection reported. A peer that sent
    /// one malformed frame is not trusted again, even before Hello completed.
    private var protocolDefect: PfsLocalClientError?
    private var connection: PfsConnection?
    private var connectingTask: Task<Void, Error>?
    /// True once Hello succeeded on `connection`. It is never reset: losing
    /// an established connection ends the session.
    private var sessionEstablished = false
    private var resolved = false
    private var eventSink: PfsEventSink?
    private var pending: [UInt64: PfsPendingRequest] = [:]
    private var nextRequestID: UInt64 = 1
    private var isShutdown = false
    private var attachIsDetaching = false
    private var beforeNextResourceSettlement: (@Sendable () async -> Void)?

    /// Only terminal session state permits frontend-only ownership retirement.
    var isDetachingOrStopped: Bool {
        attachIsDetaching || isShutdown || isSessionLost
    }

    private var isSessionLost: Bool {
        sessionEstablished && connection == nil
    }

    public nonisolated var hasActivePublicationBoundary: Bool {
        PfsPublicationContext.collector != nil
    }

    public init(socketPath: String, configuration: Configuration = Configuration()) {
        self.socketPathProvider = { socketPath }
        self.configuration = configuration
    }

    public init(
        socketPathProvider: @escaping @Sendable () async throws -> String,
        configuration: Configuration = Configuration()
    ) {
        self.socketPathProvider = socketPathProvider
        self.configuration = configuration
    }

    deinit {
        connection?.socket.close()
        eventSink?.finish()
    }

    /// Sends a raw pfslocal request body and returns the matching reply envelope.
    public func request(_ body: PfsEnvelope.OneOf_Body) async throws -> PfsEnvelope {
        try Task.checkCancellation()
        try await ensureBound()
        if let collector = PfsPublicationContext.collector {
            let envelope = try await sendRequestOnCurrentConnection(body)
            if let itemIDs = pfsReplyResourceItemIDs(envelope.body) {
                // The raw API transfers ownership at envelope return even when
                // a surrounding framework boundary defers the wire verdict.
                // Typed VolumeCore paths use requestResource and mark their
                // later actor/framework installation explicitly instead.
                if pfsReplyHasHandle(envelope.body) {
                    collector.acceptResourceReply(
                        targetRequestID: envelope.requestID
                    )
                }
                collector.acceptResourceItemPrefix(
                    targetRequestID: envelope.requestID,
                    count: UInt32(clamping: itemIDs.count)
                )
            }
            return envelope
        }
        let collector = PfsPublicationCollector()
        let outcome: Result<PfsEnvelope, Error> = await PfsPublicationContext
            .$collector.withValue(collector) {
                do {
                    return .success(try await self.sendRequestOnCurrentConnection(body))
                } catch {
                    // Cacheable negative replies are publications too. Their
                    // operation ID was bound when the request was stamped, so
                    // the settlement below acknowledges it either way.
                    return .failure(error)
                }
            }
        if case let .success(envelope) = outcome,
           let itemIDs = pfsReplyResourceItemIDs(envelope.body) {
            // The raw request API hands the resource-bearing envelope to its
            // caller as the value itself, so returning it is the local
            // ownership install boundary.
            if pfsReplyHasHandle(envelope.body) {
                collector.acceptResourceReply(targetRequestID: envelope.requestID)
            }
            collector.acceptResourceItemPrefix(
                targetRequestID: envelope.requestID,
                count: UInt32(clamping: itemIDs.count)
            )
        }
        await completeBoundary(collector.snapshot(itemsPublished: true))
        return try outcome.get()
    }

    /// Typed resource-bearing request whose ownership boundary extends through
    /// the caller's actor-state installation. When an outer FSKit publication
    /// boundary exists, the returned lease contributes to it. Direct
    /// `VolumeCore` callers receive a standalone lease and must complete it
    /// after mapping/install succeeds or fails.
    func requestResource(
        _ body: PfsEnvelope.OneOf_Body
    ) async throws -> PfsResourceReplyLease {
        try Task.checkCancellation()
        try await ensureBound()
        if let collector = PfsPublicationContext.collector {
            let envelope = try await sendRequestOnCurrentConnection(body)
            return PfsResourceReplyLease(
                envelope: envelope,
                collector: collector,
                completion: nil
            )
        }

        let collector = PfsPublicationCollector()
        let outcome: Result<PfsEnvelope, Error> = await PfsPublicationContext
            .$collector.withValue(collector) {
                do {
                    return .success(
                        try await self.sendRequestOnCurrentConnection(body)
                    )
                } catch {
                    return .failure(error)
                }
            }
        let envelope: PfsEnvelope
        do {
            envelope = try outcome.get()
        } catch {
            await completeBoundary(
                collector.snapshot(itemsPublished: false)
            )
            throw error
        }
        return PfsResourceReplyLease(
            envelope: envelope,
            collector: collector,
            completion: { itemsPublished in
                await self.completeBoundary(
                    collector.snapshot(itemsPublished: itemsPublished)
                )
            }
        )
    }

    /// Extends every request issued by operation through the point where the
    /// FSKit adapter has copied/installed the returned values. The daemon
    /// keeps the operation's source-publication holds until this one-way
    /// acknowledgement and its semantic-commit verdict arrive.
    public nonisolated func withPublicationBoundary<T>(
        _ operation: () async throws -> T
    ) async throws -> T {
        if PfsPublicationContext.collector != nil {
            return try await operation()
        }
        let (result, complete) = await withDeferredPublication(operation)
        if case .success = result {
            await complete(true)
        } else {
            await complete(false)
        }
        return try result.get()
    }

    /// Collects the requests issued by `operation` without acknowledging
    /// them. Callback-based FSKit witnesses invoke the returned completion
    /// only after their reply handler returns, providing a real framework
    /// publication boundary rather than an approximation before an async
    /// method return.
    ///
    /// The operation runs exactly once. A daemon never withdraws a reply it
    /// has sent, so no outcome here is an instruction to reissue it.
    public nonisolated func withDeferredPublication<T>(
        _ operation: () async throws -> T
    ) async -> (Result<T, Error>, @Sendable (Bool) async -> Void) {
        let collector = PfsPublicationCollector()
        let outcome: Result<T, Error> = await PfsPublicationContext.$collector
            .withValue(collector) {
                do {
                    return .success(try await operation())
                } catch {
                    return .failure(error)
                }
            }
        return (outcome, { itemsPublished in
            await self.completeBoundary(
                collector.snapshot(itemsPublished: itemsPublished)
            )
        })
    }

    /// Binds this session to one attach. A connection resolves exactly once;
    /// a refused Resolve leaves it unbound and may be retried.
    @discardableResult
    public func resolve(attachRef: String) async throws -> PfsResolveReply {
        try Task.checkCancellation()
        try await ensureConnected()
        guard !resolved else {
            throw PfsLocalClientError.unexpectedReply(
                "resolve: this connection is already bound to an attach"
            )
        }
        var request = PfsResolveRequest()
        request.attachRef = attachRef
        let envelope = try await sendRequestOnCurrentConnection(.resolve(request))
        guard case let .resolveReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        resolved = true
        return reply
    }

    /// Binds this resolved connection's event stream. The binding is the
    /// daemon's evidence that this frontend observes its attach state; the
    /// stream finishes exactly when the connection closes, so its end is the
    /// frontend's single terminal signal. A failed subscription is terminal:
    /// a connection that cannot receive attach state must not keep serving.
    public func subscribeEvents() async throws -> AsyncStream<PfsEvent> {
        try Task.checkCancellation()
        try await ensureBound()
        guard eventSink == nil, let connection else {
            throw PfsLocalClientError.unexpectedReply(
                "subscribe: this connection already has its event binding"
            )
        }
        // Install the sink before SubscribeEvents can expose the first event.
        let sink = PfsEventSink()
        eventSink = sink
        do {
            let envelope = try await sendRequestOnCurrentConnection(
                .subscribeEvents(PfsSubscribeEventsRequest())
            )
            guard case .subscribeEventsReply? = envelope.body else {
                throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
            }
            return sink.stream
        } catch {
            closeCurrentConnection(connection.id, error: error)
            throw error
        }
    }

    /// Closes the session and fails all in-flight requests.
    public func close() {
        guard !isShutdown else {
            return
        }
        isShutdown = true
        connectingTask?.cancel()
        connectingTask = nil
        connection?.socket.close()
        connection = nil
        failAllPending(with: PfsLocalClientError.shutdown)
        eventSink?.finish()
    }

    private func ensureBound() async throws {
        try await ensureConnected()
        guard resolved else {
            throw PfsLocalClientError.unresolved
        }
    }

    private func ensureConnected() async throws {
        if attachIsDetaching {
            throw PfsLocalClientError.daemon(errno: ENXIO, message: "attach is detaching")
        }
        if isShutdown {
            throw PfsLocalClientError.shutdown
        }
        if let protocolDefect {
            throw protocolDefect
        }
        if sessionEstablished {
            guard connection != nil else {
                throw PfsLocalClientError.connectionClosed
            }
            return
        }
        if let task = connectingTask {
            try await task.value
            return
        }

        let task = Task { try await self.establishConnectionWithBackoff() }
        connectingTask = task
        do {
            try await task.value
            connectingTask = nil
        } catch {
            connectingTask = nil
            throw error
        }
    }

    private func establishConnectionWithBackoff() async throws {
        var delay = configuration.connectRetryBaseDelayNanoseconds
        var lastError: Error = PfsLocalClientError.connectionClosed

        for attempt in 0..<max(1, configuration.maxConnectAttempts) {
            if isShutdown {
                throw PfsLocalClientError.shutdown
            }
            do {
                try await establishConnectionOnce()
                return
            } catch {
                lastError = error
                if attempt + 1 >= max(1, configuration.maxConnectAttempts)
                    || !Self.isConnectionFailure(error) {
                    break
                }
                try await Task.sleep(nanoseconds: delay)
                delay = min(configuration.connectRetryMaxDelayNanoseconds, delay * 2)
            }
        }

        throw lastError
    }

    /// Only a failure to reach or keep the peer is worth another connection.
    /// A protocol defect, a daemon error reply, or a version mismatch would
    /// repeat, and retrying it would hide the peer's actual answer.
    private static func isConnectionFailure(_ error: Error) -> Bool {
        switch error as? PfsLocalClientError {
        case .system?, .connectionClosed?:
            return true
        default:
            return false
        }
    }

    private func establishConnectionOnce() async throws {
        let path = try await socketPathProvider()
        let socket = try await PfsAsyncSocket.connect(path: path, maxFrameLength: configuration.maxFrameLength)
        let newConnection = PfsConnection(socket: socket)
        connection = newConnection
        startReader(for: newConnection)

        do {
            try await helloOnCurrentConnection()
        } catch {
            closeCurrentConnection(newConnection.id, error: error)
            throw error
        }
        guard connection?.id == newConnection.id else {
            throw PfsLocalClientError.connectionClosed
        }
        sessionEstablished = true
    }

    private func startReader(for connection: PfsConnection) {
        let connectionID = connection.id
        connection.socket.startReading { [weak self] envelope in
            Task(priority: .userInitiated) {
                await self?.receive(envelope, from: connectionID)
            }
        } onClose: { [weak self] error in
            Task(priority: .userInitiated) {
                await self?.connectionDidClose(connectionID, error: error)
            }
        }
    }

    private func receive(_ envelope: PfsEnvelope, from connectionID: UUID) {
        guard connection?.id == connectionID else {
            return
        }

        if envelope.requestID == 0 {
            // Request-ID-zero daemon frames are Events, and only after this
            // connection subscribed. Anything else is a frame defect.
            guard case let .event(event)? = envelope.body, let eventSink else {
                closeCurrentConnection(
                    connectionID,
                    error: PfsLocalClientError.invalidFrame(
                        "request-ID-zero frame is not a subscribed event"
                    )
                )
                return
            }
            if case let .attachState(state)? = event.kind, state.state == .detaching {
                attachIsDetaching = true
            }
            eventSink.yield(event)
            return
        }

        guard let request = pending.removeValue(forKey: envelope.requestID) else {
            // Cancellation/timeout won the client actor race, but a successful
            // resource-bearing reply still arrived. Its daemon-side resource
            // is provisional and has no possible VolumeCore owner, so retire
            // it explicitly on this same connection instead of silently
            // dropping the frame and leaking capacity.
            if pfsReplyResourceItemIDs(envelope.body) != nil, let connection {
                let ticket = PfsResourceReplyTicket(
                    connection: connection,
                    targetRequestID: envelope.requestID,
                    acceptHandles: false,
                    itemCount: UInt32(clamping:
                        pfsReplyResourceItemIDs(envelope.body)?.count ?? 0
                    ),
                    acceptedItemCount: 0,
                    settleLocalItems: nil
                )
                Task {
                    await self.completeResources([ticket])
                }
            }
            return
        }
        request.timeoutTask?.cancel()
        if let itemIDs = pfsReplyResourceItemIDs(envelope.body), let connection {
            request.publicationCollector?.appendResourceReply(
                connection: connection,
                targetRequestID: envelope.requestID,
                itemIDs: itemIDs
            )
        }

        if case let .error(error)? = envelope.body {
            request.continuation.resume(throwing: PfsLocalClientError.daemon(errno: error.errno, message: error.message))
        } else {
            request.continuation.resume(returning: envelope)
        }
    }

    private func connectionDidClose(_ connectionID: UUID, error: Error) {
        guard connection?.id == connectionID else {
            return
        }
        closeCurrentConnection(connectionID, error: error)
    }

    private func closeCurrentConnection(_ connectionID: UUID, error: Error) {
        guard connection?.id == connectionID else {
            return
        }
        // The one place every connection teardown passes through. Once the
        // session is established this close ends it, so the cause is logged
        // here, where it is always known.
        pfsClientLogger.error(
            "pfslocal connection closed: \(String(describing: error), privacy: .public); established=\(self.sessionEstablished) pending=\(self.pending.count)"
        )
        if protocolDefect == nil,
           let defect = error as? PfsLocalClientError,
           defect.isProtocolDefect {
            protocolDefect = defect
        }
        let socket = connection?.socket
        connection = nil
        socket?.close()
        eventSink?.finish()
        failAllPending(with: error)
    }

    private func failAllPending(with error: Error) {
        let requests = pending.values
        pending.removeAll()
        for request in requests {
            request.timeoutTask?.cancel()
            request.continuation.resume(throwing: error)
        }
    }

    private func helloOnCurrentConnection() async throws {
        var hello = PfsHello()
        hello.protocolMajor = Self.protocolMajor
        hello.protocolMinor = Self.protocolMinor
        hello.clientName = configuration.clientName
        hello.clientVersion = configuration.clientVersion

        let envelope = try await sendRequestOnCurrentConnection(.hello(hello))
        guard case let .helloReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        // The daemon, extension and CLI are one sealed release: the private
        // interface is equal in both numbers or it is a different contract.
        guard reply.protocolMajor == Self.protocolMajor,
              reply.protocolMinor == Self.protocolMinor else {
            throw PfsLocalClientError.protocolMismatch(major: reply.protocolMajor, minor: reply.protocolMinor)
        }
        // The daemon owns the per-request bound. A zero bound has no meaning;
        // there is no local default to fall back to.
        guard reply.requestDeadlineMs > 0 else {
            throw PfsLocalClientError.invalidFrame("HelloReply omitted its required request deadline")
        }
        connection?.requestDeadlineNanoseconds = UInt64(reply.requestDeadlineMs) * 1_000_000
    }

    private func sendRequestOnCurrentConnection(
        _ body: PfsEnvelope.OneOf_Body
    ) async throws -> PfsEnvelope {
        if isShutdown {
            throw PfsLocalClientError.shutdown
        }
        guard let connection else {
            throw PfsLocalClientError.connectionClosed
        }
        let collector = PfsPublicationContext.collector
        let orderedMutation = pfsRequestIsOrderedMutation(body)
        let exactLifecycleOutcome = pfsRequestRequiresExactLifecycleOutcome(body)
        // Cancellation before dispatch is definite and may be surfaced. Once
        // the frame is enqueued, cancellation is only a request by the caller
        // to stop waiting; it cannot change the mutation's authority outcome.
        if orderedMutation, Task.isCancelled {
            throw PfsLocalClientError.cancelled
        }
        if orderedMutation {
            collector?.noteOrderedMutation()
        }
        var operationID: UInt64 = 0
        if let collector {
            if pfsRequestPublishes(body) {
                let binding = collector.bind(
                    to: connection,
                    allocating: connection.nextOperationID
                )
                operationID = binding.id
                if binding.isNew {
                    guard connection.nextOperationID != UInt64.max else {
                        closeCurrentConnection(
                            connection.id,
                            error: PfsLocalClientError.system(
                                errno: EOVERFLOW,
                                operation: "allocate publication operation ID"
                            )
                        )
                        throw PfsLocalClientError.connectionClosed
                    }
                    connection.nextOperationID += 1
                }
            } else if let existing = collector.existingOperationID {
                // Once a callback has published cacheable state, all later
                // requests in that same callback share its completion gate,
                // even if an individual request (for example close) does not
                // itself publish cache state. Before that, a nonpublishing
                // request carries zero: operation IDs are allocated lazily.
                operationID = existing
            }
        }

        let requestID = nextRequestID
        nextRequestID += 1

        var envelope = PfsEnvelope()
        envelope.requestID = requestID
        envelope.operationID = operationID
        envelope.body = body

        let deadline = connection.requestDeadlineNanoseconds == 0
            ? configuration.handshakeDeadlineNanoseconds
            : connection.requestDeadlineNanoseconds

        let replyEnvelope: PfsEnvelope
        do {
            replyEnvelope = try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    let timeoutTask = Task.detached { [requestID, deadline] in
                        do {
                            try await Task.sleep(nanoseconds: deadline)
                            await self.timeoutRequest(requestID)
                        } catch {}
                    }
                    pending[requestID] = PfsPendingRequest(
                        continuation: continuation,
                        timeoutTask: timeoutTask,
                        publicationCollector: collector,
                        orderedMutation: orderedMutation,
                        exactLifecycleOutcome: exactLifecycleOutcome,
                        connectionID: connection.id
                    )
                    // The write is NOT skipped for an already-cancelled task. A
                    // publishing request may have just stamped a fresh operation
                    // ID into the collector, and the boundary will acknowledge
                    // that ID when the callback ends; an acknowledgement for an
                    // operation the daemon never saw on a request is a protocol
                    // violation that costs the whole connection. Writing
                    // unconditionally keeps the stamp and the daemon's view
                    // identical; the caller's cancellation is delivered by
                    // `onCancel` either way.
                    let writeReceipt = connection.writer.enqueue(envelope, lane: .request)
                    if operationID != 0 {
                        // The operation's acknowledgement is gated on this frame
                        // having left the writer; see PfsPublicationTicket.
                        collector?.noteStampedWrite(writeReceipt)
                    }
                    Task.detached { [connectionID = connection.id, writeReceipt] in
                        do {
                            try await writeReceipt.wait()
                        } catch {
                            await self.writeFailed(requestID, connectionID: connectionID, error: error)
                        }
                    }
                }
            } onCancel: {
                Task {
                    await self.cancelRequest(requestID, error: .cancelled)
                }
            }
        } catch {
            if case .reclaim = body { throw PfsDispatchedReclaimError(cause: error) }
            throw error
        }
        return replyEnvelope
    }

    /// Settles resource ownership before releasing publication gates. The
    /// daemon may admit an overlapping peer as soon as PublicationAck is
    /// observed, so accepting/retiring every provisional resource first keeps
    /// capacity and ownership in the same callback order as kernel visibility.
    private nonisolated func completeBoundary(
        _ tickets: PfsBoundaryTickets
    ) async {
        await completeResources(tickets.resources)
        await completePublications(tickets.publications)
    }

    private nonisolated func completeResources(
        _ tickets: [PfsResourceReplyTicket]
    ) async {
        for (index, ticket) in tickets.enumerated() {
            var disposition = PfsResourceReplyDisposition()
            disposition.targetRequestID = ticket.targetRequestID
            disposition.acceptHandles = ticket.acceptHandles
            disposition.acceptedItemCount = ticket.acceptedItemCount
            var envelope = PfsEnvelope()
            envelope.requestID = 0
            envelope.body = .resourceReplyDisposition(disposition)
            let writeReceipt = ticket.connection.writer.enqueue(
                envelope,
                lane: .publication
            )
            do {
                try await writeReceipt.wait()
                // Reclaim may resume from this settlement. Its request must be
                // ordered after the ownership disposition on the same writer.
                await beforeResourceSettlement()
                await ticket.settleLocalItems?(ticket.acceptedItemCount)
            } catch {
                // A disposition belongs to the connection that delivered the
                // provisional resource. Retire that connection and let daemon
                // disconnect cleanup own the result.
                await closeResourceConnection(ticket.connection.id, error: error)
                for unsettled in tickets[index...] {
                    await unsettled.settleLocalItems?(0)
                }
                return
            }
        }
    }

    private func closeResourceConnection(_ connectionID: UUID, error: Error) {
        closeCurrentConnection(connectionID, error: error)
    }

    private nonisolated func completePublications(_ tickets: [PfsPublicationTicket]) async {
        for ticket in tickets {
            // Every stamped request frame must have left the writer before the
            // acknowledgement is enqueued: the ack's priority lane would
            // otherwise overtake a still-queued request, and the daemon
            // rightly kills a connection that acknowledges an operation it
            // has never been shown. A failed write resolves its receipt too —
            // the connection is already closed then, and the ack enqueue
            // below surfaces that through the existing terminal path.
            for receipt in ticket.stampedWrites {
                try? await receipt.wait()
            }
            var ack = PfsPublicationAck()
            ack.operationID = ticket.operationID
            ack.semanticCommit = ticket.semanticCommit
            var envelope = PfsEnvelope()
            envelope.requestID = 0
            envelope.body = .publicationAck(ack)
            let writeReceipt = ticket.connection.writer.enqueue(
                envelope,
                lane: .publication
            )
            do {
                try await writeReceipt.wait()
            } catch {
                // A ticket is bound to the connection that exposed its reply.
                // Closing that connection ends the session; the daemon then
                // owns the exposed-but-unacknowledged result in its terminal
                // drain.
                await closePublicationConnection(
                    ticket.connection.id,
                    error: error
                )
                return
            }
        }
    }

    private func closePublicationConnection(_ connectionID: UUID, error: Error) {
        closeCurrentConnection(connectionID, error: error)
    }

    /// Fails one read-only request whose reply never arrived. A dispatched
    /// ordered mutation or lifecycle retirement is different: no local timeout
    /// can prove whether the authority applied or retired it, so losing its
    /// exact reply ends the session instead of inventing a retryable
    /// per-request outcome.
    ///
    /// A read-only timeout deliberately does not close the connection: that
    /// would strand every other in-flight operation's publication and turn
    /// one wedged request into a whole-mount failure. A late reply is already
    /// handled: `receive` finds no pending entry and drops the frame (retiring
    /// any provisional resource it carried), while the operation itself is
    /// acknowledged as a whole from the stamp-time binding. The deadline is
    /// the daemon's own, far above any healthy handler.
    private func timeoutRequest(_ requestID: UInt64) {
        guard let request = pending[requestID] else {
            return
        }
        if request.requiresExactOutcome {
            let operation = request.exactLifecycleOutcome && !request.orderedMutation
                && request.publicationCollector?.hasSubmittedOrderedMutation != true
                ? "exact lifecycle outcome deadline"
                : "ordered mutation outcome deadline"
            closeCurrentConnection(
                request.connectionID,
                error: PfsLocalClientError.system(
                    errno: ETIMEDOUT,
                    operation: operation
                )
            )
            return
        }
        pending.removeValue(forKey: requestID)
        request.continuation.resume(throwing: PfsLocalClientError.timeout)
    }

    /// Fails one read-only request whose framework task was cancelled. Once
    /// this callback has dispatched an ordered mutation or lifecycle
    /// retirement, cancellation cannot remove its pending continuation: doing
    /// so would let the daemon change durable or owned state after FSKit
    /// received a retryable EINTR.
    ///
    /// Like a timeout, cancellation never closes the connection: FSKit cancels
    /// a callback whenever its process is interrupted, which bursts of
    /// short-lived processes produce routinely, and one interrupted process
    /// must not end every other callback's publication.
    private func cancelRequest(
        _ requestID: UInt64,
        error: PfsLocalClientError
    ) {
        guard let request = pending[requestID] else {
            return
        }
        if request.requiresExactOutcome {
            return
        }
        pending.removeValue(forKey: requestID)
        request.timeoutTask?.cancel()
        request.continuation.resume(throwing: error)
    }

    private func writeFailed(_ requestID: UInt64, connectionID: UUID, error: Error) {
        if let request = pending.removeValue(forKey: requestID) {
            request.timeoutTask?.cancel()
            request.continuation.resume(throwing: error)
        }
        closeCurrentConnection(connectionID, error: error)
    }

    func testingBeforeNextResourceSettlement(_ hook: @escaping @Sendable () async -> Void) {
        beforeNextResourceSettlement = hook
    }

    private func beforeResourceSettlement() async {
        let hook = beforeNextResourceSettlement
        beforeNextResourceSettlement = nil
        await hook?()
    }

    func testingFailResourceDispositionWrites() {
        connection?.writer.testingFailWrites()
    }

    public func testingPendingRequestCount() -> Int {
        pending.count
    }
}
