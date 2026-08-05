import Foundation
@preconcurrency import Darwin

private final class PfsEventSink: @unchecked Sendable {
    let stream: AsyncStream<PfsEvent>
    private let lock = NSLock()
    private var continuation: AsyncStream<PfsEvent>.Continuation?
    private var delivered = 0

    init(
        bufferingPolicy: AsyncStream<PfsEvent>.Continuation.BufferingPolicy = .bufferingNewest(1024)
    ) {
        var captured: AsyncStream<PfsEvent>.Continuation?
        stream = AsyncStream(PfsEvent.self, bufferingPolicy: bufferingPolicy) { continuation in
            captured = continuation
        }
        continuation = captured
    }

    func yield(_ event: PfsEvent) {
        lock.lock()
        let continuation = continuation
        delivered += 1
        lock.unlock()
        continuation?.yield(event)
    }

    func deliveredCount() -> Int {
        lock.lock()
        let count = delivered
        lock.unlock()
        return count
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
    var resolvedAttachRef: String?
    var eventsSubscribed = false
    var nextOperationID: UInt64 = 1
    /// The per-request reply bound this connection's DAEMON asked for
    /// (HelloReply.request_deadline_ms, protocol minor 7). It is per connection
    /// because it is a property of the peer, not of this process: a client
    /// compiled-in constant is exactly what could not see the daemon's own
    /// budgets and expired ahead of them. Zero until Hello completes, which is
    /// why `deadlineNanoseconds(default:)` falls back to the configuration for
    /// the Hello exchange itself.
    var negotiatedRequestDeadlineNanoseconds: UInt64 = 0

    func deadlineNanoseconds(default fallback: UInt64) -> UInt64 {
        negotiatedRequestDeadlineNanoseconds == 0
            ? fallback
            : negotiatedRequestDeadlineNanoseconds
    }

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
/// control lane so a callback can release its daemon handoff before a large
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
            Task.detached {
                await self.drain()
            }
        }
        return receipt
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
}

private struct PfsPublicationTicket: Sendable {
    var connection: PfsConnection
    var operationID: UInt64
}

private enum PfsExistingPublicationBinding {
    case unbound
    case current(UInt64)
    case differentConnection
}

private final class PfsPublicationCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var connections: [UUID: PfsConnection] = [:]
    private var boundConnectionID: UUID?
    private var operationID: UInt64?
    private var retracted = false

    /// Records that the daemon retracted this logical operation. The flag is
    /// sticky: a single retracted reply condemns every value the operation
    /// produced, including values that arrived on earlier replies and were
    /// individually fine, because the framework installs the callback's
    /// result as one unit.
    func markRetracted() {
        lock.lock()
        retracted = true
        lock.unlock()
    }

    var isRetracted: Bool {
        lock.lock()
        defer { lock.unlock() }
        return retracted
    }

    /// Binds this operation to `connection` and RECORDS THE ACKNOWLEDGEMENT
    /// OBLIGATION IN THE SAME STEP.
    ///
    /// ── WHY THE TICKET IS CREATED HERE AND NOT ON THE REPLY ─────────────────
    ///
    /// The daemon creates its logical operation the instant it sees this
    /// operation ID on a request (`reserveLogicalOperation`), and from that
    /// moment only a `PublicationAck` for that ID can retire it. The obligation
    /// is therefore incurred when the ID is STAMPED, not when a reply comes
    /// back.
    ///
    /// The ticket used to be created in `receive`, on observing
    /// `publicationAckRequired`. That left a gap with nothing bridging it: an
    /// operation whose reply was never observed — dropped because its `pending`
    /// entry had already been removed, or never delivered at all — produced an
    /// operation ID the daemon was holding and a collector that would snapshot
    /// to an EMPTY ticket list. `snapshot()` returning `[]` while `operationID`
    /// is non-nil means precisely "we told the daemon to create operation N and
    /// then forgot about it", and it was silent: no ack, no log, no fallback.
    /// The daemon's side is not silent about it — the operation stays pinned in
    /// the publication set forever, blocking every delegation handoff over its
    /// scope and refusing clean unmount, on a connection that is perfectly
    /// healthy. That is the accumulation of exposed-unacknowledged publications
    /// on a CONNECTED frontend that the live battery recorded on an idle mount.
    ///
    /// Acknowledging an operation whose reply was never seen is not merely safe,
    /// it is the STRONGER statement: the ack says the callback has finished and
    /// whatever the operation published is now installed or discarded, and a
    /// reply that was never observed installed nothing at all.
    func bind(
        to connection: PfsConnection,
        allocating candidate: UInt64
    ) -> (id: UInt64, isNew: Bool)? {
        lock.lock()
        defer { lock.unlock() }
        if let boundConnectionID {
            guard boundConnectionID == connection.id, let operationID else {
                return nil
            }
            return (operationID, false)
        }
        boundConnectionID = connection.id
        operationID = candidate
        connections[connection.id] = connection
        return (candidate, true)
    }

    func existingBinding(to connectionID: UUID) -> PfsExistingPublicationBinding {
        lock.lock()
        defer { lock.unlock() }
        guard let boundConnectionID else {
            return .unbound
        }
        guard boundConnectionID == connectionID, let operationID else {
            return .differentConnection
        }
        return .current(operationID)
    }

    func append(connection: PfsConnection) {
        lock.lock()
        connections[connection.id] = connection
        lock.unlock()
    }

    func snapshot() -> [PfsPublicationTicket] {
        lock.lock()
        let result: [PfsPublicationTicket]
        if let operationID {
            result = connections.values.map {
                PfsPublicationTicket(connection: $0, operationID: operationID)
            }
        } else {
            result = []
        }
        lock.unlock()
        return result
    }
}

private enum PfsPublicationContext {
    @TaskLocal static var collector: PfsPublicationCollector?
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
    case .lookup, .enumerate, .getAttr, .setAttr, .read, .write,
         .create, .mkdir, .remove, .rename, .symlink, .readlink,
         .hardLink, .xattrGet, .xattrSet, .xattrList, .xattrRemove:
        return true
    default:
        return false
    }
}

/// Async pfslocal client for length-prefixed protobuf over a Unix domain socket.
///
/// `PfsLocalClient` multiplexes concurrent requests over one stream by assigning
/// strictly increasing request IDs and completing the matching continuation when
/// a reply arrives. Replies may arrive out of order. Server-initiated events are
/// delivered on `events` after `subscribeEvents()` succeeds.
public actor PfsLocalClient {
    public struct Configuration: Sendable {
        public var maxFrameLength: Int
        public var maxReconnectAttempts: Int
        public var reconnectBaseDelayNanoseconds: UInt64
        public var reconnectMaxDelayNanoseconds: UInt64
        public var requestDeadlineNanoseconds: UInt64
        public var clientName: String
        public var clientVersion: String

        public init(
            maxFrameLength: Int = PfsFrameCodec.defaultMaxFrameLength,
            maxReconnectAttempts: Int = 5,
            reconnectBaseDelayNanoseconds: UInt64 = 50_000_000,
            reconnectMaxDelayNanoseconds: UInt64 = 1_000_000_000,
            requestDeadlineNanoseconds: UInt64 = 60_000_000_000,
            clientName: String = "portablefskit",
            clientVersion: String = "1"
        ) {
            self.maxFrameLength = maxFrameLength
            self.maxReconnectAttempts = maxReconnectAttempts
            self.reconnectBaseDelayNanoseconds = reconnectBaseDelayNanoseconds
            self.reconnectMaxDelayNanoseconds = reconnectMaxDelayNanoseconds
            self.requestDeadlineNanoseconds = requestDeadlineNanoseconds
            self.clientName = clientName
            self.clientVersion = clientVersion
        }
    }

    private let socketPathProvider: @Sendable () async throws -> String
    private let configuration: Configuration
    private let eventSink = PfsEventSink()
    /// A strict-v3 subscription is bound to one physical UDS connection. Its
    /// authority bridge treats loss of that frontend connection as terminal;
    /// replay must never be silently migrated through the legacy reconnect
    /// stream.
    private var strictV3EventSink: PfsEventSink?
    private var strictV3ConnectionID: UUID?
    private var strictV3Terminal = false
    private var connection: PfsConnection?
    private var connectingTask: Task<Void, Error>?
    private var pending: [UInt64: PfsPendingRequest] = [:]
    private var nextRequestID: UInt64 = 1
    private var resolvedAttachRef: String?
    private var wantsEvents = false
    private var isShutdown = false
    private var attachIsDetaching = false

    public nonisolated var events: AsyncStream<PfsEvent> {
        eventSink.stream
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
        eventSink.finish()
        strictV3EventSink?.finish()
    }

    /// Sends a raw pfslocal request body and returns the matching reply envelope.
    public func request(_ body: PfsEnvelope.OneOf_Body) async throws -> PfsEnvelope {
        try Task.checkCancellation()
        if attachIsDetaching {
            throw PfsLocalClientError.daemon(errno: ENXIO, message: "attach is detaching")
        }
        try await ensureConnected()
        if PfsPublicationContext.collector != nil {
            return try await sendRequestOnCurrentConnection(body)
        }
        // The reissue loop is spelled out here rather than delegated to
        // `runPublicationBoundary` because `sendRequestOnCurrentConnection` is
        // isolated to this actor: handing it to a nonisolated helper would send
        // an actor-isolated closure across domains. The policy is identical —
        // see `runPublicationBoundary` for why a retracted attempt is
        // acknowledged and then reissued rather than surfaced.
        var attempt = 0
        while true {
            let collector = PfsPublicationCollector()
            let outcome: Result<PfsEnvelope, Error> = await PfsPublicationContext
                .$collector.withValue(collector) {
                    do {
                        return .success(try await self.sendRequestOnCurrentConnection(body))
                    } catch {
                        // Cacheable negative replies are publications too.
                        // `receive` records their request ID before resuming the
                        // throwing continuation, so the daemon gate is released
                        // by the settlement below either way.
                        return .failure(error)
                    }
                }
            await completePublications(collector.snapshot())
            guard collector.isRetracted else {
                return try outcome.get()
            }
            attempt += 1
            if attempt >= PfsLocalClient.publicationRetractionReissueLimit {
                throw PfsLocalClientError.publicationRetracted
            }
        }
    }

    /// Runs `operation` as ONE logical publication boundary, REISSUING it in
    /// full if the daemon retracts it, and returns the surviving attempt's
    /// tickets as a deferred acknowledgement.
    ///
    /// ── WHY THE EXTENSION RETRIES AND NOT THE KERNEL ────────────────────────
    ///
    /// A retraction used to be surfaced to FSKit as EINTR on the belief that the
    /// kernel would then restart the syscall against a frontend holding nothing
    /// — the belief is written out in `PfsLocalClientError.publicationRetracted`
    /// and it is FALSE on macOS 26. FSKit does not restart rmdir(2): the EINTR
    /// propagates all the way to userspace. `/bin/rmdir` and `rm -rf` do not
    /// retry EINTR either, so every cold-cycle rmdir that a delegation handoff
    /// happened to cross failed the application, deterministically, on an
    /// otherwise idle mount (live: 8/8).
    ///
    /// The retry has to happen below userspace, and this is the only place that
    /// both knows the operation was retracted and still holds everything needed
    /// to run it again. Nothing about the retraction contract changes; what
    /// changes is who honours it.
    ///
    /// ── WHY REISSUING IS SOUND, INCLUDING FOR MUTATIONS ─────────────────────
    ///
    /// The daemon refuses a retracted operation's UNANSWERED requests without
    /// executing them, so the reissue cannot double-apply a mutation: the
    /// request that was going to mutate is precisely the one that did not run.
    /// (Structurally, a crossing is only ever taken against an operation whose
    /// participants are ALL PARKED — a parked request has not dispatched — so
    /// there is no interleaving in which the mutation landed and the operation
    /// was still retracted.)
    ///
    /// ── WHY THE ACK COMES BEFORE THE REISSUE ────────────────────────────────
    ///
    /// The retracted attempt still owes its acknowledgement: that ack is what
    /// releases the daemon's handoff gate. Reissuing while holding it would
    /// queue the new attempt behind a handoff that is waiting for this very ack.
    /// So each retracted attempt is acknowledged in full before the next begins,
    /// which is also what makes the daemon's convergence promise apply — the
    /// refusal only becomes reachable once the handoff has completed, so the
    /// reissue finds nothing left to hand off.
    ///
    /// ── WHY IT IS BOUNDED ───────────────────────────────────────────────────
    ///
    /// One reissue converges against the handoff that caused the retraction, but
    /// an unrelated handoff can always cross a later attempt. The bound keeps a
    /// pathological mount from spinning a syscall forever; on exhaustion the old
    /// behaviour is restored exactly (EINTR to the framework), so this is never
    /// worse than what it replaces.
    private nonisolated func runPublicationBoundary<T>(
        _ operation: () async throws -> T
    ) async -> (Result<T, Error>, @Sendable () async -> Void) {
        var attempt = 0
        while true {
            let collector = PfsPublicationCollector()
            let outcome: Result<T, Error> = await PfsPublicationContext.$collector
                .withValue(collector) {
                    do {
                        return .success(try await operation())
                    } catch {
                        // Cacheable negative replies are publications too.
                        // `receive` records their request ID before resuming the
                        // throwing continuation, so the daemon gate is released
                        // by the ticket settlement below either way.
                        return .failure(error)
                    }
                }
            let tickets = collector.snapshot()
            guard collector.isRetracted else {
                return (outcome, { await self.completePublications(tickets) })
            }
            await completePublications(tickets)
            attempt += 1
            if attempt >= PfsLocalClient.publicationRetractionReissueLimit {
                return (.failure(PfsLocalClientError.publicationRetracted), {})
            }
        }
    }

    /// How many times a retracted logical operation is reissued by the
    /// extension before the retraction is surfaced to the framework.
    static let publicationRetractionReissueLimit = 4

    /// Extends every request issued by operation through the point where the
    /// FSKit adapter has copied/installed the returned values. The daemon
    /// holds overlapping delegation handoffs until these one-way
    /// acknowledgements arrive.
    public nonisolated func withPublicationBoundary<T>(
        _ operation: () async throws -> T
    ) async throws -> T {
        if PfsPublicationContext.collector != nil {
            return try await operation()
        }
        // A retracted operation is REISSUED rather than handed back, and only a
        // retraction that survives the reissue bound reaches the caller. See
        // `runPublicationBoundary`.
        let (result, complete) = await runPublicationBoundary(operation)
        await complete()
        return try result.get()
    }

    /// Collects the request IDs issued by `operation` without acknowledging
    /// them. Callback-based FSKit witnesses invoke the returned completion
    /// only after their reply handler returns, providing a real framework
    /// publication boundary rather than an approximation before an async
    /// method return.
    public nonisolated func withDeferredPublication<T>(
        _ operation: () async throws -> T
    ) async -> (Result<T, Error>, @Sendable () async -> Void) {
        // The retraction verdict is applied INSIDE the boundary, before this
        // function returns, so a caller that hands `result` to a framework reply
        // handler physically cannot hand back retracted values: a retracted
        // attempt is reissued, and only a retraction that survives the reissue
        // bound comes back — already as a thrown EINTR, never as values. Every
        // reply for an attempt has been received before it is judged
        // (`operation()` cannot have returned otherwise), so each verdict is
        // final. See `runPublicationBoundary`.
        return await runPublicationBoundary(operation)
    }

    /// Resolves this connection to an attach reference and remembers it for reconnects.
    @discardableResult
    public func resolve(attachRef: String) async throws -> PfsResolveReply {
        try await ensureConnected()
        let reply = try await resolveOnCurrentConnection(attachRef: attachRef)
        if reply.hasV3Coherence {
            guard let connection else {
                strictV3Terminal = true
                throw PfsLocalClientError.connectionClosed
            }
            // Bind strict intent at the Resolve reply, before SubscribeEvents.
            // A disconnect in that gap is participant loss and may not be
            // repaired by transparently resolving the attach on connection B.
            strictV3ConnectionID = connection.id
            if connection.eventsSubscribed {
                let error = PfsLocalClientError.unexpectedReply(
                    "strict-v3 resolve cannot adopt a legacy event subscription"
                )
                closeCurrentConnection(connection.id, error: error)
                throw error
            }
        }
        resolvedAttachRef = attachRef
        connection?.resolvedAttachRef = attachRef
        return reply
    }

    /// Subscribes to daemon events and returns the shared event stream.
    @discardableResult
    public func subscribeEvents() async throws -> AsyncStream<PfsEvent> {
        wantsEvents = true
        try await ensureConnected()
        if connection?.eventsSubscribed != true {
            try await subscribeOnCurrentConnection()
            connection?.eventsSubscribed = true
        }
        return eventSink.stream
    }

    /// Subscribes on one exact physical connection for strict-v3 coherence.
    /// Unlike the legacy diagnostic stream, this stream finishes as soon as
    /// that UDS connection closes and permanently disables client reconnect.
    /// Losing the local participant is an authority-session failure, not an
    /// invitation to wait indefinitely for another connection epoch.
    public func subscribeStrictV3Events() async throws -> AsyncStream<PfsEvent> {
        guard strictV3EventSink == nil, !strictV3Terminal else {
            throw PfsLocalClientError.connectionClosed
        }
        guard let connection,
              let strictV3ConnectionID,
              strictV3ConnectionID == connection.id else {
            throw PfsLocalClientError.connectionClosed
        }
        if connection.eventsSubscribed {
            let error = PfsLocalClientError.unexpectedReply(
                "strict-v3 subscription cannot join an event stream already in progress"
            )
            closeCurrentConnection(connection.id, error: error)
            throw error
        }

        // Install the sink before SubscribeEvents can expose the first event.
        // Otherwise an immediately-ready authority barrier could arrive in the
        // actor turn between the subscribe reply and this method's return.
        wantsEvents = true
        let sink = PfsEventSink(bufferingPolicy: .unbounded)
        strictV3EventSink = sink
        do {
            try await subscribeOnCurrentConnection()
            connection.eventsSubscribed = true
            return sink.stream
        } catch {
            if self.strictV3ConnectionID == connection.id {
                // Once Resolve selected strict-v3, failing to establish its
                // subscription on that exact connection is terminal. Leaving
                // the socket live here would let ordinary filesystem requests
                // continue on a participant that cannot receive barriers.
                closeCurrentConnection(connection.id, error: error)
            }
            throw error
        }
    }

    /// Sends one v3 visibility cursor verdict on the priority control lane.
    /// Acknowledging a repair is what releases the authority-side mutation, so
    /// this request must not queue behind an arbitrary backlog of filesystem
    /// calls on the same local connection.
    public func acknowledgeVisibility(_ request: PfsVisibilityAckRequest) async throws {
        try Task.checkCancellation()
        if attachIsDetaching {
            throw PfsLocalClientError.daemon(errno: ENXIO, message: "attach is detaching")
        }
        guard !isShutdown,
              !strictV3Terminal,
              let strictV3ConnectionID,
              connection?.id == strictV3ConnectionID else {
            throw PfsLocalClientError.connectionClosed
        }
        let envelope = try await sendRequestOnCurrentConnection(
            .visibilityAck(request),
            lane: .publication
        )
        guard case .visibilityAckReply? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
    }

    /// Performs the strict frontend's on-demand daemon-to-authority liveness
    /// round trip on the priority lane of the exact resolved connection.
    /// This deliberately bypasses `ensureConnected`: reconnecting would turn
    /// loss of the authority participant into a new, unrelated UDS session.
    public func checkV3Liveness(
        _ request: PfsV3LivenessRequest
    ) async throws -> PfsV3LivenessReply {
        try Task.checkCancellation()
        guard !isShutdown,
              !strictV3Terminal,
              let strictV3ConnectionID,
              connection?.id == strictV3ConnectionID else {
            throw PfsLocalClientError.connectionClosed
        }
        let envelope = try await sendRequestOnCurrentConnection(
            .v3Liveness(request),
            lane: .publication
        )
        guard case let .v3LivenessReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return reply
    }

    /// Closes the active connection and fails all in-flight requests.
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
        eventSink.finish()
        strictV3EventSink?.finish()
        strictV3EventSink = nil
        strictV3ConnectionID = nil
        strictV3Terminal = true
    }

    private func ensureConnected() async throws {
        if attachIsDetaching {
            throw PfsLocalClientError.daemon(errno: ENXIO, message: "attach is detaching")
        }
        if isShutdown {
            throw PfsLocalClientError.shutdown
        }
        if strictV3Terminal {
            throw PfsLocalClientError.connectionClosed
        }
        if let task = connectingTask {
            try await task.value
            return
        }
        if connection != nil {
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
        var delay = configuration.reconnectBaseDelayNanoseconds
        var lastError: Error = PfsLocalClientError.connectionClosed

        for attempt in 0..<max(1, configuration.maxReconnectAttempts) {
            if isShutdown {
                throw PfsLocalClientError.shutdown
            }
            do {
                try await establishConnectionOnce()
                return
            } catch {
                lastError = error
                if attempt + 1 >= max(1, configuration.maxReconnectAttempts) {
                    break
                }
                try await Task.sleep(nanoseconds: delay)
                delay = min(configuration.reconnectMaxDelayNanoseconds, delay * 2)
            }
        }

        throw lastError
    }

    private func establishConnectionOnce() async throws {
        let path = try await socketPathProvider()
        let socket = try await PfsAsyncSocket.connect(path: path, maxFrameLength: configuration.maxFrameLength)
        let newConnection = PfsConnection(socket: socket)
        connection = newConnection
        startReader(for: newConnection)

        do {
            try await helloOnCurrentConnection()
            if let attachRef = resolvedAttachRef {
                _ = try await resolveOnCurrentConnection(attachRef: attachRef)
                newConnection.resolvedAttachRef = attachRef
            }
            if wantsEvents {
                try await subscribeOnCurrentConnection()
                newConnection.eventsSubscribed = true
            }
        } catch {
            closeCurrentConnection(newConnection.id, error: error)
            throw error
        }
    }

    private func startReader(for connection: PfsConnection) {
        let connectionID = connection.id
        connection.socket.startReading { [weak self] envelope in
            Task {
                await self?.receive(envelope, from: connectionID)
            }
        } onClose: { [weak self] error in
            Task {
                await self?.connectionDidClose(connectionID, error: error)
            }
        }
    }

    private func receive(_ envelope: PfsEnvelope, from connectionID: UUID) {
        guard connection?.id == connectionID else {
            return
        }

        if envelope.requestID == 0 {
            if case let .event(event)? = envelope.body {
                if case let .attachState(state)? = event.kind, state.state == .detaching {
                    attachIsDetaching = true
                }
                if strictV3ConnectionID == connectionID {
                    strictV3EventSink?.yield(event)
                } else {
                    eventSink.yield(event)
                }
            }
            return
        }

        guard let request = pending.removeValue(forKey: envelope.requestID) else {
            return
        }
        request.timeoutTask?.cancel()
        if envelope.publicationAckRequired {
            if let connection {
                request.publicationCollector?.append(connection: connection)
            }
        }
        if envelope.publicationRetracted {
            // The retraction rides this reply's own frame, so recording it
            // here — before the continuation resumes — is what makes it
            // strictly ordered ahead of the framework install. The daemon
            // guarantees at least one further reply for a crossed operation
            // precisely so this bit has a frame to ride; a separate message
            // would race the reply, because every decoded frame is handed to
            // its own Task by the reader above.
            //
            // In practice that frame is usually an ErrorReply: the daemon
            // refuses the crossed operation's still-undispatched requests
            // with EINTR instead of running them, and the refusal is what
            // carries the bit. Marking before the error branch below is
            // therefore load-bearing — the collector's verdict must win over
            // the per-request errno so the caller sees one retraction for the
            // operation rather than an incidental EINTR on one request.
            request.publicationCollector?.markRetracted()
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
        if strictV3ConnectionID == connectionID {
            strictV3Terminal = true
            strictV3EventSink?.finish()
            strictV3EventSink = nil
            strictV3ConnectionID = nil
        }
        let socket = connection?.socket
        connection = nil
        socket?.close()
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

    func testingEventDeliveryCounts() -> (legacy: Int, strictV3: Int) {
        (
            legacy: eventSink.deliveredCount(),
            strictV3: strictV3EventSink?.deliveredCount() ?? 0
        )
    }

    private func helloOnCurrentConnection() async throws {
        var hello = PfsHello()
        hello.protocolMajor = 1
        // Protocol minor 6: this frontend honours
        // Envelope.publication_retracted. The daemon refuses any frontend
        // below its own minor, which is what makes the retraction bit safe to
        // rely on — an extension that ignored it would install state the
        // daemon has withdrawn, and nothing on the wire would say so.
        //
        // Protocol minor 7: this frontend takes its per-request reply deadline
        // from HelloReply.request_deadline_ms instead of from a constant of its
        // own. The same gate applies for the same reason — a frontend that
        // ignored the field would keep the compiled-in 60s bound that was
        // observed live to expire ahead of the daemon's own 50s admission
        // budget, and nothing on the wire would say so.
        // Protocol minor 8: this wire client understands the resolved v3
        // coherence contract, ordered visibility events, and request/reply
        // cursor acks. VolumeCore still rejects a strict attach until its live
        // namespace index, callback barrier, and backend are installed;
        // recognizing and refusing is materially different from ignoring.
        // Protocol minor 9: a strict frontend independently demands an exact
        // daemon-to-authority liveness round trip on its resolved session.
        hello.protocolMinor = 9
        hello.clientName = configuration.clientName
        hello.clientVersion = configuration.clientVersion

        let envelope = try await sendRequestOnCurrentConnection(.hello(hello))
        guard case let .helloReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        guard reply.protocolMajor == 1, reply.protocolMinor >= 9 else {
            throw PfsLocalClientError.protocolMismatch(major: reply.protocolMajor, minor: reply.protocolMinor)
        }
        // ADOPT THE DAEMON'S BOUND, AND NEVER SHORTEN IT.
        //
        // max() with the configured value is deliberate: the configuration is a
        // floor for tests and for a daemon that answers zero, never a ceiling.
        // A frontend that could shorten the daemon's bound would reintroduce
        // exactly the defect the field exists to remove.
        if reply.requestDeadlineMs != 0 {
            connection?.negotiatedRequestDeadlineNanoseconds = max(
                configuration.requestDeadlineNanoseconds,
                UInt64(reply.requestDeadlineMs) * 1_000_000
            )
        }
    }

    private func resolveOnCurrentConnection(attachRef: String) async throws -> PfsResolveReply {
        var request = PfsResolveRequest()
        request.attachRef = attachRef
        let envelope = try await sendRequestOnCurrentConnection(.resolve(request))
        guard case let .resolveReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return reply
    }

    private func subscribeOnCurrentConnection() async throws {
        let envelope = try await sendRequestOnCurrentConnection(.subscribeEvents(PfsSubscribeEventsRequest()))
        guard case .subscribeEventsReply? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
    }

    private func sendRequestOnCurrentConnection(
        _ body: PfsEnvelope.OneOf_Body,
        lane: PfsEnvelopeWriteLane = .request
    ) async throws -> PfsEnvelope {
        if isShutdown {
            throw PfsLocalClientError.shutdown
        }
        guard let connection else {
            throw PfsLocalClientError.connectionClosed
        }
        var operationID: UInt64 = 0
        if let collector = PfsPublicationContext.collector {
            if pfsRequestPublishes(body) {
                guard let binding = collector.bind(
                    to: connection,
                    allocating: connection.nextOperationID
                ) else {
                    // A framework reply cannot combine cacheable results from two
                    // ownership epochs. The callback fails as one unit; the old
                    // connection close has already retired its daemon-side gate.
                    throw PfsLocalClientError.connectionClosed
                }
                operationID = binding.id
                // The publication-barrier ticket must learn this callback's
                // logical operation ID at the same instant the daemon does:
                // it is the identity a source COMPLETE names, and stamping it
                // any later would let a PREPARE barrier mistake the initiating
                // callback for an ordinary one and deadlock draining it.
                PfsMacOSCallbackAdmission.ticket?.noteOperationID(binding.id)
                if binding.isNew {
                    guard connection.nextOperationID != UInt64.max else {
                        connection.socket.close()
                        throw PfsLocalClientError.connectionClosed
                    }
                    connection.nextOperationID += 1
                }
            } else {
                switch collector.existingBinding(to: connection.id) {
                case .unbound:
                    // Protocol minor 3 allocates an operation ID lazily at
                    // the first publishing request in a framework callback.
                    break
                case let .current(existing):
                    // Once a callback has published cacheable state, all later
                    // requests in that same callback share its completion gate,
                    // even if an individual request (for example close/fsync)
                    // does not itself publish cache state.
                    operationID = existing
                case .differentConnection:
                    // A nonpublishing continuation is part of the same
                    // framework callback and cannot cross ownership epochs.
                    throw PfsLocalClientError.connectionClosed
                }
            }
        }

        let requestID = nextRequestID
        nextRequestID += 1

        var envelope = PfsEnvelope()
        envelope.requestID = requestID
        envelope.operationID = operationID
        envelope.body = body

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let timeoutTask = Task.detached { [
                    requestID,
                    deadline = connection.deadlineNanoseconds(
                        default: configuration.requestDeadlineNanoseconds
                    ),
                ] in
                    do {
                        try await Task.sleep(nanoseconds: deadline)
                        await self.timeoutRequest(requestID)
                    } catch {}
                }
                pending[requestID] = PfsPendingRequest(
                    continuation: continuation,
                    timeoutTask: timeoutTask,
                    publicationCollector: PfsPublicationContext.collector
                )
                if Task.isCancelled {
                    cancelRequest(requestID)
                    return
                }
                let outboundEnvelope = envelope
                let writeReceipt = connection.writer.enqueue(
                    outboundEnvelope,
                    lane: lane
                )
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
                await self.cancelRequest(requestID)
            }
        }
    }

    private nonisolated func completePublications(_ tickets: [PfsPublicationTicket]) async {
        for ticket in tickets {
            var ack = PfsPublicationAck()
            ack.operationID = ticket.operationID
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
                // A ticket is permanently bound to the connection that
                // exposed its reply. Never replay it on a replacement
                // connection; closing that exact epoch makes the daemon fail
                // coherence closed if the result was already exposed.
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

    /// Fails ONE request whose reply never arrived, and leaves the connection —
    /// and therefore every other operation's publication — untouched.
    ///
    /// ── WHY THIS NO LONGER RESETS THE CONNECTION ────────────────────────────
    ///
    /// It used to, and the justification was that a late reply for this request
    /// would otherwise arrive with nobody to acknowledge it, leaving an
    /// unacknowledgeable operation in the daemon's handoff gate. That reasoning
    /// is about ONE operation and the remedy it chose was mount-wide: closing
    /// the connection strands every OTHER in-flight operation's publication too,
    /// and the daemon's disconnect path treats an exposed-unacknowledged
    /// publication as a kernel-coherence failure. So a single slow reply — a
    /// latency outlier on a healthy mount, which the live battery recorded as a
    /// 58.8s cold create against a 60s bound — became a permanent whole-mount
    /// EIO. The cure was categorically worse than the disease.
    ///
    /// It is also unnecessary. A late reply is already handled: `receive` looks
    /// the request ID up in `pending`, finds nothing, and drops the frame —
    /// including its publication ticket. What the OPERATION owes is unaffected,
    /// because the operation is acknowledged as a whole by `completePublications`
    /// from the tickets its ALREADY-RECEIVED publishing replies registered, and
    /// the daemon retires it when its own handler finishes. The two orders are
    /// independent by construction (see the daemon's acknowledgePublication /
    /// finishLogicalRequest pair).
    ///
    /// The deadline itself is now the daemon's own (protocol minor 7), set far
    /// above anything a healthy handler can reach, so reaching it means a wedged
    /// request rather than a slow one — and a wedged request deserves a definite
    /// answer for itself, not a mount-wide verdict.
    private func timeoutRequest(_ requestID: UInt64) {
        guard let request = pending.removeValue(forKey: requestID) else {
            return
        }
        request.continuation.resume(throwing: PfsLocalClientError.timeout)
    }

    private func cancelRequest(_ requestID: UInt64) {
        guard let request = pending.removeValue(forKey: requestID) else {
            return
        }
        let connectionID = connection?.id
        request.timeoutTask?.cancel()
        request.continuation.resume(throwing: PfsLocalClientError.cancelled)
        if let connectionID {
            closeCurrentConnection(connectionID, error: PfsLocalClientError.cancelled)
        }
    }

    private func writeFailed(_ requestID: UInt64, connectionID: UUID, error: Error) {
        if let request = pending.removeValue(forKey: requestID) {
            request.timeoutTask?.cancel()
            request.continuation.resume(throwing: error)
        }
        closeCurrentConnection(connectionID, error: error)
    }

    public func testingPendingRequestCount() -> Int {
        pending.count
    }
}
