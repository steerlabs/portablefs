import Foundation
@preconcurrency import Darwin

private final class PfsEventSink: @unchecked Sendable {
    let stream: AsyncStream<PfsEvent>
    private let lock = NSLock()
    private var continuation: AsyncStream<PfsEvent>.Continuation?

    init() {
        var captured: AsyncStream<PfsEvent>.Continuation?
        stream = AsyncStream(PfsEvent.self, bufferingPolicy: .bufferingNewest(1024)) { continuation in
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
    var resolvedAttachRef: String?
    var eventsSubscribed = false
    var nextOperationID: UInt64 = 1

    init(socket: PfsAsyncSocket) {
        self.socket = socket
        self.writer = PfsOrderedEnvelopeWriter { envelope in
            try await socket.write(envelope)
        }
    }
}

/// Chains socket writes in the same order they were enqueued. Request IDs are
/// allocated by `PfsLocalClient`'s actor, and every request plus one-way
/// publication acknowledgement enters this queue synchronously while on that
/// actor. Detached task scheduling therefore cannot reorder stream frames.
final class PfsOrderedEnvelopeWriter: @unchecked Sendable {
    private let write: @Sendable (PfsEnvelope) async throws -> Void
    private var tail: Task<Void, Error>?

    init(write: @escaping @Sendable (PfsEnvelope) async throws -> Void) {
        self.write = write
    }

    func enqueue(_ envelope: PfsEnvelope) -> Task<Void, Error> {
        let predecessor = tail
        let write = self.write
        let task = Task.detached {
            if let predecessor {
                try await predecessor.value
            }
            try await write(envelope)
        }
        tail = task
        return task
    }
}

private struct PfsPendingRequest: Sendable {
    var continuation: CheckedContinuation<PfsEnvelope, Error>
    var timeoutTask: Task<Void, Never>?
    var publicationCollector: PfsPublicationCollector?
}

private struct PfsPublicationTicket: Sendable {
    var connectionID: UUID
    var operationID: UInt64
}

private enum PfsExistingPublicationBinding {
    case unbound
    case current(UInt64)
    case differentConnection
}

private final class PfsPublicationCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var connectionIDs: Set<UUID> = []
    private var boundConnectionID: UUID?
    private var operationID: UInt64?

    func bind(to connectionID: UUID, allocating candidate: UInt64) -> (id: UInt64, isNew: Bool)? {
        lock.lock()
        defer { lock.unlock() }
        if let boundConnectionID {
            guard boundConnectionID == connectionID, let operationID else {
                return nil
            }
            return (operationID, false)
        }
        boundConnectionID = connectionID
        operationID = candidate
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

    func append(connectionID: UUID) {
        lock.lock()
        connectionIDs.insert(connectionID)
        lock.unlock()
    }

    func snapshot() -> [PfsPublicationTicket] {
        lock.lock()
        let result: [PfsPublicationTicket]
        if let operationID {
            result = connectionIDs.map {
                PfsPublicationTicket(connectionID: $0, operationID: operationID)
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
        let collector = PfsPublicationCollector()
        return try await PfsPublicationContext.$collector.withValue(collector) {
            do {
                let envelope = try await self.sendRequestOnCurrentConnection(body)
                await self.completePublications(collector.snapshot())
                return envelope
            } catch {
                // Cacheable negative replies are publications too. `receive`
                // records their request ID before resuming the throwing
                // continuation, so the daemon gate is released only here.
                await self.completePublications(collector.snapshot())
                throw error
            }
        }
    }

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
        let collector = PfsPublicationCollector()
        return try await PfsPublicationContext.$collector.withValue(collector) {
            do {
                let value = try await operation()
                await self.completePublications(collector.snapshot())
                return value
            } catch {
                await self.completePublications(collector.snapshot())
                throw error
            }
        }
    }

    /// Collects the request IDs issued by `operation` without acknowledging
    /// them. Callback-based FSKit witnesses invoke the returned completion
    /// only after their reply handler returns, providing a real framework
    /// publication boundary rather than an approximation before an async
    /// method return.
    public nonisolated func withDeferredPublication<T>(
        _ operation: () async throws -> T
    ) async -> (Result<T, Error>, @Sendable () async -> Void) {
        let collector = PfsPublicationCollector()
        let result: Result<T, Error> = await PfsPublicationContext.$collector.withValue(collector) {
            do {
                return .success(try await operation())
            } catch {
                return .failure(error)
            }
        }
        let tickets = collector.snapshot()
        let complete: @Sendable () async -> Void = {
            await self.completePublications(tickets)
        }
        return (result, complete)
    }

    /// Resolves this connection to an attach reference and remembers it for reconnects.
    @discardableResult
    public func resolve(attachRef: String) async throws -> PfsResolveReply {
        try await ensureConnected()
        let reply = try await resolveOnCurrentConnection(attachRef: attachRef)
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
    }

    private func ensureConnected() async throws {
        if attachIsDetaching {
            throw PfsLocalClientError.daemon(errno: ENXIO, message: "attach is detaching")
        }
        if isShutdown {
            throw PfsLocalClientError.shutdown
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
                eventSink.yield(event)
            }
            return
        }

        guard let request = pending.removeValue(forKey: envelope.requestID) else {
            return
        }
        request.timeoutTask?.cancel()
        if envelope.publicationAckRequired {
            request.publicationCollector?.append(connectionID: connectionID)
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

    private func helloOnCurrentConnection() async throws {
        var hello = PfsHello()
        hello.protocolMajor = 1
        hello.protocolMinor = 4
        hello.clientName = configuration.clientName
        hello.clientVersion = configuration.clientVersion

        let envelope = try await sendRequestOnCurrentConnection(.hello(hello))
        guard case let .helloReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        guard reply.protocolMajor == 1, reply.protocolMinor >= 4 else {
            throw PfsLocalClientError.protocolMismatch(major: reply.protocolMajor, minor: reply.protocolMinor)
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

    private func sendRequestOnCurrentConnection(_ body: PfsEnvelope.OneOf_Body) async throws -> PfsEnvelope {
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
                    to: connection.id,
                    allocating: connection.nextOperationID
                ) else {
                    // A framework reply cannot combine cacheable results from two
                    // ownership epochs. The callback fails as one unit; the old
                    // connection close has already retired its daemon-side gate.
                    throw PfsLocalClientError.connectionClosed
                }
                operationID = binding.id
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
                let timeoutTask = Task.detached { [requestID, deadline = configuration.requestDeadlineNanoseconds] in
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
                let writeTask = connection.writer.enqueue(outboundEnvelope)
                Task.detached { [connectionID = connection.id, writeTask] in
                    do {
                        try await writeTask.value
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

    private func completePublications(_ tickets: [PfsPublicationTicket]) async {
        for ticket in tickets {
            guard let connection, connection.id == ticket.connectionID else {
                // Closing the old connection synchronously retires all of its
                // daemon-side publication tickets. Never replay a stale
                // request ID onto a replacement connection.
                continue
            }
            var ack = PfsPublicationAck()
            ack.operationID = ticket.operationID
            var envelope = PfsEnvelope()
            envelope.requestID = 0
            envelope.body = .publicationAck(ack)
            let writeTask = connection.writer.enqueue(envelope)
            do {
                try await writeTask.value
            } catch {
                closeCurrentConnection(connection.id, error: error)
                return
            }
        }
    }

    private func timeoutRequest(_ requestID: UInt64) {
        guard let request = pending.removeValue(forKey: requestID) else {
            return
        }
        let connectionID = connection?.id
        request.continuation.resume(throwing: PfsLocalClientError.timeout)
        if let connectionID {
            // The daemon may still publish a late reply for this request. A
            // connection reset is the exact cancellation boundary: it
            // retires every server-side publication ticket instead of
            // leaving an unacknowledgeable operation in the handoff gate.
            closeCurrentConnection(connectionID, error: PfsLocalClientError.timeout)
        }
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
