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
    var resolvedAttachRef: String?
    var eventsSubscribed = false

    init(socket: PfsAsyncSocket) {
        self.socket = socket
    }
}

private struct PfsPendingRequest: Sendable {
    var continuation: CheckedContinuation<PfsEnvelope, Error>
    var timeoutTask: Task<Void, Never>?
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
        return try await sendRequestOnCurrentConnection(body)
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
        if connection != nil {
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
        hello.protocolMinor = 0
        hello.clientName = configuration.clientName
        hello.clientVersion = configuration.clientVersion

        let envelope = try await sendRequestOnCurrentConnection(.hello(hello))
        guard case let .helloReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        guard reply.protocolMajor == 1 else {
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

        let requestID = nextRequestID
        nextRequestID += 1

        var envelope = PfsEnvelope()
        envelope.requestID = requestID
        envelope.body = body

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let timeoutTask = Task.detached { [requestID, deadline = configuration.requestDeadlineNanoseconds] in
                    do {
                        try await Task.sleep(nanoseconds: deadline)
                        await self.timeoutRequest(requestID)
                    } catch {}
                }
                pending[requestID] = PfsPendingRequest(continuation: continuation, timeoutTask: timeoutTask)
                if Task.isCancelled {
                    cancelRequest(requestID)
                    return
                }
                let outboundEnvelope = envelope
                Task.detached { [socket = connection.socket, connectionID = connection.id, outboundEnvelope] in
                    do {
                        try await socket.write(outboundEnvelope)
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
        request.timeoutTask?.cancel()
        request.continuation.resume(throwing: PfsLocalClientError.cancelled)
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
