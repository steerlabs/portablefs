import Foundation
@preconcurrency import Darwin

/// One admitted FSKit callback. It occupies one window slot from admission
/// until its settlement has replied to FSKit.
public final class PfsCallbackTicket: Sendable {
    fileprivate init() {}
}

/// Serializes session termination with the final synchronous framework reply.
/// It is independent of actor scheduling: a socket close or core teardown
/// revokes publication before changing session state, even while the window
/// or event consumer is occupied. The lock covers the reply itself, so no
/// check/reply interval can admit a terminal transition.
///
/// Once the session is terminal, no FSKit callback that publishes data, metadata,
/// namespace or durability reports success. Resource loading, volume activation
/// and mounting are serving callbacks and obey the same rule. Session termination
/// and each serving callback's final synchronous reply share one publication gate:
/// a reply that wins the gate precedes termination; when termination wins, the
/// final gate rejects publication with the first terminal cause. Earlier definite
/// request refusals remain failures.
///
/// Volume deactivation and resource unloading acknowledge local teardown only.
/// They must perform their local cleanup even after terminal failure and report
/// success only after the cleanup they acknowledge has completed. An earlier
/// session-terminal cause does not make completed cleanup fail. A genuine error
/// in the teardown request or its local cleanup remains an error. Repeated
/// completed teardown is idempotent. Unmount's errorless completion acknowledges
/// the same local cleanup boundary.
///
/// A teardown acknowledgement does not certify durability, erase or replace the
/// first terminal cause, revive a session, prove kernel mount absence, prove
/// authority acceptance of absence, or certify daemon/CLI reconciliation. Mutation
/// and synchronize failures retain their existing error paths. Every successful
/// FSKit mutation reply still requires authority-storage durability before publication.
final class PfsSessionPublicationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var terminal: Error?

    var terminalError: Error? {
        lock.lock()
        defer { lock.unlock() }
        return terminal
    }

    @discardableResult
    func revoke(_ error: Error) -> Error {
        lock.lock()
        defer { lock.unlock() }
        if terminal == nil { terminal = error }
        return terminal ?? error
    }

    func synchronized<T>(_ operation: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try operation()
    }

    func whileLive(_ operation: () -> Void) {
        synchronized { if terminal == nil { operation() } }
    }

    /// The condition and first-cause latch are one transition. Callers take
    /// their state lock inside this gate, as grant and withdrawal admission do.
    func revoke(if cause: () -> Error?) -> Error? {
        synchronized {
            guard terminal == nil, let error = cause() else { return nil }
            terminal = error
            return error
        }
    }

    func check() throws {
        if let error = terminalError { throw error }
    }

    @discardableResult
    func decide(_ reply: (Error?) -> Void) -> Bool {
        decide({}, terminalCause: { _ in nil }) { outcome in
            switch outcome {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        }
    }

    @discardableResult
    func decide<Value>(
        _ decision: () throws -> Value,
        terminalCause: (Error) -> Error?,
        reply: (Result<Value, Error>) -> Void
    ) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let outcome: Result<Value, Error>
        if let terminal { outcome = .failure(terminal) }
        else {
            do { outcome = .success(try decision()) }
            catch {
                if let cause = terminalCause(error) { terminal = cause }
                outcome = .failure(terminal ?? error)
            }
        }
        reply(outcome)
        if case .success = outcome { return true }
        return false
    }
}

/// Bounds one volume's callbacks from admission through their framework reply.
/// Slots pass directly to FIFO waiters. The client's shared publication gate
/// decides every reply; the event consumer only drains queued admissions after
/// termination. Admitted callbacks still settle their slots and resources once.
public actor PfsCallbackWindow {
    public static let defaultCapacity = 128

    private let capacity: Int
    nonisolated let publicationGate: PfsSessionPublicationGate
    private var beforeSettlement: (@Sendable () async -> Void)?
    private var beforeTerminalDrain: (@Sendable () async -> Void)?
    private var admitted: Set<ObjectIdentifier> = []
    private var waiters: [UUID: CheckedContinuation<PfsCallbackTicket, Error>] = [:]
    private var waiterOrder: [UUID] = []
    private var waiterHead = 0

    public init(capacity: Int = PfsCallbackWindow.defaultCapacity) {
        precondition(capacity > 0)
        self.capacity = capacity
        self.publicationGate = PfsSessionPublicationGate()
    }

    init(capacity: Int, publicationGate: PfsSessionPublicationGate) {
        precondition(capacity > 0)
        self.capacity = capacity
        self.publicationGate = publicationGate
    }

    /// Waits for a slot. Cancellation while queued surfaces as the client's
    /// cancellation verdict; a slot already handed to this caller is returned
    /// and must still be published.
    public func admit() async throws -> PfsCallbackTicket {
        if Task.isCancelled { throw PfsLocalClientError.cancelled }
        if let terminal = publicationGate.terminalError { throw terminal }
        if admitted.count < capacity, waiters.isEmpty {
            return admitTicket()
        }
        let waiterID = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                if let terminal = publicationGate.terminalError {
                    continuation.resume(throwing: terminal)
                    return
                }
                if Task.isCancelled {
                    continuation.resume(throwing: PfsLocalClientError.cancelled)
                    return
                }
                waiters[waiterID] = continuation
                waiterOrder.append(waiterID)
            }
        } onCancel: {
            Task { await self.cancelWaiter(waiterID) }
        }
    }

    /// Replies under the session gate and releases this slot exactly once.
    /// False means a duplicate settlement or an unsuccessful final decision.
    public func settle(
        _ ticket: PfsCallbackTicket,
        reply: @Sendable (_ terminal: Error?) -> Void
    ) async -> Bool {
        await settle(ticket, decision: {}, terminalCause: { _ in nil }) { outcome in
            switch outcome {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        }
    }

    func settle<Value>(
        _ ticket: PfsCallbackTicket,
        decision: @Sendable () throws -> Value,
        terminalCause: @Sendable (Error) -> Error?,
        reply: @Sendable (Result<Value, Error>) -> Void
    ) async -> Bool {
        if let beforeSettlement { await beforeSettlement() }
        guard admitted.remove(ObjectIdentifier(ticket)) != nil else { return false }
        let published = publicationGate.decide(decision, terminalCause: terminalCause, reply: reply)
        handOffFreedSlots()
        return published
    }

    /// The window's single terminal transition.
    public func fail(_ error: Error) {
        let error = publicationGate.revoke(error)
        let pending = waiterOrder[waiterHead...].compactMap { waiters[$0] }
        waiters.removeAll()
        waiterOrder.removeAll()
        waiterHead = 0
        for waiter in pending {
            waiter.resume(throwing: error)
        }
    }

    public func admittedCount() -> Int { admitted.count }
    public func waiterCount() -> Int { waiters.count }
    public func isFailed() -> Bool { publicationGate.terminalError != nil }

    /// The session has already revoked publication at its terminal source.
    /// Draining admission can run later without allowing a completed result
    /// to escape in that interval.
    func sessionEnded(_ error: Error) async {
        let hook = beforeTerminalDrain
        beforeTerminalDrain = nil
        await hook?()
        fail(error)
    }

    func testingBeforeSettlement(_ hook: @escaping @Sendable () async -> Void) {
        beforeSettlement = hook
    }

    func testingBeforeTerminalDrain(_ hook: @escaping @Sendable () async -> Void) {
        beforeTerminalDrain = hook
    }

    private func admitTicket() -> PfsCallbackTicket {
        let ticket = PfsCallbackTicket()
        admitted.insert(ObjectIdentifier(ticket))
        return ticket
    }

    private func handOffFreedSlots() {
        guard publicationGate.terminalError == nil else { return }
        while admitted.count < capacity, waiterHead < waiterOrder.count {
            let waiterID = waiterOrder[waiterHead]
            waiterHead += 1
            guard let waiter = waiters.removeValue(forKey: waiterID) else { continue }
            waiter.resume(returning: admitTicket())
        }
        if waiterHead >= 256, waiterHead * 2 >= waiterOrder.count {
            waiterOrder.removeFirst(waiterHead)
            waiterHead = 0
        }
    }

    private func cancelWaiter(_ waiterID: UUID) {
        guard let waiter = waiters.removeValue(forKey: waiterID) else { return }
        waiter.resume(throwing: PfsLocalClientError.cancelled)
    }
}

/// Consumes the one event stream bound to a volume's pfslocal connection and
/// drains admissions after its end or a terminal attach state. The client
/// has already revoked publication. There is no frontend heartbeat: the
/// daemon is the only authority-renewal owner, and loss of this binding is
/// the frontend's signal.
enum PfsAttachEventMonitor {
    /// The terminal cause an event carries, or nil for a healthy attach.
    static func terminalCause(of event: PfsEvent) -> PfsLocalClientError? {
        switch event.kind {
        case let .attachState(state)?:
            switch state.state {
            case .attached:
                return nil
            case .degraded:
                return .daemon(errno: EIO, message: "attach degraded: \(state.detail)")
            case .detaching:
                return .daemon(errno: ENXIO, message: "attach is detaching")
            case .unspecified, .UNRECOGNIZED:
                return .invalidFrame("attach state event names no defined state")
            }
        case .cacheProof?:
            return nil
        case nil:
            return .invalidFrame("event has no body")
        }
    }

    /// The client revokes publication when it receives a terminal event or
    /// closes the connection. This consumer drains window waiters afterward;
    /// its scheduling is never the publication boundary.
    static func run(
        events: AsyncStream<PfsEvent>,
        client: PfsLocalClient,
        window: PfsCallbackWindow,
        cache: PfsKernelCache? = nil
    ) async {
        var cause = PfsLocalClientError.connectionClosed
        for await event in events {
            if case let .cacheProof(proof)? = event.kind { cache?.proof(proof.horizonNanos, authorization: proof.authorizationDeadlineUnixNanos) }
            if let terminal = terminalCause(of: event) {
                cause = terminal
                break
            }
        }
        let terminal = client.publicationGate.terminalError ?? cause
        pfsClientLogger.error(
            "FSKit volume session ended: \(String(describing: terminal), privacy: .public)"
        )
        await cache?.withdraw(.revoke)
        await window.sessionEnded(terminal)
        await client.close(error: terminal)
    }
}
