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

    func check() throws {
        if let error = terminalError { throw error }
    }

    @discardableResult
    func decide(_ reply: (Error?) -> Void) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        reply(terminal)
        return terminal == nil
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
    /// False means a duplicate settlement or a terminal verdict; either way
    /// the caller must not publish its original successful result.
    public func settle(
        _ ticket: PfsCallbackTicket,
        reply: @Sendable (_ terminal: Error?) -> Void
    ) async -> Bool {
        if let beforeSettlement { await beforeSettlement() }
        guard admitted.remove(ObjectIdentifier(ticket)) != nil else { return false }
        let published = publicationGate.decide(reply)
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
        window: PfsCallbackWindow
    ) async {
        var cause = PfsLocalClientError.connectionClosed
        for await event in events {
            if let terminal = terminalCause(of: event) {
                cause = terminal
                break
            }
        }
        let terminal = client.publicationGate.terminalError ?? cause
        pfsClientLogger.error(
            "FSKit volume session ended: \(String(describing: terminal), privacy: .public)"
        )
        await window.sessionEnded(terminal)
        await client.close(error: terminal)
    }
}
