import Foundation
@preconcurrency import Darwin

/// One admitted FSKit callback. It occupies one window slot from admission
/// until its settlement has replied to FSKit.
public final class PfsCallbackTicket: Sendable {
    fileprivate init() {}
}

/// Bounds the FSKit callbacks one volume executes at once.
///
/// Kernel open, getattr and reclaim bursts can be far larger than the
/// daemon's request window. Each callback holds a slot from admission until
/// its reply has returned to FSKit, so a burst queues here in FIFO order
/// instead of piling requests onto the session. A freed slot is handed
/// directly to the oldest waiter, so a later arrival can never overtake it.
///
/// The window has exactly one terminal path: `fail` refuses every later
/// admission and wakes every waiter with the terminal error. The attach event
/// monitor invokes it on connection loss and on a degraded or detaching
/// attach, and volume teardown invokes it too.
///
/// Final publication and terminal revocation are one serialized decision on
/// this actor. An admitted callback replies to FSKit only inside `settle`:
/// before `fail` it replies with its own outcome, after `fail` with the
/// terminal error. A callback that already holds a result therefore cannot
/// install it into FSKit once the session has ended, and no terminal
/// transition can interleave between the decision and the reply.
public actor PfsCallbackWindow {
    public static let defaultCapacity = 128

    private let capacity: Int
    private var terminal: Error?
    private var admitted: Set<ObjectIdentifier> = []
    private var waiters: [UUID: CheckedContinuation<PfsCallbackTicket, Error>] = [:]
    private var waiterOrder: [UUID] = []
    private var waiterHead = 0

    public init(capacity: Int = PfsCallbackWindow.defaultCapacity) {
        precondition(capacity > 0)
        self.capacity = capacity
    }

    /// Waits for a slot. Cancellation while queued surfaces as the client's
    /// cancellation verdict; a slot already handed to this caller is returned
    /// and must still be published.
    public func admit() async throws -> PfsCallbackTicket {
        if Task.isCancelled { throw PfsLocalClientError.cancelled }
        if let terminal { throw terminal }
        if admitted.count < capacity, waiters.isEmpty {
            return admitTicket()
        }
        let waiterID = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                if let terminal {
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

    /// The callback's final publication. `reply` runs here, on the actor
    /// that serializes `fail`: with nil while the window is live, so the
    /// callback replies with its own outcome, or with the terminal error once
    /// the window failed, so a publication that lost to terminal failure
    /// replies with that error instead. Either way the slot is released after
    /// the reply returned. Returns whether the callback's own outcome reached
    /// FSKit; the caller settles its publication unit as published only then.
    ///
    /// A ticket settles exactly once. A second settlement runs nothing and
    /// frees no slot.
    public func settle(
        _ ticket: PfsCallbackTicket,
        reply: @Sendable (_ terminal: Error?) -> Void
    ) -> Bool {
        guard admitted.remove(ObjectIdentifier(ticket)) != nil else { return false }
        reply(terminal)
        handOffFreedSlots()
        return terminal == nil
    }

    /// The window's single terminal transition.
    public func fail(_ error: Error) {
        guard terminal == nil else { return }
        terminal = error
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
    public func isFailed() -> Bool { terminal != nil }

    private func admitTicket() -> PfsCallbackTicket {
        let ticket = PfsCallbackTicket()
        admitted.insert(ObjectIdentifier(ticket))
        return ticket
    }

    private func handOffFreedSlots() {
        guard terminal == nil else { return }
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
/// turns its end, or a terminal attach state, into the session's terminal
/// transition. There is no frontend heartbeat: the daemon is the only
/// authority-renewal owner, and loss of this binding is the frontend's signal.
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

    /// Runs until the stream ends or reports a terminal state, then fails
    /// the window, which decides every later publication as revoked, wakes
    /// its waiters and refuses admission, and closes the client, which fails
    /// every in-flight request and ends the session. The window fails first
    /// so the terminal decision precedes the requests' failures.
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
        pfsClientLogger.error(
            "FSKit volume session ended: \(String(describing: cause), privacy: .public)"
        )
        await window.fail(cause)
        await client.close()
    }
}
