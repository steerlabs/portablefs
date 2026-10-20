import Foundation
import FSKit
import OSLog
@preconcurrency import Darwin
@preconcurrency import Dispatch

/// One cache owner shared with VolumeCore. The publication gate orders grant
/// replies against withdrawal admission; no lock crosses the synchronous kernel
/// call. Pins keep reentrant final-close/reclaim cleanup behind its completion.
final class PfsKernelCache: @unchecked Sendable {
    enum Mode: Sendable { case none, readWithCache, readWriteWithCache }
    enum Coherency: Sendable { case noCache, readCache, writeThrough }
    enum Action: Sendable { case push, pushInvalidate, revoke }
    struct Transition: Sendable {
        let mode: Mode
        let coherency: Coherency
        let action: Action
    }
    enum AdmissionFailure: Error {
        case authorizationExpired
        case clock(Error)
        var cause: Error {
            switch self {
            case .authorizationExpired: return POSIXError(.EACCES)
            case let .clock(error): return error
            }
        }
    }
    typealias Actuator = @Sendable (PortableFSItem, Transition) -> Error?
    private struct Entry {
        let item: PortableFSItem
        var mode = Mode.none
        var coherency = Coherency.noCache
        let ownershipID = UUID()
        var retiring = false
        var access = PfsOpenMode.unspecified
        var pins = 0
        var cleanup: [@Sendable () async -> Void] = []
    }
    private let lock = NSLock()
    private let gate: PfsSessionPublicationGate
    private let clock: @Sendable () throws -> UInt64
    private let authorizationNow: @Sendable () -> Double
    private let beforeAuthorizationExpiry: @Sendable () async -> Void
    private let failure: @Sendable (Error) async -> Void
    private var actuator: Actuator?
    private var entries: [ObjectIdentifier: Entry] = [:]
    private var horizon: UInt64 = 0
    private var authorizationDeadline: UInt64 = 0
    private var proofID = UUID()
    private var withdrawing = 0
    private var revoked = false
    private var unmounting = false
    private var expiry: Task<Void, Never>?
    private var withdrawal: Task<Error?, Never>?
    private var withdrawalAction: Action?
    private let logger = Logger(subsystem: "dev.portablefs.fskit", category: "KernelCache")
    private let blockingCalls = DispatchQueue(label: "dev.portablefs.fskit.cache-control", qos: .userInitiated)

    init(gate: PfsSessionPublicationGate,
         clock: @escaping @Sendable () throws -> UInt64 = PfsKernelCache.continuousNanos,
         authorizationNow: @escaping @Sendable () -> Double = { Date().timeIntervalSince1970 * 1e9 },
         beforeAuthorizationExpiry: @escaping @Sendable () async -> Void = {},
         failure: @escaping @Sendable (Error) async -> Void) {
        self.gate = gate
        self.clock = clock
        self.authorizationNow = authorizationNow
        self.beforeAuthorizationExpiry = beforeAuthorizationExpiry
        self.failure = failure
    }

    static func continuousNanos() throws -> UInt64 {
        var now = timespec()
        guard clock_gettime(CLOCK_MONOTONIC_RAW, &now) == 0,
              now.tv_sec >= 0, now.tv_nsec >= 0 else {
            throw POSIXError(.EIO)
        }
        let (seconds, overflow) = UInt64(now.tv_sec).multipliedReportingOverflow(by: 1_000_000_000)
        let (value, additionOverflow) = seconds.addingReportingOverflow(UInt64(now.tv_nsec))
        guard !overflow, !additionOverflow else { throw POSIXError(.EOVERFLOW) }
        return value
    }

    func install(_ actuator: @escaping Actuator) {
        lock.withLock { self.actuator = actuator }
    }

    func retain(_ item: PortableFSItem) {
        lock.withLock {
            if entries[ObjectIdentifier(item)] == nil {
                entries[ObjectIdentifier(item)] = Entry(item: item)
            }
        }
    }

    func ownership(_ item: PortableFSItem, access: PfsOpenMode) {
        lock.withLock {
            entries[ObjectIdentifier(item)]?.access = access
            if access == .unspecified { entries[ObjectIdentifier(item)]?.coherency = .noCache }
        }
    }

    func retiring(_ item: PortableFSItem, _ retiring: Bool) {
        lock.withLock { entries[ObjectIdentifier(item)]?.retiring = retiring }
    }

    func forget(_ item: PortableFSItem) {
        lock.withLock { _ = entries.removeValue(forKey: ObjectIdentifier(item)) }
    }

    /// Called inside the publication gate, at the actual framework reply.
    /// Cache fills require an authority-granted retained read description,
    /// including when the application descriptor itself is O_WRONLY.
    /// Writers get writeThrough: each write(2) reaches the authority before it
    /// returns, so quota, space and I/O errors surface at that write instead
    /// of as a deferred EIO at fsync or close.
    func grant(_ item: PortableFSItem, requested: Mode) throws -> Coherency {
        let now: UInt64
        do { now = try clock() } catch { throw AdmissionFailure.clock(error) }
        return try lock.withLock {
            try checkAuthorization()
            guard let entry = entries[ObjectIdentifier(item)], !entry.retiring, entry.access != .unspecified else {
                throw POSIXError(.EBADF)
            }
            guard requested != .none, entry.access.grantsRead, item.kind == .file, !revoked,
                  !unmounting, withdrawing == 0, horizon > now else { return .noCache }
            let coherency: Coherency = requested == .readWriteWithCache && entry.access.grantsWrite
                ? .writeThrough : .readCache
            entries[ObjectIdentifier(item)]?.mode = requested
            entries[ObjectIdentifier(item)]?.coherency = coherency
            return coherency
        }
    }

    /// Avoid acquiring optional rights when a cache grant is already
    /// ineligible. This is only an acquisition check: grant rechecks everything
    /// at publication after the authority await and any intervening withdrawal.
    func canAcquireRead(_ item: PortableFSItem) throws -> Bool {
        let now: UInt64
        do { now = try clock() } catch { throw AdmissionFailure.clock(error) }
        return try lock.withLock {
            try checkAuthorization()
            guard let entry = entries[ObjectIdentifier(item)] else { return false }
            return item.kind == .file && !entry.retiring && !revoked && !unmounting
                && withdrawing == 0 && horizon > now
        }
    }

    private func checkAuthorization() throws {
        if authorizationDeadline != 0, authorizationNow() >= Double(authorizationDeadline) {
            throw AdmissionFailure.authorizationExpired
        }
    }

    /// No callback slot or source/lifecycle gate may span this wait. The push
    /// itself reenters ordinary durable WRITE callbacks on the same connection.
    /// writeThrough delivers write(2) synchronously; a push covers whatever
    /// the kernel still holds dirty for a write-cached item, such as pages
    /// stored through a writable mapping.
    func push(_ items: [PortableFSItem]) async throws {
        try await change(.push, items: items)
    }

    func drainForUnmount() async throws {
        gate.synchronized { lock.withLock { unmounting = true } }
        try await change(.pushInvalidate)
    }

    func proof(_ deadline: UInt64, authorization: UInt64 = 0) {
        gate.whileLive {
            lock.withLock {
                guard !revoked else { return }
                horizon = deadline
                authorizationDeadline = authorization
                let id = UUID()
                proofID = id
                expiry?.cancel()
                expiry = Task.detached { [weak self] in
                    guard let self else { return }
                    do {
                        var invalidated = false
                        while true {
                            try Task.checkCancellation()
                            let now = try self.clock()
                            let remaining = Double(authorization) - self.authorizationNow()
                            if authorization != 0, remaining <= 0 {
                                await self.beforeAuthorizationExpiry()
                                if await self.terminateProof(id, error: POSIXError(.EACCES), expiredAuthorization: authorization) { return }
                                continue
                            }
                            if now >= deadline, !invalidated {
                                await self.withdraw(.pushInvalidate, expiredDeadline: deadline)
                                invalidated = true
                                continue
                            }
                            let cacheWait = invalidated ? UInt64.max : deadline - now
                            let authWait = authorization == 0 ? UInt64.max : UInt64(remaining)
                            let wait = min(cacheWait, authWait)
                            if wait == UInt64.max { return }
                            try await Task.sleep(nanoseconds: wait)
                        }
                    } catch is CancellationError {
                    } catch {
                        _ = await self.terminateProof(id, error: error)
                    }
                }
            }
        }
    }

    private func terminateProof(_ id: UUID, error: Error, expiredAuthorization: UInt64? = nil) async -> Bool {
        var waitAgain = false
        let cause = gate.revoke {
            lock.withLock {
                guard !revoked, proofID == id else { return nil }
                if let expiredAuthorization {
                    guard authorizationDeadline == expiredAuthorization else { return nil }
                    if authorizationNow() < Double(expiredAuthorization) {
                        waitAgain = true
                        return nil
                    }
                }
                horizon = 0
                return error
            }
        }
        guard let cause else { return !waitAgain }
        await withdraw(.revoke)
        await failure(cause)
        return true
    }

    func testingExpiryTask() -> Task<Void, Never>? { lock.withLock { expiry } }

    /// Reentrant cleanup acknowledges the kernel callback without releasing
    /// resources still used by setCacheState. The last pin owns that cleanup.
    func isPinned(_ item: PortableFSItem) -> Bool {
        lock.withLock { entries[ObjectIdentifier(item)]?.pins ?? 0 > 0 }
    }

    func testingPinCount(_ item: PortableFSItem) -> Int {
        lock.withLock { entries[ObjectIdentifier(item)]?.pins ?? 0 }
    }

    func deferCleanup(_ item: PortableFSItem, _ cleanup: @escaping @Sendable () async -> Void) -> Bool {
        lock.withLock {
            let id = ObjectIdentifier(item)
            guard entries[id]?.pins ?? 0 > 0 else { return false }
            entries[id]?.cleanup.append(cleanup)
            return true
        }
    }

    func withdraw(_ action: Action, expiredDeadline: UInt64? = nil) async {
        do { try await change(action, expiredDeadline: expiredDeadline) }
        catch { /* change has latched and reported the failure. */ }
    }

    private struct Work: Sendable {
        let item: PortableFSItem
        let ownershipID: UUID
        let transition: Transition
        let actuator: Actuator?
    }

    private func change(_ action: Action, items: [PortableFSItem]? = nil, expiredDeadline: UInt64? = nil) async throws {
        if action == .revoke { gate.revoke(PfsLocalClientError.shutdown) }
        let task: Task<Error?, Never>? = gate.synchronized {
            lock.withLock {
                if let expiredDeadline, horizon != expiredDeadline { return nil }
                if action == .revoke {
                    if revoked { return withdrawal }
                    revoked = true
                    horizon = 0
                    expiry?.cancel()
                } else if revoked { return withdrawal }
                if action == .pushInvalidate, withdrawing > 0, withdrawalAction == .pushInvalidate {
                    return withdrawal
                }
                let selected = items.map { Set($0.map(ObjectIdentifier.init)) }
                let work: [Work] = entries.keys.compactMap { id in
                    guard let entry = entries[id], selected == nil || selected?.contains(id) == true,
                          action == .revoke || (action == .push ? entry.coherency == .writeThrough : entry.coherency != .noCache)
                    else { return nil }
                    entries[id]?.pins += 1
                    let transition = Transition(mode: action == .push ? entry.mode : .none,
                                                coherency: action == .push ? entry.coherency : .noCache, action: action)
                    return Work(item: entry.item, ownershipID: entry.ownershipID, transition: transition, actuator: actuator)
                }
                // An old expiry can arrive after a completed downgrade. It
                // has no remaining cache state to withdraw and must not start
                // a redundant transition that suppresses a renewed grant.
                guard !work.isEmpty else { return nil }
                withdrawing += 1
                let previous = withdrawal
                let task = Task.detached { [self] in
                    _ = await previous?.value
                    return await perform(work: work)
                }
                withdrawal = task
                withdrawalAction = action
                return task
            }
        }
        if let error = await task?.value {
            if action != .revoke { await withdraw(.revoke) }
            await failure(error)
            throw error
        }
        // A queued push or an in-flight successful kernel action cannot
        // certify an old owner's cut after terminal loss wins publication.
        if action != .revoke { try gate.check() }
    }

    private func perform(work: [Work]) async -> Error? {
        var firstError: Error?
        for work in work {
            let action = work.transition.action
            var error: Error? = await withCheckedContinuation { continuation in
                blockingCalls.async { [self] in
                    if action != .revoke {
                        do {
                            try gate.check()
                            try lock.withLock { try checkAuthorization() }
                        } catch {
                            continuation.resume(returning: (error as? AdmissionFailure)?.cause ?? error)
                            return
                        }
                    }
                    // A preceding downgrade may already have drained this
                    // queued cut. Do not upgrade it back to the old mode.
                    if action != .revoke,
                       lock.withLock({ entries[ObjectIdentifier(work.item)]?.coherency == .noCache }) {
                        continuation.resume(returning: nil)
                        return
                    }
                    // FSKit may synchronously wait for callbacks into Swift.
                    // Neither module lock nor a cooperative worker crosses it.
                    continuation.resume(returning: work.actuator?(work.item, work.transition)
                        ?? (work.actuator == nil ? POSIXError(.ENOTSUP) : nil))
                }
            }
            if error == nil, action != .revoke {
                gate.decide({
                    try self.lock.withLock {
                        try self.checkAuthorization()
                        let id = ObjectIdentifier(work.item)
                        guard self.entries[id]?.ownershipID == work.ownershipID,
                              self.entries[id]?.access != .unspecified else { throw POSIXError(.EBADF) }
                        if action == .pushInvalidate { self.entries[id]?.coherency = .noCache }
                    }
                }, terminalCause: { ($0 as? AdmissionFailure)?.cause ?? $0 }, reply: { result in
                    if case let .failure(cause) = result { error = cause }
                })
            }
            logger.notice("cache action file=\(work.item.fileID) action=\(String(describing: action), privacy: .public) errno=\((error as NSError?)?.code ?? 0)")
            if let error {
                if firstError == nil { firstError = error }
                gate.revoke(error)
            }
            let cleanup = lock.withLock {
                let id = ObjectIdentifier(work.item)
                if error == nil, action == .revoke { entries[id]?.coherency = .noCache }
                entries[id]?.pins -= 1
                guard entries[id]?.pins == 0 else { return [@Sendable () async -> Void]() }
                let pending = entries[id]?.cleanup ?? []
                entries[id]?.cleanup.removeAll()
                return pending
            }
            Task.detached { for operation in cleanup { await operation() } }
        }
        lock.withLock { if withdrawing > 0 { withdrawing -= 1 } }
        return firstError
    }
}
