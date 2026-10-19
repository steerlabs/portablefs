import Foundation
import FSKit
import OSLog
@preconcurrency import Darwin
@preconcurrency import Dispatch

/// One cache owner shared with VolumeCore. The publication gate orders grant
/// replies against withdrawal admission; no lock crosses the synchronous kernel
/// call. Pins keep reentrant final-close/reclaim cleanup behind its completion.
final class PfsKernelCache: @unchecked Sendable {
    enum Action: Sendable { case invalidate, revoke }
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
    typealias Actuator = @Sendable (PortableFSItem, Action) -> Error?
    private struct Entry {
        let item: PortableFSItem
        var cached = false
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
    private var expiry: Task<Void, Never>?
    private var withdrawal: Task<Error?, Never>?
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
            if access == .unspecified { entries[ObjectIdentifier(item)]?.cached = false }
        }
    }

    func retiring(_ item: PortableFSItem, _ retiring: Bool) {
        lock.withLock { entries[ObjectIdentifier(item)]?.retiring = retiring }
    }

    func forget(_ item: PortableFSItem) {
        lock.withLock { _ = entries.removeValue(forKey: ObjectIdentifier(item)) }
    }

    /// Called inside the publication gate, at the actual framework reply.
    /// A write-only description never grants permission to fill a read cache.
    func grant(_ item: PortableFSItem, requested: Bool, ownsRead: Bool) throws -> Bool {
        let now: UInt64
        do { now = try clock() } catch { throw AdmissionFailure.clock(error) }
        return try lock.withLock {
            if authorizationDeadline != 0, authorizationNow() >= Double(authorizationDeadline) {
                throw AdmissionFailure.authorizationExpired
            }
            guard let entry = entries[ObjectIdentifier(item)], !entry.retiring, entry.access != .unspecified else {
                throw POSIXError(.EBADF)
            }
            guard requested, ownsRead, entry.access.grantsRead, item.kind == .file, !revoked,
                  withdrawing == 0, horizon > now else { return false }
            entries[ObjectIdentifier(item)]?.cached = true
            return true
        }
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
                                await self.withdraw(.invalidate, expiredDeadline: deadline)
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

    func deferCleanup(_ item: PortableFSItem, _ cleanup: @escaping @Sendable () async -> Void) -> Bool {
        lock.withLock {
            let id = ObjectIdentifier(item)
            guard entries[id]?.pins ?? 0 > 0 else { return false }
            entries[id]?.cleanup.append(cleanup)
            return true
        }
    }

    func withdraw(_ action: Action, expiredDeadline: UInt64? = nil) async {
        let task: Task<Error?, Never>? = gate.synchronized {
            lock.withLock {
                if let expiredDeadline, horizon != expiredDeadline { return nil }
                if action == .revoke {
                    if revoked { return withdrawal }
                    revoked = true
                    horizon = 0
                    expiry?.cancel()
                } else {
                    // A second expiry cannot overtake a withdrawal already in
                    // flight. Terminal revocation queues behind it instead.
                    guard !revoked, withdrawing == 0 else { return nil }
                }
                withdrawing += 1
                let work: [(PortableFSItem, Actuator?)] = entries.keys.compactMap { id in
                    guard let entry = entries[id], action == .revoke || entry.cached else { return nil }
                    entries[id]?.pins += 1
                    return (entry.item, actuator)
                }
                let previous = withdrawal
                let task = Task.detached { [self] in
                    _ = await previous?.value
                    return await perform(action, work: work)
                }
                withdrawal = task
                return task
            }
        }
        guard let task else { return }
        if let error = await task.value {
            if action != .revoke { await withdraw(.revoke) }
            await failure(error)
        }
    }

    private func perform(_ action: Action, work: [(PortableFSItem, Actuator?)]) async -> Error? {
        // FSKit's synchronous request can wait for callbacks into Swift. Keep
        // that wait off the cooperative pool; the withdrawal owner and pins
        // still span the entire request, with neither module lock held.
        var firstError: Error?
        for (item, actuator) in work {
            let error: Error? = await withCheckedContinuation { continuation in
                blockingCalls.async {
                    continuation.resume(returning: actuator?(item, action) ?? (actuator == nil ? POSIXError(.ENOTSUP) : nil))
                }
            }
            logger.notice("cache withdrawal file=\(item.fileID) action=\(action == .revoke ? "revoke" : "invalidate", privacy: .public) errno=\((error as NSError?)?.code ?? 0)")
            if let error {
                if firstError == nil { firstError = error }
                gate.revoke(error)
            }
            let cleanup = lock.withLock {
                let id = ObjectIdentifier(item)
                if error == nil { entries[id]?.cached = false }
                entries[id]?.pins -= 1
                guard entries[id]?.pins == 0 else { return [@Sendable () async -> Void]() }
                let pending = entries[id]?.cleanup ?? []
                entries[id]?.cleanup.removeAll()
                return pending
            }
            Task.detached { for operation in cleanup { await operation() } }
        }
        lock.withLock { if withdrawing > 0 { withdrawing -= 1 } }
        // Failure leaves the kernel cache unchanged. The caller terminates
        // serving and requests revoke, after this task has released its pins.
        return firstError
    }
}
