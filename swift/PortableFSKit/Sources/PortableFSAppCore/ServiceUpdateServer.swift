import CryptoKit
import Darwin
import Foundation
import Security

public final class PortableFSDServiceUpdateServer: @unchecked Sendable {
    public enum StartupDisposition: Equatable, Sendable {
        case normal
        case installerControlled
    }

    public struct Callbacks: @unchecked Sendable {
        public let quiesceNormalLifecycle: () throws -> Void
        public let resumeNormalLifecycle: () -> Void
        fileprivate let prepareHostExit: () throws -> Void
        fileprivate let requestHostExit: () -> Void

        public init(
            quiesceNormalLifecycle: @escaping () throws -> Void,
            resumeNormalLifecycle: @escaping () -> Void,
            prepareHostExit: @escaping () throws -> Void = {},
            requestHostExit: @escaping () -> Void
        ) {
            self.quiesceNormalLifecycle = quiesceNormalLifecycle
            self.resumeNormalLifecycle = resumeNormalLifecycle
            self.prepareHostExit = prepareHostExit
            self.requestHostExit = requestHostExit
        }

        /// The only host-termination boundary. Every exit first closes and
        /// re-proves the exact listener name; an optional acknowledgement is
        /// written only after that proof. Once absence is proven, a lost reply
        /// still exits so the token holder can reconcile the durable phase.
        func exitHost(
            acknowledging: (() throws -> Void)? = nil
        ) throws {
            try prepareHostExit()
            do {
                try acknowledging?()
            } catch {
                requestHostExit()
                throw error
            }
            requestHostExit()
        }
    }

    public let startupDisposition: StartupDisposition

    private let listener: PortableFSDUpdateListener
    private let handler: PortableFSDServiceUpdateSessionHandler
    private let stateLock = NSLock()
    private var stopped = false

    public static func start(
        bundle: Bundle = .main,
        callbacks: Callbacks
    ) throws -> PortableFSDServiceUpdateServer {
        let store = try PortableFSDUpdateLeaseStore.production()
        let sealed = try PortableFSDServiceCoordinator.sealedReleaseIdentity(
            bundle: bundle
        )
        let lease = try store.load()
        let disposition: StartupDisposition
        if let lease {
            try Self.validateStartupLease(lease, sealed: sealed, now: Self.nowMilliseconds())
            disposition = lease.phase.isComplete ? .normal : .installerControlled
        } else {
            disposition = .normal
        }
        let listener = try PortableFSDUpdateListener(store: store)
        let actions = PortableFSDServiceUpdateActions(
            sealedRelease: { sealed },
            proveActive: { release in
                try PortableFSDServiceCoordinator.proveActiveInstallerRelease(
                    expectedRelease: release,
                    bundle: bundle
                )
            },
            prepareOld: {
                try PortableFSDServiceCoordinator.prepareForInstallerUpdate(
                    bundle: bundle
                )
            },
            activate: { release in
                try PortableFSDServiceCoordinator.activateForInstaller(
                    expectedRelease: release,
                    bundle: bundle
                )
            },
            fence: { release in
                try PortableFSDServiceCoordinator.fenceForInstaller(
                    expectedRelease: release,
                    bundle: bundle
                )
            },
            restoreCancelledOld: { release in
                try PortableFSDServiceCoordinator.restoreCancelledInstallerUpdate(
                    expectedRelease: release,
                    bundle: bundle
                )
            }
        )
        // The listener owns the canonical host-exit publication edge. Host
        // callbacks cannot accidentally terminate the app before its exact
        // listener inode has been closed, removed, and re-proved absent.
        let sessionCallbacks = Callbacks(
            quiesceNormalLifecycle: callbacks.quiesceNormalLifecycle,
            resumeNormalLifecycle: callbacks.resumeNormalLifecycle,
            prepareHostExit: {
                try listener.stopAndProveAbsent()
            },
            requestHostExit: callbacks.requestHostExit
        )
        let handler = PortableFSDServiceUpdateSessionHandler(
            store: store,
            actions: actions,
            callbacks: sessionCallbacks,
            nowMilliseconds: Self.nowMilliseconds
        )
        let server = PortableFSDServiceUpdateServer(
            listener: listener,
            handler: handler,
            startupDisposition: disposition
        )
        server.startAcceptLoop()
        return server
    }

    private init(
        listener: PortableFSDUpdateListener,
        handler: PortableFSDServiceUpdateSessionHandler,
        startupDisposition: StartupDisposition
    ) {
        self.listener = listener
        self.handler = handler
        self.startupDisposition = startupDisposition
    }

    deinit {
        stop()
    }

    public func stop() {
        let shouldStop = stateLock.withLock {
            guard !stopped else { return false }
            stopped = true
            return true
        }
        if shouldStop {
            listener.stop()
        }
    }

    private func startAcceptLoop() {
        Thread.detachNewThread { [weak self] in
            guard let self else { return }
            Self.runAcceptLoop(
                isStopped: {
                    self.stateLock.withLock { self.stopped }
                },
                acceptAndHandle: {
                    let connection = try self.listener.accept()
                    self.handler.handle(connection)
                    connection.close()
                },
                stop: {
                    self.stop()
                }
            )
        }
    }

    /// Runs the single authenticated listener loop. Transient accept errors
    /// are handled by `PortableFSDUpdateListener.accept()` itself; any error
    /// escaping that boundary invalidates the listener and stops it without
    /// in-process recreation.
    static func runAcceptLoop(
        isStopped: () -> Bool,
        acceptAndHandle: () throws -> Void,
        stop: () -> Void
    ) {
        while !isStopped() {
            do {
                try acceptAndHandle()
            } catch {
                if isStopped() { return }
                stop()
                return
            }
        }
    }

    private static func validateStartupLease(
        _ lease: PortableFSDUpdateLease,
        sealed: PortableFSDReleaseIdentity,
        now: Int64
    ) throws {
        try lease.validate(atUnixMilliseconds: now)
        let expected: PortableFSDReleaseIdentity
        switch lease.phase {
        case .preparingOld:
            expected = lease.oldRelease
        case .oldAbsent:
            guard sealed == lease.oldRelease || sealed == lease.targetRelease else {
                throw PortableFSDServiceUpdateServerError.releaseMismatch
            }
            return
        case .targetReady, .targetActive:
            expected = lease.targetRelease
        case .rollbackAbsent, .rollbackReady, .rollbackActive:
            expected = lease.oldRelease
        case .targetComplete:
            expected = lease.targetRelease
        case .rollbackComplete:
            expected = lease.oldRelease
        }
        guard sealed == expected else {
            throw PortableFSDServiceUpdateServerError.releaseMismatch
        }
    }

    private static func nowMilliseconds() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1_000)
    }
}

enum PortableFSDServiceUpdateServerError: Error, Equatable {
    case invalidFrame
    case invalidToken
    case invalidPhase
    case releaseMismatch
    case randomFailure
}

protocol PortableFSDUpdateConnectionIO: AnyObject {
    var peerPID: pid_t { get }
    func readFrame() throws -> Data
    func writeFrame(_ data: Data) throws
    func close()
}

extension PortableFSDUpdateConnection: PortableFSDUpdateConnectionIO {}

struct PortableFSDServiceUpdateActions: @unchecked Sendable {
    let sealedRelease: () throws -> PortableFSDReleaseIdentity
    let proveActive: (PortableFSDReleaseIdentity) throws -> Void
    let prepareOld: () throws -> PortableFSDReleaseIdentity
    let activate: (PortableFSDReleaseIdentity) throws -> Void
    let fence: (PortableFSDReleaseIdentity) throws -> Void
    let restoreCancelledOld: (PortableFSDReleaseIdentity) throws -> Void
}

final class PortableFSDServiceUpdateSessionHandler: @unchecked Sendable {
    private static let schemaVersion = 1
    private let store: PortableFSDUpdateLeaseStore
    private let actions: PortableFSDServiceUpdateActions
    private let callbacks: PortableFSDServiceUpdateServer.Callbacks
    private let nowMilliseconds: () -> Int64
    private let tokenGenerator: () throws -> String

    init(
        store: PortableFSDUpdateLeaseStore,
        actions: PortableFSDServiceUpdateActions,
        callbacks: PortableFSDServiceUpdateServer.Callbacks,
        nowMilliseconds: @escaping () -> Int64,
        tokenGenerator: @escaping () throws -> String = {
            try PortableFSDServiceUpdateSessionHandler.newToken()
        }
    ) {
        self.store = store
        self.actions = actions
        self.callbacks = callbacks
        self.nowMilliseconds = nowMilliseconds
        self.tokenGenerator = tokenGenerator
    }

    func handle(_ connection: any PortableFSDUpdateConnectionIO) {
        do {
            let first = try connection.readFrame()
            let operation = try Self.operation(in: first)
            switch operation {
            case "prepare-update":
                try handlePrepare(first, connection: connection)
            case "activate-target":
                try handleActivation(first, kind: .target, connection: connection)
            case "activate-rollback":
                try handleActivation(first, kind: .rollback, connection: connection)
            case "resume-target":
                try handleActiveResume(first, kind: .target, connection: connection)
            case "resume-rollback":
                try handleActiveResume(first, kind: .rollback, connection: connection)
            default:
                throw PortableFSDServiceUpdateServerError.invalidFrame
            }
        } catch {
            // Invalid, stale, replayed, or unauthenticated sessions receive no
            // oracle and cause no state transition.
        }
    }

    private func handlePrepare(
        _ frame: Data,
        connection: any PortableFSDUpdateConnectionIO
    ) throws {
        let request: PrepareRequest = try Self.decode(
            frame,
            keys: ["schemaVersion", "operation", "targetRelease"],
            releaseKeys: ["targetRelease"]
        )
        guard request.schemaVersion == Self.schemaVersion,
              request.operation == "prepare-update" else {
            throw PortableFSDServiceUpdateServerError.invalidPhase
        }
        try request.targetRelease.validate()
        let oldRelease = try actions.sealedRelease()
        try oldRelease.validate()
        let baseline = try store.load()
        if let baseline {
            try baseline.validate(atUnixMilliseconds: nowMilliseconds())
            guard baseline.phase.isComplete,
                  baseline.activeRelease == oldRelease else {
                throw PortableFSDServiceUpdateServerError.invalidPhase
            }
            // A completed marker is consumed only after the exact active side
            // is sealed, registered, and live. Unknown or stale state never
            // becomes a new installer transaction merely because a host ran.
            try actions.proveActive(oldRelease)
        }

        let token = try tokenGenerator()
        guard Self.validToken(token) else {
            throw PortableFSDServiceUpdateServerError.invalidToken
        }
        let created = nowMilliseconds()
        let preparing = PortableFSDUpdateLease(
            schemaVersion: Self.schemaVersion,
            phase: .preparingOld,
            tokenSHA256: Self.tokenHash(token),
            oldRelease: oldRelease,
            targetRelease: request.targetRelease,
            createdAtUnixMs: created,
            deadlineUnixMs: created + PortableFSDUpdateLease.lifetimeMilliseconds
        )
        try preparing.validate(atUnixMilliseconds: created)
        try callbacks.quiesceNormalLifecycle()
        do {
            if let baseline {
                try store.transition(from: baseline, to: preparing)
            } else {
                try store.create(preparing)
            }
        } catch {
            try recoverPreparingPublication(
                baseline: baseline,
                preparing: preparing
            )
            callbacks.resumeNormalLifecycle()
            throw error
        }

        var handoffCommitted = false
        var lifecycleResumed = false
        do {
            let preparedOld = try actions.prepareOld()
            guard preparedOld == oldRelease else {
                throw PortableFSDServiceUpdateServerError.releaseMismatch
            }
            let oldAbsent = preparing.withPhase(.oldAbsent)
            try store.transition(from: preparing, to: oldAbsent)
            try connection.writeFrame(try Self.encode(PreparedReply(
                schemaVersion: Self.schemaVersion,
                state: "prepared",
                token: token,
                hostPid: Int(getpid()),
                oldRelease: oldRelease,
                targetRelease: request.targetRelease
            )))

            let finishFrame = try connection.readFrame()
            let finish: FinishRequest = try Self.decode(
                finishFrame,
                keys: ["schemaVersion", "operation", "token"]
            )
            guard finish.schemaVersion == Self.schemaVersion,
                  Self.tokenMatches(finish.token, hash: oldAbsent.tokenSHA256),
                  try store.load() == oldAbsent else {
                throw PortableFSDServiceUpdateServerError.invalidToken
            }
            switch finish.operation {
            case "cancel":
                _ = try restoreOld(oldAbsent)
                callbacks.resumeNormalLifecycle()
                lifecycleResumed = true
                try connection.writeFrame(try Self.encode(FinishReply(
                    schemaVersion: Self.schemaVersion,
                    state: "cancelled",
                    token: token
                )))
            case "commit-exit":
                // A valid commit request is the irreversible handoff edge. If
                // the acknowledgement is lost, the durable old-absent lease
                // still lets the installer reconcile without reviving old.
                handoffCommitted = true
                // Stop and re-prove the listener name before acknowledging the
                // handoff. The accepted session remains usable after the
                // listening descriptor closes, so the reply edge is exact and
                // no stale socket can strand a tokenized installer.
                do {
                    try callbacks.exitHost {
                        try connection.writeFrame(try Self.encode(FinishReply(
                            schemaVersion: Self.schemaVersion,
                            state: "exiting",
                            token: token
                        )))
                    }
                } catch {
                    throw error
                }
            default:
                throw PortableFSDServiceUpdateServerError.invalidFrame
            }
        } catch {
            if !handoffCommitted, !lifecycleResumed {
                do {
                    try restoreVisibleOld(
                        preparing: preparing,
                        oldAbsent: preparing.withPhase(.oldAbsent)
                    )
                    callbacks.resumeNormalLifecycle()
                } catch {
                    // Leave the exact nonterminal phase for explicit recovery.
                }
            }
            throw error
        }
    }

    @discardableResult
    private func restoreOld(
        _ lease: PortableFSDUpdateLease
    ) throws -> PortableFSDUpdateLease {
        guard lease.phase == .preparingOld || lease.phase == .oldAbsent else {
            throw PortableFSDServiceUpdateServerError.invalidPhase
        }
        try actions.restoreCancelledOld(lease.oldRelease)
        let completed = lease.withPhase(.rollbackComplete)
        try transitionTerminal(from: lease, to: completed)
        return completed
    }

    private func restoreVisibleOld(
        preparing: PortableFSDUpdateLease,
        oldAbsent: PortableFSDUpdateLease
    ) throws {
        guard let current = try store.load() else {
            throw PortableFSDServiceUpdateServerError.invalidPhase
        }
        if current == preparing || current == oldAbsent {
            _ = try restoreOld(current)
            return
        }
        guard current == preparing.withPhase(.rollbackComplete) else {
            throw PortableFSDServiceUpdateServerError.invalidPhase
        }
    }

    private func recoverPreparingPublication(
        baseline: PortableFSDUpdateLease?,
        preparing: PortableFSDUpdateLease
    ) throws {
        let current = try store.load()
        if current == baseline { return }
        guard current == preparing else {
            throw PortableFSDServiceUpdateServerError.invalidPhase
        }
        if let baseline {
            try store.transition(from: preparing, to: baseline)
        } else {
            try transitionTerminal(
                from: preparing,
                to: preparing.withPhase(.rollbackComplete)
            )
        }
    }

    private enum ActivationKind {
        case target
        case rollback

        var requestOperation: String {
            self == .target ? "activate-target" : "activate-rollback"
        }
        var resumeOperation: String {
            self == .target ? "resume-target" : "resume-rollback"
        }
        var releaseKeyPath: KeyPath<PortableFSDUpdateLease, PortableFSDReleaseIdentity> {
            self == .target ? \.targetRelease : \.oldRelease
        }
        var readyPhase: PortableFSDUpdatePhase {
            self == .target ? .targetReady : .rollbackReady
        }
        var activePhase: PortableFSDUpdatePhase {
            self == .target ? .targetActive : .rollbackActive
        }
        var readyState: String { self == .target ? "target-ready" : "rollback-ready" }
        var fencedState: String { self == .target ? "target-fenced" : "rollback-fenced" }
        var acceptOperation: String { self == .target ? "accept-target" : "accept-rollback" }
        var fenceOperation: String { self == .target ? "fence-target" : "fence-rollback" }
        var activeState: String { self == .target ? "target-active" : "rollback-active" }
        var fencedPhase: PortableFSDUpdatePhase { .rollbackAbsent }
        var completionOperation: String { self == .target ? "complete-target" : "complete-rollback" }
        var completedPhase: PortableFSDUpdatePhase {
            self == .target ? .targetComplete : .rollbackComplete
        }
    }

    private func handleActivation(
        _ frame: Data,
        kind: ActivationKind,
        connection: any PortableFSDUpdateConnectionIO
    ) throws {
        let request: ActivationRequest = try Self.decode(
            frame,
            keys: ["schemaVersion", "operation", "token", "release"],
            releaseKeys: ["release"]
        )
        guard request.schemaVersion == Self.schemaVersion,
              request.operation == kind.requestOperation else {
            throw PortableFSDServiceUpdateServerError.invalidFrame
        }
        try request.release.validate()
        guard let starting = try store.load() else {
            throw PortableFSDServiceUpdateServerError.invalidPhase
        }
        try starting.validate(atUnixMilliseconds: nowMilliseconds())
        let expectedRelease = starting[keyPath: kind.releaseKeyPath]
        guard request.release == expectedRelease,
              try actions.sealedRelease() == expectedRelease,
              Self.tokenMatches(request.token, hash: starting.tokenSHA256) else {
            throw PortableFSDServiceUpdateServerError.releaseMismatch
        }
        switch kind {
        case .target:
            guard starting.phase == .oldAbsent else {
                throw PortableFSDServiceUpdateServerError.invalidPhase
            }
        case .rollback:
            guard starting.phase == .rollbackAbsent || starting.phase == .oldAbsent else {
                throw PortableFSDServiceUpdateServerError.invalidPhase
            }
        }

        var ready: PortableFSDUpdateLease?
        do {
            try actions.activate(expectedRelease)
            let next = starting.withPhase(kind.readyPhase)
            try store.transition(from: starting, to: next)
            ready = next
            try connection.writeFrame(try Self.encode(ActivationReply(
                schemaVersion: Self.schemaVersion,
                state: kind.readyState,
                token: request.token,
                hostPid: Int(getpid()),
                release: expectedRelease,
                error: nil
            )))
        } catch {
            try fenceAfterFailedActivation(
                from: ready ?? starting,
                kind: kind,
                release: expectedRelease
            )
            try callbacks.exitHost {
                try connection.writeFrame(try Self.encode(ActivationReply(
                    schemaVersion: Self.schemaVersion,
                    state: kind.fencedState,
                    token: request.token,
                    hostPid: Int(getpid()),
                    release: expectedRelease,
                    error: "PortableFS service activation failed and was fenced"
                )))
            }
            return
        }
        guard let ready else { return }

        do {
            let decisionFrame = try connection.readFrame()
            let decision: ActivationDecision = try Self.decode(
                decisionFrame,
                keys: ["schemaVersion", "operation", "token"]
            )
            guard decision.schemaVersion == Self.schemaVersion,
                  Self.tokenMatches(decision.token, hash: ready.tokenSHA256),
                  try store.load() == ready else {
                throw PortableFSDServiceUpdateServerError.invalidToken
            }
            if decision.operation == kind.fenceOperation {
                try fenceReady(
                    ready,
                    kind: kind
                )
                try callbacks.exitHost {
                    try connection.writeFrame(try Self.encode(ActivationDecisionReply(
                        schemaVersion: Self.schemaVersion,
                        state: kind.fencedState,
                        token: request.token
                    )))
                }
                return
            }
            guard decision.operation == kind.acceptOperation else {
                throw PortableFSDServiceUpdateServerError.invalidFrame
            }
            let active = ready.withPhase(kind.activePhase)
            try store.transition(from: ready, to: active)
            // Once active is durable, a lost acknowledgement is ambiguous and
            // must never cause an automatic fence or rollback.
            try connection.writeFrame(try Self.encode(ActivationDecisionReply(
                schemaVersion: Self.schemaVersion,
                state: kind.activeState,
                token: request.token
            )))
            try handleActiveCompletion(
                active,
                kind: kind,
                token: request.token,
                connection: connection
            )
        } catch {
            if (try? store.load()) == ready {
                do {
                    try fenceReady(
                        ready,
                        kind: kind
                    )
                    try callbacks.exitHost()
                } catch {
                    // A failed fence stays target/rollback-ready and is not
                    // advertised as absent.
                }
            }
            throw error
        }
    }

    /// Reconnects only the in-memory token holder to an exact durable active
    /// phase after the original accept acknowledgement was lost. This path
    /// never activates or fences a service: it proves the sealed/live active
    /// release and both transaction identities before exposing the completion
    /// edge on the replacement credentialed connection.
    private func handleActiveResume(
        _ frame: Data,
        kind: ActivationKind,
        connection: any PortableFSDUpdateConnectionIO
    ) throws {
        let request: ActivationResumeRequest = try Self.decode(
            frame,
            keys: [
                "schemaVersion", "operation", "token", "release",
                "oldRelease", "targetRelease",
            ],
            releaseKeys: ["release", "oldRelease", "targetRelease"]
        )
        guard request.schemaVersion == Self.schemaVersion,
              request.operation == kind.resumeOperation else {
            throw PortableFSDServiceUpdateServerError.invalidFrame
        }
        try request.release.validate()
        try request.oldRelease.validate()
        try request.targetRelease.validate()
        guard let active = try store.load() else {
            throw PortableFSDServiceUpdateServerError.invalidPhase
        }
        try active.validate(atUnixMilliseconds: nowMilliseconds())
        let expectedRelease = active[keyPath: kind.releaseKeyPath]
        guard active.phase == kind.activePhase,
              active.oldRelease == request.oldRelease,
              active.targetRelease == request.targetRelease,
              request.release == expectedRelease,
              try actions.sealedRelease() == expectedRelease,
              Self.tokenMatches(request.token, hash: active.tokenSHA256) else {
            throw PortableFSDServiceUpdateServerError.releaseMismatch
        }
        try actions.proveActive(expectedRelease)
        // Re-read after the live proof so another session cannot change the
        // durable phase between authorization and publication of resumability.
        guard try store.load() == active else {
            throw PortableFSDServiceUpdateServerError.invalidPhase
        }
        try connection.writeFrame(try Self.encode(ActivationResumeReply(
            schemaVersion: Self.schemaVersion,
            state: kind.activeState,
            token: request.token,
            hostPid: Int(getpid()),
            release: expectedRelease
        )))
        try handleActiveCompletion(
            active,
            kind: kind,
            token: request.token,
            connection: connection
        )
    }

    private func handleActiveCompletion(
        _ active: PortableFSDUpdateLease,
        kind: ActivationKind,
        token: String,
        connection: any PortableFSDUpdateConnectionIO
    ) throws {
        let completionFrame = try connection.readFrame()
        let completion: CompletionRequest = try Self.decode(
            completionFrame,
            keys: ["schemaVersion", "operation", "token"]
        )
        guard completion.schemaVersion == Self.schemaVersion,
              completion.operation == kind.completionOperation,
              Self.tokenMatches(completion.token, hash: active.tokenSHA256),
              try store.load() == active else {
            throw PortableFSDServiceUpdateServerError.invalidToken
        }
        try transitionTerminal(
            from: active,
            to: active.withPhase(kind.completedPhase)
        )
        callbacks.resumeNormalLifecycle()
        try connection.writeFrame(try Self.encode(CompletionReply(
            schemaVersion: Self.schemaVersion,
            state: "complete",
            token: token
        )))
    }

    private func fenceAfterFailedActivation(
        from lease: PortableFSDUpdateLease,
        kind: ActivationKind,
        release: PortableFSDReleaseIdentity
    ) throws {
        try actions.fence(release)
        let fenced = lease.withPhase(kind.fencedPhase)
        try store.transition(from: lease, to: fenced)
    }

    private func fenceReady(
        _ ready: PortableFSDUpdateLease,
        kind: ActivationKind
    ) throws {
        try actions.fence(ready[keyPath: kind.releaseKeyPath])
        let fenced = ready.withPhase(kind.fencedPhase)
        try store.transition(from: ready, to: fenced)
    }

    /// A terminal marker is authoritative only after its directory fsync
    /// succeeds. If rename became visible but durability failed, restore the
    /// exact prior nonterminal phase before returning the error so no client can
    /// race a transient complete marker and reinterpret it as success.
    private func transitionTerminal(
        from expected: PortableFSDUpdateLease,
        to completed: PortableFSDUpdateLease
    ) throws {
        do {
            try store.transition(from: expected, to: completed)
        } catch {
            if try store.load() == completed {
                try store.transition(from: completed, to: expected)
            }
            throw error
        }
    }

    private struct PrepareRequest: Decodable {
        let schemaVersion: Int
        let operation: String
        let targetRelease: PortableFSDReleaseIdentity
    }
    private struct PreparedReply: Encodable {
        let schemaVersion: Int
        let state: String
        let token: String
        let hostPid: Int
        let oldRelease: PortableFSDReleaseIdentity
        let targetRelease: PortableFSDReleaseIdentity
    }
    private struct FinishRequest: Decodable {
        let schemaVersion: Int
        let operation: String
        let token: String
    }
    private struct FinishReply: Encodable {
        let schemaVersion: Int
        let state: String
        let token: String
    }
    private struct ActivationRequest: Decodable {
        let schemaVersion: Int
        let operation: String
        let token: String
        let release: PortableFSDReleaseIdentity
    }
    private struct ActivationReply: Encodable {
        let schemaVersion: Int
        let state: String
        let token: String
        let hostPid: Int
        let release: PortableFSDReleaseIdentity
        let error: String?
    }
    private struct ActivationResumeRequest: Decodable {
        let schemaVersion: Int
        let operation: String
        let token: String
        let release: PortableFSDReleaseIdentity
        let oldRelease: PortableFSDReleaseIdentity
        let targetRelease: PortableFSDReleaseIdentity
    }
    private struct ActivationResumeReply: Encodable {
        let schemaVersion: Int
        let state: String
        let token: String
        let hostPid: Int
        let release: PortableFSDReleaseIdentity
    }
    private struct ActivationDecision: Decodable {
        let schemaVersion: Int
        let operation: String
        let token: String
    }
    private struct ActivationDecisionReply: Encodable {
        let schemaVersion: Int
        let state: String
        let token: String
    }
    private struct CompletionRequest: Decodable {
        let schemaVersion: Int
        let operation: String
        let token: String
    }
    private struct CompletionReply: Encodable {
        let schemaVersion: Int
        let state: String
        let token: String
    }

    private static func operation(in frame: Data) throws -> String {
        let payload = try payloadWithoutNewline(frame)
        try PortableFSDStrictJSON.validate(payload)
        guard let root = try JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let operation = root["operation"] as? String else {
            throw PortableFSDServiceUpdateServerError.invalidFrame
        }
        return operation
    }

    private static func decode<T: Decodable>(
        _ frame: Data,
        keys: Set<String>,
        releaseKeys: Set<String> = []
    ) throws -> T {
        let payload = try payloadWithoutNewline(frame)
        try PortableFSDStrictJSON.validate(payload)
        guard let root = try JSONSerialization.jsonObject(with: payload) as? [String: Any],
              Set(root.keys) == keys else {
            throw PortableFSDServiceUpdateServerError.invalidFrame
        }
        let expectedReleaseKeys: Set<String> = [
            "codeDirectoryHash", "executableSHA256", "daemonVersion",
            "identitySchema", "controlProtocol", "pfslocalMajor", "pfslocalMinor",
        ]
        for key in releaseKeys {
            guard let release = root[key] as? [String: Any],
                  Set(release.keys) == expectedReleaseKeys else {
                throw PortableFSDServiceUpdateServerError.invalidFrame
            }
        }
        do {
            return try JSONDecoder().decode(T.self, from: payload)
        } catch {
            throw PortableFSDServiceUpdateServerError.invalidFrame
        }
    }

    private static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        var data = try encoder.encode(value)
        data.append(0x0a)
        guard data.count <= PortableFSDUpdateConnection.maximumFrameBytes else {
            throw PortableFSDServiceUpdateServerError.invalidFrame
        }
        return data
    }

    private static func payloadWithoutNewline(_ frame: Data) throws -> Data {
        guard !frame.isEmpty,
              frame.count <= PortableFSDUpdateConnection.maximumFrameBytes,
              frame.last == 0x0a,
              !frame.dropLast().contains(0x0a) else {
            throw PortableFSDServiceUpdateServerError.invalidFrame
        }
        return frame.dropLast()
    }

    private static func newToken() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw PortableFSDServiceUpdateServerError.randomFailure
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func tokenHash(_ token: String) -> String {
        SHA256.hash(data: Data(token.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }

    private static func tokenMatches(_ token: String, hash expected: String) -> Bool {
        guard validToken(token) else { return false }
        let actual = Array(tokenHash(token).utf8)
        let expectedBytes = Array(expected.utf8)
        guard actual.count == expectedBytes.count else { return false }
        var difference: UInt8 = 0
        for index in actual.indices {
            difference |= actual[index] ^ expectedBytes[index]
        }
        return difference == 0
    }

    private static func validToken(_ token: String) -> Bool {
        token.utf8.count == 64 && token.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }
}

private extension PortableFSDUpdateLease {
    func withPhase(_ phase: PortableFSDUpdatePhase) -> PortableFSDUpdateLease {
        PortableFSDUpdateLease(
            schemaVersion: schemaVersion,
            phase: phase,
            tokenSHA256: tokenSHA256,
            oldRelease: oldRelease,
            targetRelease: targetRelease,
            createdAtUnixMs: createdAtUnixMs,
            deadlineUnixMs: deadlineUnixMs
        )
    }

    func validate(atUnixMilliseconds now: Int64) throws {
        try validate()
        guard now >= createdAtUnixMs - 60_000 else {
            throw PortableFSDUpdateLeaseError.invalidContract
        }
        if phase.isComplete { return }
        guard now < deadlineUnixMs else {
            throw PortableFSDUpdateLeaseError.invalidContract
        }
    }

    var activeRelease: PortableFSDReleaseIdentity? {
        switch phase {
        case .targetComplete:
            targetRelease
        case .rollbackComplete:
            oldRelease
        default:
            nil
        }
    }
}

private extension PortableFSDUpdatePhase {
    var isComplete: Bool {
        self == .targetComplete || self == .rollbackComplete
    }
}
