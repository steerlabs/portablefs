import Foundation

public struct WorkspaceSleepNotification {
    public let id: UInt64
    public let arrivedAt: UInt64
    public init(id: UInt64, arrivedAt: UInt64) { self.id = id; self.arrivedAt = arrivedAt }
}
public enum WorkspacePowerEvent { case sleep(WorkspaceSleepNotification), wake, cancelledSleep, darkWake, unknown }
public enum WorkspacePhase: String { case stopped, starting, running, draining, pausing, pausedCold, pausedDiscard, resuming, recovering, stopping, unknown }
public enum WorkspaceVMState { case stopped, running, paused, unknown }

// The model, adapter entry points and every callback execute on MainActor.
// The VZ adapter uses the main serial dispatch queue as its VM-owner queue.
// Descriptor I/O uses dedicated queues; no operation blocks MainActor.
// Completion proves the framework finished the operation on this exact VM.
@MainActor public protocol WorkspaceVirtualMachine {
    func start(completion: @escaping (Result<Void, Error>) -> Void)
    func pause(completion: @escaping (Result<Void, Error>) -> Void)
    func resume(completion: @escaping (Result<Void, Error>) -> Void)
    func stop(completion: @escaping (Result<Void, Error>) -> Void)
    func shutdown(completion: @escaping (Result<Void, Error>) -> Void)
    func inspect(completion: @escaping (WorkspaceVMState) -> Void)
}
@MainActor public protocol WorkspacePowerNotifications {
    // Timestamp on the native notification callback, before queueing its actor
    // hop. IDs are nonzero and strictly increasing within this registration.
    func register(handler: @escaping (WorkspacePowerEvent) -> Void) throws
    func acknowledgeSleep(notificationID: UInt64, fenced: Bool)
    func unregister()
}
@MainActor public protocol WorkspaceGuestChannel {
    // True when no queued or active control exchange remains. Hello connection
    // and proof reads may still have an armed deadline during startup; the
    // coordinator cannot reach pause before Hello completes.
    var isIdle: Bool { get }
    func hello(_ host: WorkspaceHello, deadline: UInt64, completion: @escaping (Result<WorkspaceHello, Error>) -> Void)
    func suspend(_ request: WorkspaceSuspension, deadline: UInt64, completion: @escaping (Result<WorkspaceSuspendAck, Error>) -> Void)
    func resume(_ token: WorkspaceResumeToken, deadline: UInt64, completion: @escaping (Result<WorkspaceResumeAck, Error>) -> Void)
    func acknowledgeRetired(through sequence: UInt64, deadline: UInt64, completion: @escaping (Result<Void, Error>) -> Void)
    func status(deadline: UInt64, completion: @escaping (Result<WorkspaceStatusReply, Error>) -> Void)
}
// Continuous nanoseconds include host sleep. Deliver deadlines even if a
// channel never replies; late callbacks must still compare now with the deadline.
@MainActor public protocol WorkspaceContinuousClock {
    var now: UInt64 { get }
    func schedule(at deadline: UInt64, action: @escaping () -> Void)
}
@MainActor public protocol WorkspaceNonceSource { func next() -> Data }

@MainActor public final class WorkspaceCoordinator {
    private struct Window {
        let drain: UInt64
        let pause: UInt64
        let total: UInt64
    }
    private struct SuspendTransaction {
        let request: WorkspaceSuspension
        let window: Window
    }
    private struct ResumeTransaction {
        let token: WorkspaceResumeToken
        let deadline: UInt64
    }
    private enum WakeIntent { case asleep, awake }
    private final class StopTransaction {
        var outcome: StopOutcome = .pending
    }
    private enum StopOutcome { case pending, failed }
    // Eligibility exists only as the associated value of pausedCold. A new
    // transition consumes it; no Boolean or stored spare token can recreate it.
    private enum State {
        case idle, stopped, starting, running
        case draining(SuspendTransaction, WakeIntent)
        case pausing(SuspendTransaction, WorkspaceSuspension?, WakeIntent)
        case pausedCold(WorkspaceSuspension), pausedDiscard
        case resuming(ResumeTransaction), resumingForSleep(ResumeTransaction, Window, WakeIntent)
        case recovering(WorkspaceResumeToken)
        case stopping(StopTransaction), unknown(StopTransaction?)
    }
    public var onChange: (() -> Void)?
    private var state: State { didSet { onChange?() } }
    public var phase: WorkspacePhase {
        switch state {
        case .idle, .stopped: .stopped
        case .starting: .starting
        case .running: .running
        case .draining: .draining
        case .pausing: .pausing
        case .pausedCold: .pausedCold
        case .pausedDiscard: .pausedDiscard
        case .resuming, .resumingForSleep: .resuming
        case .recovering: .recovering
        case .stopping: .stopping
        case .unknown: .unknown
        }
    }
    public private(set) var generation: UInt64 = 0
    public private(set) var reason = ""
    public private(set) var retiredStatus: [WorkspaceMountStatus] = []
    public private(set) var mountStatus: [WorkspaceMountStatus] = []
    public var attachAllowed: Bool { phase == .running }
    private let vm: any WorkspaceVirtualMachine
    private let power: any WorkspacePowerNotifications
    private let channel: any WorkspaceGuestChannel
    private let clock: any WorkspaceContinuousClock
    private let nonces: any WorkspaceNonceSource
    private let host: WorkspaceHello
    private var guestServiceID = Data()
    private var lastNotificationID: UInt64 = 0
    private var retirementAckInFlight: UInt64?
    private var acknowledgedRetirement: UInt64 = 0
    private var notifications: [UInt64: UInt64] = [:]
    private let startBudget: UInt64
    private let drainBudget: UInt64
    private let totalBudget: UInt64

    public init(host: WorkspaceHello, oldInstanceAbsent: Bool = false,
                vm: any WorkspaceVirtualMachine, power: any WorkspacePowerNotifications,
                channel: any WorkspaceGuestChannel, clock: any WorkspaceContinuousClock,
                nonces: any WorkspaceNonceSource, startBudget: UInt64 = 20_000_000_000, drainBudget: UInt64 = 15_000_000_000,
                totalBudget: UInt64 = 20_000_000_000) throws {
        guard WorkspaceControl.validRelease(host.release), WorkspaceControl.id(host.bootID),
              WorkspaceControl.id(host.hostServiceID), host.guestServiceID.isEmpty,
              drainBudget > 0, totalBudget > drainBudget, totalBudget < 30_000_000_000 else { throw WorkspaceControlError.grammar }
        self.startBudget = startBudget
        self.host = host; self.vm = vm; self.power = power; self.channel = channel
        self.clock = clock; self.nonces = nonces; self.drainBudget = drainBudget; self.totalBudget = totalBudget
        state = oldInstanceAbsent ? .idle : .unknown(nil)
    }
    private func window(at arrival: UInt64) -> Window? {
        let (total, overflow) = arrival.addingReportingOverflow(totalBudget)
        guard !overflow else { return nil }
        return Window(drain: arrival + drainBudget, pause: arrival + drainBudget + (totalBudget - drainBudget) / 2, total: total)
    }
    public func start() throws {
        guard case .idle = state, startBudget > 0, clock.now <= UInt64.max - startBudget else { throw WorkspaceControlError.transition }
        let startDeadline = clock.now + startBudget
        try power.register { [weak self] in self?.powerEvent($0) }
        state = .starting
        clock.schedule(at: startDeadline) { [weak self] in
            guard let self, case .starting = self.state else { return }
            self.stopUnsafe("VM start or guest hello deadline expired")
        }
        vm.start { [weak self] result in
            guard let self, case .starting = self.state else { return }
            guard case .success = result, self.clock.now < startDeadline else { self.stopUnsafe("VM startup not proven within deadline"); return }
            self.channel.hello(self.host, deadline: startDeadline) { [weak self] reply in
                guard let self, case .starting = self.state else { return }
                do {
                    guard self.clock.now < startDeadline else { throw WorkspaceControlError.transition }
                    let guest = try reply.get()
                    try WorkspaceControl.pair(host: self.host, guest: guest)
                    self.guestServiceID = guest.guestServiceID
                    self.state = .running; self.reason = ""
                } catch { self.stopUnsafe("exact guest release pairing not proven within deadline") }
            }
        }
    }
    public func discardUnknown() { if case .unknown = state { reconcileUnknown() } }

    public func powerEvent(_ event: WorkspacePowerEvent) {
        switch event {
        case .sleep(let notification):
            guard notification.id > lastNotificationID else { return }
            lastNotificationID = notification.id
            guard let window = window(at: notification.arrivedAt) else {
                power.acknowledgeSleep(notificationID: notification.id, fenced: phase == .stopped || phase == .pausedCold || phase == .pausedDiscard)
                stopUnsafe("sleep continuous deadline overflow"); return
            }
            notifications[notification.id] = window.total
            clock.schedule(at: window.total) { [weak self] in self?.expireNotification(notification.id) }
            switch state {
            case .idle, .stopped: acknowledgeAll(fenced: true)
            case .pausedCold, .pausedDiscard: acknowledgeAll(fenced: true)
            case .running, .recovering: beginSuspend(window)
            case .resuming(let resume):
                state = .resumingForSleep(resume, window, .asleep)
                clock.schedule(at: window.drain) { [weak self] in
                    guard let self, case .resumingForSleep(let current, let pending, _) = self.state,
                          current.token == resume.token, pending.total == window.total else { return }
                    self.stopUnsafe("sleep overtook VM resume; drain budget exhausted")
                }
            case .starting: stopUnsafe("sleep during unpaired VM startup")
            case .unknown: acknowledgeAll(fenced: false); reconcileUnknown()
            case .draining(let transaction, _): state = .draining(transaction, .asleep)
            case .pausing(let transaction, let proof, _): state = .pausing(transaction, proof, .asleep)
            case .resumingForSleep(let transaction, let original, _): state = .resumingForSleep(transaction, original, .asleep)
            case .stopping: break
            }
            if clock.now >= window.total { expireNotification(notification.id) }
        case .wake, .cancelledSleep:
            switch state {
            case .pausedCold(let suspension): resumeCold(suspension)
            case .pausedDiscard: stopUnsafe("cold drain incomplete; discard VM")
            case .unknown: reconcileUnknown()
            case .resumingForSleep(let transaction, let window, _): state = .resumingForSleep(transaction, window, .awake)
            case .draining(let transaction, _): state = .draining(transaction, .awake)
            case .pausing(let transaction, let cold, _): state = .pausing(transaction, cold, .awake)
            default: break
            }
        case .darkWake:
            switch state {
            case .resumingForSleep(let transaction, let window, _): state = .resumingForSleep(transaction, window, .asleep)
            case .draining(let transaction, _): state = .draining(transaction, .asleep)
            case .pausing(let transaction, let cold, _): state = .pausing(transaction, cold, .asleep)
            default: break
            }
        case .unknown: stopUnsafe("unknown power transition")
        }
    }
    private func expireNotification(_ id: UInt64) {
        guard notifications.removeValue(forKey: id) != nil else { return }
        let fenced = phase == .stopped || phase == .pausedCold || phase == .pausedDiscard
        power.acknowledgeSleep(notificationID: id, fenced: fenced)
        if !fenced {
            reason = "sleep notification released unfenced: deadline expired"
            stopUnsafe(reason)
            if case .stopping(let transaction) = state { state = .unknown(transaction) }
        }
    }
    private func acknowledgeAll(fenced: Bool) {
        for id in notifications.keys.sorted() {
            notifications.removeValue(forKey: id)
            power.acknowledgeSleep(notificationID: id, fenced: fenced)
        }
    }
    private func beginSuspend(_ window: Window, intent: WakeIntent = .asleep) {
        guard generation < UInt64.max, clock.now < window.drain else { stopUnsafe("no time remaining for cold suspension"); return }
        generation += 1
        var request = WorkspaceSuspension()
        request.bootID = host.bootID; request.hostServiceID = host.hostServiceID; request.guestServiceID = guestServiceID
        request.generation = generation; request.nonce = nonces.next()
        guard WorkspaceControl.validSuspension(request) else { stopUnsafe("invalid suspension identity"); return }
        let transaction = SuspendTransaction(request: request, window: window)
        state = .draining(transaction, intent)
        clock.schedule(at: window.drain) { [weak self] in
            guard let self, case .draining(let current, _) = self.state, current.request == request else { return }
            self.pause(cold: nil)
        }
        clock.schedule(at: window.pause) { [weak self] in
            guard let self else { return }
            switch self.state {
            case .draining(let current, _), .pausing(let current, _, _):
                if current.request == request { self.stopUnsafe("pause budget expired without confirmed fence") }
            default: break
            }
        }
        channel.suspend(request, deadline: window.drain) { [weak self] reply in
            guard let self, case .draining(let current, _) = self.state, current.request == request else { return }
            guard case .success(let ack) = reply, self.clock.now < window.drain,
                  WorkspaceControl.validColdAck(ack), WorkspaceControl.acknowledges(ack.suspension, request: request) else {
                self.pause(cold: nil); return
            }
            self.mountStatus = ack.mounts.map {
                var status = WorkspaceMountStatus(); status.mount = $0.mount
                status.state = "suspended-cold"; status.cleanup = "retained"; status.loss = $0.loss; return status
            }
            self.pause(cold: ack.suspension)
        }
    }
    private func pause(cold: WorkspaceSuspension?) {
        guard case .draining(let transaction, let intent) = state else { return }
        guard clock.now < transaction.window.pause else { stopUnsafe("no time left to pause"); return }
        guard channel.isIdle else { stopUnsafe("control queue not empty before VM pause"); return }
        state = .pausing(transaction, cold, intent)
        vm.pause { [weak self] result in
            guard let self, case .pausing(let current, let proof, let intent) = self.state,
                  current.request == transaction.request else { return }
            guard case .success = result, self.clock.now < current.window.pause else { self.stopUnsafe("VM pause not confirmed within budget"); return }
            self.state = proof.map(State.pausedCold) ?? .pausedDiscard
            if proof != nil { self.reason = "" }
            self.acknowledgeAll(fenced: true)
            if case .awake = intent {
                if let proof { self.resumeCold(proof) } else { self.stopUnsafe("cold drain incomplete; discard VM") }
            }
        }
    }
    private func resumeCold(_ suspension: WorkspaceSuspension) {
        var token = WorkspaceResumeToken(); token.suspension = suspension; token.wakeNonce = nonces.next()
        guard WorkspaceControl.validToken(token), let window = window(at: clock.now) else { stopUnsafe("invalid resume identity or deadline"); return }
        let transaction = ResumeTransaction(token: token, deadline: window.total)
        state = .resuming(transaction)
        clock.schedule(at: transaction.deadline) { [weak self] in
            guard let self else { return }
            switch self.state {
            case .resuming(let current), .resumingForSleep(let current, _, _):
                if current.token == token { self.stopUnsafe("VM resume completion deadline expired") }
            default: break
            }
        }
        vm.resume { [weak self] result in
            guard let self else { return }
            let pending: (Window, WakeIntent)?
            switch self.state {
            case .resuming(let current) where current.token == token: pending = nil
            case .resumingForSleep(let current, let window, let intent) where current.token == token: pending = (window, intent)
            default: return
            }
            guard case .success = result, self.clock.now < transaction.deadline else { self.stopUnsafe("VM resume not confirmed within deadline"); return }
            if let (window, intent) = pending { self.beginSuspend(window, intent: intent); return }
            self.state = .recovering(token)
            self.channel.resume(token, deadline: transaction.deadline) { [weak self] reply in
                guard let self, case .recovering(let current) = self.state, current == token else { return }
                guard case .success(let ack) = reply, ack.token == token, WorkspaceControl.validResumeAck(ack) else {
                    self.reason = "guest recovery reply unavailable or invalid; mounts remain unavailable"; return
                }
                guard self.retainsLoss(ack.mounts) else { self.reason = "guest recovery erased retained loss"; return }
                self.mountStatus = ack.mounts; self.state = .running; self.reason = ""
            }
        }
    }
    private func retainsLoss(_ mounts: [WorkspaceMountStatus], retired: [WorkspaceMountStatus] = []) -> Bool {
        mountStatus.allSatisfy { old in
            guard let current = (mounts + retired).first(where: { $0.mount == old.mount }) else { return false }
            return WorkspaceControl.retainsLoss(current.loss, prior: old.loss)
        }
    }
    // The observer retains exact outcomes before acknowledging their sequence.
    // One in-flight ack avoids duplicate UI actions and bounds the control queue.
    public func acknowledgeRetired(_ observed: [WorkspaceMountStatus]) throws {
        guard phase == .running || phase == .recovering,
              !observed.isEmpty, observed.count <= 16,
              let through = observed.last?.retirementSequence, through > 0 else { throw WorkspaceControlError.transition }
        if observed.allSatisfy({ $0.retirementSequence > 0 && $0.retirementSequence <= acknowledgedRetirement }) { return }
        guard Array(retiredStatus.prefix(observed.count)) == observed else { throw WorkspaceControlError.transition }
        if retirementAckInFlight == through { return }
        guard retirementAckInFlight == nil else { throw WorkspaceControlError.transition }
        retirementAckInFlight = through
        channel.acknowledgeRetired(through: through, deadline: clock.now + totalBudget) { [weak self] result in
            guard let self, self.retirementAckInFlight == through else { return }
            self.retirementAckInFlight = nil
            guard case .success = result else { return }
            self.acknowledgedRetirement = max(self.acknowledgedRetirement, through)
            self.retiredStatus.removeAll { $0.retirementSequence <= through }
        }
    }
    // Called by the status UI/poller. Authority recovery has no VM-killing
    // deadline; an invalid decoded ResumeAck can be reconciled by exact guest status.
    public func refreshStatus() {
        guard phase == .running || phase == .recovering else { return }
        let gen = generation
        channel.status(deadline: clock.now + totalBudget) { [weak self] reply in
            guard let self, self.generation == gen, self.phase == .running || self.phase == .recovering,
                  case .success(let status) = reply, WorkspaceControl.validStatus(status),
                  status.bootID == self.host.bootID, status.hostServiceID == self.host.hostServiceID,
                  status.guestServiceID == self.guestServiceID, status.generation == gen,
                  status.state == "running" else { return }
            let unacknowledged = status.retired.filter { $0.retirementSequence > self.acknowledgedRetirement }
            let knownThrough = self.retiredStatus.last?.retirementSequence ?? self.acknowledgedRetirement
            let added = unacknowledged.filter { $0.retirementSequence > knownThrough }
            guard unacknowledged.allSatisfy({ next in
                next.retirementSequence > knownThrough || self.retiredStatus.contains(next)
            }), added.isEmpty || (knownThrough < UInt64.max && added[0].retirementSequence == knownThrough + 1) else {
                self.reason = "retired outcome sequence mismatch"; return
            }
            guard self.retiredStatus.count + added.count <= 128 else { self.reason = "retired outcome acknowledgement required"; return }
            self.retiredStatus.append(contentsOf: added)
            guard self.retainsLoss(status.mounts, retired: status.retired + self.retiredStatus) else {
                self.reason = "waiting for earlier retired outcomes before replacing active status"; return
            }
            self.mountStatus = status.mounts; self.state = .running; self.reason = ""
        }
    }
    // A lost paired channel cannot restore eligibility. While awake, terminate
    // the VM here rather than leaving a paused VM waiting for a power event.
    public func channelLost(_ why: String) {
        let failure = "control channel lost: " + why
        switch state {
        case .stopped, .stopping, .unknown: break
        default: stopUnsafe(failure)
        }
    }
    public func vmStopped(reason: String) { finishStop() }
    public func stop() {
        if case .unknown = state { reconcileUnknown(); return }
        let clean = phase == .running
        stopUnsafe("owner requested stop", clean: clean)
    }
    private func stopUnsafe(_ why: String, clean: Bool = false) {
        switch state {
        case .stopped: acknowledgeAll(fenced: true); return
        case .stopping, .unknown(.some): return
        default: break
        }
        reason = why
        let transaction = StopTransaction()
        state = .stopping(transaction)
        if let window = window(at: clock.now) {
            clock.schedule(at: window.total) { [weak self] in
                guard let self, case .stopping(let current) = self.state, current === transaction else { return }
                self.state = .unknown(transaction)
                self.acknowledgeAll(fenced: false)
            }
        }
        let completion: (Result<Void, Error>) -> Void = { [weak self] result in
            guard let self else { return }
            switch self.state {
            case .stopping(let current), .unknown(.some(let current)):
                guard current === transaction else { return }
                switch result {
                case .success: self.finishStop()
                case .failure:
                    transaction.outcome = .failed; self.state = .unknown(transaction)
                    self.acknowledgeAll(fenced: false)
                    if clean { self.reconcileUnknown() }
                }
            default: break
            }
        }
        if clean { vm.shutdown(completion: completion) } else { vm.stop(completion: completion) }
    }
    private func reconcileUnknown() {
        guard case .unknown(let attempt) = state else { return }
        vm.inspect { [weak self] actual in
            guard let self, case .unknown(let current) = self.state, current === attempt else { return }
            if case .stopped = actual { self.finishStop(); return }
            if let current, case .pending = current.outcome { return }
            // A completed failed stop can be retried, but an outstanding stop
            // cannot be duplicated by another wake notification.
            self.state = .unknown(nil)
            self.stopUnsafe("exact VM state requires termination")
        }
    }
    private func finishStop() {
        state = .stopped; acknowledgeAll(fenced: true); power.unregister()
        guestServiceID = Data(); mountStatus = []
    }
}
