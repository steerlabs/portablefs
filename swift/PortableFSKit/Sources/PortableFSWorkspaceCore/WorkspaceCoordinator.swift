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
@MainActor public protocol WorkspaceGuestChannel: AnyObject {
    // True when no queued or active control exchange remains. Hello connection
    // and proof reads may still have an armed deadline during startup; the
    // coordinator cannot reach pause before Hello completes.
    var isIdle: Bool { get }
    // Called synchronously before completing Status or dispatching another exchange.
    var statusObserver: ((WorkspaceStatusReply) throws -> Void)? { get set }
    func hello(_ host: WorkspaceHello, deadline: UInt64, completion: @escaping (Result<WorkspaceHello, Error>) -> Void)
    func suspend(_ request: WorkspaceSuspension, deadline: UInt64, completion: @escaping (Result<WorkspaceSuspendAck, Error>) -> Void)
    func recoverAwake(_ token: WorkspaceResumeToken, deadline: UInt64, completion: @escaping (Result<WorkspaceResumeAck, Error>) -> Void)
    func resume(_ token: WorkspaceResumeToken, deadline: UInt64, completion: @escaping (Result<WorkspaceResumeAck, Error>) -> Void)
    func acknowledgeRetired(through sequence: UInt64, deadline: UInt64, completion: @escaping (Result<Void, Error>) -> Void)
    func status(deadline: UInt64, completion: @escaping (Result<WorkspaceStatusReply, Error>) -> Void)
    func mount(_ mount: WorkspaceMountID, deadline: UInt64, completion: @escaping (Result<WorkspaceResult, Error>) -> Void)
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
    private var state: State { didSet { onChange?(); scheduleMounts() } }
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
    public private(set) var retiredStatus: [WorkspaceRetiredOutcome] = []
    public private(set) var mountStatus: [WorkspaceMountStatus] = []
    public private(set) var jobStatus: [WorkspaceMountJob] = []
    public var attachAllowed: Bool { phase == .running && pendingSleep == nil }
    private final class MountRequest {
        let mount: WorkspaceMountID
        var sent = false
        var completion: ((Result<WorkspaceResult, Error>) -> Void)?
        init(_ mount: WorkspaceMountID, _ completion: @escaping (Result<WorkspaceResult, Error>) -> Void) {
            self.mount = mount; self.completion = completion
        }
    }
    private var requestedMounts: [MountRequest] = []
    private var mountsScheduled = false
    private var pendingSleep: (Window, WakeIntent)?
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
    private var statusInFlight = false
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
              drainBudget > 0, drainBudget <= WorkspaceControl.maxDrainBudget, totalBudget > drainBudget, totalBudget < 30_000_000_000 else { throw WorkspaceControlError.grammar }
        self.startBudget = startBudget
        self.host = host; self.vm = vm; self.power = power; self.channel = channel
        self.clock = clock; self.nonces = nonces; self.drainBudget = drainBudget; self.totalBudget = totalBudget
        state = oldInstanceAbsent ? .idle : .unknown(nil)
        channel.statusObserver = { [weak self] status in
            guard let self else { throw WorkspaceControlError.transition }
            try self.observeStatus(status)
        }
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
                    self.scheduleStatus()
                } catch { self.stopUnsafe("exact guest release pairing not proven within deadline") }
            }
        }
    }
    public func discardUnknown() { if case .unknown = state { reconcileUnknown() } }

    // Retain user intent outside the paired FIFO across power transitions.
    // A Mount already dispatched joins its initial job before Suspend, within
    // the notification's original budget. This avoids cancelling a consumed
    // single-use Attach and then trying to recreate it with the same grant.
    public func mount(_ mount: WorkspaceMountID, completion: @escaping (Result<WorkspaceResult, Error>) -> Void) {
        guard WorkspaceControl.validMount(mount), requestedMounts.count < 64,
              !requestedMounts.contains(where: { $0.mount == mount }),
              phase != .stopped, phase != .stopping, phase != .unknown else {
            completion(.failure(WorkspaceControlError.transition)); return
        }
        requestedMounts.append(MountRequest(mount, completion))
        scheduleMounts()
    }
    private func scheduleMounts() {
        guard attachAllowed, !mountsScheduled, requestedMounts.contains(where: { !$0.sent }) else { return }
        mountsScheduled = true
        clock.schedule(at: clock.now) { [weak self] in
            guard let self else { return }; self.mountsScheduled = false
            guard self.attachAllowed, self.clock.now <= UInt64.max - self.totalBudget else { return }
            for request in self.requestedMounts where !request.sent {
                guard self.attachAllowed else { break }
                request.sent = true
                self.channel.mount(request.mount, deadline: self.clock.now + self.totalBudget) { [weak self, weak request] result in
                    guard let self, let request else { return }
                    let complete = request.completion; request.completion = nil
                    if case .success(let accepted) = result, accepted.code == "accepted" {
                        self.refreshStatus()
                    } else {
                        self.requestedMounts.removeAll { $0 === request }
                        self.finishPendingSleep()
                    }
                    complete?(result)
                }
            }
        }
    }
    private func requestSuspend(_ window: Window, intent: WakeIntent = .asleep) {
        guard requestedMounts.contains(where: { $0.sent }) else { beginSuspend(window, intent: intent); return }
        pendingSleep = (window, intent)
        clock.schedule(at: window.drain) { [weak self] in
            guard let self, let pending = self.pendingSleep, pending.0.total == window.total else { return }
            self.stopUnsafe("initial mount did not join within the sleep drain budget")
        }
        refreshStatus()
    }
    private func finishPendingSleep() {
        guard let (window, intent) = pendingSleep, !requestedMounts.contains(where: { $0.sent }) else { return }
        pendingSleep = nil
        beginSuspend(window, intent: intent)
    }

    public func powerEvent(_ event: WorkspacePowerEvent) {
        switch event {
        case .sleep(let notification):
            guard notification.id > lastNotificationID else {
                notifications.removeValue(forKey: notification.id)
                powerEvent(.unknown)
                power.acknowledgeSleep(notificationID: notification.id,
                    fenced: phase == .stopped || phase == .pausedCold || phase == .pausedDiscard)
                return
            }
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
            case .running, .recovering:
                if let pending = pendingSleep { pendingSleep = (pending.0, .asleep) }
                else { requestSuspend(window) }
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
            if let pending = pendingSleep { pendingSleep = (pending.0, .awake) }
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
            if let pending = pendingSleep { pendingSleep = (pending.0, .asleep) }
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
            let coldMounts = ack.mounts.map {
                var status = WorkspaceMountStatus(); status.mount = $0.mount
                status.state = "suspended-cold"; status.cleanup = "retained"; status.loss = $0.loss; status.outcome = $0.outcome; return status
            }
            // Owners absent from the fixed roster may still await a later
            // retirement page. Keep their evidence until that page arrives.
            let pending = self.mountStatus.filter { !ack.suspension.roster.contains($0.mount) }
            guard self.retainsLoss(coldMounts + pending) else { self.pause(cold: nil); return }
            self.mountStatus = pending + coldMounts
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
            guard self.channel.isIdle else { self.stopUnsafe("control queue changed during VM pause"); return }
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
            self.recoverCold(transaction)
        }
    }
    private func recoverCold(_ transaction: ResumeTransaction) {
        let token = transaction.token
        state = .recovering(token)
        channel.resume(token, deadline: transaction.deadline) { [weak self] reply in
                guard let self, case .recovering(let current) = self.state, current == token else { return }
                guard case .success(let ack) = reply, ack.token == token, WorkspaceControl.validResumeAck(ack) else {
                    self.reason = "guest recovery reply unavailable or invalid; mounts remain unavailable"; return
                }
                let pending = self.mountStatus.filter { !token.suspension.roster.contains($0.mount) }
                guard self.retainsLoss(ack.mounts + pending) else { self.reason = "guest recovery erased retained loss"; return }
                self.mountStatus = pending + ack.mounts; self.state = .running; self.reason = ""
                // Suspend can interrupt page observation or its acknowledgement.
                self.refreshStatus()
        }
    }
    // Awake proof loss owns the same cold/recovery work without a power
    // deadline. Only admission is acknowledged here; each guest mount keeps its
    // worker and accepted data until it reaches ready or a terminal result.
    private func beginAwakeRecovery() {
        guard generation < UInt64.max, clock.now <= UInt64.max - totalBudget else { stopUnsafe("awake recovery identity exhausted"); return }
        generation += 1
        var token = WorkspaceResumeToken()
        token.suspension.bootID = host.bootID; token.suspension.hostServiceID = host.hostServiceID
        token.suspension.guestServiceID = guestServiceID; token.suspension.generation = generation
        token.suspension.nonce = nonces.next(); token.suspension.awakeRecovery = true
        token.wakeNonce = nonces.next()
        guard WorkspaceControl.validToken(token) else { stopUnsafe("invalid awake recovery identity"); return }
        state = .recovering(token)
        channel.recoverAwake(token, deadline: clock.now + totalBudget) { [weak self] reply in
            guard let self, case .recovering(let current) = self.state, current == token else { return }
            guard case .success(let ack) = reply, WorkspaceControl.validResumeAck(ack),
                  WorkspaceControl.acknowledges(ack.token.suspension, request: token.suspension),
                  ack.token.wakeNonce == token.wakeNonce else { self.stopUnsafe("awake recovery admission unavailable or invalid"); return }
            let pending = self.mountStatus.filter { !ack.token.suspension.roster.contains($0.mount) }
            guard self.retainsLoss(ack.mounts + pending) else { self.stopUnsafe("awake recovery erased retained loss"); return }
            self.mountStatus = pending + ack.mounts; self.state = .running; self.reason = ""
            self.refreshStatus()
        }
    }
    private func retainsLoss(_ mounts: [WorkspaceMountStatus], retired: [WorkspaceRetiredOutcome] = []) -> Bool {
        mountStatus.allSatisfy { old in
            guard let current = (mounts + retired.filter(\.hasMountStatus).map(\.mountStatus)).first(where: { $0.mount == old.mount }) else { return false }
            return WorkspaceControl.retainsLoss(current.loss, prior: old.loss)
        }
    }
    // The observer retains exact outcomes before acknowledging their sequence.
    // One in-flight ack avoids duplicate UI actions and bounds the control queue.
    public func acknowledgeRetired(_ observed: [WorkspaceRetiredOutcome]) throws {
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
            if !self.retiredStatus.isEmpty, self.phase == .running || self.phase == .recovering {
                try? self.acknowledgeRetired(Array(self.retiredStatus.prefix(16)))
            } else if observed.count == 16 { self.refreshStatus() }
        }
    }
    // All observers, including the dev probe, hand snapshots to this owner.
    // Retirement reconciliation precedes acknowledgement and is independent for
    // each mount/job: a missing later page cannot pin an already retired owner.
    public func observeStatus(_ status: WorkspaceStatusReply) throws {
        guard WorkspaceControl.validStatus(status), status.bootID == host.bootID,
              status.hostServiceID == host.hostServiceID, status.guestServiceID == guestServiceID else { throw WorkspaceControlError.transition }
        // The sole correlated FIFO consumes each snapshot before dispatching
        // another exchange. A pre-ack snapshot cannot arrive after its ack.
        let publishesReadiness = (phase == .running || phase == .recovering) && status.generation == generation && status.state == "running"
        let unacknowledged = status.retired.filter { $0.retirementSequence > acknowledgedRetirement }
        let knownThrough = retiredStatus.last?.retirementSequence ?? acknowledgedRetirement
        let added = unacknowledged.filter { $0.retirementSequence > knownThrough }
        guard unacknowledged.allSatisfy({ $0.retirementSequence > knownThrough || retiredStatus.contains($0) }),
              added.isEmpty || (knownThrough < UInt64.max && added[0].retirementSequence == knownThrough + 1) else {
            reason = "retired outcome sequence mismatch"; throw WorkspaceControlError.transition
        }
        guard retiredStatus.count + added.count <= 128 else { throw WorkspaceControlError.transition }
        // Validate against retained owners before consuming either kind of
        // evidence. A contradictory retirement never earns an acknowledgement.
        for outcome in added {
            if outcome.hasMountStatus, let old = mountStatus.first(where: { $0.mount == outcome.mountStatus.mount }) {
                guard WorkspaceControl.retainsLoss(outcome.mountStatus.loss, prior: old.loss) else { throw WorkspaceControlError.transition }
            }
            if outcome.hasJob, let old = jobStatus.first(where: { $0.mount == outcome.job.mount && $0.requestID <= outcome.job.requestID }) {
                guard WorkspaceControl.retainsJob(outcome.job, prior: old) else { throw WorkspaceControlError.transition }
            }
        }
        let remainingJobs = jobStatus.filter { old in
            !(retiredStatus + added).contains { $0.hasJob && WorkspaceControl.retainsJob($0.job, prior: old) }
        }
        for next in status.jobs {
            if let old = remainingJobs.first(where: { $0.mount == next.mount }) {
                guard WorkspaceControl.retainsJob(next, prior: old) else { throw WorkspaceControlError.transition }
            }
        }
        retiredStatus.append(contentsOf: added)
        mountStatus.removeAll { old in retiredStatus.contains { $0.hasMountStatus && $0.mountStatus.mount == old.mount } }
        jobStatus = remainingJobs

        // Preserve only owners still missing their own evidence, while advancing
        // every other owner from this snapshot. Conflicting replacements wait
        // in the guest snapshot until the old owner's retirement page arrives.
        let pendingMounts = mountStatus.filter { old in
            !status.mounts.contains { $0.mount == old.mount && WorkspaceControl.retainsLoss($0.loss, prior: old.loss) }
        }
        let pendingJobs = jobStatus.filter { old in !status.jobs.contains { WorkspaceControl.retainsJob($0, prior: old) } }
        if publishesReadiness {
            mountStatus = pendingMounts + status.mounts.filter { next in
                !pendingMounts.contains { $0.mount.authorityID == next.mount.authorityID && $0.mount.volumeID == next.mount.volumeID }
            }
        }
        jobStatus = pendingJobs + status.jobs.filter { next in !pendingJobs.contains { $0.mount == next.mount } }
        let observedJobs = status.jobs + status.retired.filter(\.hasJob).map(\.job)
        requestedMounts.removeAll { request in
            request.sent && request.completion == nil && observedJobs.contains {
                $0.mount == request.mount && $0.operation == "mount" && ($0.phase == "complete" || $0.phase == "failed")
            }
        }
        guard publishesReadiness else { finishPendingSleep(); return }
        reason = !pendingJobs.isEmpty ? "waiting for earlier retired jobs before replacing active status" :
            (!pendingMounts.isEmpty ? "waiting for earlier retired outcomes before replacing active status" : "")
        state = .running
        if retirementAckInFlight == nil, !retiredStatus.isEmpty {
            try acknowledgeRetired(Array(retiredStatus.prefix(16)))
        }
        // A local proof refusal is latched closed. Only this coordinator may
        // obtain a fresh generation/token through the same cold transaction
        // used for power transitions. Terminal mounts require explicit replacement.
        if case .running = state, pendingSleep == nil,
           status.mounts.contains(where: { $0.state == "closed" && !$0.reason.isEmpty && $0.cleanup == "retained" }),
           clock.now <= UInt64.max - totalBudget {
            beginAwakeRecovery()
        }
        finishPendingSleep()
    }
    private func scheduleStatus() {
        guard phase != .stopped, clock.now <= UInt64.max - 250_000_000 else { return }
        clock.schedule(at: clock.now + 250_000_000) { [weak self] in
            guard let self, self.phase != .stopped else { return }
            if self.channel.isIdle { self.refreshStatus() }
            self.scheduleStatus()
        }
    }
    // Authority recovery has no VM-killing deadline; exact status can reconcile
    // a lost ResumeAck. Socket failure does not erase the retained observation.
    public func refreshStatus() {
        guard (phase == .running || phase == .recovering), !statusInFlight,
              clock.now <= UInt64.max - totalBudget else { return }
        statusInFlight = true
        channel.status(deadline: clock.now + totalBudget) { [weak self] reply in
            self?.statusInFlight = false
            if case .failure(let error) = reply { self?.channelLost(String(describing: error)) }
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
    public func vmStopped(reason: String) { self.reason = reason; finishStop() }
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
        pendingSleep = nil
        let transaction = StopTransaction()
        state = .stopping(transaction)
        let mounts = requestedMounts; requestedMounts = []
        for request in mounts { request.completion?(.failure(WorkspaceControlError.transition)) }
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
        guestServiceID = Data(); mountStatus = []; jobStatus = []
    }
}
