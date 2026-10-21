import Foundation

public enum WorkspacePowerEvent { case sleep, wake, cancelledSleep, darkWake, unknown }
public enum WorkspacePhase: String { case stopped, starting, running, draining, pausing, pausedCold, pausedDiscard, resuming, recovering, stopping, unknown }

// Adapters must stay on the serialized VM owner queue. Completion means the
// framework completed the operation on that exact VM, never just accepted it.
@MainActor public protocol WorkspaceVirtualMachine {
    func start(completion: @escaping (Result<Void, Error>) -> Void)
    func pause(completion: @escaping (Result<Void, Error>) -> Void)
    func resume(completion: @escaping (Result<Void, Error>) -> Void)
    func stop(completion: @escaping (Result<Void, Error>) -> Void)
}
@MainActor public protocol WorkspacePowerNotifications {
    func register(handler: @escaping (WorkspacePowerEvent) -> Void) throws
    func acknowledgeSleep(generation: UInt64, fenced: Bool)
}
@MainActor public protocol WorkspaceGuestChannel {
    func hello(_ host: WorkspaceHello, completion: @escaping (Result<WorkspaceHello, Error>) -> Void)
    func suspend(_ request: WorkspaceSuspension, completion: @escaping (Result<WorkspaceSuspendAck, Error>) -> Void)
    func resume(_ token: WorkspaceResumeToken, completion: @escaping (Result<WorkspaceResumeAck, Error>) -> Void)
}
// now and scheduled deadlines use host continuous nanoseconds, including sleep.
// An adapter must deliver deadline callbacks even when a channel never replies.
@MainActor public protocol WorkspaceContinuousClock {
    var now: UInt64 { get }
    func schedule(at deadline: UInt64, action: @escaping () -> Void)
}
// Return a fresh cryptographically random nonce, or invalid/empty data on failure.
@MainActor public protocol WorkspaceNonceSource { func next() -> Data }

@MainActor public final class WorkspaceCoordinator {
    public private(set) var phase: WorkspacePhase
    public private(set) var generation: UInt64 = 0
    public private(set) var reason = ""
    public private(set) var mountStatus: [WorkspaceMountStatus] = []
    public var attachAllowed: Bool { phase == .running }
    private let vm: any WorkspaceVirtualMachine
    private let power: any WorkspacePowerNotifications
    private let channel: any WorkspaceGuestChannel
    private let clock: any WorkspaceContinuousClock
    private let nonces: any WorkspaceNonceSource
    private var host: WorkspaceHello
    private var guestServiceID = Data()
    private var roster: [WorkspaceMountID] = []
    private var suspension: WorkspaceSuspension?
    private var token: WorkspaceResumeToken?
    private var registered = false
    private var bootConsumed = false
    private var sleepAcknowledged = false
    private var pauseDeadline: UInt64 = 0
    private var operation: UInt64 = 0
    private var pendingWake = false
    private var sleepDuringResume = false
    private var totalDeadline: UInt64 = 0
    private let drainBudget: UInt64
    private let totalBudget: UInt64

    public init(host: WorkspaceHello, oldInstanceAbsent: Bool = false,
                vm: any WorkspaceVirtualMachine, power: any WorkspacePowerNotifications,
                channel: any WorkspaceGuestChannel, clock: any WorkspaceContinuousClock,
                nonces: any WorkspaceNonceSource, drainBudget: UInt64 = 15_000_000_000,
                totalBudget: UInt64 = 20_000_000_000) throws {
        guard WorkspaceControl.validRelease(host.release), WorkspaceControl.id(host.bootID),
              WorkspaceControl.id(host.hostServiceID), host.guestServiceID.isEmpty,
              drainBudget > 0, totalBudget > drainBudget, totalBudget < 30_000_000_000 else { throw WorkspaceControlError.grammar }
        self.host = host; self.vm = vm; self.power = power; self.channel = channel
        self.clock = clock; self.nonces = nonces; self.drainBudget = drainBudget; self.totalBudget = totalBudget
        phase = oldInstanceAbsent ? .stopped : .unknown
    }

    public func start() throws {
        guard phase == .stopped, !bootConsumed else { throw WorkspaceControlError.transition }
        if !registered {
            try power.register { [weak self] event in self?.powerEvent(event) }
            registered = true
        }
        bootConsumed = true
        phase = .starting
        operation += 1
        let op = operation
        vm.start { [weak self] result in
            guard let self, self.operation == op, self.phase == .starting else { return }
            guard case .success = result else { self.stopUnsafe("VM startup not proven"); return }
            self.channel.hello(self.host) { [weak self] reply in
                guard let self, self.operation == op, self.phase == .starting else { return }
                do {
                    let guest = try reply.get()
                    try WorkspaceControl.pair(host: self.host, guest: guest)
                    self.guestServiceID = guest.guestServiceID
                    self.phase = .running
                } catch { self.stopUnsafe("exact guest release pairing failed") }
            }
        }
    }
    public func setRoster(_ mounts: [WorkspaceMountID]) throws {
        guard attachAllowed, WorkspaceControl.validRoster(mounts) else { throw WorkspaceControlError.transition }
        roster = mounts
    }
    public func discardUnknown() { if phase == .unknown { stopUnsafe("missing service state; discard old VM") } }

    public func powerEvent(_ event: WorkspacePowerEvent) {
        switch event {
        case .sleep:
            token = nil
            sleepAcknowledged = false
            pendingWake = false
            switch phase {
            case .running, .recovering: beginSuspend()
            case .resuming: sleepDuringResume = true
            case .pausedCold, .pausedDiscard:
                // No old token survives another transition. A fully cold paused
                // guest stays paused; a new transaction runs before execution.
                sleepDuringResume = true
                acknowledgeSleep(fenced: true)
            case .starting: stopUnsafe("sleep during unpaired VM startup")
            default: break
            }
        case .wake, .cancelledSleep:
            pendingWake = true
            if phase == .pausedCold { resumeCold() }
            else if phase == .pausedDiscard || phase == .unknown { stopUnsafe("discard-only or uncertain VM") }
        case .darkWake: pendingWake = false
        case .unknown: stopUnsafe("unknown power transition")
        }
    }
    private func beginSuspend() {
        token = nil
        guard generation < UInt64.max else { stopUnsafe("suspend generation exhausted"); return }
        generation += 1
        sleepAcknowledged = false
        var s = WorkspaceSuspension()
        s.bootID = host.bootID; s.hostServiceID = host.hostServiceID; s.guestServiceID = guestServiceID
        s.generation = generation; s.roster = roster; s.nonce = nonces.next()
        guard WorkspaceControl.validSuspension(s) else { stopUnsafe("invalid suspension identity"); return }
        suspension = s
        phase = .draining
        let gen = generation
        let start = clock.now
        let (drain, overflow1) = start.addingReportingOverflow(drainBudget)
        let (total, overflow2) = start.addingReportingOverflow(totalBudget)
        guard !overflow1, !overflow2 else { stopUnsafe("continuous deadline overflow"); return }
        totalDeadline = total
        pauseDeadline = drain + (totalBudget - drainBudget) / 2
        clock.schedule(at: drain) { [weak self] in
            guard let self, self.generation == gen, self.phase == .draining else { return }
            self.pause(cold: false)
        }
        clock.schedule(at: pauseDeadline) { [weak self] in
            guard let self, self.generation == gen, [.draining, .pausing].contains(self.phase) else { return }
            self.stopUnsafe("pause budget expired without confirmed fence", deadline: total)
        }
        clock.schedule(at: total) { [weak self] in
            guard let self, self.generation == gen, [.draining, .pausing, .stopping, .unknown].contains(self.phase) else { return }
            self.phase = .unknown
            self.acknowledgeSleep(fenced: false)
        }
        channel.suspend(s) { [weak self] reply in
            guard let self, self.generation == gen, self.phase == .draining else { return }
            let cold: Bool
            if case .success(let ack) = reply {
                cold = self.clock.now < drain && WorkspaceControl.validColdAck(ack) && ack.suspension == s && ack.mounts.allSatisfy(\.coldComplete)
                if WorkspaceControl.validColdAck(ack), ack.suspension == s {
                    self.mountStatus = ack.mounts.map {
                        var status = WorkspaceMountStatus(); status.mount = $0.mount
                        status.state = $0.coldComplete ? "suspended-cold" : "closed"
                        status.cleanup = "retained"; status.loss = $0.loss; return status
                    }
                }
            } else { cold = false }
            self.pause(cold: cold)
        }
    }
    private func pause(cold: Bool) {
        guard phase == .draining else { return }
        if clock.now >= pauseDeadline { stopUnsafe("no time left to pause"); return }
        phase = .pausing
        operation += 1
        let op = operation
        let gen = generation
        vm.pause { [weak self] result in
            guard let self, self.operation == op, self.generation == gen, self.phase == .pausing else { return }
            guard case .success = result, self.clock.now < self.pauseDeadline else { self.stopUnsafe("VM pause not confirmed within budget", deadline: self.totalDeadline); return }
            self.phase = cold ? .pausedCold : .pausedDiscard
            self.acknowledgeSleep(fenced: true)
            if self.pendingWake {
                if cold { self.resumeCold() } else { self.stopUnsafe("cold drain incomplete; discard VM") }
            }
        }
    }
    private func resumeCold() {
        guard phase == .pausedCold, let suspension else { return }
        // A sleep while resume was pending must run another generation before
        // any token is sent. VM operations themselves remain serialized.
        var next = WorkspaceResumeToken(); next.suspension = suspension; next.wakeNonce = nonces.next()
        guard WorkspaceControl.validToken(next) else { stopUnsafe("invalid wake nonce"); return }
        token = next
        phase = .resuming
        operation += 1
        let op = operation
        let gen = generation
        let (deadline, overflow) = clock.now.addingReportingOverflow(totalBudget)
        guard !overflow else { stopUnsafe("resume deadline overflow"); return }
        clock.schedule(at: deadline) { [weak self] in
            guard let self, self.operation == op, [.resuming, .recovering].contains(self.phase) else { return }
            self.stopUnsafe("resume recovery budget expired")
        }
        vm.resume { [weak self] result in
            guard let self, self.operation == op, self.generation == gen, self.phase == .resuming else { return }
            guard case .success = result, self.clock.now < deadline else { self.stopUnsafe("VM resume not confirmed"); return }
            if self.sleepDuringResume {
                self.sleepDuringResume = false
                self.token = nil
                self.beginSuspend()
                return
            }
            guard self.token == next else { self.stopUnsafe("resume authorization invalidated"); return }
            self.token = nil
            self.phase = .recovering
            self.channel.resume(next) { [weak self] reply in
                guard let self, self.operation == op, self.generation == gen, self.phase == .recovering else { return }
                guard case .success(let ack) = reply, ack.token == next, self.clock.now < deadline else { self.stopUnsafe("guest cold recovery not proven"); return }
                var envelope = WorkspaceEnvelope(); envelope.version = 8; envelope.requestID = 1; envelope.body = .resumeAck(ack)
                guard (try? WorkspaceControl.validate(envelope)) != nil else { self.stopUnsafe("invalid recovery roster"); return }
                for old in self.mountStatus {
                    guard let current = ack.mounts.first(where: { $0.mount == old.mount }),
                          Array(current.loss.prefix(old.loss.count)) == old.loss else {
                        self.stopUnsafe("recovery erased retained loss"); return
                    }
                }
                self.mountStatus = ack.mounts
                self.phase = .running
                self.pendingWake = false
            }
        }
    }
    private func acknowledgeSleep(fenced: Bool) {
        guard generation > 0, !sleepAcknowledged else { return }
        sleepAcknowledged = true
        power.acknowledgeSleep(generation: generation, fenced: fenced)
    }
    private func stopUnsafe(_ why: String, deadline suppliedDeadline: UInt64? = nil) {
        token = nil; suspension = nil; reason = why
        bootConsumed = true
        if phase == .stopping { return }
        phase = .stopping
        operation += 1
        let op = operation
        let (deadline, overflow) = clock.now.addingReportingOverflow(totalBudget)
        if !overflow || suppliedDeadline != nil {
            clock.schedule(at: suppliedDeadline ?? deadline) { [weak self] in
                guard let self, self.operation == op, self.phase == .stopping else { return }
                self.phase = .unknown
                self.acknowledgeSleep(fenced: false)
            }
        }
        vm.stop { [weak self] result in
            guard let self, self.operation == op else { return }
            switch result {
            case .success:
                self.phase = .stopped
                self.acknowledgeSleep(fenced: true)
                // This coordinator is bound to one boot. A fresh VM requires a
                // new coordinator/boot nonce, never reuse old RAM or roster.
                self.guestServiceID = Data(); self.roster = []; self.mountStatus = []
            case .failure: self.phase = .unknown
            }
        }
    }
}
