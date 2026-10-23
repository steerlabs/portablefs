import Foundation
import Testing
@testable import PortableFSWorkspaceCore

private enum InjectedFailure: Error { case failed }
@MainActor private final class FakeVM: WorkspaceVirtualMachine {
    var calls: [String] = []
    var pauses: [(Result<Void, Error>) -> Void] = []
    var resumes: [(Result<Void, Error>) -> Void] = []
    var stops: [(Result<Void, Error>) -> Void] = []
    var holdStart = false
    var starts: [(Result<Void, Error>) -> Void] = []
    var actual: WorkspaceVMState = .running
    var inspections = 0
    var beforeStart: (() -> Void)?
    func start(completion: @escaping (Result<Void, Error>) -> Void) { beforeStart?(); calls.append("start"); if holdStart { starts.append(completion) } else { completion(.success(())) } }
    func shutdown(completion: @escaping (Result<Void, Error>) -> Void) { calls.append("shutdown"); stops.append(completion) }
    func inspect(completion: @escaping (WorkspaceVMState) -> Void) { inspections += 1; completion(actual) }
    func pause(completion: @escaping (Result<Void, Error>) -> Void) { calls.append("pause"); pauses.append(completion) }
    func resume(completion: @escaping (Result<Void, Error>) -> Void) { calls.append("resume"); resumes.append(completion) }
    func stop(completion: @escaping (Result<Void, Error>) -> Void) { calls.append("stop"); stops.append(completion) }
}
@MainActor private final class FakePower: WorkspacePowerNotifications {
    var registered = false
    var unregisters = 0
    var nextID: UInt64 = 0
    var fail = false
    var handler: ((WorkspacePowerEvent) -> Void)?
    var acknowledgements: [(UInt64, Bool)] = []
    func register(handler: @escaping (WorkspacePowerEvent) -> Void) throws {
        if fail { throw InjectedFailure.failed }
        registered = true; self.handler = handler
    }
    func acknowledgeSleep(notificationID: UInt64, fenced: Bool) { acknowledgements.append((notificationID, fenced)) }
    func unregister() { registered = false; unregisters += 1; handler = nil }
}
@MainActor private final class FakeClock: WorkspaceContinuousClock {
    var now: UInt64 = 1_000
    var scheduled: [(UInt64, () -> Void)] = []
    func schedule(at deadline: UInt64, action: @escaping () -> Void) { scheduled.append((deadline, action)) }
    func advance(_ delta: UInt64) {
        now += delta
        while let index = scheduled.indices.filter({ scheduled[$0].0 <= now }).min(by: { scheduled[$0].0 < scheduled[$1].0 }) {
            scheduled.remove(at: index).1()
        }
    }
}
@MainActor private final class FakeNonce: WorkspaceNonceSource {
    var value: UInt8 = 20
    func next() -> Data { value += 1; return Data(repeating: value, count: 16) }
}
@MainActor private final class FakeChannel: WorkspaceGuestChannel {
    var isIdle = true
    var statusObserver: ((WorkspaceStatusReply) throws -> Void)?
    var wrongRelease = false
    var holdHello = false
    var hellos: [(Result<WorkspaceHello, Error>) -> Void] = []
    var roster: [WorkspaceMountID] = []
    var retiredAcks: [(UInt64, (Result<Void, Error>) -> Void)] = []
    func acknowledgeRetired(through sequence: UInt64, deadline: UInt64, completion: @escaping (Result<Void, Error>) -> Void) { retiredAcks.append((sequence, completion)) }
    var statuses: [(Result<WorkspaceStatusReply, Error>) -> Void] = []
    var suspensions: [(WorkspaceSuspension, (Result<WorkspaceSuspendAck, Error>) -> Void)] = []
    var resumes: [(WorkspaceResumeToken, (Result<WorkspaceResumeAck, Error>) -> Void)] = []
    func hello(_ host: WorkspaceHello, deadline: UInt64, completion: @escaping (Result<WorkspaceHello, Error>) -> Void) {
        var guest = host; guest.guestServiceID = Data(repeating: 6, count: 16)
        if wrongRelease { guest.release.appVersion = "other" }
        if holdHello { hellos.append(completion) } else { completion(.success(guest)) }
    }
    func status(deadline: UInt64, completion: @escaping (Result<WorkspaceStatusReply, Error>) -> Void) { statuses.append { [self] result in
        completion(result.flatMap { status in
            do { try statusObserver?(status); return .success(status) }
            catch { return .failure(error) }
        })
    } }
    func suspend(_ request: WorkspaceSuspension, deadline: UInt64, completion: @escaping (Result<WorkspaceSuspendAck, Error>) -> Void) { suspensions.append((request, completion)) }
    func resume(_ token: WorkspaceResumeToken, deadline: UInt64, completion: @escaping (Result<WorkspaceResumeAck, Error>) -> Void) { resumes.append((token, completion)) }
    func acknowledge(_ index: Int = 0, cold: Bool = true, loss: Bool = false) {
        var ack = WorkspaceSuspendAck(); ack.suspension = suspensions[index].0; ack.suspension.roster = roster
        ack.mounts = ack.suspension.roster.map {
            var mount = WorkspaceMountCold(); mount.outcome = unknownTestOutcome(); mount.mount = $0
            if loss { var item = WorkspaceLoss(); item.sequence = 1; item.acceptedBytes = 4096; item.reason = "accepted tail unprovable"; mount.loss = [item] }
            return mount
        }
        if !cold { ack.mounts = [] }
        suspensions[index].1(.success(ack))
    }
    func recovered(_ index: Int = 0, state: String = "ready") {
        var ack = WorkspaceResumeAck(); ack.token = resumes[index].0
        ack.mounts = ack.token.suspension.roster.map { var m = WorkspaceMountStatus(); m.outcome = unknownTestOutcome(); m.mount = $0; m.state = state; if state == "ready" { m.renewal = installedTestRenewal() }; if state == "terminal" || state == "authorization-required" { m.reason = "fresh authorization required" }; m.cleanup = "retained"; return m }
        resumes[index].1(.success(ack))
    }
}
@MainActor private struct Rig {
    let vm = FakeVM()
    let power = FakePower()
    let clock = FakeClock()
    let channel = FakeChannel()
    let nonce = FakeNonce()
    let coordinator: WorkspaceCoordinator
    init(start: Bool = true, absent: Bool = true, wrongRelease: Bool = false) throws {
        let host = try WorkspaceControl.decode(workspaceGolden("hello")).hello
        coordinator = try WorkspaceCoordinator(host: host, oldInstanceAbsent: absent, vm: vm, power: power, channel: channel, clock: clock, nonces: nonce)
        channel.wrongRelease = wrongRelease
        if start {
            try coordinator.start()
            channel.roster = try WorkspaceControl.decode(workspaceGolden("suspend_ack")).suspendAck.suspension.roster
        }
    }
    func sleep(arrival: UInt64? = nil) {
        power.nextID += 1
        coordinator.powerEvent(.sleep(WorkspaceSleepNotification(id: power.nextID, arrivedAt: arrival ?? clock.now)))
    }
    func cold() {
        sleep()
        channel.acknowledge()
        vm.pauses.removeFirst()(.success(()))
    }
    func wake() { coordinator.powerEvent(.wake); vm.resumes.removeFirst()(.success(())) }
}

@Test @MainActor func workspaceRegistersPowerBeforeStartingAndRefusesRegistrationFailure() throws {
    let r = try Rig(start: false)
    r.vm.beforeStart = { #expect(r.power.registered) }
    r.power.fail = true
    #expect(throws: (any Error).self) { try r.coordinator.start() }
    #expect(r.vm.calls.isEmpty)
    r.power.fail = false
    try r.coordinator.start()
    #expect(r.vm.calls == ["start"])
}
@Test @MainActor func workspaceEligibilityRequiresCompleteRosterAndConfirmedPause() throws {
    let r = try Rig(); r.sleep()
    #expect(!r.coordinator.attachAllowed)
    r.channel.acknowledge()
    #expect(r.coordinator.phase == .pausing)
    #expect(r.power.acknowledgements.isEmpty)
    r.vm.pauses.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .pausedCold)
    #expect(r.power.acknowledgements.count == 1)
    #expect(r.power.acknowledgements[0].1)
}

@Test @MainActor func workspaceQueuedControlRefusesPauseAndColdEligibility() throws {
    for queueDuringPause in [false, true] {
        let r = try Rig(); r.sleep()
        if !queueDuringPause { r.channel.isIdle = false }
        r.channel.acknowledge()
        if queueDuringPause {
            #expect(r.coordinator.phase == .pausing)
            r.channel.isIdle = false
            r.vm.pauses.removeFirst()(.success(()))
        } else { #expect(r.vm.pauses.isEmpty) }
        #expect(r.coordinator.phase == .stopping)
        #expect(!r.coordinator.attachAllowed)
        #expect(r.power.acknowledgements.isEmpty)
        #expect(r.vm.stops.count == 1)
        r.vm.stops.removeFirst()(.success(()))
        #expect(r.coordinator.phase == .stopped)
        #expect(r.power.acknowledgements.count == 1)
    }
}
@Test @MainActor func workspaceMissingAckBecomesDiscardOnlyAndNeverResumes() throws {
    let r = try Rig(); r.sleep()
    r.clock.advance(15_000_000_000)
    r.vm.pauses.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .pausedDiscard)
    r.coordinator.powerEvent(.wake)
    #expect(r.vm.resumes.isEmpty)
    #expect(r.coordinator.phase == .stopping)
    r.vm.stops.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .stopped)
    #expect(throws: (any Error).self) { try r.coordinator.start() }
}
@Test @MainActor func workspaceFailedInvalidationCannotEarnColdEligibility() throws {
    let r = try Rig(); r.sleep()
    r.channel.acknowledge(cold: false)
    r.vm.pauses.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .pausedDiscard)
}
@Test @MainActor func workspacePauseFailureAttemptsExactStop() throws {
    let r = try Rig(); r.sleep(); r.channel.acknowledge()
    r.vm.pauses.removeFirst()(.failure(InjectedFailure.failed))
    #expect(r.coordinator.phase == .stopping)
    #expect(r.power.acknowledgements.isEmpty)
    r.vm.stops.removeFirst()(.success(()))
    #expect(r.power.acknowledgements[0].1)
}
@Test @MainActor func workspacePauseAndStopTimeoutRemainUnknownWithinOneBudget() throws {
    let r = try Rig(); r.sleep(); r.channel.acknowledge()
    r.clock.advance(17_500_000_000)
    #expect(r.vm.stops.count == 1)
    r.clock.advance(2_500_000_000)
    #expect(r.coordinator.phase == .unknown)
    #expect(r.power.acknowledgements.count == 1)
    #expect(!r.power.acknowledgements[0].1)
    #expect(!r.coordinator.attachAllowed)
}
@Test @MainActor func workspaceLatePauseCompletionCannotRestoreEligibility() throws {
    let r = try Rig(); r.sleep(); r.channel.acknowledge()
    let late = r.vm.pauses.removeFirst()
    r.clock.advance(17_500_000_000)
    late(.success(()))
    #expect(r.coordinator.phase == .stopping)
    r.coordinator.powerEvent(.wake)
    #expect(r.vm.resumes.isEmpty)
}
@Test @MainActor func workspaceLateColdAckCannotUpgradeDiscardOnlyPause() throws {
    let r = try Rig(); r.sleep()
    r.clock.advance(15_000_000_000)
    r.channel.acknowledge()
    r.vm.pauses.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .pausedDiscard)
}
@Test @MainActor func workspaceRosterMismatchRefusesColdEligibility() throws {
    let r = try Rig(); r.sleep()
    var ack = WorkspaceSuspendAck(); ack.suspension = r.channel.suspensions[0].0
    ack.suspension.roster = r.channel.roster
    r.channel.suspensions[0].1(.success(ack))
    r.vm.pauses.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .pausedDiscard)
}
@Test @MainActor func workspaceCancelledSleepReconcilesCurrentGeneration() throws {
    let r = try Rig(); r.sleep()
    r.coordinator.powerEvent(.cancelledSleep)
    r.channel.acknowledge()
    r.vm.pauses.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .resuming)
    r.vm.resumes.removeFirst()(.success(()))
    r.channel.recovered()
    #expect(r.coordinator.phase == .running)
    #expect(r.channel.resumes.count == 1)
}
@Test @MainActor func workspaceDarkWakeKeepsColdVMStopped() throws {
    let r = try Rig(); r.cold(); r.coordinator.powerEvent(.darkWake)
    #expect(r.coordinator.phase == .pausedCold)
    #expect(r.vm.resumes.isEmpty)
}
@Test @MainActor func workspaceSecondSleepInvalidatesTokenBeforeResumeCompletion() throws {
    let r = try Rig(); r.cold(); r.coordinator.powerEvent(.wake)
    r.sleep()
    r.vm.resumes.removeFirst()(.success(()))
    #expect(r.channel.resumes.isEmpty)
    #expect(r.coordinator.generation == 2)
    #expect(r.coordinator.phase == .draining)
}
@Test @MainActor func workspaceDelayedRecoveryReplyLosesToSecondSleep() throws {
    let r = try Rig(); r.cold(); r.wake()
    #expect(r.coordinator.phase == .recovering)
    r.sleep()
    r.channel.recovered()
    #expect(r.coordinator.phase == .draining)
    #expect(!r.coordinator.attachAllowed)
    r.channel.acknowledge(1)
    r.vm.pauses.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .pausedCold)
}
@Test @MainActor func workspaceRepeatedColdSleepAcknowledgesWithoutExtraResumeCycle() throws {
    let r = try Rig(); r.cold(); r.sleep(); r.coordinator.powerEvent(.wake)
    r.vm.resumes.removeFirst()(.success(()))
    #expect(r.channel.resumes.count == 1)
    #expect(r.coordinator.generation == 1)
    #expect(r.channel.suspensions.count == 1)
    #expect(r.power.acknowledgements.count == 2)
}
@Test @MainActor func workspaceServiceRestartDiscardsWithoutExecutingOldGuest() throws {
    let r = try Rig(start: false, absent: false)
    #expect(r.coordinator.phase == .unknown)
    #expect(throws: (any Error).self) { try r.coordinator.start() }
    r.coordinator.discardUnknown()
    #expect(r.vm.resumes.isEmpty)
    r.vm.stops.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .stopped)
    #expect(throws: (any Error).self) { try r.coordinator.start() }
}
@Test @MainActor func workspaceUnequalReleaseStopsBeforeProvisioning() throws {
    let r = try Rig(wrongRelease: true)
    #expect(r.coordinator.phase == .stopping)
    #expect(!r.coordinator.attachAllowed)
}
@Test @MainActor func workspaceResumeFailureDiscards() throws {
    let r = try Rig(); r.cold(); r.coordinator.powerEvent(.wake)
    r.vm.resumes.removeFirst()(.failure(InjectedFailure.failed))
    #expect(r.coordinator.phase == .stopping)
    #expect(r.channel.resumes.isEmpty)
}
@Test @MainActor func workspaceMismatchedResumeReplyCannotReopenHostAdmission() throws {
    let r = try Rig(); r.cold(); r.wake()
    var ack = WorkspaceResumeAck(); ack.token = r.channel.resumes[0].0
    ack.token.wakeNonce = Data(repeating: 55, count: 16)
    r.channel.resumes[0].1(.success(ack))
    #expect(r.coordinator.phase == .recovering)
    #expect(!r.coordinator.attachAllowed)
}
@Test @MainActor func workspaceRecoveryKeepsTerminalMountVisible() throws {
    let r = try Rig(); r.cold(); r.wake(); r.channel.recovered(state: "authorization-required")
    #expect(r.coordinator.phase == .running)
    #expect(r.coordinator.mountStatus[0].state == "authorization-required")
    #expect(r.coordinator.mountStatus[0].cleanup == "retained")
}
@Test @MainActor func workspaceContinuousTimeRejectsLateAckBeforeTimerRuns() throws {
    let r = try Rig(); r.sleep()
    r.clock.now += 16_000_000_000
    r.channel.acknowledge()
    r.vm.pauses.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .pausedDiscard)
}
@Test @MainActor func workspaceMountStartCannotChangeFixedRoster() throws {
    let r = try Rig(); r.sleep()
    #expect(r.channel.suspensions[0].0.roster.isEmpty)
    r.channel.acknowledge()
    #expect(r.coordinator.mountStatus.count == 1)
}
@Test @MainActor func workspaceStopFailureRetainsUnknownState() throws {
    let r = try Rig(); r.coordinator.powerEvent(.unknown)
    r.vm.stops.removeFirst()(.failure(InjectedFailure.failed))
    #expect(r.coordinator.phase == .unknown)
    #expect(throws: (any Error).self) { try r.coordinator.start() }
}
@Test @MainActor func workspaceColdLossIsIndependentOfEligibility() throws {
    let r = try Rig(); r.sleep(); r.channel.acknowledge(loss: true)
    r.vm.pauses.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .pausedCold)
    #expect(r.coordinator.mountStatus[0].loss[0].acceptedBytes == 4096)
}
@Test @MainActor func workspaceSlowRecoveryHasNoVMKillingDeadlineOrTokenReuse() throws {
    let r = try Rig(); r.cold(); r.wake()
    r.clock.advance(200_000_000_000)
    #expect(r.coordinator.phase == .recovering)
    #expect(r.vm.stops.isEmpty)
    r.channel.recovered()
    #expect(r.coordinator.phase == .running)
    r.coordinator.powerEvent(.wake)
    #expect(r.channel.resumes.count == 1)
}

@Test @MainActor func workspaceRecoveryCannotEraseColdLossLedger() throws {
    let r = try Rig(); r.sleep(); r.channel.acknowledge(loss: true)
    r.vm.pauses.removeFirst()(.success(())); r.wake()
    r.channel.recovered()
    #expect(r.coordinator.phase == .recovering)
    #expect(r.vm.stops.isEmpty)
    #expect(r.coordinator.mountStatus[0].loss[0].sequence == 1)
}

@Test @MainActor func workspaceSleepDuringResumeUsesArrivalDeadline() throws {
    let r = try Rig(); r.cold(); r.coordinator.powerEvent(.wake)
    r.sleep()
    r.clock.advance(14_000_000_000)
    r.vm.resumes.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .draining)
    r.clock.advance(1_000_000_000)
    #expect(r.coordinator.phase == .pausing)
    r.clock.advance(2_500_000_000)
    #expect(r.coordinator.phase == .stopping)
    r.clock.advance(2_500_000_000)
    #expect(r.power.acknowledgements.count == 2)
    #expect(!r.power.acknowledgements[1].1)
    #expect(r.coordinator.phase == .unknown)
}
@Test @MainActor func workspaceSleepDuringHungResumeStopsWithinOriginalBudget() throws {
    let r = try Rig(); r.cold(); r.coordinator.powerEvent(.wake); r.sleep()
    r.clock.advance(15_000_000_000)
    #expect(r.vm.stops.count == 1)
    r.clock.advance(5_000_000_000)
    #expect(r.power.acknowledgements.count == 2)
    #expect(!r.power.acknowledgements[1].1)
    r.vm.resumes.removeFirst()(.success(()))
    #expect(r.channel.resumes.isEmpty)
}
@Test @MainActor func workspaceDelayedNotificationDoesNotRestartBudget() throws {
    let r = try Rig()
    let arrival = r.clock.now
    r.clock.now += 19_000_000_000
    r.sleep(arrival: arrival)
    #expect(r.coordinator.phase == .stopping)
    #expect(r.channel.suspensions.isEmpty)
    r.clock.advance(1_000_000_000)
    #expect(r.power.acknowledgements.count == 1)
    #expect(!r.power.acknowledgements[0].1)
}
@Test @MainActor func workspaceEveryNotificationAcknowledgedOnceInEveryPhase() throws {
    for target in ["idle", "starting", "running", "draining", "pausing", "pausedCold", "pausedDiscard", "resuming", "recovering", "stopping", "unknown", "stopped"] {
        let r = try Rig(start: false, absent: target != "unknown")
        switch target {
        case "idle", "unknown": break
        case "starting": r.vm.holdStart = true; try r.coordinator.start()
        default:
            try r.coordinator.start()
            r.channel.roster = try WorkspaceControl.decode(workspaceGolden("suspend_ack")).suspendAck.suspension.roster
            switch target {
            case "draining": r.sleep()
            case "pausing": r.sleep(); r.channel.acknowledge()
            case "pausedCold": r.cold()
            case "pausedDiscard": r.sleep(); r.channel.acknowledge(cold: false); r.vm.pauses.removeFirst()(.success(()))
            case "resuming": r.cold(); r.coordinator.powerEvent(.wake)
            case "recovering": r.cold(); r.wake()
            case "stopping", "stopped":
                r.coordinator.powerEvent(.unknown)
                if target == "stopped" { r.vm.stops.removeFirst()(.success(())) }
            default: break
            }
        }
        r.sleep(); r.sleep()
        let issued = r.power.nextID
        r.clock.advance(20_000_000_000)
        #expect(r.power.acknowledgements.count == Int(issued), "phase: \(target)")
        #expect(Set(r.power.acknowledgements.map(\.0)).count == Int(issued), "phase: \(target)")
        if !r.vm.stops.isEmpty { r.vm.stops.removeFirst()(.success(())) }
        r.clock.advance(60_000_000_000)
        #expect(r.power.acknowledgements.count == Int(issued), "late callback phase: \(target)")
    }
}
@Test @MainActor func workspaceTerminalStopUnregistersAndLateCompletionCanResolveUnknown() throws {
    let r = try Rig(); r.coordinator.powerEvent(.unknown)
    r.clock.advance(20_000_000_000)
    #expect(r.coordinator.phase == .unknown)
    r.coordinator.powerEvent(.wake)
    #expect(r.vm.inspections == 1)
    #expect(r.vm.stops.count == 1)
    r.vm.stops.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .stopped)
    #expect(r.power.unregisters == 1)
    #expect(!r.power.registered)
}
@Test @MainActor func workspaceUnknownQueriesActualStateBeforeRetryingFailedStop() throws {
    let r = try Rig(); r.coordinator.powerEvent(.unknown)
    r.vm.stops.removeFirst()(.failure(InjectedFailure.failed))
    r.vm.actual = .stopped
    r.coordinator.powerEvent(.wake)
    #expect(r.coordinator.phase == .stopped)
    #expect(r.vm.stops.isEmpty)
    #expect(r.power.unregisters == 1)
}
@Test @MainActor func workspaceStartAndHelloAreBounded() throws {
    for holdStart in [true, false] {
        let r = try Rig(start: false)
        r.vm.holdStart = holdStart; r.channel.holdHello = !holdStart
        try r.coordinator.start()
        r.clock.advance(20_000_000_000)
        #expect(r.coordinator.phase == .stopping)
        #expect(!r.coordinator.attachAllowed)
        if holdStart { r.vm.starts.removeFirst()(.success(())) }
        else { r.channel.hellos.removeFirst()(.success(try WorkspaceControl.decode(workspaceGolden("hello_ack")).helloAck)) }
        #expect(r.coordinator.phase == .stopping)
    }
}
@Test @MainActor func workspaceOnlyVMResumeCompletionHasWakeDeadline() throws {
    let r = try Rig(); r.cold(); r.coordinator.powerEvent(.wake)
    r.clock.advance(20_000_000_000)
    #expect(r.coordinator.phase == .stopping)
    #expect(r.channel.resumes.isEmpty)
}
@Test @MainActor func workspaceLostResumeAckReconcilesPerMountStatusWithoutDiscard() throws {
    let r = try Rig(); r.cold(); r.wake()
    r.clock.advance(200_000_000_000)
    r.coordinator.refreshStatus()
    var status = WorkspaceStatusReply()
    let token = r.channel.resumes[0].0
    status.bootID = token.suspension.bootID; status.hostServiceID = token.suspension.hostServiceID
    status.guestServiceID = token.suspension.guestServiceID; status.generation = token.suspension.generation
    status.state = "running"
    status.mounts = token.suspension.roster.map { var m = WorkspaceMountStatus(); m.outcome = unknownTestOutcome(); m.mount = $0; m.state = "recovering"; m.cleanup = "retained"; return m }

    r.channel.statuses.removeFirst()(.success(status))
    #expect(r.coordinator.phase == .running)
    #expect(r.coordinator.mountStatus[0].state == "recovering")
    #expect(r.vm.stops.isEmpty)
}

@Test @MainActor func workspaceGuestReplacementUpdatesStatusAndRetiresExactOldOutcome() throws {
    let r = try Rig(); r.cold(); r.wake(); r.channel.recovered()
    r.coordinator.refreshStatus()
    let token = r.channel.resumes[0].0
    var status = WorkspaceStatusReply()
    status.bootID = token.suspension.bootID; status.hostServiceID = token.suspension.hostServiceID
    status.guestServiceID = token.suspension.guestServiceID; status.generation = token.suspension.generation
    status.state = "running"
    var old = r.coordinator.mountStatus[0]; old.state = "terminal"; old.reason = "session ended"; old.cleanup = "complete"
    var replacement = old; replacement.mount.incarnation = Data(repeating: 99, count: 16)
    replacement.state = "ready"; replacement.renewal = installedTestRenewal(); replacement.reason = ""; replacement.cleanup = "retained"
    let retired = retiredTestOutcome(old, sequence: 1)
    status.mounts = [replacement]; status.retired = [retired]

    r.channel.statuses.removeFirst()(.success(status))
    #expect(r.coordinator.mountStatus == [replacement])
    #expect(r.coordinator.retiredStatus == [retired])
    try r.coordinator.acknowledgeRetired([retired])
    r.channel.retiredAcks.removeFirst().1(.success(()))
    #expect(r.coordinator.retiredStatus.isEmpty)
}

@Test @MainActor func workspaceCancelledSleepDuringResumeReconcilesNewGeneration() throws {
    let r = try Rig(); r.cold(); r.coordinator.powerEvent(.wake)
    r.sleep(); r.coordinator.powerEvent(.cancelledSleep)
    r.vm.resumes.removeFirst()(.success(()))
    r.channel.acknowledge(1); r.vm.pauses.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .resuming)
    #expect(r.coordinator.generation == 2)
    r.vm.resumes.removeFirst()(.success(()))
    #expect(r.channel.resumes.count == 1)
}
@Test @MainActor func workspaceNewSleepClearsEarlierPendingWake() throws {
    let r = try Rig(); r.sleep(); r.coordinator.powerEvent(.cancelledSleep); r.sleep()
    r.channel.acknowledge(); r.vm.pauses.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .pausedCold)
    #expect(r.vm.resumes.isEmpty)
    #expect(r.power.acknowledgements.count == 2)
}

@Test @MainActor func workspaceOldResumeSleepTimerCannotStopNewTransaction() throws {
    let r = try Rig(); r.cold(); r.coordinator.powerEvent(.wake); r.sleep()
    r.vm.resumes.removeFirst()(.success(()))
    r.channel.acknowledge(1); r.vm.pauses.removeFirst()(.success(()))
    r.clock.advance(10_000_000_000)
    r.coordinator.powerEvent(.wake); r.sleep()
    r.clock.advance(5_000_000_000)
    #expect(r.coordinator.phase == .resuming)
    #expect(r.vm.stops.isEmpty)
}

@Test @MainActor func workspaceRetiredBacklogCanAdvanceBeforeReplacementStatus() throws {
    let r = try Rig(); r.cold(); r.wake(); r.channel.recovered()
    let token = r.channel.resumes[0].0
    var status = WorkspaceStatusReply()
    status.bootID = token.suspension.bootID; status.hostServiceID = token.suspension.hostServiceID
    status.guestServiceID = token.suspension.guestServiceID; status.generation = token.suspension.generation
    status.state = "running"
    var old = r.coordinator.mountStatus[0]; old.state = "terminal"; old.reason = "session ended"; old.cleanup = "complete"
    var earlier = old; earlier.mount.volumeID = "earlier"
    var replacement = old; replacement.mount.incarnation = Data(repeating: 99, count: 16)
    replacement.state = "ready"; replacement.renewal = installedTestRenewal(); replacement.reason = ""; replacement.cleanup = "retained"
    let earlierRetired = retiredTestOutcome(earlier, sequence: 1); let retired = retiredTestOutcome(old, sequence: 2)
    status.mounts = [replacement]; status.retired = [earlierRetired]

    r.coordinator.refreshStatus(); r.channel.statuses.removeFirst()(.success(status))
    #expect(r.coordinator.retiredStatus == [earlierRetired])
    #expect(r.coordinator.mountStatus[0].mount == old.mount)
    try r.coordinator.acknowledgeRetired([earlierRetired]); r.channel.retiredAcks.removeFirst().1(.success(()))
    status.retired = [retired]

    r.coordinator.refreshStatus(); r.channel.statuses.removeFirst()(.success(status))
    #expect(r.coordinator.mountStatus == [replacement])
}

@Test @MainActor func workspaceChannelLossStopsWithoutWaitingForWake() throws {
    let r = try Rig()
    r.coordinator.channelLost("peer EOF")
    #expect(r.coordinator.phase == .stopping)
    #expect(r.vm.calls == ["start", "stop"])
    #expect(r.vm.pauses.isEmpty)
    #expect(r.coordinator.reason.contains("peer EOF"))
    #expect(r.vm.resumes.isEmpty)
}
@Test @MainActor func workspaceUnexpectedStopUnregistersAndRevokesEligibility() throws {
    let r = try Rig(); r.cold()
    r.coordinator.vmStopped(reason: "guest panic")
    #expect(r.coordinator.phase == .stopped)
    #expect(!r.power.registered)
    r.coordinator.powerEvent(.wake)
    #expect(r.vm.resumes.isEmpty)
    #expect(r.coordinator.reason == "guest panic")
}
@Test @MainActor func workspaceReleasedUnfencedCannotBecomeColdOnLateCompletion() throws {
    let r = try Rig(); r.sleep(); r.channel.acknowledge()
    r.clock.advance(20_000_000_000)
    #expect(r.power.acknowledgements.count == 1)
    #expect(!r.power.acknowledgements[0].1)
    r.vm.pauses.removeFirst()(.success(()))
    #expect(r.coordinator.phase != .pausedCold)
    r.coordinator.powerEvent(.wake)
    #expect(r.vm.resumes.isEmpty)
}
@Test @MainActor func workspaceOwnerStopUsesCoordinatedShutdownAndRetriesFailure() throws {
    let r = try Rig()
    r.coordinator.stop()
    #expect(r.vm.calls == ["start", "shutdown"])
    r.vm.stops.removeFirst()(.failure(InjectedFailure.failed))
    #expect(r.vm.inspections == 1)
    #expect(r.vm.calls == ["start", "shutdown", "stop"])
    r.vm.stops.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .stopped)
    #expect(r.power.unregisters == 1)
}

@Test @MainActor func workspaceAwakeProofLossOwnsColdRecoveryWithoutPowerEvent() throws {
    let r = try Rig()
    var status = WorkspaceStatusReply()
    let host = try WorkspaceControl.decode(workspaceGolden("hello")).hello
    status.bootID = host.bootID; status.hostServiceID = host.hostServiceID
    status.guestServiceID = Data(repeating: 6, count: 16); status.state = "running"
    var mount = WorkspaceMountStatus(); mount.mount = r.channel.roster[0]
    mount.state = "closed"; mount.reason = "workspace clock or subscription proof unavailable"
    mount.cleanup = "retained"; mount.outcome = unknownTestOutcome()
    var loss = WorkspaceLoss(); loss.sequence = 1; loss.acceptedBytes = 23; loss.reason = "accepted tail lost"
    mount.loss = [loss]; status.mounts = [mount]
    r.channel.roster = [mount.mount]
    // The coordinator itself polls; neither a power event nor UI action drives it.
    r.clock.advance(250_000_000)
    #expect(r.channel.statuses.count == 1)
    r.channel.statuses.removeFirst()(.success(status))
    #expect(r.coordinator.phase == .draining)
    #expect(r.coordinator.generation == 1)
    try r.coordinator.observeStatus(status)
    #expect(r.channel.suspensions.count == 1)
    var cold = WorkspaceSuspendAck(); cold.suspension = r.channel.suspensions[0].0
    cold.suspension.roster = [mount.mount]
    var proof = WorkspaceMountCold(); proof.mount = mount.mount; proof.loss = [loss]; proof.outcome = unknownTestOutcome()
    cold.mounts = [proof]
    r.channel.suspensions[0].1(.success(cold))
    r.vm.pauses.removeFirst()(.success(()))
    #expect(r.coordinator.phase == .resuming)
    #expect(r.power.acknowledgements.isEmpty)
    r.vm.resumes.removeFirst()(.success(()))
    let token = r.channel.resumes[0].0
    #expect(token.suspension.generation == 1)
    #expect(token.wakeNonce != token.suspension.nonce)
    var resumed = WorkspaceResumeAck(); resumed.token = token
    mount.state = "ready"; mount.reason = ""; mount.renewal = installedTestRenewal()
    resumed.mounts = [mount]
    r.channel.resumes[0].1(.success(resumed))
    #expect(r.coordinator.phase == .running)
    #expect(r.coordinator.mountStatus[0].loss == [loss])
    #expect(r.vm.calls == ["start", "pause", "resume"])
}

@Test @MainActor func workspaceAwakeRecoveryDeduplicatesSleepAndLeavesTerminalExplicit() throws {
    for terminal in [false, true] {
        let r = try Rig()
        var status = WorkspaceStatusReply()
        let host = try WorkspaceControl.decode(workspaceGolden("hello")).hello
        status.bootID = host.bootID; status.hostServiceID = host.hostServiceID
        status.guestServiceID = Data(repeating: 6, count: 16); status.state = "running"
        var mount = WorkspaceMountStatus(); mount.mount = r.channel.roster[0]
        mount.state = terminal ? "terminal" : "closed"; mount.reason = "proof unavailable"
        mount.cleanup = "retained"; mount.outcome = unknownTestOutcome(); status.mounts = [mount]
        try r.coordinator.observeStatus(status)
        if terminal { #expect(r.channel.suspensions.isEmpty); continue }
        r.sleep()
        #expect(r.channel.suspensions.count == 1)
        r.channel.acknowledge()
        r.vm.pauses.removeFirst()(.success(()))
        #expect(r.coordinator.phase == .pausedCold)
        #expect(r.vm.resumes.isEmpty)
        r.wake()
        #expect(r.channel.resumes.count == 1)
    }
}

@Test @MainActor func workspaceAwakeColdAckCannotEraseLoss() throws {
    let r = try Rig()
    var status = WorkspaceStatusReply()
    let host = try WorkspaceControl.decode(workspaceGolden("hello")).hello
    status.bootID = host.bootID; status.hostServiceID = host.hostServiceID
    status.guestServiceID = Data(repeating: 6, count: 16); status.state = "running"
    var mount = WorkspaceMountStatus(); mount.mount = r.channel.roster[0]
    mount.state = "closed"; mount.reason = "proof unavailable"; mount.cleanup = "retained"; mount.outcome = unknownTestOutcome()
    var loss = WorkspaceLoss(); loss.sequence = 1; loss.acceptedBytes = 23; loss.reason = "accepted tail lost"
    mount.loss = [loss]; status.mounts = [mount]
    r.channel.roster = [mount.mount]
    try r.coordinator.observeStatus(status)
    r.channel.acknowledge() // Omits the already retained ticket.
    r.vm.pauses.removeFirst()(.success(()))
    #expect(r.vm.calls == ["start", "pause", "stop"])
    #expect(r.coordinator.mountStatus[0].loss == [loss])
    #expect(r.channel.resumes.isEmpty)
}
