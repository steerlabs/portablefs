import Foundation
import Testing
@testable import PortableFSWorkspaceCore

// Re-review probes; reuse the private rig by duplicating minimal fakes.
@MainActor private final class RRVM: WorkspaceVirtualMachine {
    var calls: [String] = []
    var pauses: [(Result<Void, Error>) -> Void] = []
    var resumes: [(Result<Void, Error>) -> Void] = []
    var stops: [(Result<Void, Error>) -> Void] = []
    func start(completion: @escaping (Result<Void, Error>) -> Void) { calls.append("start"); completion(.success(())) }
    
    func shutdown(completion: @escaping (Result<Void, Error>) -> Void) { calls.append("shutdown"); stops.append(completion) }
    func inspect(completion: @escaping (WorkspaceVMState) -> Void) { completion(.running) }
    func pause(completion: @escaping (Result<Void, Error>) -> Void) { calls.append("pause"); pauses.append(completion) }
    func resume(completion: @escaping (Result<Void, Error>) -> Void) { calls.append("resume"); resumes.append(completion) }
    func stop(completion: @escaping (Result<Void, Error>) -> Void) { calls.append("stop"); stops.append(completion) }
}
@MainActor private final class RRPower: WorkspacePowerNotifications {
    var handler: ((WorkspacePowerEvent) -> Void)?
    var acknowledgements: [(UInt64, Bool)] = []
    func register(handler: @escaping (WorkspacePowerEvent) -> Void) throws { self.handler = handler }
    func acknowledgeSleep(notificationID: UInt64, fenced: Bool) { acknowledgements.append((notificationID, fenced)) }
    func unregister() { handler = nil }
}
@MainActor private final class RRClock: WorkspaceContinuousClock {
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
@MainActor private final class RRNonce: WorkspaceNonceSource {
    var value: UInt8 = 40
    func next() -> Data { value += 1; return Data(repeating: value, count: 16) }
}
@MainActor private final class RRChannel: WorkspaceGuestChannel {
    var isIdle = true
    var retiredAcks: [(UInt64, (Result<Void, Error>) -> Void)] = []
    var statuses: [(Result<WorkspaceStatusReply, Error>) -> Void] = []
    var suspensions: [(WorkspaceSuspension, (Result<WorkspaceSuspendAck, Error>) -> Void)] = []
    var resumes: [(WorkspaceResumeToken, (Result<WorkspaceResumeAck, Error>) -> Void)] = []
    func hello(_ host: WorkspaceHello, deadline: UInt64, completion: @escaping (Result<WorkspaceHello, Error>) -> Void) {
        var guest = host; guest.guestServiceID = Data(repeating: 6, count: 16); completion(.success(guest))
    }
    func acknowledgeRetired(through sequence: UInt64, deadline: UInt64, completion: @escaping (Result<Void, Error>) -> Void) { retiredAcks.append((sequence, completion)) }
    func status(deadline: UInt64, completion: @escaping (Result<WorkspaceStatusReply, Error>) -> Void) { statuses.append(completion) }
    func suspend(_ request: WorkspaceSuspension, deadline: UInt64, completion: @escaping (Result<WorkspaceSuspendAck, Error>) -> Void) { suspensions.append((request, completion)) }
    func resume(_ token: WorkspaceResumeToken, deadline: UInt64, completion: @escaping (Result<WorkspaceResumeAck, Error>) -> Void) { resumes.append((token, completion)) }
}
private func rrGolden(_ name: String) throws -> Data {
    let url = try #require(Bundle.module.url(forResource: name, withExtension: "hex", subdirectory: "Goldens"))
    let text = try String(contentsOf: url, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
    var data = Data(); var index = text.startIndex
    while index < text.endIndex { let next = text.index(index, offsetBy: 2); data.append(UInt8(text[index..<next], radix: 16)!); index = next }
    return data
}
@MainActor private func rrRig() throws -> (WorkspaceCoordinator, RRVM, RRPower, RRClock, RRChannel) {
    let host = try WorkspaceControl.decode(rrGolden("hello")).hello
    let vm = RRVM(), power = RRPower(), clock = RRClock(), channel = RRChannel()
    let c = try WorkspaceCoordinator(host: host, oldInstanceAbsent: true, vm: vm, power: power, channel: channel, clock: clock, nonces: RRNonce())
    try c.start()
    return (c, vm, power, clock, channel)
}
@MainActor private func runningWithRetired(_ c: WorkspaceCoordinator, _ ch: RRChannel) throws -> WorkspaceRetiredOutcome {
    c.refreshStatus()
    var status = WorkspaceStatusReply()
    let h = try WorkspaceControl.decode(rrGolden("hello")).hello
    status.bootID = h.bootID; status.hostServiceID = h.hostServiceID; status.guestServiceID = Data(repeating: 6, count: 16)
    status.state = "running"; status.generation = c.generation
    var old = WorkspaceMountStatus(); old.outcome = unknownTestOutcome(); old.mount.authorityID = Data(repeating: 1, count: 32); old.mount.volumeID = "v"; old.mount.incarnation = Data(repeating: 3, count: 16)
    old.state = "terminal"; old.reason = "session ended"; old.cleanup = "complete"
    status.retired = [retiredTestOutcome(old, sequence: 1)]
    ch.statuses.removeFirst()(.success(status))
    return status.retired[0]
}

@Test @MainActor func workspaceConcurrentRetirementAcknowledgementsCoalesce() throws {
    let (c, _, _, _, ch) = try rrRig()
    let old = try runningWithRetired(c, ch)
    #expect(c.retiredStatus == [old])
    try c.acknowledgeRetired([old])
    try c.acknowledgeRetired([old]) // UI double action / retry before the first completes
    #expect(ch.retiredAcks.count == 1, "second identical RetireAck was sent")
}
@Test @MainActor func workspaceRetirementAcknowledgementRefusedWhilePausedCold() throws {
    let (c, vm, power, _, ch) = try rrRig()
    let old = try runningWithRetired(c, ch)
    power.handler?(.sleep(WorkspaceSleepNotification(id: 1, arrivedAt: 1_000)))
    var ack = WorkspaceSuspendAck(); ack.suspension = ch.suspensions[0].0
    ch.suspensions[0].1(.success(ack)); vm.pauses.removeFirst()(.success(()))
    #expect(c.phase == .pausedCold)
    #expect(throws: (any Error).self, "acknowledgeRetired accepted while VM is paused") { try c.acknowledgeRetired([old]) }
}
@Test @MainActor func workspacePauseFailureReplacesEarlierStatusReason() throws {
    let (c, _, _, clock, ch) = try rrRig()
    // Benign informational reason during normal running.
    c.refreshStatus()
    var status = WorkspaceStatusReply()
    let h = try WorkspaceControl.decode(rrGolden("hello")).hello
    status.bootID = h.bootID; status.hostServiceID = h.hostServiceID; status.guestServiceID = Data(repeating: 6, count: 16)
    status.state = "running"; status.generation = c.generation
    var r = WorkspaceMountStatus(); r.outcome = unknownTestOutcome(); r.mount.authorityID = Data(repeating: 1, count: 32); r.mount.volumeID = "v"; r.mount.incarnation = Data(repeating: 3, count: 16)
    r.state = "terminal"; r.reason = "x"; r.cleanup = "complete"
    status.retired = [retiredTestOutcome(r, sequence: 1)]
    ch.statuses.removeFirst()(.success(status))
    // Now a real failure: start a sleep and let pause budget expire.
    c.powerEvent(.sleep(WorkspaceSleepNotification(id: 1, arrivedAt: clock.now)))
    clock.advance(17_600_000_000)
    #expect(c.phase == .stopping)
    #expect(c.reason.contains("pause"), "reason was \(c.reason)")
}
@Test @MainActor func workspaceChannelLossWhileAwakeStopsVM() throws {
    let (c, vm, _, clock, _) = try rrRig()
    c.channelLost("peer EOF")
    #expect(vm.calls.last == "stop")
    vm.stops.removeFirst()(.success(()))
    clock.advance(3_600_000_000_000)
    #expect(c.phase != .pausedDiscard, "discard-only VM remains paused with no stop until a power event or owner action")
}

@Test @MainActor func workspaceControlQueueMustBeEmptyBeforePause() throws {
    let (c, vm, power, _, ch) = try rrRig()
    power.handler?(.sleep(WorkspaceSleepNotification(id: 1, arrivedAt: 1_000)))
    ch.isIdle = false
    var ack = WorkspaceSuspendAck(); ack.suspension = ch.suspensions[0].0
    ch.suspensions[0].1(.success(ack))
    #expect(vm.pauses.isEmpty)
    #expect(vm.calls.last == "stop")
}
@Test @MainActor func workspaceSuccessfulStatusClearsPreviousTransitionReason() throws {
    let (c, vm, power, _, ch) = try rrRig()
    power.handler?(.sleep(WorkspaceSleepNotification(id: 1, arrivedAt: 1_000)))
    var cold = WorkspaceSuspendAck(); cold.suspension = ch.suspensions[0].0
    ch.suspensions[0].1(.success(cold)); vm.pauses.removeFirst()(.success(()))
    c.powerEvent(.wake); vm.resumes.removeFirst()(.success(()))
    ch.resumes[0].1(.failure(WorkspaceControlError.grammar))
    #expect(!c.reason.isEmpty)
    _ = try runningWithRetired(c, ch)
    #expect(c.reason.isEmpty)
}

// A. Failure-driven stop: is the reason still visible once the stop completes?
@Test @MainActor func workspaceStopReasonSurvivesConfirmedStop() throws {
    let (c, vm, _, _, _) = try rrRig()
    c.channelLost("peer EOF")
    #expect(c.phase == .stopping)
    #expect(c.reason.contains("control channel lost"))
    vm.stops.removeFirst()(.success(()))
    #expect(c.phase == .stopped)
    #expect(c.reason == "control channel lost: peer EOF")
}
// A2. Unfenced release reason after the stop completes.
@Test @MainActor func workspaceUnfencedReleaseReasonSurvivesStop() throws {
    let (c, vm, power, clock, ch) = try rrRig()
    power.handler?(.sleep(WorkspaceSleepNotification(id: 1, arrivedAt: clock.now)))
    _ = ch
    clock.advance(20_000_000_001)
    #expect(power.acknowledgements.last?.1 == false)
    #expect(c.reason.contains("unfenced") || c.reason.contains("pause"), "reason was \(c.reason)")
    let reason = c.reason
    while !vm.stops.isEmpty { vm.stops.removeFirst()(.success(())) }
    #expect(c.phase == .stopped)
    #expect(c.reason == reason)
}

// D. Host-side idempotency after completion.
@Test @MainActor func workspaceRetirementRetryAfterCompletionIsIdempotent() throws {
    let (c, _, _, _, ch) = try rrRig()
    let old = try runningWithRetired(c, ch)
    try c.acknowledgeRetired([old])
    ch.retiredAcks.removeFirst().1(.success(()))
    #expect(c.retiredStatus.isEmpty)
    #expect(throws: Never.self, "UI retry after successful acknowledgement throws") { try c.acknowledgeRetired([old]) }
}

@Test @MainActor func workspaceNonIncreasingNotificationIDsStopVM() throws {
    for id in [UInt64(0), 4, 5] {
        let (c, vm, power, _, ch) = try rrRig()
        c.powerEvent(.sleep(WorkspaceSleepNotification(id: 5, arrivedAt: 1_000)))
        c.powerEvent(.sleep(WorkspaceSleepNotification(id: id, arrivedAt: 1_000)))
        #expect(c.phase == .stopping)
        #expect(vm.calls.last == "stop")
        #expect(c.reason == "unknown power transition")
        #expect(power.acknowledgements.count == 1)
        #expect(power.acknowledgements[0].0 == id && !power.acknowledgements[0].1)
        var ack = WorkspaceSuspendAck(); ack.suspension = ch.suspensions[0].0
        ch.suspensions[0].1(.success(ack))
        #expect(vm.pauses.isEmpty)
        vm.stops.removeFirst()(.success(()))
        #expect(c.phase == .stopped)
        #expect(c.reason == "unknown power transition")
        #expect(power.acknowledgements.filter { $0.0 == 5 }.count == 1)
    }
}

// B. Duplicate (non-increasing) notification while draining: unfenced release without unsafe transition?
@Test @MainActor func workspaceDuplicateNotificationStopsBeforeUnfencedRelease() throws {
    let (c, vm, power, _, _) = try rrRig()
    c.powerEvent(.sleep(WorkspaceSleepNotification(id: 5, arrivedAt: 1_000)))
    #expect(c.phase == .draining)
    c.powerEvent(.sleep(WorkspaceSleepNotification(id: 5, arrivedAt: 1_000)))
    #expect(power.acknowledgements.count == 1 && power.acknowledgements[0] == (5, false))
    #expect(c.phase == .stopping)
    #expect(vm.calls.last == "stop")
    #expect(c.reason == "unknown power transition")
}

@Test @MainActor func workspaceJoinedJobRetirementPreservesObservationAndAcknowledgement() throws {
    let (c, _, _, _, ch) = try rrRig()
    var status = try WorkspaceControl.decode(rrGolden("job_running")).statusReply
    status.generation = c.generation; status.jobs[0].generation = c.generation
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    let running = status.jobs[0]
    #expect(c.jobStatus == [running])
    ch.retiredAcks.removeFirst().1(.success(()))
    // A missing retirement page must leave the last observed owner intact.
    status.jobs = []
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.jobStatus == [running])
    #expect(c.reason.contains("retired jobs"))
    var joined = running; joined.phase = "failed"; joined.failure = "unavailable"; joined.reason = "real mount driver unavailable"
    var outcome = WorkspaceRetiredOutcome(); outcome.retirementSequence = 2; outcome.job = joined
    status.retired.append(outcome)
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.jobStatus.isEmpty)
    #expect(c.retiredStatus.last == outcome)
    #expect(c.reason.isEmpty)
    let observed = c.retiredStatus
    try c.acknowledgeRetired(observed)
    ch.retiredAcks.removeFirst().1(.success(()))
    #expect(c.retiredStatus.isEmpty)
    status.retired = []
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.reason.isEmpty)
}

@Test @MainActor func workspaceMixedRetirementPagesReconcileMountBeforeLaterJob() throws {
    let (c, _, _, _, ch) = try rrRig()
    var status = try WorkspaceControl.decode(rrGolden("status_reply")).statusReply
    status.generation = c.generation
    status.retired = []
    var old = status.mounts[0]
    old.state = "terminal"; old.reason = "session ended"; old.cleanup = "complete"
    status.mounts = [old]
    var job = try WorkspaceControl.decode(rrGolden("job_running")).statusReply.jobs[0]
    job.generation = c.generation; job.mount.volumeID = "pending"
    status.jobs = [job]
    #expect(WorkspaceControl.validStatus(status))
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.mountStatus == [old] && c.jobStatus == [job])

    var replacement = old
    replacement.mount.incarnation = Data(repeating: 99, count: 16)
    replacement.state = "closed"; replacement.reason = ""; replacement.cleanup = "retained"
    status.mounts = [replacement]; status.jobs = []
    status.retired = [retiredTestOutcome(old, sequence: 1)]
    for seq in 2...16 {
        var filler = job; filler.mount.volumeID = "filler-" + String(seq); filler.requestID = UInt64(seq + 100); filler.phase = "complete"
        var outcome = WorkspaceRetiredOutcome(); outcome.retirementSequence = UInt64(seq); outcome.job = filler
        status.retired.append(outcome)
    }
    #expect(WorkspaceControl.validStatus(status))
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.mountStatus == [replacement])
    #expect(c.jobStatus == [job])
    #expect(ch.retiredAcks.map(\.0) == [16])
    try c.acknowledgeRetired(c.retiredStatus)
    ch.retiredAcks.removeFirst().1(.success(()))

    job.phase = "complete"
    var last = WorkspaceRetiredOutcome(); last.retirementSequence = 17; last.job = job
    status.retired = [last]
    #expect(WorkspaceControl.validStatus(status))
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.jobStatus.isEmpty)
    #expect(ch.retiredAcks.map(\.0) == [17])
    try c.acknowledgeRetired(c.retiredStatus)
    ch.retiredAcks.removeFirst().1(.success(()))
    status.retired = []
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.reason.isEmpty, "both pages were observed and acknowledged")
    #expect(c.mountStatus == [replacement], "old mount stayed pinned after its evidence was acknowledged and deleted")
}

// R2 review: refreshStatus never acknowledges, and an acknowledgement sent on
// the channel outside the coordinator (WorkspaceDev.observeUnavailableJob)
// leaves a sequence gap that wedges coordinator observation permanently.
@Test @MainActor func workspaceObservationOwnsAcknowledgementAndReconcilesStalePages() throws {
    let (c, _, _, _, ch) = try rrRig()
    var status = try WorkspaceControl.decode(rrGolden("job_running")).statusReply
    status.generation = c.generation; status.jobs[0].generation = c.generation
    var joined = status.jobs[0]; joined.phase = "failed"; joined.failure = "unavailable"; joined.reason = "real mount driver unavailable"
    status.jobs = []
    var first = WorkspaceRetiredOutcome(); first.retirementSequence = 1; first.job = joined
    status.retired = [first]
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.retiredStatus == [first])
    #expect(ch.retiredAcks.map(\.0) == [1])
    ch.retiredAcks.removeFirst().1(.success(()))
    // A snapshot queued before the ack can arrive after its completion.
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.retiredStatus.isEmpty && c.reason.isEmpty)
    var second = first; second.retirementSequence = 2; second.job.requestID += 1
    status.retired = [second]
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.retiredStatus == [second])
    #expect(ch.retiredAcks.map(\.0) == [2])
    ch.retiredAcks.removeFirst().1(.success(()))
    status.retired = []
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.retiredStatus.isEmpty && c.reason.isEmpty)
}

@Test @MainActor func workspaceMixedRetirementPagesReconcileJobBeforeLaterMount() throws {
    let (c, _, _, _, ch) = try rrRig()
    var status = try WorkspaceControl.decode(rrGolden("status_reply")).statusReply
    status.generation = c.generation
    status.retired = []
    var old = status.mounts[0]
    old.state = "terminal"; old.reason = "session ended"; old.cleanup = "complete"
    status.mounts = [old]
    var job = try WorkspaceControl.decode(rrGolden("job_running")).statusReply.jobs[0]
    job.generation = c.generation; job.mount.volumeID = "pending"
    status.jobs = [job]
    #expect(WorkspaceControl.validStatus(status))
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.mountStatus == [old] && c.jobStatus == [job])

    var replacement = old
    replacement.mount.incarnation = Data(repeating: 99, count: 16)
    replacement.state = "closed"; replacement.reason = ""; replacement.cleanup = "retained"
    status.mounts = [replacement]; status.jobs = []
    var joined = job; joined.phase = "complete"
    var first = WorkspaceRetiredOutcome(); first.retirementSequence = 1; first.job = joined
    status.retired = [first]
    for seq in 2...16 {
        var filler = job; filler.mount.volumeID = "filler-" + String(seq); filler.requestID = UInt64(seq + 100); filler.phase = "complete"
        var outcome = WorkspaceRetiredOutcome(); outcome.retirementSequence = UInt64(seq); outcome.job = filler
        status.retired.append(outcome)
    }
    #expect(WorkspaceControl.validStatus(status))
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.mountStatus == [old])
    #expect(c.jobStatus.isEmpty)
    #expect(ch.retiredAcks.map(\.0) == [16])
    try c.acknowledgeRetired(c.retiredStatus)
    ch.retiredAcks.removeFirst().1(.success(()))

    job.phase = "complete"
    let last = retiredTestOutcome(old, sequence: 17)
    status.retired = [last]
    #expect(WorkspaceControl.validStatus(status))
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.jobStatus.isEmpty)
    #expect(ch.retiredAcks.map(\.0) == [17])
    try c.acknowledgeRetired(c.retiredStatus)
    ch.retiredAcks.removeFirst().1(.success(()))
    status.retired = []
    c.refreshStatus(); ch.statuses.removeFirst()(.success(status))
    #expect(c.reason.isEmpty, "both pages were observed and acknowledged")
    #expect(c.mountStatus == [replacement], "old mount stayed pinned after its evidence was acknowledged and deleted")
}
