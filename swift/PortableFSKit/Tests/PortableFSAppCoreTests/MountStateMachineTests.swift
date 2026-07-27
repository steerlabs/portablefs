import Foundation
import Testing
@testable import PortableFSAppCore

/// Applies a sequence of events and returns the accept/reject verdicts.
/// (Hoisted out of `#expect` because the macro cannot call mutating members.)
private func run(_ machine: inout MountStateMachine, _ events: [VolumeMountEvent]) -> [Bool] {
    events.map { machine.apply($0) }
}

@Test func mountHappyPath() {
    var machine = MountStateMachine()
    let verdicts = run(&machine, [
        .mountRequested,
        .sessionMinted,
        .attachEnsured(attachRef: "att_1"),
        .mountCompleted(mountPath: "/m/vol")
    ])
    #expect(verdicts == [true, true, true, true])
    #expect(machine.state == .mounted(attachRef: "att_1", mountPath: "/m/vol"))
    #expect(machine.state.isMounted)
    #expect(!machine.state.isBusy)
    #expect(machine.state.attachRef == "att_1")
    #expect(machine.state.mountPath == "/m/vol")
}

@Test func mountIntermediateStatesAreBusy() {
    var machine = MountStateMachine()
    let accepted = run(&machine, [.mountRequested])
    #expect(accepted == [true])
    #expect(machine.state == .mintingSession)
    #expect(machine.state.isBusy)

    let minted = run(&machine, [.sessionMinted])
    #expect(minted == [true])
    #expect(machine.state == .attaching)

    let attached = run(&machine, [.attachEnsured(attachRef: "att_1")])
    #expect(attached == [true])
    #expect(machine.state == .mounting(attachRef: "att_1"))
    #expect(machine.state.attachRef == "att_1")
}

@Test func unmountHappyPath() {
    var machine = MountStateMachine(state: .mounted(attachRef: "att_1", mountPath: "/m/vol"))
    let requested = run(&machine, [.unmountRequested])
    #expect(requested == [true])
    #expect(machine.state == .unmounting(attachRef: "att_1", mountPath: "/m/vol"))

    let unmounted = run(&machine, [.unmountCompleted])
    #expect(unmounted == [true])
    #expect(machine.state == .detaching(attachRef: "att_1"))

    let detached = run(&machine, [.detachCompleted])
    #expect(detached == [true])
    #expect(machine.state == .unmounted)
}

@Test func invalidTransitionsAreRejected() {
    var machine = MountStateMachine()
    let rejected = run(&machine, [.sessionMinted, .unmountRequested])
    #expect(rejected == [false, false])
    #expect(machine.state == .unmounted)

    let first = run(&machine, [.mountRequested])
    #expect(first == [true])
    // A second mount request mid-flight must not restart the flow.
    let second = run(&machine, [.mountRequested])
    #expect(second == [false])
    #expect(machine.state == .mintingSession)

    var mounted = MountStateMachine(state: .mounted(attachRef: "a", mountPath: "/m"))
    // Mount requests and failure events do not apply to a settled mount.
    let ignored = run(&mounted, [.mountRequested, .failed(message: "x")])
    #expect(ignored == [false, false])
    #expect(mounted.state.isMounted)
}

@Test func failureFromAnyBusyState() {
    for busy: VolumeMountState in [
        .mintingSession,
        .attaching,
        .mounting(attachRef: "a"),
        .unmounting(attachRef: "a", mountPath: "/m"),
        .detaching(attachRef: "a")
    ] {
        var machine = MountStateMachine(state: busy)
        let failed = run(&machine, [.failed(message: "boom")])
        #expect(failed == [true])
        #expect(machine.state == .failed(message: "boom"))
    }
    // Retry after failure is allowed.
    var machine = MountStateMachine(state: .failed(message: "boom"))
    let retried = run(&machine, [.mountRequested])
    #expect(retried == [true])
    #expect(machine.state == .mintingSession)
}

@Test func observedReconciliationOnlyAppliesWhenIdle() {
    var machine = MountStateMachine()
    let observed = run(&machine, [.observedMounted(attachRef: "att_ext", mountPath: "/m")])
    #expect(observed == [true])
    #expect(machine.state == .mounted(attachRef: "att_ext", mountPath: "/m"))
    let gone = run(&machine, [.observedUnmounted])
    #expect(gone == [true])
    #expect(machine.state == .unmounted)

    var failed = MountStateMachine(state: .failed(message: "old failure"))
    let recovered = run(&failed, [.observedMounted(attachRef: "a", mountPath: "/m")])
    #expect(recovered == [true])
    #expect(failed.state.isMounted)

    // Reconciliation must not stomp an in-flight operation.
    var busy = MountStateMachine(state: .attaching)
    let stomped = run(&busy, [.observedMounted(attachRef: "a", mountPath: "/m"), .observedUnmounted])
    #expect(stomped == [false, false])
    #expect(busy.state == .attaching)

    // A refresh while mounted keeps the freshest mount info.
    var mounted = MountStateMachine(state: .mounted(attachRef: "a", mountPath: "/m"))
    let refreshed = run(&mounted, [.observedMounted(attachRef: "b", mountPath: "/m2")])
    #expect(refreshed == [true])
    #expect(mounted.state == .mounted(attachRef: "b", mountPath: "/m2"))
}

@Test func menuLabelsAreHumanReadable() {
    #expect(VolumeMountState.unmounted.menuStatusLabel == "Not mounted")
    #expect(VolumeMountState.mounted(attachRef: "a", mountPath: "/m").menuStatusLabel == "Mounted")
    #expect(VolumeMountState.failed(message: "socket down").menuStatusLabel.contains("socket down"))
}
