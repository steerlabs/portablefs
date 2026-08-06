import Foundation
import Testing

@testable import PortableFSKit

// The two-writer drain deadlock, pinned. A PREPARE drain may wait for a
// callback only while it is publishing — bounded local work. A callback that
// parked an authority-ordered mutation cannot publish until the barrier
// completes, because the authority orders that mutation strictly after the
// barrier; a drain that waits for it is waiting on itself, and the mount dies
// at its repair budget. `git init`'s concurrent short-lived mutations produced
// exactly this against a live kernel.

private let drainLocalSession = Data(repeating: 0x5A, count: 16)
private let drainPeerSession = Data(repeating: 0xA5, count: 16)

private func drainEvent(
    initiatorSession: Data,
    localOperationID: UInt64? = nil
) throws -> PfsMacOSCoherenceEvent {
    try PfsMacOSCoherenceEvent(
        epoch: Data(repeating: 0xE0, count: 16),
        sequence: 7,
        phase: .prepare,
        initiator: PfsMacOSMutationInitiator(
            sessionID: initiatorSession,
            replaySlot: 1,
            mutationSequence: 7,
            localOperationID: localOperationID
        ),
        repairs: []
    )
}

@available(macOS 26.0, *)
@Test func prepareReleasesACallbackThatAlreadyParkedAMutation() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let parked = try await barrier.admit()
    parked.orderedMutationSubmitted()

    // A peer barrier exempts nothing by operation ID; the parked callback
    // must be released by its parked state alone or this never returns.
    try await barrier.prepare(drainEvent(initiatorSession: drainPeerSession))
}

@available(macOS 26.0, *)
@Test func prepareReleasesACallbackTheMomentItParksMidDrain() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let ticket = try await barrier.admit()

    let prepare = Task {
        try await barrier.prepare(drainEvent(initiatorSession: drainPeerSession))
    }
    // Let the drain begin waiting on the un-parked, un-published ticket.
    try await Task.sleep(nanoseconds: 50_000_000)
    ticket.orderedMutationSubmitted()

    try await prepare.value
}

private actor DrainCompletion {
    private var done = false
    func mark() { done = true }
    func value() -> Bool { done }
}

// The release verdicts. A callback released for a parked MUTATION installs
// normally — the authority orders that mutation after the barrier. A callback
// released with only reads in flight that already holds cache-producing
// replies may combine pre-barrier values into its install, so it is crossed
// and the adapter refuses the install with EINTR.
@available(macOS 26.0, *)
@Test func releaseVerdictsCrossExactlyTheExposedReadCallbacks() {
    let exposedReads = PfsMacOSAdmittedCallbackTicket()
    exposedReads.ordinaryRequestSubmitted()
    exposedReads.publishingReplyReceived()
    exposedReads.markCrossedIfExposedReadsWereReleased()
    #expect(exposedReads.isCrossed())

    let freshRead = PfsMacOSAdmittedCallbackTicket()
    freshRead.ordinaryRequestSubmitted()
    freshRead.markCrossedIfExposedReadsWereReleased()
    #expect(!freshRead.isCrossed())

    let parkedMutation = PfsMacOSAdmittedCallbackTicket()
    parkedMutation.publishingReplyReceived()
    parkedMutation.orderedMutationSubmitted()
    parkedMutation.markCrossedIfExposedReadsWereReleased()
    #expect(!parkedMutation.isCrossed())

    let installing = PfsMacOSAdmittedCallbackTicket()
    installing.publishingReplyReceived()
    installing.markCrossedIfExposedReadsWereReleased()
    #expect(!installing.isCrossed())
}

@available(macOS 26.0, *)
@Test func prepareReleasesACallbackWithAnOrdinaryReadInFlight() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let reading = try await barrier.admit()
    reading.ordinaryRequestSubmitted()
    try await barrier.prepare(drainEvent(initiatorSession: drainPeerSession))
    #expect(!reading.isCrossed())
}

@available(macOS 26.0, *)
@Test func prepareStillDrainsAPublishingCallback() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let publishing = try await barrier.admit()

    let completion = DrainCompletion()
    let prepare = Task {
        try await barrier.prepare(drainEvent(initiatorSession: drainPeerSession))
        await completion.mark()
    }
    try await Task.sleep(nanoseconds: 100_000_000)
    // The barrier must still be waiting: nothing released this callback.
    #expect(!(await completion.value()))

    await barrier.published(publishing)
    try await prepare.value
    #expect(await completion.value())
}

@available(macOS 26.0, *)
@Test func aSettledMutationDoesNotKeepTheNextBarrierExempt() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let ticket = try await barrier.admit()
    ticket.orderedMutationSubmitted()
    ticket.orderedMutationSettled()

    let completion = DrainCompletion()
    let prepare = Task {
        try await barrier.prepare(drainEvent(initiatorSession: drainPeerSession))
        await completion.mark()
    }
    try await Task.sleep(nanoseconds: 100_000_000)
    // With its mutation settled the callback is publishing again and the
    // drain must hold until publication.
    #expect(!(await completion.value()))
    await barrier.published(ticket)
    try await prepare.value
    #expect(await completion.value())
}
