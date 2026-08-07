import Foundation
import Testing

@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

// The two-writer drain deadlock, pinned. Every intersecting callback releases
// its FSKit pathname/namespace lane before the nested VFS repair begins. The
// authority classifies an interrupted mutation definite-preapply, so policy v2
// can surface ECANCELED without fencing or risking partial work.

private let drainLocalSession = Data(repeating: 0x5A, count: 16)
private let drainPeerSession = Data(repeating: 0xA5, count: 16)

private func drainNamespaceScope(
    parent: PfsMacOSStableIdentity,
    name: Data,
    parentMutation: Bool = false
) -> PfsMacOSCallbackScope {
    var selectors: Set<PfsMacOSAdmissionSelector> = [
        .namespace(PfsMacOSNamespaceCoordinate(parentIdentity: parent, name: name)),
    ]
    if parentMutation {
        selectors.insert(.directory(parent))
        selectors.insert(.orderedMutation)
    }
    return PfsMacOSCallbackScope(selectors: selectors)
}

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

private func drainLocalEvent(
    phase: PfsMacOSVisibilityPhase,
    localOperationID: UInt64,
    sequence: UInt64 = 17
) throws -> PfsMacOSCoherenceEvent {
    try PfsMacOSCoherenceEvent(
        epoch: Data(repeating: 0xE0, count: 16),
        sequence: sequence,
        phase: phase,
        initiator: PfsMacOSMutationInitiator(
            sessionID: drainLocalSession,
            replaySlot: 1,
            mutationSequence: sequence,
            localOperationID: localOperationID
        ),
        repairs: []
    )
}

@Test func callbackAdmissionDiagnosticSummaryContainsNoIdentityOrNameMaterial() throws {
    let parent = try PfsMacOSStableIdentity(Data(repeating: 0x73, count: 16))
    let rawName = Data("private-callback-name".utf8)
    let scope = drainNamespaceScope(
        parent: parent,
        name: rawName,
        parentMutation: true
    )
    let summary = scope.diagnosticSummary
    #expect(summary == "conservative=false ordered=true namespace=1 directory=1 item=0")
    #expect(!summary.contains("private-callback-name"))
    #expect(!summary.contains(parent.bytes.base64EncodedString()))
}

@available(macOS 26.0, *)
@Test func prepareWaitsForAnInterruptedMutationCallbackToPublish() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let parked = try await barrier.admit()
    parked.orderedMutationSubmitted()

    let completion = DrainCompletion()
    let prepare = Task {
        try await barrier.prepare(drainEvent(initiatorSession: drainPeerSession))
        await completion.mark()
    }
    try await Task.sleep(nanoseconds: 50_000_000)
    #expect(!(await completion.value()))
    parked.orderedMutationSettled()
    await barrier.published(parked)
    try await prepare.value
    #expect(await completion.value())
}

@available(macOS 26.0, *)
@Test func synchronousIngressBeforePrepareIsAdoptedIntoTheExistingDrain() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let scope = PfsMacOSCallbackScope(selectors: [.orderedMutation])
    let reservation = barrier.reserveCallbackIngress(
        scope: scope,
        callbackKind: "renameItem",
        ingressUptimeNanoseconds: 1
    )
    #expect(await barrier.pendingIngressReservationCount() == 1)

    let event = try drainEvent(initiatorSession: drainPeerSession)
    let preparing = Task { try await barrier.prepare(event) }
    while await barrier.pendingIngressReservationCount() != 0 {
        await Task.yield()
    }
    #expect(await barrier.admittedCallbackCount() == 1)

    let ticket = try #require(try await barrier.resolveAdmission(
        for: reservation,
        exemptFromAdmission: false
    ))
    #expect(ticket === reservation.ticket)
    #expect(!ticket.orderedMutationSubmitted())
    await barrier.callbackReplyReturned(reservation)
    try await preparing.value
    #expect(await barrier.admittedCallbackCount() == 0)

    let complete = try PfsMacOSCoherenceEvent(
        epoch: event.epoch,
        sequence: event.sequence,
        phase: .complete,
        initiator: event.initiator,
        repairs: event.repairs
    )
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
}

@available(macOS 26.0, *)
@Test func frozenV1PreCutIngressKeepsItsExistingEBUSYTicketVerdict() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession,
        policy: .synchronousVFSRepairV1
    )
    let reservation = barrier.reserveCallbackIngress(
        scope: PfsMacOSCallbackScope(selectors: [.orderedMutation]),
        callbackKind: "renameItem",
        ingressUptimeNanoseconds: 1
    )
    let event = try drainEvent(initiatorSession: drainPeerSession)
    let preparing = Task { try await barrier.prepare(event) }
    while await barrier.pendingIngressReservationCount() != 0 {
        await Task.yield()
    }
    let ticket = try #require(try await barrier.resolveAdmission(
        for: reservation,
        exemptFromAdmission: false
    ))
    #expect(ticket.admissionRefusalError() == .publicationAdmissionBusy)
    #expect(ticket.admissionRefusalError().posixErrno == EBUSY)
    #expect(!ticket.orderedMutationSubmitted())
    await barrier.callbackReplyReturned(reservation)
    try await preparing.value

    let complete = try PfsMacOSCoherenceEvent(
        epoch: event.epoch,
        sequence: event.sequence,
        phase: .complete,
        initiator: event.initiator,
        repairs: event.repairs
    )
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
}

@available(macOS 26.0, *)
@Test func prepareCutBeforeIngressUsesTheExistingPostPrepareRefusal() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let event = try drainEvent(initiatorSession: drainPeerSession)
    try await barrier.prepare(event)
    let reservation = barrier.reserveCallbackIngress(
        scope: PfsMacOSCallbackScope(selectors: [.orderedMutation]),
        callbackKind: "renameItem",
        ingressUptimeNanoseconds: 1
    )

    do {
        _ = try await barrier.resolveAdmission(
            for: reservation,
            exemptFromAdmission: false
        )
        Issue.record("post-cut ingress reservation escaped repair admission")
    } catch let error as PfsLocalClientError {
        #expect(error == .publicationAdmissionClosed)
    }
    await barrier.callbackReplyReturned(reservation)
    #expect(await barrier.pendingIngressReservationCount() == 0)
    #expect(await barrier.admittedCallbackCount() == 0)
    let counts = await barrier.refusedCallbackCounts()
    #expect(counts.ordered == 1)

    let complete = try PfsMacOSCoherenceEvent(
        epoch: event.epoch,
        sequence: event.sequence,
        phase: .complete,
        initiator: event.initiator,
        repairs: event.repairs
    )
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
}

@available(macOS 26.0, *)
@Test func preflightFailurePublishesAnIngressReservationAdoptedByPrepare() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let reservation = barrier.reserveCallbackIngress(
        scope: PfsMacOSCallbackScope(selectors: [.orderedMutation]),
        callbackKind: "setXattr",
        ingressUptimeNanoseconds: 1
    )
    let event = try drainEvent(initiatorSession: drainPeerSession)
    let preparing = Task { try await barrier.prepare(event) }
    while await barrier.pendingIngressReservationCount() != 0 {
        await Task.yield()
    }

    // The capability preflight replied without ever resolving admission. Its
    // framework reply still owns the reservation's publication boundary.
    await barrier.callbackReplyReturned(reservation)
    try await preparing.value
    #expect(await barrier.admittedCallbackCount() == 0)
}

@available(macOS 26.0, *)
@Test func authenticatedRepairBypassRetiresPostCutIngressWithoutContentionDebt() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let event = try drainEvent(initiatorSession: drainPeerSession)
    try await barrier.prepare(event)
    let reservation = barrier.reserveCallbackIngress(
        scope: PfsMacOSCallbackScope(selectors: [.orderedMutation]),
        callbackKind: "removeItem",
        ingressUptimeNanoseconds: 1
    )

    let ticket = try await barrier.resolveAdmission(
        for: reservation,
        exemptFromAdmission: true
    )
    #expect(ticket == nil)
    await barrier.callbackReplyReturned(reservation)
    #expect(await barrier.pendingIngressReservationCount() == 0)
    let counts = await barrier.refusedCallbackCounts()
    #expect(counts.ordered == 0)
    #expect(counts.other == 0)

    let complete = try PfsMacOSCoherenceEvent(
        epoch: event.epoch,
        sequence: event.sequence,
        phase: .complete,
        initiator: event.initiator,
        repairs: event.repairs
    )
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
}

@available(macOS 26.0, *)
@Test func localSourcePrepareParksAnAdoptedPristineReservationThroughExactAck() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let reservation = barrier.reserveCallbackIngress(
        scope: PfsMacOSCallbackScope(selectors: [.orderedMutation]),
        callbackKind: "createItem",
        ingressUptimeNanoseconds: 1
    )
    let prepare = try drainLocalEvent(
        phase: .prepare,
        localOperationID: 808,
        sequence: 108
    )
    try await barrier.prepare(prepare)
    let ticket = try #require(try await barrier.resolveAdmission(
        for: reservation,
        exemptFromAdmission: false
    ))
    let submission = Task { try await ticket.orderedMutationSubmittedWhenPermitted() }
    await Task.yield()

    let complete = try drainLocalEvent(
        phase: .complete,
        localOperationID: 808,
        sequence: 108
    )
    try await barrier.resume(complete)
    let wrongComplete = try drainLocalEvent(
        phase: .complete,
        localOperationID: 808,
        sequence: 109
    )
    await barrier.acknowledged(wrongComplete)
    #expect(!submission.isCancelled)
    #expect(ticket.orderedMutationSubmission() == nil)

    await barrier.acknowledged(complete)
    #expect(try await submission.value)
    ticket.orderedMutationSettled()
    await barrier.callbackReplyReturned(reservation)
    #expect(await barrier.admittedCallbackCount() == 0)
}

@available(macOS 26.0, *)
@Test func disjointPreCutReservationRemainsUsableWhilePrepareDrainsItsAudience() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let repairedParent = try PfsMacOSStableIdentity(Data(repeating: 0x31, count: 16))
    let disjointParent = try PfsMacOSStableIdentity(Data(repeating: 0x32, count: 16))
    let reservation = barrier.reserveCallbackIngress(
        scope: drainNamespaceScope(
            parent: disjointParent,
            name: Data("unrelated".utf8)
        ),
        callbackKind: "lookupItem",
        ingressUptimeNanoseconds: 1
    )
    let event = try PfsMacOSCoherenceEvent(
        epoch: Data(repeating: 0xE0, count: 16),
        sequence: 110,
        phase: .prepare,
        initiator: PfsMacOSMutationInitiator(
            sessionID: drainPeerSession,
            replaySlot: 1,
            mutationSequence: 110
        ),
        repairs: [
            .purgeNegative(
                parent: try PfsMacOSRelativePath(components: []),
                parentIdentity: repairedParent,
                name: Data("changed".utf8)
            ),
        ]
    )
    try await barrier.prepare(event)
    let ticket = try #require(try await barrier.resolveAdmission(
        for: reservation,
        exemptFromAdmission: false
    ))
    let requestID = try #require(ticket.ordinaryRequestSubmitted())
    ticket.ordinaryRequestSettled(requestID)
    await barrier.callbackReplyReturned(reservation)

    let complete = try PfsMacOSCoherenceEvent(
        epoch: event.epoch,
        sequence: event.sequence,
        phase: .complete,
        initiator: event.initiator,
        repairs: event.repairs
    )
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
}

@available(macOS 26.0, *)
@Test func prepareLockCutPartitionsReservationsAndRetiresEveryTicket() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let scope = PfsMacOSCallbackScope(selectors: [.orderedMutation])
    let before = (0..<8).map { index in
        barrier.reserveCallbackIngress(
            scope: scope,
            callbackKind: "before-\(index)",
            ingressUptimeNanoseconds: UInt64(index + 1)
        )
    }
    let event = try drainEvent(initiatorSession: drainPeerSession)
    let preparing = Task { try await barrier.prepare(event) }
    while await barrier.pendingIngressReservationCount() != 0 {
        await Task.yield()
    }
    let after = (0..<8).map { index in
        barrier.reserveCallbackIngress(
            scope: scope,
            callbackKind: "after-\(index)",
            ingressUptimeNanoseconds: UInt64(index + 9)
        )
    }
    let ids = Set((before + after).map { $0.ticket.diagnosticID })
    #expect(ids.count == 16)

    for reservation in before {
        let ticket = try #require(try await barrier.resolveAdmission(
            for: reservation,
            exemptFromAdmission: false
        ))
        #expect(ticket === reservation.ticket)
        await barrier.callbackReplyReturned(reservation)
    }
    try await preparing.value
    for reservation in after {
        await #expect(throws: PfsLocalClientError.self) {
            _ = try await barrier.resolveAdmission(
                for: reservation,
                exemptFromAdmission: false
            )
        }
        await barrier.callbackReplyReturned(reservation)
    }
    #expect(await barrier.pendingIngressReservationCount() == 0)
    #expect(await barrier.admittedCallbackCount() == 0)

    let complete = try PfsMacOSCoherenceEvent(
        epoch: event.epoch,
        sequence: event.sequence,
        phase: .complete,
        initiator: event.initiator,
        repairs: event.repairs
    )
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
}

@available(macOS 26.0, *)
@Test func terminalFailureRetiresPendingAndPrepareAdoptedReservationsWithoutLeaks() async throws {
    let scope = PfsMacOSCallbackScope(selectors: [.orderedMutation])

    let pendingBarrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let pending = pendingBarrier.reserveCallbackIngress(
        scope: scope,
        callbackKind: "pending",
        ingressUptimeNanoseconds: 1
    )
    await pendingBarrier.fail(PfsMacOSCoherenceError.transportClosed)
    await #expect(throws: (any Error).self) {
        _ = try await pendingBarrier.resolveAdmission(
            for: pending,
            exemptFromAdmission: false
        )
    }
    await pendingBarrier.callbackReplyReturned(pending)
    #expect(await pendingBarrier.pendingIngressReservationCount() == 0)
    #expect(await pendingBarrier.admittedCallbackCount() == 0)

    let adoptedBarrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let adopted = adoptedBarrier.reserveCallbackIngress(
        scope: scope,
        callbackKind: "adopted",
        ingressUptimeNanoseconds: 2
    )
    let event = try drainEvent(initiatorSession: drainPeerSession)
    let preparing = Task { try await adoptedBarrier.prepare(event) }
    while await adoptedBarrier.pendingIngressReservationCount() != 0 {
        await Task.yield()
    }
    await adoptedBarrier.fail(PfsMacOSCoherenceError.transportClosed)
    await adoptedBarrier.callbackReplyReturned(adopted)
    await #expect(throws: (any Error).self) {
        try await preparing.value
    }
    #expect(await adoptedBarrier.pendingIngressReservationCount() == 0)
    #expect(await adoptedBarrier.admittedCallbackCount() == 0)
}

@available(macOS 26.0, *)
@Test func prepareRevokesDeclaredMutationIntentBeforeAuthoritySubmission() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let ticket = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    let event = try drainEvent(initiatorSession: drainPeerSession)
    let prepare = Task { try await barrier.prepare(event) }
    try await Task.sleep(nanoseconds: 50_000_000)
    #expect(!ticket.orderedMutationSubmitted())
    await barrier.published(ticket)
    try await prepare.value
    let complete = try PfsMacOSCoherenceEvent(
        epoch: event.epoch,
        sequence: event.sequence,
        phase: .complete,
        initiator: event.initiator,
        repairs: event.repairs
    )
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
}

@available(macOS 26.0, *)
@Test func overlappingMutationAdmissionReturnsECANCELEDBeforeAuthoritySubmission() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let event = try drainEvent(initiatorSession: drainPeerSession)
    try await barrier.prepare(event)
    do {
        _ = try await barrier.admit(
            scope: PfsMacOSCallbackScope(selectors: [.orderedMutation])
        )
        Issue.record("closed admission accepted an ordered mutation")
    } catch let error as PfsLocalClientError {
        #expect(error == .publicationAdmissionClosed)
        #expect(error.posixErrno == ECANCELED)
    }
    let counts = await barrier.refusedCallbackCounts()
    #expect(counts.ordered == 1)
    #expect(counts.other == 0)

    let complete = try PfsMacOSCoherenceEvent(
        epoch: event.epoch,
        sequence: event.sequence,
        phase: .complete,
        initiator: event.initiator,
        repairs: event.repairs
    )
    try await barrier.resume(complete)
    #expect(await barrier.orderedAdmissionContended(for: complete))
    await barrier.acknowledged(complete)
    #expect(!(await barrier.orderedAdmissionContended(for: complete)))
}

@available(macOS 26.0, *)
@Test func frozenV1AdmissionCarriesEBUSYThroughTheTicket() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession,
        policy: .synchronousVFSRepairV1
    )
    let ticket = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    #expect(ticket.admissionRefusalError() == .publicationAdmissionBusy)
    #expect(ticket.admissionRefusalError().posixErrno == EBUSY)

    let prepare = try drainEvent(initiatorSession: drainPeerSession)
    let preparing = Task { try await barrier.prepare(prepare) }
    for _ in 0..<100 where ticket.orderedMutationSubmitted() {
        ticket.orderedMutationSettled()
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    #expect(!ticket.orderedMutationSubmitted())
    await barrier.published(ticket)
    try await preparing.value

    do {
        _ = try await barrier.admit(scope: PfsMacOSCallbackScope(
            selectors: [.orderedMutation]
        ))
        Issue.record("v1 active repair admitted an overlapping callback")
    } catch let error as PfsLocalClientError {
        #expect(error == .publicationAdmissionBusy)
        #expect(error.posixErrno == EBUSY)
    }

    let complete = try PfsMacOSCoherenceEvent(
        epoch: prepare.epoch,
        sequence: prepare.sequence,
        phase: .complete,
        initiator: prepare.initiator,
        repairs: prepare.repairs
    )
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
}

@available(macOS 26.0, *)
@Test func frozenV1RevokedTicketRefusesBeforeDispatchWithEBUSY() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")
    let ticket = PfsMacOSAdmittedCallbackTicket(
        admissionRefusal: .publicationAdmissionBusy
    )
    ticket.revokeFutureRequests()

    var create = PfsCreateRequest()
    create.dir = resolved.root
    create.name = Data("v1-refused-before-dispatch".utf8)
    create.mode = 0o644
    create.exclusive = true
    do {
        _ = try await PfsMacOSCallbackAdmission.$ticket.withValue(ticket) {
            try await client.request(.create(create))
        }
        Issue.record("revoked v1 ticket dispatched an ordered mutation")
    } catch let error as PfsLocalClientError {
        #expect(error == .publicationAdmissionBusy)
        #expect(error.posixErrno == EBUSY)
    }
    #expect(await daemon.stats().createRequests == 0)
}

@available(macOS 26.0, *)
@Test func frozenV1InFlightReadCancellationReturnsEBUSY() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(
        lookupDelaysNanoseconds: ["slow-v1": 250_000_000]
    ))
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")
    let ticket = PfsMacOSAdmittedCallbackTicket(
        admissionRefusal: .publicationAdmissionBusy
    )

    var lookup = PfsLookupRequest()
    lookup.dir = resolved.root
    lookup.name = Data("slow-v1".utf8)
    let request = Task {
        try await PfsMacOSCallbackAdmission.$ticket.withValue(ticket) {
            try await client.request(.lookup(lookup))
        }
    }
    for _ in 0..<100 where await client.testingPendingRequestCount() != 1 {
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    #expect(await client.testingPendingRequestCount() == 1)

    ticket.revokeFutureRequests()
    do {
        _ = try await request.value
        Issue.record("revoked v1 read returned a value")
    } catch let error as PfsLocalClientError {
        #expect(error == .publicationAdmissionBusy)
        #expect(error.posixErrno == EBUSY)
    }

    // The request-local refusal must not retire the shared connection when the
    // discarded wire reply arrives later.
    try await Task.sleep(nanoseconds: 300_000_000)
    _ = try await client.request(.statfs(PfsStatfsRequest()))
}

@Test func namespaceReservationCollisionsRemainOrdinaryEBUSY() async throws {
    let root = try PfsMacOSStableIdentity(Data(repeating: 0x71, count: 16))
    let item = try PfsMacOSStableIdentity(Data(repeating: 0x72, count: 16))
    let name = Data("reserved".utf8)
    let index = PfsMacOSNamespaceIndex(rootIdentity: root)
    let reservation = try #require(try await index.reserveRecord(
        parentIdentity: root,
        name: name,
        capacity: 8
    ))
    defer { Task { await index.cancel(reservation) } }

    func expectBusy(_ operation: () async throws -> Void) async {
        do {
            try await operation()
            Issue.record("namespace reservation collision did not fail")
        } catch let error as PfsLocalClientError {
            #expect(error == .publicationAdmissionBusy)
            #expect(error.posixErrno == EBUSY)
        } catch {
            Issue.record("namespace reservation collision returned \(error)")
        }
    }

    await expectBusy {
        _ = try await index.reserveRecord(
            parentIdentity: root,
            name: name,
            capacity: 8
        )
    }
    await expectBusy {
        _ = try await index.reserveForget(
            parentIdentity: root,
            name: name,
            expectedIdentity: item
        )
    }
    await expectBusy {
        _ = try await index.reserveMove(
            parentIdentity: root,
            name: name,
            toParentIdentity: root,
            toName: Data("destination".utf8),
            expectedIdentity: item
        )
    }
}

@Test func crossedSuccessRefusalStaysBoundToTheTicketPolicy() throws {
    for (refusal, expectedErrno) in [
        (PfsLocalClientError.publicationAdmissionBusy, EBUSY),
        (PfsLocalClientError.publicationAdmissionClosed, ECANCELED),
    ] {
        let ticket = PfsMacOSAdmittedCallbackTicket(admissionRefusal: refusal)
        _ = try #require(ticket.ordinaryRequestSubmitted())
        ticket.markCrossedIfExposedReadsWereReleased()
        #expect(ticket.isCrossed())
        #expect(ticket.admissionRefusalError() == refusal)
        #expect(PfsErrorMapper.fsKitError(
            for: ticket.admissionRefusalError()
        ).code == Int(expectedErrno))
    }
}

@available(macOS 26.0, *)
@Test func admissionParksAfterLocalCompleteUntilTheExactAuthorityAck() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let prepare = try drainEvent(initiatorSession: drainPeerSession)
    let complete = try PfsMacOSCoherenceEvent(
        epoch: prepare.epoch,
        sequence: prepare.sequence,
        phase: .complete,
        initiator: prepare.initiator,
        repairs: prepare.repairs
    )
    try await barrier.prepare(prepare)
    try await barrier.resume(complete)

    let admitted = DrainCompletion()
    let waiter = Task {
        let ticket = try await barrier.admit(scope: PfsMacOSCallbackScope(
            selectors: [.orderedMutation]
        ))
        await admitted.mark()
        return ticket
    }
    for _ in 0..<100 where await barrier.pendingAdmissionWaiterCount() == 0 {
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    #expect(await barrier.pendingAdmissionWaiterCount() == 1)
    #expect(!(await admitted.value()))

    let wrongComplete = try PfsMacOSCoherenceEvent(
        epoch: prepare.epoch,
        sequence: prepare.sequence + 1,
        phase: .complete,
        initiator: prepare.initiator,
        repairs: prepare.repairs
    )
    await barrier.acknowledged(wrongComplete)
    try await Task.sleep(nanoseconds: 30_000_000)
    #expect(await barrier.pendingAdmissionWaiterCount() == 1)
    #expect(!(await admitted.value()))

    await barrier.acknowledged(complete)
    #expect(await barrier.pendingAdmissionWaiterCount() == 0)
    #expect(await barrier.isAdmissionClosed() == false)
    for _ in 0..<100 where !(await admitted.value()) {
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    guard await admitted.value() else {
        waiter.cancel()
        _ = try? await waiter.value
        Issue.record("exact COMPLETE acknowledgement did not release admission")
        return
    }
    let ticket = try await waiter.value
    #expect(await admitted.value())
    await barrier.published(ticket)
}

@available(macOS 26.0, *)
@Test func localPrepareParksNewMutationsThroughPublicationAndCompleteAck() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let initiator = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    initiator.noteOperationID(71)
    let prepare = try drainLocalEvent(phase: .prepare, localOperationID: 71)
    let complete = try drainLocalEvent(phase: .complete, localOperationID: 71)
    try await barrier.prepare(prepare)

    let admitted = DrainCompletion()
    let waiter = Task {
        let ticket = try await barrier.admit(scope: PfsMacOSCallbackScope(
            selectors: [.orderedMutation]
        ))
        await admitted.mark()
        return ticket
    }
    for _ in 0..<100 where await barrier.pendingAdmissionWaiterCount() == 0 {
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    #expect(await barrier.pendingAdmissionWaiterCount() == 1)
    #expect(!(await admitted.value()))

    // Source publication makes COMPLETE safe to acknowledge, but does not
    // release the next callback while authority mutation order is still held.
    await barrier.published(initiator)
    try await barrier.resume(complete)
    #expect(await barrier.pendingAdmissionWaiterCount() == 1)
    #expect(!(await admitted.value()))

    await barrier.acknowledged(complete)
    let ticket = try await waiter.value
    #expect(await admitted.value())
    await barrier.published(ticket)
}

@available(macOS 26.0, *)
@Test func orderedSubmissionTokenIsQueueableOnlyWithoutOrdinaryRequestHistory() async throws {
    let ticket = PfsMacOSAdmittedCallbackTicket(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))

    let orderedOnly = try #require(ticket.orderedMutationSubmission())
    #expect(orderedOnly.sourcePhaseQueueable)
    ticket.orderedMutationSettled()

    // Settling the ordinary request does not erase its history.  If a later
    // ordered request starts a source phase, Swift must drain this mixed
    // callback, so the authority must interrupt rather than queue it.
    let ordinary = try #require(ticket.ordinaryRequestSubmitted())
    ticket.ordinaryRequestSettled(ordinary)
    let mixed = try #require(
        try await ticket.orderedMutationSubmissionWhenPermitted()
    )
    #expect(!mixed.sourcePhaseQueueable)
    ticket.orderedMutationSettled()
}

@available(macOS 26.0, *)
@Test func ordinaryAdmissionCannotContradictAnInFlightQueueabilityProof() async throws {
    let ticket = PfsMacOSAdmittedCallbackTicket(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    let ordered = try #require(ticket.orderedMutationSubmission())
    #expect(ordered.sourcePhaseQueueable)
    let concurrentOrdered = try #require(ticket.orderedMutationSubmission())
    #expect(concurrentOrdered.sourcePhaseQueueable)

    // The synchronous form is deliberately conservative. The production
    // async form waits instead of converting a proof already on the wire from
    // ordered-only to mixed behind the authority's back.
    #expect(ticket.ordinaryRequestSubmitted() == nil)
    let ordinary = Task {
        try await ticket.ordinaryRequestSubmittedWhenPermitted()
    }
    for _ in 0..<100 where ticket.pendingOrdinaryAdmissionWaiterCount() == 0 {
        await Task.yield()
    }
    #expect(ticket.pendingOrdinaryAdmissionWaiterCount() == 1)

    ticket.orderedMutationSettled()
    #expect(ticket.pendingOrdinaryAdmissionWaiterCount() == 1)
    ticket.orderedMutationSettled()
    let ordinaryRequestID = try #require(try await ordinary.value)
    ticket.ordinaryRequestSettled(ordinaryRequestID)

    // History is durable: every subsequent ordered request is mixed even
    // though the ordinary request itself has completed.
    let laterOrdered = try #require(ticket.orderedMutationSubmission())
    #expect(!laterOrdered.sourcePhaseQueueable)
    ticket.orderedMutationSettled()
}

@available(macOS 26.0, *)
@Test func localV2PrepareDrainsAMixedDistinctCallbackAuthorityMustInterrupt() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let initiator = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    #expect(initiator.orderedMutationSubmitted())
    initiator.noteOperationID(79)

    let mixed = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    let ordinary = try #require(mixed.ordinaryRequestSubmitted())
    mixed.ordinaryRequestSettled(ordinary)
    let submission = try #require(
        try await mixed.orderedMutationSubmissionWhenPermitted()
    )
    #expect(!submission.sourcePhaseQueueable)
    mixed.noteOperationID(80)

    let prepareEvent = try drainLocalEvent(
        phase: .prepare,
        localOperationID: 79,
        sequence: 79
    )
    let completeEvent = try drainLocalEvent(
        phase: .complete,
        localOperationID: 79,
        sequence: 79
    )
    let prepared = DrainCompletion()
    let prepare = Task {
        try await barrier.prepare(prepareEvent)
        await prepared.mark()
    }
    try await Task.sleep(nanoseconds: 30_000_000)
    #expect(!(await prepared.value()))

    // Model the daemon returning the definite-preapply interruption selected
    // by sourcePhaseQueueable=false.  PREPARE then drains the framework reply
    // instead of waiting forever on a request the authority queued behind it.
    mixed.orderedMutationSettled()
    await barrier.published(mixed)
    try await prepare.value
    #expect(await prepared.value())
    #expect(!mixed.orderedMutationSubmitted())

    initiator.orderedMutationSettled()
    await barrier.published(initiator)
    try await barrier.resume(completeEvent)
    await barrier.acknowledged(completeEvent)
}

@available(macOS 26.0, *)
@Test func localV2PrepareParksAnAlreadyAdmittedPristineWriteUntilExactAck() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let initiator = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    #expect(initiator.orderedMutationSubmitted())
    initiator.noteOperationID(81)
    let queuedWrite = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    let prepare = try drainLocalEvent(
        phase: .prepare,
        localOperationID: 81,
        sequence: 81
    )
    let complete = try drainLocalEvent(
        phase: .complete,
        localOperationID: 81,
        sequence: 81
    )

    // This is the live sparse-write shape: FSKit admitted the next write
    // callback, but VolumeCore's descriptor gate has not let it issue even one
    // pfslocal request. Source PREPARE must preserve and park it, not synthesize
    // ECANCELED before dispatch.
    try await barrier.prepare(prepare)
    let submitted = DrainCompletion()
    let submitting = Task {
        let accepted = try await queuedWrite
            .orderedMutationSubmittedWhenPermitted()
        if accepted { await submitted.mark() }
        return accepted
    }
    try await Task.sleep(nanoseconds: 30_000_000)
    #expect(!(await submitted.value()))

    initiator.orderedMutationSettled()
    await barrier.published(initiator)
    try await barrier.resume(complete)
    try await Task.sleep(nanoseconds: 30_000_000)
    #expect(!(await submitted.value()))

    await barrier.acknowledged(complete)
    #expect(try await submitting.value)
    #expect(await submitted.value())
    queuedWrite.orderedMutationSettled()
    await barrier.published(queuedWrite)
}

@available(macOS 26.0, *)
@Test func localV2SourceParkStopsTheRealClientBeforeWireDispatchThenReleasesIt() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")

    var create = PfsCreateRequest()
    create.dir = resolved.root
    create.name = Data("source-parked-write".utf8)
    create.mode = 0o644
    let created = try await client.withPublicationBoundary {
        try await client.request(.create(create))
    }
    guard case let .createReply(createReply)? = created.body else {
        Issue.record("mock create omitted its reply")
        return
    }
    await daemon.resetStats()

    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let initiator = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    #expect(initiator.orderedMutationSubmitted())
    initiator.noteOperationID(87)
    let queuedWrite = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    let prepare = try drainLocalEvent(
        phase: .prepare,
        localOperationID: 87,
        sequence: 87
    )
    let complete = try drainLocalEvent(
        phase: .complete,
        localOperationID: 87,
        sequence: 87
    )
    try await barrier.prepare(prepare)

    var write = PfsWriteRequest()
    write.handle = createReply.handle
    write.data = Data("queued".utf8)
    let callback = Task {
        try await PfsMacOSCallbackAdmission.$ticket.withValue(queuedWrite) {
            try await client.withPublicationBoundary {
                try await client.request(.write(write))
            }
        }
    }
    try await Task.sleep(nanoseconds: 30_000_000)
    #expect(await daemon.stats().writeRequests == 0)
    #expect(queuedWrite.currentOperationID() == nil)

    initiator.orderedMutationSettled()
    await barrier.published(initiator)
    try await barrier.resume(complete)
    #expect(await daemon.stats().writeRequests == 0)
    await barrier.acknowledged(complete)

    let reply = try await callback.value
    guard case let .writeReply(writeReply)? = reply.body else {
        Issue.record("source-parked write omitted its reply")
        return
    }
    #expect(writeReply.written == 6)
    #expect(await daemon.stats().writeRequests == 1)
    #expect(queuedWrite.currentOperationID() != nil)
    await barrier.published(queuedWrite)
}

@available(macOS 26.0, *)
@Test func localV2PrepareLinearizesInsideOrderedAdmissionBeforeOperationStamp() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let initiator = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    #expect(initiator.orderedMutationSubmitted())
    initiator.noteOperationID(88)

    let dispatchCommitting = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    // Freeze the exact production interleaving after ticket admission commits
    // this ordered request but before PfsPublicationCollector binds/stamps it.
    #expect(dispatchCommitting.orderedMutationSubmitted())
    #expect(dispatchCommitting.currentOperationID() == nil)
    let prepare = try drainLocalEvent(
        phase: .prepare,
        localOperationID: 88,
        sequence: 88
    )
    let complete = try drainLocalEvent(
        phase: .complete,
        localOperationID: 88,
        sequence: 88
    )

    // PREPARE must neither revoke nor drain this identity-pending request. It
    // cannot be the initiator (the event already names stamped operation 88),
    // and every ordered body publishes, so its eventual ID is distinct.
    try await barrier.prepare(prepare)
    dispatchCommitting.noteOperationID(89)
    #expect(dispatchCommitting.currentOperationID() == 89)

    let nextRequestReached = DrainCompletion()
    let nextRequest = Task {
        let accepted = try await dispatchCommitting
            .orderedMutationSubmittedWhenPermitted()
        if accepted { await nextRequestReached.mark() }
        return accepted
    }
    try await Task.sleep(nanoseconds: 30_000_000)
    #expect(!(await nextRequestReached.value()))

    initiator.orderedMutationSettled()
    await barrier.published(initiator)
    try await barrier.resume(complete)
    #expect(!(await nextRequestReached.value()))
    await barrier.acknowledged(complete)
    #expect(try await nextRequest.value)

    dispatchCommitting.orderedMutationSettled()
    dispatchCommitting.orderedMutationSettled()
    await barrier.published(dispatchCommitting)
}

@available(macOS 26.0, *)
@Test func cancellingASourceParkedTicketThenAcknowledgingCannotLeakOrDoubleResume() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let initiator = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    #expect(initiator.orderedMutationSubmitted())
    initiator.noteOperationID(90)
    let parked = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    let prepare = try drainLocalEvent(
        phase: .prepare,
        localOperationID: 90,
        sequence: 90
    )
    let complete = try drainLocalEvent(
        phase: .complete,
        localOperationID: 90,
        sequence: 90
    )
    try await barrier.prepare(prepare)

    let waiting = Task {
        try await parked.orderedMutationSubmittedWhenPermitted()
    }
    try await Task.sleep(nanoseconds: 30_000_000)
    waiting.cancel()
    await #expect(throws: CancellationError.self) {
        try await waiting.value
    }
    // Model the canceled FSKit callback crossing its reply boundary. Exact ACK
    // later still owns a strong reference to this ticket and will call release;
    // the removed waiter must not be resumed a second time or leak admission.
    await barrier.published(parked)

    initiator.orderedMutationSettled()
    await barrier.published(initiator)
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
    #expect(await barrier.admittedCallbackCount() == 0)
}

@available(macOS 26.0, *)
@Test func terminalBarrierFailureWakesAPristineSourceParkAndPreventsDispatch() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let initiator = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    #expect(initiator.orderedMutationSubmitted())
    initiator.noteOperationID(91)
    let parked = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    try await barrier.prepare(try drainLocalEvent(
        phase: .prepare,
        localOperationID: 91,
        sequence: 91
    ))

    let waiting = Task {
        try await parked.orderedMutationSubmittedWhenPermitted()
    }
    try await Task.sleep(nanoseconds: 30_000_000)
    await barrier.fail(PfsMacOSCoherenceError.transportClosed)
    #expect(try await waiting.value == false)
    #expect(!parked.orderedMutationSubmitted())
    await barrier.published(parked)
    initiator.orderedMutationSettled()
    await barrier.published(initiator)
}

@available(macOS 26.0, *)
@Test func wrongCompleteAckCannotReleaseAnAlreadyAdmittedSourcePark() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let initiator = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    #expect(initiator.orderedMutationSubmitted())
    initiator.noteOperationID(92)
    let parked = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    let prepare = try drainLocalEvent(
        phase: .prepare,
        localOperationID: 92,
        sequence: 92
    )
    let complete = try drainLocalEvent(
        phase: .complete,
        localOperationID: 92,
        sequence: 92
    )
    try await barrier.prepare(prepare)
    let reached = DrainCompletion()
    let waiting = Task {
        let accepted = try await parked.orderedMutationSubmittedWhenPermitted()
        if accepted { await reached.mark() }
        return accepted
    }

    initiator.orderedMutationSettled()
    await barrier.published(initiator)
    try await barrier.resume(complete)
    let wrong = try drainLocalEvent(
        phase: .complete,
        localOperationID: 92,
        sequence: 93
    )
    await barrier.acknowledged(wrong)
    try await Task.sleep(nanoseconds: 30_000_000)
    #expect(!(await reached.value()))

    await barrier.acknowledged(complete)
    #expect(try await waiting.value)
    parked.orderedMutationSettled()
    await barrier.published(parked)
}

@available(macOS 26.0, *)
@Test func localV2PreparePreservesADistinctOrderedOnlyCallback() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let initiator = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    #expect(initiator.orderedMutationSubmitted())
    initiator.noteOperationID(82)

    let pipelined = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    #expect(pipelined.orderedMutationSubmitted())
    pipelined.noteOperationID(83)
    let prepare = try drainLocalEvent(
        phase: .prepare,
        localOperationID: 82,
        sequence: 82
    )
    let complete = try drainLocalEvent(
        phase: .complete,
        localOperationID: 82,
        sequence: 82
    )

    // A distinct callback carrying only authority-ordered mutations is queued
    // behind the source operation by the v2 pipelined authority profile. It is
    // neither the initiating callback nor a stale-read carrier, so PREPARE must
    // not revoke or drain its already-submitted request.
    try await barrier.prepare(prepare)
    let nextChunkSubmitted = DrainCompletion()
    let nextChunk = Task {
        let accepted = try await pipelined
            .orderedMutationSubmittedWhenPermitted()
        if accepted { await nextChunkSubmitted.mark() }
        return accepted
    }
    try await Task.sleep(nanoseconds: 30_000_000)
    #expect(!(await nextChunkSubmitted.value()))

    initiator.orderedMutationSettled()
    await barrier.published(initiator)
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
    #expect(try await nextChunk.value)
    #expect(await nextChunkSubmitted.value())

    pipelined.orderedMutationSettled()
    pipelined.orderedMutationSettled()
    await barrier.published(pipelined)
}

@available(macOS 26.0, *)
@Test func localV2PrepareNaturallyDrainsADistinctCallbackThatIssuedAnOrdinaryRequest() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let initiator = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    #expect(initiator.orderedMutationSubmitted())
    initiator.noteOperationID(84)

    let reading = try await barrier.admit(scope: .conservative)
    let requestID = try #require(reading.ordinaryRequestSubmitted())
    reading.noteOperationID(85)
    let canceled = DrainCompletion()
    reading.installOrdinaryRequestCancellation(requestID) {
        Task { await canceled.mark() }
    }
    let prepare = try drainLocalEvent(
        phase: .prepare,
        localOperationID: 84,
        sequence: 84
    )
    let complete = try drainLocalEvent(
        phase: .complete,
        localOperationID: 84,
        sequence: 84
    )

    let prepared = DrainCompletion()
    let prepareTask = Task {
        try await barrier.prepare(prepare)
        await prepared.mark()
    }
    for _ in 0..<100 where !reading.hasClosedFutureRequests() {
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    #expect(!(await canceled.value()))
    #expect(!(await prepared.value()))
    #expect(!reading.isCrossed())
    #expect(reading.ordinaryRequestSubmitted() == nil)
    reading.ordinaryRequestSettled(requestID)
    await barrier.published(reading)
    try await prepareTask.value
    #expect(await prepared.value())

    initiator.orderedMutationSettled()
    await barrier.published(initiator)
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
}

@available(macOS 26.0, *)
@Test func localV1StillRevokesAndDrainsAnAlreadyAdmittedPristineWrite() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession,
        policy: .synchronousVFSRepairV1
    )
    let initiator = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    #expect(initiator.orderedMutationSubmitted())
    initiator.noteOperationID(86)
    let queuedWrite = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    let prepare = try drainLocalEvent(
        phase: .prepare,
        localOperationID: 86,
        sequence: 86
    )
    let complete = try drainLocalEvent(
        phase: .complete,
        localOperationID: 86,
        sequence: 86
    )
    let prepared = DrainCompletion()
    let preparing = Task {
        try await barrier.prepare(prepare)
        await prepared.mark()
    }

    for _ in 0..<100 where queuedWrite.orderedMutationSubmitted() {
        queuedWrite.orderedMutationSettled()
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    #expect(!queuedWrite.orderedMutationSubmitted())
    #expect(queuedWrite.admissionRefusalError() == .publicationAdmissionBusy)
    #expect(!(await prepared.value()))
    await barrier.published(queuedWrite)
    try await preparing.value

    initiator.orderedMutationSettled()
    await barrier.published(initiator)
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
}

@available(macOS 26.0, *)
@Test func cancellingALocalPrepareWaiterCannotLeakAnAdmission() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let initiator = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    initiator.noteOperationID(72)
    let prepare = try drainLocalEvent(
        phase: .prepare,
        localOperationID: 72,
        sequence: 18
    )
    let complete = try drainLocalEvent(
        phase: .complete,
        localOperationID: 72,
        sequence: 18
    )
    try await barrier.prepare(prepare)

    let waiter = Task {
        try await barrier.admit(scope: PfsMacOSCallbackScope(
            selectors: [.orderedMutation]
        ))
    }
    for _ in 0..<100 where await barrier.pendingAdmissionWaiterCount() == 0 {
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    #expect(await barrier.pendingAdmissionWaiterCount() == 1)
    waiter.cancel()
    await #expect(throws: CancellationError.self) { try await waiter.value }
    #expect(await barrier.pendingAdmissionWaiterCount() == 0)
    #expect(await barrier.admittedCallbackCount() == 1)

    await barrier.published(initiator)
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
    #expect(await barrier.admittedCallbackCount() == 0)
}

@available(macOS 26.0, *)
@Test func cancellingAPostRepairAdmissionWaiterCannotLeakIt() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let prepare = try drainEvent(initiatorSession: drainPeerSession)
    let complete = try PfsMacOSCoherenceEvent(
        epoch: prepare.epoch,
        sequence: prepare.sequence,
        phase: .complete,
        initiator: prepare.initiator,
        repairs: prepare.repairs
    )
    try await barrier.prepare(prepare)
    try await barrier.resume(complete)

    let waiter = Task {
        try await barrier.admit(scope: PfsMacOSCallbackScope(
            selectors: [.orderedMutation]
        ))
    }
    try await Task.sleep(nanoseconds: 30_000_000)
    waiter.cancel()
    await #expect(throws: CancellationError.self) { try await waiter.value }
    #expect(await barrier.admittedCallbackCount() == 0)

    await barrier.acknowledged(complete)
    let next = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    await barrier.published(next)
}

@available(macOS 26.0, *)
@Test func cancellationRacingCompleteAckLeavesNoUnpublishedAdmission() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let prepare = try drainEvent(initiatorSession: drainPeerSession)
    let complete = try PfsMacOSCoherenceEvent(
        epoch: prepare.epoch,
        sequence: prepare.sequence,
        phase: .complete,
        initiator: prepare.initiator,
        repairs: prepare.repairs
    )
    try await barrier.prepare(prepare)
    try await barrier.resume(complete)

    let waiter = Task {
        try await barrier.admit(scope: PfsMacOSCallbackScope(
            selectors: [.orderedMutation]
        ))
    }
    try await Task.sleep(nanoseconds: 30_000_000)

    // Deliberately make ACK and cancellation adjacent. If ACK wins all the way
    // through ticket creation, publish that returned ticket; otherwise the
    // canceled task must leave no admission behind.
    let ack = Task { await barrier.acknowledged(complete) }
    waiter.cancel()
    await ack.value
    do {
        let ticket = try await waiter.value
        await barrier.published(ticket)
    } catch is CancellationError {
        // Expected when cancellation wins before post-wake admission.
    }
    #expect(await barrier.admittedCallbackCount() == 0)
}

@available(macOS 26.0, *)
@Test func terminalFailureWakesPostRepairAdmissionWaiters() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let prepare = try drainEvent(initiatorSession: drainPeerSession)
    let complete = try PfsMacOSCoherenceEvent(
        epoch: prepare.epoch,
        sequence: prepare.sequence,
        phase: .complete,
        initiator: prepare.initiator,
        repairs: prepare.repairs
    )
    try await barrier.prepare(prepare)
    try await barrier.resume(complete)

    let waiter = Task {
        try await barrier.admit(scope: PfsMacOSCallbackScope(
            selectors: [.orderedMutation]
        ))
    }
    try await Task.sleep(nanoseconds: 30_000_000)
    await barrier.fail(PfsMacOSCoherenceError.transportClosed)
    await #expect(throws: PfsMacOSCoherenceError.transportClosed) {
        try await waiter.value
    }
}

@available(macOS 26.0, *)
@Test func cancelledSourcePublicationWaitCannotReopenAfterTerminalFailure() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let ticket = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.orderedMutation]
    ))
    ticket.noteOperationID(41)
    let prepare = try PfsMacOSCoherenceEvent(
        epoch: Data(repeating: 0xE0, count: 16),
        sequence: 41,
        phase: .prepare,
        initiator: PfsMacOSMutationInitiator(
            sessionID: drainLocalSession,
            replaySlot: 1,
            mutationSequence: 41,
            localOperationID: 41
        ),
        repairs: []
    )
    let complete = try PfsMacOSCoherenceEvent(
        epoch: prepare.epoch,
        sequence: prepare.sequence,
        phase: .complete,
        initiator: prepare.initiator,
        repairs: prepare.repairs
    )
    try await barrier.prepare(prepare)

    let resuming = Task { try await barrier.resume(complete) }
    try await Task.sleep(nanoseconds: 30_000_000)
    resuming.cancel()
    await #expect(throws: CancellationError.self) { try await resuming.value }

    await barrier.fail(PfsMacOSCoherenceError.transportClosed)
    await barrier.published(ticket)
    #expect(await barrier.isAdmissionClosed() == false)
    await #expect(throws: PfsMacOSCoherenceError.transportClosed) {
        try await barrier.admit(scope: PfsMacOSCallbackScope(
            selectors: [.orderedMutation]
        ))
    }
}

@available(macOS 26.0, *)
@Test func prepareNaturallyDrainsAnIntersectingOrdinaryRequestThroughFrameworkPublication() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let parent = try PfsMacOSStableIdentity(Data(repeating: 0x31, count: 16))
    let ticket = try await barrier.admit(scope: drainNamespaceScope(
        parent: parent,
        name: Data("peer-created".utf8)
    ))
    let requestID = try #require(ticket.ordinaryRequestSubmitted())
    let canceled = DrainCompletion()
    ticket.installOrdinaryRequestCancellation(requestID) {
        Task { await canceled.mark() }
    }

    let event = try PfsMacOSCoherenceEvent(
        epoch: Data(repeating: 0xE0, count: 16),
        sequence: 10,
        phase: .prepare,
        initiator: PfsMacOSMutationInitiator(
            sessionID: drainPeerSession,
            replaySlot: 1,
            mutationSequence: 10
        ),
        repairs: [
            .purgeNegative(
                parent: try PfsMacOSRelativePath(components: []),
                parentIdentity: parent,
                name: Data("peer-created".utf8)
            ),
        ]
    )
    let prepared = DrainCompletion()
    let prepare = Task {
        try await barrier.prepare(event)
        await prepared.mark()
    }

    // v2 closes future requests but does not cancel the request that already
    // belongs to this PREPARE's exact audience.
    for _ in 0..<100 where !ticket.hasClosedFutureRequests() {
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    #expect(!(await canceled.value()))
    #expect(!(await prepared.value()))
    #expect(!ticket.isCrossed())
    #expect(ticket.ordinaryRequestSubmitted() == nil)
    #expect(!ticket.orderedMutationSubmitted())
    ticket.ordinaryRequestSettled(requestID)
    #expect(!(await prepared.value()))
    await barrier.published(ticket)
    try await prepare.value
    #expect(await prepared.value())
}

private actor DrainCompletion {
    private var done = false
    func mark() { done = true }
    func value() -> Bool { done }
}

private actor DrainErrorBox {
    private var code: Int32?
    func set(_ code: Int32) { self.code = code }
    func value() -> Int32? { code }
}

private actor DrainPublicationGate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if isOpen { return }
        await withCheckedContinuation { continuation in
            if isOpen {
                continuation.resume()
            } else {
                waiters.append(continuation)
            }
        }
    }

    func open() {
        guard !isOpen else { return }
        isOpen = true
        let waiters = waiters
        self.waiters.removeAll()
        for waiter in waiters { waiter.resume() }
    }
}

@available(macOS 26.0, *)
@Test func naturallyDrainedWireReadCompletesBeforePrepareUsesItsFrameworkLane() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(
        lookupDelaysNanoseconds: ["slow": 250_000_000]
    ))
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")
    let parent = try PfsMacOSStableIdentity(resolved.root.stableIdentity)
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let ticket = try await barrier.admit(scope: PfsMacOSCallbackScope(selectors: [
        .namespace(PfsMacOSNamespaceCoordinate(
            parentIdentity: parent,
            name: Data("slow".utf8)
        )),
        .directory(parent),
    ]))

    var lookup = PfsLookupRequest()
    lookup.dir = resolved.root
    lookup.name = Data("slow".utf8)
    let callbackReached = DrainCompletion()
    let callbackError = DrainErrorBox()
    let publicationGate = DrainPublicationGate()
    let callback = Task {
        let (result, complete) = await PfsMacOSCallbackAdmission.$ticket.withValue(ticket) {
            await client.withDeferredPublication {
                try await client.request(.lookup(lookup))
            }
        }
        let code: Int32
        do {
            _ = try result.get()
            code = 0
        } catch let error as PfsLocalClientError {
            code = error.posixErrno
        } catch {
            code = EIO
        }
        await callbackError.set(code)
        await callbackReached.mark()
        // Model a framework reply handler that has entered but not returned.
        // PREPARE may not enter the actuator while this gate is closed.
        await publicationGate.wait()
        await barrier.published(ticket)
        await complete(code == 0)
    }

    for _ in 0..<100 where await client.testingPendingRequestCount() != 1 {
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    #expect(await client.testingPendingRequestCount() == 1)

    let event = try PfsMacOSCoherenceEvent(
        epoch: Data(repeating: 0xE0, count: 16),
        sequence: 11,
        phase: .prepare,
        initiator: PfsMacOSMutationInitiator(
            sessionID: drainPeerSession,
            replaySlot: 1,
            mutationSequence: 11
        ),
        repairs: [
            .purgeNegative(
                parent: try PfsMacOSRelativePath(components: []),
                parentIdentity: parent,
                name: Data("slow".utf8)
            ),
        ]
    )
    let prepared = DrainCompletion()
    let prepare = Task {
        try await barrier.prepare(event)
        await prepared.mark()
    }

    for _ in 0..<400 where !(await callbackReached.value()) {
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    #expect(await callbackReached.value())
    #expect(await callbackError.value() == ENOENT)
    #expect(!ticket.isCrossed())
    #expect(!(await prepared.value()))

    await publicationGate.open()
    await callback.value
    try await prepare.value
    #expect(await prepared.value())

    let complete = try PfsMacOSCoherenceEvent(
        epoch: event.epoch,
        sequence: event.sequence,
        phase: .complete,
        initiator: event.initiator,
        repairs: event.repairs
    )
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
    // Natural drain is request-scoped and leaves the shared connection intact.
    _ = try await client.request(.statfs(PfsStatfsRequest()))
}

// The terminal/frozen-v1 release verdicts. v2 PREPARE does not use this path:
// its exact ordinary-request audience drains naturally without crossing.
@available(macOS 26.0, *)
@Test func releaseVerdictsCrossExactlyTheExposedReadCallbacks() {
    let exposedReads = PfsMacOSAdmittedCallbackTicket()
    exposedReads.ordinaryRequestSubmitted()
    exposedReads.markCrossedIfExposedReadsWereReleased()
    #expect(exposedReads.isCrossed())

    let freshRead = PfsMacOSAdmittedCallbackTicket()
    freshRead.ordinaryRequestSubmitted()
    freshRead.markCrossedIfExposedReadsWereReleased()
    #expect(freshRead.isCrossed())

    let parkedMutation = PfsMacOSAdmittedCallbackTicket()
    parkedMutation.orderedMutationSubmitted()
    parkedMutation.markCrossedIfExposedReadsWereReleased()
    #expect(!parkedMutation.isCrossed())

    let mutationThenRead = PfsMacOSAdmittedCallbackTicket()
    mutationThenRead.orderedMutationSubmitted()
    mutationThenRead.orderedMutationSettled()
    mutationThenRead.ordinaryRequestSubmitted()
    mutationThenRead.markCrossedIfExposedReadsWereReleased()
    #expect(!mutationThenRead.isCrossed())

    let installing = PfsMacOSAdmittedCallbackTicket()
    installing.markCrossedIfExposedReadsWereReleased()
    #expect(!installing.isCrossed())
}

@available(macOS 26.0, *)
@Test func prepareWaitsForNaturallyCompletedOrdinaryReadPublication() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let reading = try await barrier.admit()
    let requestID = try #require(reading.ordinaryRequestSubmitted())
    let canceled = DrainCompletion()
    reading.installOrdinaryRequestCancellation(requestID) {
        Task { await canceled.mark() }
    }
    let prepared = DrainCompletion()
    let prepare = Task {
        try await barrier.prepare(drainEvent(initiatorSession: drainPeerSession))
        await prepared.mark()
    }
    try await Task.sleep(nanoseconds: 30_000_000)
    #expect(!(await canceled.value()))
    #expect(!(await prepared.value()))
    #expect(!reading.isCrossed())
    reading.ordinaryRequestSettled(requestID)
    await barrier.published(reading)
    try await prepare.value
    #expect(await prepared.value())
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

@available(macOS 26.0, *)
@Test func closedAdmissionRejectsOnlyOverlappingPostPrepareCallbacks() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let parentIdentity = Data(repeating: 0x31, count: 16)
    let repairedName = Data("peer-created".utf8)
    let parent = try PfsMacOSStableIdentity(parentIdentity)
    let event = try PfsMacOSCoherenceEvent(
        epoch: Data(repeating: 0xE0, count: 16),
        sequence: 8,
        phase: .prepare,
        initiator: PfsMacOSMutationInitiator(
            sessionID: drainPeerSession,
            replaySlot: 1,
            mutationSequence: 8,
            localOperationID: nil
        ),
        repairs: [
            .purgeNegative(
                parent: try PfsMacOSRelativePath(components: []),
                parentIdentity: parent,
                name: repairedName
            ),
        ]
    )
    try await barrier.prepare(event)

    // Exact target, every callback that occupies this parent lane, a mutation
    // in another parent (ordered globally), and parent attributes all overlap
    // this repair and fail immediately.
    for scope in [
        drainNamespaceScope(parent: parent, name: repairedName),
        drainNamespaceScope(
            parent: parent,
            name: Data("unrelated-child".utf8),
            parentMutation: true
        ),
        drainNamespaceScope(
            parent: try PfsMacOSStableIdentity(Data(repeating: 0x74, count: 16)),
            name: Data("other-parent-child".utf8),
            parentMutation: true
        ),
        PfsMacOSCallbackScope(selectors: [.item(parent)]),
    ] {
        do {
            _ = try await barrier.admit(scope: scope)
            Issue.record("closed admission accepted an ordinary callback")
        } catch let error as PfsLocalClientError {
            #expect(error == .publicationAdmissionClosed)
            #expect(error.posixErrno == ECANCELED)
        }
    }

    let siblingLookupScope = PfsMacOSCallbackScope(selectors: [
        .namespace(PfsMacOSNamespaceCoordinate(
            parentIdentity: parent,
            name: Data("unrelated-child".utf8)
        )),
        .directory(parent),
    ])
    do {
        _ = try await barrier.admit(scope: siblingLookupScope)
        Issue.record("closed admission accepted a lookup in the repaired parent")
    } catch let error as PfsLocalClientError {
        #expect(error == .publicationAdmissionClosed)
    }
    let otherParent = try PfsMacOSStableIdentity(Data(repeating: 0x75, count: 16))
    let sameBasenameElsewhere = try await barrier.admit(scope: drainNamespaceScope(
        parent: otherParent,
        name: repairedName
    ))
    await barrier.published(sameBasenameElsewhere)
    let unrelatedItem = try PfsMacOSStableIdentity(Data(repeating: 0x72, count: 16))
    let itemCallback = try await barrier.admit(scope: PfsMacOSCallbackScope(
        selectors: [.item(unrelatedItem)]
    ))
    await barrier.published(itemCallback)

    let complete = try PfsMacOSCoherenceEvent(
        epoch: event.epoch,
        sequence: event.sequence,
        phase: .complete,
        initiator: event.initiator,
        repairs: event.repairs
    )
    try await barrier.resume(complete)
    await barrier.acknowledged(complete)
    let admitted = try await barrier.admit(scope: drainNamespaceScope(
        parent: parent, name: repairedName
    ))
    await barrier.published(admitted)
}

@available(macOS 26.0, *)
@Test func prepareNaturallyDrainsOnlyAlreadyAdmittedIntersectingCallbacks() async throws {
    let barrier = try PfsMacOSFSKitPublicationBarrier(
        localAuthoritySessionID: drainLocalSession
    )
    let repairedName = Data("peer-created".utf8)
    let parent = try PfsMacOSStableIdentity(Data(repeating: 0x31, count: 16))
    let disjoint = try await barrier.admit(scope: drainNamespaceScope(
        parent: parent, name: Data("local-created".utf8)
    ))
    disjoint.ordinaryRequestSubmitted()
    let affected = try await barrier.admit(scope: drainNamespaceScope(
        parent: parent, name: repairedName
    ))
    let affectedRequestID = try #require(affected.ordinaryRequestSubmitted())
    let canceled = DrainCompletion()
    affected.installOrdinaryRequestCancellation(affectedRequestID) {
        Task { await canceled.mark() }
    }

    let event = try PfsMacOSCoherenceEvent(
        epoch: Data(repeating: 0xE0, count: 16),
        sequence: 9,
        phase: .prepare,
        initiator: PfsMacOSMutationInitiator(
            sessionID: drainPeerSession,
            replaySlot: 1,
            mutationSequence: 9
        ),
        repairs: [
            .purgeNegative(
                parent: try PfsMacOSRelativePath(components: []),
                parentIdentity: parent,
                name: repairedName
            ),
        ]
    )
    let prepared = DrainCompletion()
    let prepare = Task {
        try await barrier.prepare(event)
        await prepared.mark()
    }
    for _ in 0..<100 where !affected.hasClosedFutureRequests() {
        try await Task.sleep(nanoseconds: 1_000_000)
    }

    #expect(!disjoint.isCrossed())
    #expect(!affected.isCrossed())
    #expect(!(await canceled.value()))
    #expect(!(await prepared.value()))
    affected.ordinaryRequestSettled(affectedRequestID)
    await barrier.published(affected)
    try await prepare.value
    #expect(await prepared.value())
    await barrier.published(disjoint)
}
