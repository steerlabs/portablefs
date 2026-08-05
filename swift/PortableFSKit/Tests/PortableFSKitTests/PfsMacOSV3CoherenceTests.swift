import Foundation
import Testing
@preconcurrency import Darwin
@testable import PortableFSKit

private let testEpoch = Data(repeating: 0x42, count: 16)
private let testSecret = Data((0..<32).map(UInt8.init))
private let testParentIdentity = try! PfsMacOSStableIdentity(Data(repeating: 0x31, count: 16))
private let testItemIdentity = try! PfsMacOSStableIdentity(Data(repeating: 0x32, count: 16))
private let testInitiator = try! PfsMacOSMutationInitiator(
    sessionID: Data(repeating: 0x24, count: 16),
    replaySlot: 3,
    mutationSequence: 19
)

private actor RecordingTransport: PfsMacOSCoherenceTransport {
    private(set) var acknowledgements: [PfsMacOSVisibilityCursor] = []
    private(set) var failures: [String] = []

    func nextEvent() async throws -> PfsMacOSCoherenceEvent? { nil }

    func acknowledge(epoch: Data, cursor: PfsMacOSVisibilityCursor) async throws {
        #expect(epoch == testEpoch)
        acknowledgements.append(cursor)
    }

    func failClosed(epoch: Data, cursor: PfsMacOSVisibilityCursor?, reason: String) async {
        failures.append(reason)
    }

    func acks() -> [PfsMacOSVisibilityCursor] { acknowledgements }
}

private actor RecordingBackend: PfsMacOSCoherenceBackend {
    nonisolated let policy = PfsMacOSCachePolicy.synchronousVFSRepairV1
    private(set) var events: [PfsMacOSCoherenceEvent] = []

    func repair(_ event: PfsMacOSCoherenceEvent) async throws { events.append(event) }
    func count() -> Int { events.count }
}

@Test func coherenceRunnerOrdersBothPhasesAndIdempotentlyReacks() async throws {
    let backend = RecordingBackend()
    let transport = RecordingTransport()
    let runner = try PfsMacOSCoherenceRunner(
        epoch: testEpoch,
        backend: backend,
        transport: transport
    )
    let prepare = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 1,
        phase: .prepare,
        initiator: testInitiator,
        repairs: []
    )
    let complete = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 1,
        phase: .complete,
        initiator: testInitiator,
        repairs: []
    )
    let nextPrepare = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 2,
        phase: .prepare,
        initiator: testInitiator,
        repairs: []
    )

    try await runner.consume(prepare)
    try await runner.consume(complete)
    try await runner.consume(complete)
    try await runner.consume(nextPrepare)

    #expect(await backend.count() == 3)
    #expect(await transport.acks() == [
        PfsMacOSVisibilityCursor(sequence: 1, phase: .prepare),
        PfsMacOSVisibilityCursor(sequence: 1, phase: .complete),
        PfsMacOSVisibilityCursor(sequence: 1, phase: .complete),
        PfsMacOSVisibilityCursor(sequence: 2, phase: .prepare),
    ])
}

@Test func coherenceRunnerRefusesPhaseAndSequenceGapsWithoutAck() async throws {
    let backend = RecordingBackend()
    let transport = RecordingTransport()
    let runner = try PfsMacOSCoherenceRunner(
        epoch: testEpoch,
        backend: backend,
        transport: transport
    )
    let outOfOrder = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 1,
        phase: .complete,
        initiator: testInitiator,
        repairs: []
    )
    await #expect(throws: PfsMacOSCoherenceError.self) {
        try await runner.consume(outOfOrder)
    }
    #expect(await backend.count() == 0)
    #expect(await transport.acks().isEmpty)
}

@Test func coherenceRunnerAcceptsSparseParticipantSequences() async throws {
    let backend = RecordingBackend()
    let transport = RecordingTransport()
    let runner = try PfsMacOSCoherenceRunner(
        epoch: testEpoch,
        initialAcknowledgedCursor: .init(sequence: 10, phase: .complete),
        backend: backend,
        transport: transport
    )
    let prepare = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 37,
        phase: .prepare,
        initiator: testInitiator,
        repairs: []
    )
    let complete = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 37,
        phase: .complete,
        initiator: testInitiator,
        repairs: []
    )

    try await runner.consume(prepare)
    try await runner.consume(complete)
    #expect(await backend.count() == 2)
    #expect(await runner.acknowledgedCursor() == .init(sequence: 37, phase: .complete))
}

@Test func coherenceRunnerFreshGenesisMayFirstObserveASparseSequence() async throws {
    let backend = RecordingBackend()
    let transport = RecordingTransport()
    let runner = try PfsMacOSCoherenceRunner(
        epoch: testEpoch,
        backend: backend,
        transport: transport
    )
    let prepare = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 91,
        phase: .prepare,
        initiator: testInitiator,
        repairs: []
    )
    try await runner.consume(prepare)
    #expect(await backend.count() == 1)
    #expect(await runner.acknowledgedCursor() == .init(sequence: 91, phase: .prepare))
}

@Test func coherenceRunnerStillRequiresCompleteForTheSameSparseSequence() async throws {
    let backend = RecordingBackend()
    let transport = RecordingTransport()
    let runner = try PfsMacOSCoherenceRunner(
        epoch: testEpoch,
        initialAcknowledgedCursor: .init(sequence: 10, phase: .complete),
        backend: backend,
        transport: transport
    )
    let prepare = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 37,
        phase: .prepare,
        initiator: testInitiator,
        repairs: []
    )
    let wrongComplete = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 38,
        phase: .complete,
        initiator: testInitiator,
        repairs: []
    )
    try await runner.consume(prepare)
    await #expect(throws: PfsMacOSCoherenceError.sequenceGap(expected: 37, received: 38)) {
        try await runner.consume(wrongComplete)
    }
    #expect(await backend.count() == 1)
}

@Test func repairOperandsAreSessionBoundAndTamperEvident() throws {
    let session = UUID(uuidString: "7B813942-F594-4C52-9E35-B7E58709F58F")!
    let authenticator = try PfsMacOS26RepairAuthenticator(
        mountSessionID: session,
        secret: testSecret
    )
    let operand = try authenticator.makeOperand(
        epoch: testEpoch,
        sequence: 9,
        step: 2,
        kind: .positiveEviction,
        parentIdentity: testParentIdentity,
        itemIdentity: testItemIdentity,
        sourceName: Data("source".utf8)
    )
    #expect(PfsMacOS26RepairAuthenticator.isReserved(operand))
    #expect(operand.count <= 255)
    #expect(authenticator.validate(
        operand: operand,
        epoch: testEpoch,
        sequence: 9,
        step: 2,
        kind: .positiveEviction,
        parentIdentity: testParentIdentity,
        itemIdentity: testItemIdentity,
        sourceName: Data("source".utf8)
    ))
    #expect(!authenticator.validate(
        operand: operand,
        epoch: testEpoch,
        sequence: 9,
        step: 2,
        kind: .positiveEviction,
        parentIdentity: testParentIdentity,
        itemIdentity: .zero,
        sourceName: Data("source".utf8)
    ))
    var tampered = operand
    tampered[tampered.index(before: tampered.endIndex)] ^= 1
    #expect(!authenticator.validate(
        operand: tampered,
        epoch: testEpoch,
        sequence: 9,
        step: 2,
        kind: .positiveEviction,
        parentIdentity: testParentIdentity,
        itemIdentity: testItemIdentity,
        sourceName: Data("source".utf8)
    ))
}

private actor FrozenBackend: PfsMacOSCoherenceBackend {
    nonisolated let policy = PfsMacOSCachePolicy.synchronousVFSRepairV1
    private var continuation: CheckedContinuation<Void, Never>?
    private(set) var entered = false

    func repair(_ event: PfsMacOSCoherenceEvent) async throws {
        entered = true
        await withCheckedContinuation { continuation = $0 }
        try Task.checkCancellation()
    }

    func hasEntered() -> Bool { entered }
    func release() { continuation?.resume(); continuation = nil }
}

@Test func coherenceRunnerWatchdogReturnsWithoutWaitingForAHungRepair() async throws {
    let backend = FrozenBackend()
    let transport = RecordingTransport()
    let runner = try PfsMacOSCoherenceRunner(
        epoch: testEpoch,
        repairBudgetMillis: 20,
        backend: backend,
        transport: transport
    )
    let event = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 41,
        phase: .prepare,
        initiator: testInitiator,
        repairs: []
    )

    let started = ContinuousClock.now
    await #expect(throws: PfsMacOSCoherenceError.repairDeadlineExceeded(
        sequence: 41,
        phase: .prepare,
        budgetMillis: 20
    )) {
        try await runner.consume(event)
    }
    #expect(started.duration(to: .now) < .seconds(1))
    #expect(await transport.failures.count == 1)
    await #expect(throws: PfsMacOSCoherenceError.transportClosed) {
        try await runner.consume(event)
    }

    // Let the cancelled backend task unwind; it must not update or acknowledge
    // the cursor after the watchdog already terminated the runner.
    await backend.release()
    await Task.yield()
    #expect(await runner.completedCursor() == nil)
    #expect(await transport.acks().isEmpty)
}

@Test func frozenRepairCannotFalselyAcknowledge() async throws {
    let backend = FrozenBackend()
    let transport = RecordingTransport()
    let runner = try PfsMacOSCoherenceRunner(
        epoch: testEpoch,
        backend: backend,
        transport: transport
    )
    let event = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 1,
        phase: .prepare,
        initiator: testInitiator,
        repairs: []
    )
    let task = Task { try await runner.consume(event) }
    while !(await backend.hasEntered()) { await Task.yield() }
    #expect(await transport.acks().isEmpty)
    task.cancel()
    await backend.release()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(await transport.acks().isEmpty)
}

private actor RecordingPublicationBarrier: PfsMacOSCallbackPublicationBarrier {
    private(set) var phases: [PfsMacOSVisibilityPhase] = []
    private(set) var initiators: [PfsMacOSMutationInitiator] = []
    func prepare(_ event: PfsMacOSCoherenceEvent) async throws {
        phases.append(.prepare)
        initiators.append(event.initiator)
    }
    func resume(_ event: PfsMacOSCoherenceEvent) async throws { phases.append(.complete) }
    func recorded() -> [PfsMacOSVisibilityPhase] { phases }
    func recordedInitiators() -> [PfsMacOSMutationInitiator] { initiators }
}

private actor RecordingLease: PfsMacOS26RepairArmLease {
    private(set) var finished = false
    private(set) var cancelled = false
    func finish() async throws { finished = true }
    func cancel() async { cancelled = true }
    func state() -> (Bool, Bool) { (finished, cancelled) }
}

private actor RecordingArmer: PfsMacOS26RepairArmer {
    let lease = RecordingLease()
    private(set) var plans: [PfsMacOS26RepairPlan] = []
    func arm(_ plan: PfsMacOS26RepairPlan) async throws -> any PfsMacOS26RepairArmLease {
        plans.append(plan)
        return lease
    }
    func count() -> Int { plans.count }
}

private actor RecordingActuator: PfsMacOS26RepairActuator {
    private(set) var plans: [PfsMacOS26RepairPlan] = []
    func apply(_ plan: PfsMacOS26RepairPlan) async throws { plans.append(plan) }
    func count() -> Int { plans.count }
}

@Test func macOS26BackendQuiescesBeforeRepairAndResumesAfterLeaseFinishes() async throws {
    let authenticator = try PfsMacOS26RepairAuthenticator(
        mountSessionID: UUID(),
        secret: testSecret
    )
    let armer = RecordingArmer()
    let actuator = RecordingActuator()
    let publication = RecordingPublicationBarrier()
    let backend = try PfsMacOS26CoherenceBackend(
        localAuthoritySessionID: Data(repeating: 0x99, count: 16),
        authenticator: authenticator,
        armer: armer,
        actuator: actuator,
        publicationBarrier: publication
    )
    let root = try PfsMacOSRelativePath(components: [])
    let prepare = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 1,
        phase: .prepare,
        initiator: testInitiator,
        repairs: [.purgeNegative(
            parent: root,
            parentIdentity: testParentIdentity,
            name: Data("missing".utf8)
        )]
    )
    let complete = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 1,
        phase: .complete,
        initiator: testInitiator,
        repairs: [.purgeNegative(
            parent: root,
            parentIdentity: testParentIdentity,
            name: Data("missing".utf8)
        )]
    )

    try await backend.repair(prepare)
    try await backend.repair(complete)

    #expect(await armer.count() == 1)
    #expect(await actuator.count() == 1)
    let leaseState = await armer.lease.state()
    #expect(leaseState.0)
    #expect(!leaseState.1)
    #expect(await publication.recorded() == [.prepare, .complete])
    #expect(await publication.recordedInitiators() == [testInitiator])
}

@Test func initiatingCompletePublishesNormallyWithoutNestedVFSRepair() async throws {
    let authenticator = try PfsMacOS26RepairAuthenticator(
        mountSessionID: UUID(),
        secret: testSecret
    )
    let armer = RecordingArmer()
    let actuator = RecordingActuator()
    let publication = RecordingPublicationBarrier()
    let backend = try PfsMacOS26CoherenceBackend(
        localAuthoritySessionID: testInitiator.sessionID,
        authenticator: authenticator,
        armer: armer,
        actuator: actuator,
        publicationBarrier: publication
    )
    let event = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 1,
        phase: .complete,
        initiator: testInitiator,
        repairs: [.purgeNegative(
            parent: try PfsMacOSRelativePath(components: []),
            parentIdentity: testParentIdentity,
            name: Data("missing".utf8)
        )]
    )

    try await backend.repair(event)

    #expect(await armer.count() == 0)
    #expect(await actuator.count() == 0)
    #expect(await publication.recorded() == [.complete])
}

private actor BlockingArmLease: PfsMacOS26RepairArmLease {
    private(set) var cancelled = false
    func finish() async throws {}
    func cancel() async { cancelled = true }
    func wasCancelled() -> Bool { cancelled }
}

private actor BlockingArmer: PfsMacOS26RepairArmer {
    let lease = BlockingArmLease()
    private var continuation: CheckedContinuation<Void, Never>?
    private(set) var entered = false

    func arm(_ plan: PfsMacOS26RepairPlan) async throws -> any PfsMacOS26RepairArmLease {
        entered = true
        await withCheckedContinuation { continuation = $0 }
        return lease
    }

    func release() { continuation?.resume(); continuation = nil }
    func hasEntered() -> Bool { entered }
}

@Test func cancellationAfterArmingRevokesTheOneShotPlan() async throws {
    let authenticator = try PfsMacOS26RepairAuthenticator(mountSessionID: UUID(), secret: testSecret)
    let armer = BlockingArmer()
    let backend = try PfsMacOS26CoherenceBackend(
        localAuthoritySessionID: Data(repeating: 0x99, count: 16),
        authenticator: authenticator,
        armer: armer,
        actuator: RecordingActuator(),
        publicationBarrier: RecordingPublicationBarrier()
    )
    let event = try PfsMacOSCoherenceEvent(
        epoch: testEpoch,
        sequence: 1,
        phase: .complete,
        initiator: testInitiator,
        repairs: [.purgeNegative(
            parent: try PfsMacOSRelativePath(components: []),
            parentIdentity: testParentIdentity,
            name: Data("missing".utf8)
        )]
    )
    let task = Task { try await backend.repair(event) }
    while !(await armer.hasEntered()) { await Task.yield() }
    task.cancel()
    await armer.release()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(await armer.lease.wasCancelled())
}

@Test func mappingWindowsStayBoundedForMultiTerabyteSparseFiles() throws {
    let size = UInt64(5) * 1024 * 1024 * 1024 * 1024 + 123
    let windows = try PfsMacOS26MappingWindows(fileSize: size)
    #expect(windows.count == 20_481)
    var iterator = windows.makeIterator()
    var previousEnd: UInt64 = 0
    var observed: UInt64 = 0
    var last: PfsMacOS26MappingWindows.Window?
    while let window = iterator.next() {
        #expect(window.offset == previousEnd)
        #expect(window.offset.isMultiple(of: UInt64(getpagesize())))
        #expect(window.length <= Int(PfsMacOS26MappingWindows.defaultMaximumWindowBytes))
        previousEnd = window.offset + UInt64(window.length)
        observed += 1
        last = window
    }
    #expect(observed == windows.count)
    #expect(previousEnd == size)
    #expect(last?.length == 123)
}

@Test func posixActuatorUsesAuthenticatedLocalNamespaceTransaction() async throws {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "portablefs-v3-actuator-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let rootFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    #expect(rootFD >= 0)
    defer { close(rootFD) }
    let actuator = try PfsMacOS26POSIXActuator(rootFileDescriptor: rootFD)

    let authenticator = try PfsMacOS26RepairAuthenticator(mountSessionID: UUID(), secret: testSecret)
    let operand = try authenticator.makeOperand(
        epoch: testEpoch,
        sequence: 1,
        step: 0,
        kind: .negativeScratch,
        parentIdentity: testParentIdentity,
        itemIdentity: .zero,
        sourceName: nil
    )
    let plan = PfsMacOS26RepairPlan(
        epoch: testEpoch,
        sequence: 1,
        step: 0,
        kind: .negativeScratch,
        path: try PfsMacOSRelativePath(components: []),
        parentIdentity: testParentIdentity,
        itemIdentity: .zero,
        expectedVFSFileID: nil,
        authoritativeSize: nil,
        operand: operand
    )
    try await actuator.apply(plan)
    #expect(!FileManager.default.fileExists(atPath: directory.appending(path: String(decoding: operand, as: UTF8.self)).path))
}
