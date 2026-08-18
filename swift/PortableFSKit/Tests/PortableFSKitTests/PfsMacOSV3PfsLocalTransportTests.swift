import Foundation
import PortableFSKitMockDaemon
import Testing
@testable import PortableFSKit

private let v3Epoch = Data(repeating: 0xA1, count: 16)
private let v3LocalSession = Data(repeating: 0xB2, count: 16)
private let v3PeerSession = Data(repeating: 0xC3, count: 16)

private func v3Cursor(
    sequence: UInt64,
    phase: PfsVisibilityPhase
) -> PfsVisibilityCursor {
    var cursor = PfsVisibilityCursor()
    cursor.sequence = sequence
    cursor.phase = phase
    return cursor
}

private func v3Contract(
    epoch: Data = v3Epoch,
    sessionID: Data = v3LocalSession,
    policy: String = PfsMacOSCachePolicy.synchronousVFSRepairV1.rawValue,
    repairBudgetMillis: UInt64 = 2_500,
    initialCursor: PfsVisibilityCursor? = nil
) -> PfsV3CoherenceContract {
    var contract = PfsV3CoherenceContract()
    contract.authorityProtocolMajor = 5
    contract.authorityEpoch = epoch
    contract.sessionID = sessionID
    contract.cachePolicy = policy
    contract.repairBudgetMillis = repairBudgetMillis
    if let initialCursor {
        contract.initialCursor = initialCursor
    }
    return contract
}

private func v3Target(
    scope: PfsVisibilityScope,
    identity: Data = Data(),
    parentIdentity: Data = Data(),
    name: Data = Data(),
    size: Int64 = 0,
    postIdentity: Data = Data()
) -> PfsVisibilityTarget {
    var target = PfsVisibilityTarget()
    target.scope = scope
    target.identity = identity
    target.parentIdentity = parentIdentity
    target.name = name
    target.size = size
    target.postIdentity = postIdentity
    return target
}

private func v3Event(
    sequence: UInt64 = 1,
    phase: PfsVisibilityPhase = .prepare,
    initiatorSessionID: Data = v3PeerSession,
    targets: [PfsVisibilityTarget]
) -> PfsV3VisibilityEvent {
    var event = PfsV3VisibilityEvent()
    event.authorityEpoch = v3Epoch
    event.cursor = v3Cursor(sequence: sequence, phase: phase)
    event.initiatorSessionID = initiatorSessionID
    event.mutationSlot = 7
    event.mutationSequence = 99
    event.targets = targets
    return event
}

private func v3Identity(_ byte: UInt8) throws -> PfsMacOSStableIdentity {
    try PfsMacOSStableIdentity(Data(repeating: byte, count: 16))
}

private actor V3TestBackend: PfsMacOSCoherenceBackend {
    nonisolated let policy = PfsMacOSCachePolicy.synchronousVFSRepairV1
    private var repairCount = 0
    private let reportsContention: Bool

    init(reportsContention: Bool = false) {
        self.reportsContention = reportsContention
    }

    func repair(_ event: PfsMacOSCoherenceEvent) async throws {
        repairCount += 1
    }
    func orderedAdmissionContended(for event: PfsMacOSCoherenceEvent) async -> Bool {
        reportsContention && event.phase == .complete
    }
    func acknowledged(_ event: PfsMacOSCoherenceEvent) async {}

    func count() -> Int { repairCount }
}

private func nextV3Event(
    from transport: PfsLocalMacOSV3CoherenceTransport
) async throws -> PfsMacOSCoherenceEvent {
    try await withThrowingTaskGroup(of: PfsMacOSCoherenceEvent?.self) { group in
        group.addTask {
            try await transport.nextEvent()
        }
        group.addTask {
            try await Task.sleep(for: .seconds(1))
            return nil
        }
        guard let result = try await group.next() else {
            throw PfsLocalClientError.timeout
        }
        group.cancelAll()
        guard let event = result else {
            throw PfsLocalClientError.timeout
        }
        return event
    }
}

extension PfsLocalMockDaemonTests {
@Test func v3ContractParsingAcceptsOnlyCompleteValidatedTerms() throws {
    let complete = v3Cursor(sequence: 12, phase: .complete)
    let parsed = try PfsLocalMacOSV3CoherenceTransport.parseContract(
        v3Contract(initialCursor: complete)
    )
    #expect(parsed.authorityProtocolMajor == 5)
    #expect(parsed.epoch == v3Epoch)
    #expect(parsed.sessionID == v3LocalSession)
    #expect(parsed.cachePolicy == .synchronousVFSRepairV1)
    #expect(parsed.repairBudgetMillis == 2_500)
    #expect(parsed.initialAcknowledgedCursor == .init(sequence: 12, phase: .complete))

    let withoutCursor = try PfsLocalMacOSV3CoherenceTransport.parseContract(v3Contract())
    #expect(withoutCursor.initialAcknowledgedCursor == nil)
}

@Test func v3ContractParsingRejectsEveryMalformedField() {
    var contract = v3Contract()
    contract.authorityProtocolMajor = 1
    #expect(throws: PfsMacOSCoherenceError.invalidAuthorityProtocolMajor(1)) {
        try PfsLocalMacOSV3CoherenceTransport.parseContract(contract)
    }

    contract = v3Contract()
    contract.authorityProtocolMajor = 6
    #expect(throws: PfsMacOSCoherenceError.exactVNextFSKitUnavailable(6)) {
        try PfsLocalMacOSV3CoherenceTransport.parseContract(contract)
    }

    contract = v3Contract(epoch: Data(repeating: 1, count: 15))
    #expect(throws: PfsMacOSCoherenceError.invalidEpochLength(15)) {
        try PfsLocalMacOSV3CoherenceTransport.parseContract(contract)
    }

    contract = v3Contract(sessionID: Data(repeating: 1, count: 17))
    #expect(throws: PfsMacOSCoherenceError.invalidSessionIDLength(17)) {
        try PfsLocalMacOSV3CoherenceTransport.parseContract(contract)
    }

    contract = v3Contract(policy: "automatic")
    #expect(throws: PfsMacOSCoherenceError.invalidCachePolicy("automatic")) {
        try PfsLocalMacOSV3CoherenceTransport.parseContract(contract)
    }

    contract = v3Contract(repairBudgetMillis: 0)
    #expect(throws: PfsMacOSCoherenceError.invalidRepairBudget(0)) {
        try PfsLocalMacOSV3CoherenceTransport.parseContract(contract)
    }

    contract = v3Contract(repairBudgetMillis: UInt64.max)
    #expect(throws: PfsMacOSCoherenceError.invalidRepairBudget(UInt64.max)) {
        try PfsLocalMacOSV3CoherenceTransport.parseContract(contract)
    }

    contract = v3Contract(initialCursor: v3Cursor(sequence: 1, phase: .prepare))
    #expect(throws: PfsMacOSCoherenceError.initialCursorMustBeComplete) {
        try PfsLocalMacOSV3CoherenceTransport.parseContract(contract)
    }

    contract = v3Contract(initialCursor: v3Cursor(sequence: 0, phase: .complete))
    #expect(throws: PfsMacOSCoherenceError.invalidSequence(0)) {
        try PfsLocalMacOSV3CoherenceTransport.parseContract(contract)
    }

    contract = v3Contract(initialCursor: v3Cursor(sequence: 1, phase: .UNRECOGNIZED(41)))
    #expect(throws: PfsMacOSCoherenceError.invalidVisibilityPhase(41)) {
        try PfsLocalMacOSV3CoherenceTransport.parseContract(contract)
    }
}

@Test func v3TargetDecoderUsesExactScopeShapes() throws {
    let identity = Data(repeating: 0x11, count: 16)
    let parent = Data(repeating: 0x22, count: 16)
    let name = Data("name".utf8)

    #expect(
        try PfsLocalMacOSV3CoherenceTransport.decodeTarget(
            v3Target(scope: .namespace, parentIdentity: parent, name: name)
        ) == .namespace(parentIdentity: PfsMacOSStableIdentity(parent), name: name)
    )
    #expect(
        try PfsLocalMacOSV3CoherenceTransport.decodeTarget(
            v3Target(
                scope: .namespace,
                parentIdentity: parent,
                name: name,
                postIdentity: identity
            )
        ) == .namespacePost(
            parentIdentity: PfsMacOSStableIdentity(parent),
            name: name,
            identity: PfsMacOSStableIdentity(identity)
        )
    )
    #expect(
        try PfsLocalMacOSV3CoherenceTransport.decodeTarget(
            v3Target(scope: .data, identity: identity, size: 4_096)
        ) == .data(identity: PfsMacOSStableIdentity(identity), size: 4_096)
    )
    #expect(
        try PfsLocalMacOSV3CoherenceTransport.decodeTarget(
            v3Target(scope: .attributes, identity: identity)
        ) == .attributes(identity: PfsMacOSStableIdentity(identity))
    )
}

@Test func v3TargetDecoderRejectsCrossScopeAndInvalidNameFields() {
    let identity = Data(repeating: 0x11, count: 16)
    let parent = Data(repeating: 0x22, count: 16)

    let malformed: [PfsVisibilityTarget] = [
        v3Target(scope: .unspecified),
        v3Target(scope: .UNRECOGNIZED(70)),
        v3Target(scope: .namespace, identity: identity, parentIdentity: parent, name: Data("x".utf8)),
        v3Target(scope: .namespace, parentIdentity: Data(repeating: 1, count: 15), name: Data("x".utf8)),
        v3Target(scope: .namespace, parentIdentity: parent, name: Data()),
        v3Target(scope: .namespace, parentIdentity: parent, name: Data(".".utf8)),
        v3Target(scope: .namespace, parentIdentity: parent, name: Data("..".utf8)),
        v3Target(scope: .namespace, parentIdentity: parent, name: Data("a/b".utf8)),
        v3Target(scope: .namespace, parentIdentity: parent, name: Data([0x61, 0, 0x62])),
        v3Target(scope: .namespace, parentIdentity: parent, name: Data(repeating: 0x61, count: 256)),
        v3Target(scope: .namespace, parentIdentity: parent, name: Data("x".utf8), size: 1),
        v3Target(
            scope: .namespace,
            parentIdentity: parent,
            name: Data("x".utf8),
            postIdentity: Data(repeating: 1, count: 15)
        ),
        v3Target(scope: .data, identity: Data(repeating: 1, count: 15)),
        v3Target(scope: .data, identity: identity, postIdentity: identity),
        v3Target(scope: .data, identity: identity, parentIdentity: parent),
        v3Target(scope: .data, identity: identity, name: Data("x".utf8)),
        v3Target(scope: .data, identity: identity, size: -1),
        v3Target(scope: .attributes, identity: Data(repeating: 1, count: 17)),
        v3Target(scope: .attributes, identity: identity, parentIdentity: parent),
        v3Target(scope: .attributes, identity: identity, name: Data("x".utf8)),
        v3Target(scope: .attributes, identity: identity, size: 1),
        v3Target(scope: .attributes, identity: identity, postIdentity: identity),
    ]

    for target in malformed {
        do {
            _ = try PfsLocalMacOSV3CoherenceTransport.decodeTarget(target)
            Issue.record("malformed visibility target was accepted: \(target)")
        } catch {
            #expect(error is PfsMacOSCoherenceError)
        }
    }
}

@Test func v3EventDecoderMapsWireCoordinatesThroughTheLocalIndex() async throws {
    let root = try v3Identity(1)
    let directory = try v3Identity(2)
    let file = try v3Identity(3)
    let index = PfsMacOSNamespaceIndex(rootIdentity: root)
    await index.record(
        identity: directory,
        entry: .init(parentIdentity: root, name: Data("dir".utf8), vfsFileID: 40)
    )
    await index.record(
        identity: file,
        entry: .init(parentIdentity: directory, name: Data("file".utf8), vfsFileID: 41)
    )

    let wire = v3Event(targets: [
        v3Target(scope: .namespace, parentIdentity: directory.bytes, name: Data("file".utf8)),
        v3Target(scope: .namespace, parentIdentity: directory.bytes, name: Data("missing".utf8)),
        v3Target(scope: .data, identity: file.bytes, size: 7_000),
        v3Target(scope: .attributes, identity: file.bytes),
    ])
    let decoded = try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
        wire,
        expectedEpoch: v3Epoch,
        expectedSessionID: v3LocalSession,
        planner: PfsMacOSRepairPlanner(index: index)
    )

    #expect(decoded.sequence == 1)
    #expect(decoded.phase == .prepare)
    #expect(decoded.repairs.count == 2)
    guard case let .invalidateData(dataPath, knownParent, knownIdentity, fileID, size) = decoded.repairs[0] else {
        Issue.record("expected data invalidation to subsume the same-coordinate eviction")
        return
    }
    #expect(dataPath.components == [Data("dir".utf8), Data("file".utf8)])
    #expect(knownParent == directory)
    #expect(knownIdentity == file)
    #expect(fileID == 41)
    #expect(size == 7_000)

    guard case let .purgeNegative(parentPath, negativeParent, negativeName) = decoded.repairs[1] else {
        Issue.record("expected negative-cache purge")
        return
    }
    #expect(parentPath.components == [Data("dir".utf8)])
    #expect(negativeParent == directory)
    #expect(negativeName == Data("missing".utf8))

}


@Test func v3EventDecoderAcceptsPostBindingOnlyAfterApply() async throws {
    let root = try v3Identity(1)
    let directory = try v3Identity(2)
    let file = try v3Identity(3)
    let index = PfsMacOSNamespaceIndex(rootIdentity: root)
    await index.record(
        identity: directory,
        entry: .init(parentIdentity: root, name: Data("dir".utf8), vfsFileID: 40)
    )
    let target = v3Target(
        scope: .namespace,
        parentIdentity: directory.bytes,
        name: Data("alias".utf8),
        postIdentity: file.bytes
    )
    let planner = PfsMacOSRepairPlanner(index: index)

    await #expect(throws: PfsMacOSCoherenceError.invalidVisibilityTarget) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            v3Event(phase: .prepare, targets: [target]),
            expectedEpoch: v3Epoch,
            expectedSessionID: v3LocalSession,
            planner: planner
        )
    }

    let complete = try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
        v3Event(phase: .complete, targets: [target]),
        expectedEpoch: v3Epoch,
        expectedSessionID: v3LocalSession,
        planner: planner
    )
    #expect(complete.repairs.count == 1)
    guard case let .purgeNegative(path, parent, name) = complete.repairs.first else {
        Issue.record("expected a negative purge when this mount has no retained vnode")
        return
    }
    #expect(path.components == [Data("dir".utf8)])
    #expect(parent == directory)
    #expect(name == Data("alias".utf8))
}

@Test func v3EventDecoderRejectsSourceFilesystemVisibilityEvents() async throws {
    let root = try v3Identity(1)
    let planner = PfsMacOSRepairPlanner(index: PfsMacOSNamespaceIndex(rootIdentity: root))
    let target = v3Target(scope: .attributes, identity: Data(repeating: 0x44, count: 16))

    let local = v3Event(
        initiatorSessionID: v3LocalSession,
        targets: [target]
    )
    await #expect(throws: PfsMacOSCoherenceError.invalidVisibilityTarget) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            local,
            expectedEpoch: v3Epoch,
            expectedSessionID: v3LocalSession,
            planner: planner
        )
    }
}

@Test func v3EventDecoderRejectsMalformedEnvelopeAndInitiatorFields() async throws {
    let root = try v3Identity(1)
    let planner = PfsMacOSRepairPlanner(index: PfsMacOSNamespaceIndex(rootIdentity: root))
    let target = v3Target(scope: .attributes, identity: Data(repeating: 0x44, count: 16))
    let valid = v3Event(targets: [target])

    await #expect(throws: PfsMacOSCoherenceError.invalidEpochLength(15)) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            valid,
            expectedEpoch: Data(repeating: 1, count: 15),
            expectedSessionID: v3LocalSession,
            planner: planner
        )
    }
    await #expect(throws: PfsMacOSCoherenceError.invalidSessionIDLength(15)) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            valid,
            expectedEpoch: v3Epoch,
            expectedSessionID: Data(repeating: 1, count: 15),
            planner: planner
        )
    }

    var malformed = valid
    malformed.authorityEpoch = Data(repeating: 1, count: 17)
    await #expect(throws: PfsMacOSCoherenceError.invalidEpochLength(17)) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            malformed,
            expectedEpoch: v3Epoch,
            expectedSessionID: v3LocalSession,
            planner: planner
        )
    }

    malformed = valid
    malformed.authorityEpoch = Data(repeating: 0xEE, count: 16)
    await #expect(throws: PfsMacOSCoherenceError.epochChanged) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            malformed,
            expectedEpoch: v3Epoch,
            expectedSessionID: v3LocalSession,
            planner: planner
        )
    }

    malformed = valid
    malformed.clearCursor()
    await #expect(throws: PfsMacOSCoherenceError.invalidSequence(0)) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            malformed,
            expectedEpoch: v3Epoch,
            expectedSessionID: v3LocalSession,
            planner: planner
        )
    }

    malformed = valid
    malformed.cursor = v3Cursor(sequence: 0, phase: .prepare)
    await #expect(throws: PfsMacOSCoherenceError.invalidSequence(0)) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            malformed,
            expectedEpoch: v3Epoch,
            expectedSessionID: v3LocalSession,
            planner: planner
        )
    }

    malformed = valid
    malformed.cursor = v3Cursor(sequence: 1, phase: .UNRECOGNIZED(88))
    await #expect(throws: PfsMacOSCoherenceError.invalidVisibilityPhase(88)) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            malformed,
            expectedEpoch: v3Epoch,
            expectedSessionID: v3LocalSession,
            planner: planner
        )
    }

    malformed = valid
    malformed.initiatorSessionID = Data(repeating: 1, count: 15)
    await #expect(throws: PfsMacOSCoherenceError.invalidSessionIDLength(15)) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            malformed,
            expectedEpoch: v3Epoch,
            expectedSessionID: v3LocalSession,
            planner: planner
        )
    }

    malformed = valid
    malformed.mutationSequence = 0
    await #expect(throws: PfsMacOSCoherenceError.invalidSequence(0)) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            malformed,
            expectedEpoch: v3Epoch,
            expectedSessionID: v3LocalSession,
            planner: planner
        )
    }
}

@Test func v3EventDecoderRejectsEmptyEventsAndFailsClosedOnRouteChanges() async throws {
    let root = try v3Identity(1)
    let planner = PfsMacOSRepairPlanner(index: PfsMacOSNamespaceIndex(rootIdentity: root))

    let empty = v3Event(targets: [])
    await #expect(throws: PfsMacOSCoherenceError.invalidVisibilityTarget) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            empty,
            expectedEpoch: v3Epoch,
            expectedSessionID: v3LocalSession,
            planner: planner
        )
    }

    let targetlessComplete = v3Event(
        phase: .complete,
        targets: []
    )
    let decodedComplete = try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
        targetlessComplete,
        expectedEpoch: v3Epoch,
        expectedSessionID: v3LocalSession,
        planner: planner
    )
    #expect(decodedComplete.phase == .complete)
    #expect(decodedComplete.repairs.isEmpty)

    var routes = v3Event(targets: [])
    routes.initiatorSessionID = Data(repeating: 0, count: 16)
    routes.mutationSlot = 0
    routes.mutationSequence = 0
    var change = PfsRoutesChange()
    change.revision = Data(repeating: 0xCC, count: 32)
    change.rules = Data("rules".utf8)
    routes.routes = change
    await #expect(throws: PfsMacOSCoherenceError.routesChangeRequiresRemount) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            routes,
            expectedEpoch: v3Epoch,
            expectedSessionID: v3LocalSession,
            planner: planner
        )
    }

    change.revision = Data(repeating: 0xCC, count: 31)
    routes.routes = change
    await #expect(throws: PfsMacOSCoherenceError.invalidRoutesChange) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            routes,
            expectedEpoch: v3Epoch,
            expectedSessionID: v3LocalSession,
            planner: planner
        )
    }

    routes = v3Event(targets: [
        v3Target(scope: .attributes, identity: Data(repeating: 0x44, count: 16))
    ])
    change.revision = Data(repeating: 0xCC, count: 32)
    routes.routes = change
    await #expect(throws: PfsMacOSCoherenceError.invalidRoutesChange) {
        try await PfsLocalMacOSV3CoherenceTransport.decodeEvent(
            routes,
            expectedEpoch: v3Epoch,
            expectedSessionID: v3LocalSession,
            planner: planner
        )
    }
}

@Test func namespaceIndexPreservesAndRepairsEveryHardLinkAlias() async throws {
    let root = try v3Identity(1)
    let file = try v3Identity(2)
    let index = PfsMacOSNamespaceIndex(rootIdentity: root)
    await index.record(
        identity: file,
        entry: .init(parentIdentity: root, name: Data("a".utf8), vfsFileID: 42)
    )
    await index.record(
        identity: file,
        entry: .init(parentIdentity: root, name: Data("b".utf8), vfsFileID: 42)
    )

    let repairs = try await PfsMacOSRepairPlanner(index: index).repairs(
        for: [.attributes(identity: file)]
    )
    #expect(repairs.count == 2)
    guard case let .refreshAttributes(first, _, _, _, _) = repairs[0],
          case let .refreshAttributes(second, _, _, _, _) = repairs[1] else {
        Issue.record("expected both hard-link aliases to be refreshed")
        return
    }
    #expect(first.components == [Data("a".utf8)])
    #expect(second.components == [Data("b".utf8)])

    await index.forget(parentIdentity: root, name: Data("a".utf8))
    #expect(await index.count() == 1)
    #expect(await index.binding(parentIdentity: root, name: Data("a".utf8)) == nil)
    #expect(await index.binding(parentIdentity: root, name: Data("b".utf8))?.identity == file)
}

@Test func concreteV3TransportReceivesAndAcknowledgesTheExactCursor() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(v3Coherence: v3Contract()))
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    defer { Task { await client.close() } }

    let resolved = try await client.resolve(attachRef: "mock")
    let root = try v3Identity(1)
    let transport = try await PfsLocalMacOSV3CoherenceTransport.connect(
        client: client,
        resolved: resolved,
        planner: PfsMacOSRepairPlanner(index: PfsMacOSNamespaceIndex(rootIdentity: root))
    )
    let backend = V3TestBackend()
    let runner = try await transport.makeRunner(backend: backend)
    let target = v3Target(scope: .attributes, identity: Data(repeating: 0x44, count: 16))
    daemon.emitVisibility(v3Event(targets: [target]))

    let event = try await nextV3Event(from: transport)
    #expect(event.sequence == 1)
    #expect(event.phase == .prepare)
    try await runner.consume(event)
    #expect(await backend.count() == 1)

    let acknowledgements = await daemon.visibilityAcknowledgements()
    #expect(acknowledgements.count == 1)
    #expect(acknowledgements[0].authorityEpoch == v3Epoch)
    #expect(acknowledgements[0].hasCursor)
    #expect(acknowledgements[0].cursor.sequence == 1)
    #expect(acknowledgements[0].cursor.phase == .prepare)
    #expect(!acknowledgements[0].blocked)
    #expect(acknowledgements[0].reason.isEmpty)
    #expect(await daemon.stats().visibilityAcks == 1)

    await #expect(throws: PfsMacOSCoherenceError.invalidSequence(0)) {
        try await transport.acknowledge(
            epoch: v3Epoch,
            cursor: .init(sequence: 0, phase: .complete)
        )
    }
    await #expect(throws: PfsMacOSCoherenceError.epochChanged) {
        try await transport.acknowledge(
            epoch: Data(repeating: 0xEE, count: 16),
            cursor: .init(sequence: 1, phase: .complete)
        )
    }
    #expect(await daemon.stats().visibilityAcks == 1)

    // Once success is acknowledged the transport must forget that delivered
    // cursor. A later independent failure closes the client, but cannot send a
    // contradictory BLOCKED verdict for the already-ACKed PREPARE.
    await transport.failClosed(epoch: v3Epoch, cursor: nil, reason: "later liveness failure")
    #expect(await daemon.stats().visibilityAcks == 1)
}

@Test func completeAckCarriesOrderedAdmissionContentionFeedback() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(v3Coherence: v3Contract()))
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    defer { Task { await client.close() } }

    let resolved = try await client.resolve(attachRef: "mock")
    let root = try v3Identity(1)
    let transport = try await PfsLocalMacOSV3CoherenceTransport.connect(
        client: client,
        resolved: resolved,
        planner: PfsMacOSRepairPlanner(index: PfsMacOSNamespaceIndex(rootIdentity: root))
    )
    let runner = try await transport.makeRunner(
        backend: V3TestBackend(reportsContention: true)
    )
    let target = v3Target(
        scope: .attributes,
        identity: Data(repeating: 0x44, count: 16)
    )

    daemon.emitVisibility(v3Event(phase: .prepare, targets: [target]))
    try await runner.consume(try await nextV3Event(from: transport))
    daemon.emitVisibility(v3Event(phase: .complete, targets: [target]))
    try await runner.consume(try await nextV3Event(from: transport))

    let acknowledgements = await daemon.visibilityAcknowledgements()
    #expect(acknowledgements.count == 2)
    #expect(!acknowledgements[0].orderedAdmissionContended)
    #expect(acknowledgements[1].orderedAdmissionContended)
    #expect(acknowledgements[1].cursor.phase == .complete)
}

@Test func v3TransportRefusesMissingContractBeforeSubscribing() async throws {
    let client = PfsLocalClient(socketPath: "/definitely/not/a/socket")
    defer { Task { await client.close() } }
    let root = try v3Identity(1)
    await #expect(throws: PfsMacOSCoherenceError.missingV3CoherenceContract) {
        try await PfsLocalMacOSV3CoherenceTransport.connect(
            client: client,
            resolved: PfsResolveReply(),
            planner: PfsMacOSRepairPlanner(index: PfsMacOSNamespaceIndex(rootIdentity: root))
        )
    }
}

@Test func v3TransportWithNoCursorFailsClosedByClosingTheClient() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(v3Coherence: v3Contract()))
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")
    let root = try v3Identity(1)
    let transport = try await PfsLocalMacOSV3CoherenceTransport.connect(
        client: client,
        resolved: resolved,
        planner: PfsMacOSRepairPlanner(index: PfsMacOSNamespaceIndex(rootIdentity: root))
    )

    await transport.failClosed(epoch: v3Epoch, cursor: nil, reason: "stream closed")
    await #expect(throws: PfsLocalClientError.shutdown) {
        _ = try await client.request(.statfs(PfsStatfsRequest()))
    }
    #expect(await daemon.stats().visibilityAcks == 0)
}

@Test func concreteV3TransportReportsTheRouteCursorAsBlocked() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(v3Coherence: v3Contract()))
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    defer { Task { await client.close() } }

    let resolved = try await client.resolve(attachRef: "mock")
    let root = try v3Identity(1)
    let transport = try await PfsLocalMacOSV3CoherenceTransport.connect(
        client: client,
        resolved: resolved,
        planner: PfsMacOSRepairPlanner(index: PfsMacOSNamespaceIndex(rootIdentity: root))
    )
    var routeEvent = v3Event(sequence: 9, phase: .prepare, targets: [])
    routeEvent.initiatorSessionID = Data(repeating: 0, count: 16)
    routeEvent.mutationSlot = 0
    routeEvent.mutationSequence = 0
    var routes = PfsRoutesChange()
    routes.revision = Data(repeating: 0xDD, count: 32)
    routeEvent.routes = routes
    daemon.emitVisibility(routeEvent)

    await #expect(throws: PfsMacOSCoherenceError.routesChangeRequiresRemount) {
        _ = try await nextV3Event(from: transport)
    }
    await transport.failClosed(
        epoch: v3Epoch,
        cursor: nil,
        reason: String(repeating: "🙂", count: 2_000)
    )

    let acknowledgements = await daemon.visibilityAcknowledgements()
    #expect(acknowledgements.count == 1)
    #expect(acknowledgements[0].blocked)
    #expect(acknowledgements[0].cursor.sequence == 9)
    #expect(acknowledgements[0].cursor.phase == .prepare)
    #expect(acknowledgements[0].reason.utf8.count <= 1_024)
    #expect(!acknowledgements[0].reason.isEmpty)
}

@Test func strictV3UDSDisconnectTerminatesWithoutReconnectOrQueueHang() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(v3Coherence: v3Contract()))
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    defer { Task { await client.close() } }

    let resolved = try await client.resolve(attachRef: "mock")
    let root = try v3Identity(1)
    let transport = try await PfsLocalMacOSV3CoherenceTransport.connect(
        client: client,
        resolved: resolved,
        planner: PfsMacOSRepairPlanner(index: PfsMacOSNamespaceIndex(rootIdentity: root))
    )

    daemon.dropConnections()
    let terminal = try await withThrowingTaskGroup(of: Bool.self) { group in
        group.addTask {
            try await transport.nextEvent() == nil
        }
        group.addTask {
            try await Task.sleep(for: .seconds(1))
            throw PfsLocalClientError.timeout
        }
        guard let result = try await group.next() else {
            throw PfsLocalClientError.timeout
        }
        group.cancelAll()
        return result
    }
    #expect(terminal)

    // A filesystem request cannot secretly create connection B after strict
    // participant connection A has died.
    await #expect(throws: PfsLocalClientError.connectionClosed) {
        _ = try await client.request(.statfs(PfsStatfsRequest()))
    }
}

@Test func strictV3DisconnectBetweenResolveAndSubscribeIsTerminal() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(v3Coherence: v3Contract()))
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    defer { Task { await client.close() } }

    // Resolve is the point where strict participation becomes intent. A lost
    // socket after this reply may not be replaced before SubscribeEvents.
    _ = try await client.resolve(attachRef: "mock")
    daemon.dropConnections()

    await #expect(throws: PfsLocalClientError.self) {
        _ = try await client.subscribeStrictV3Events()
    }
    await #expect(throws: PfsLocalClientError.connectionClosed) {
        _ = try await client.request(.statfs(PfsStatfsRequest()))
    }
}

@Test func strictV3ResolveRejectsAPreexistingLegacyEventSubscription() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(v3Coherence: v3Contract()))
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    defer { Task { await client.close() } }

    _ = try await client.subscribeEvents()
    await #expect(throws: PfsLocalClientError.self) {
        _ = try await client.resolve(attachRef: "mock")
    }
    await #expect(throws: PfsLocalClientError.connectionClosed) {
        _ = try await client.request(.statfs(PfsStatfsRequest()))
    }
}

@Test func strictV3EventsUseOnlyTheDedicatedUnboundedSink() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(v3Coherence: v3Contract()))
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    defer { Task { await client.close() } }

    let resolved = try await client.resolve(attachRef: "mock")
    let root = try v3Identity(1)
    let transport = try await PfsLocalMacOSV3CoherenceTransport.connect(
        client: client,
        resolved: resolved,
        planner: PfsMacOSRepairPlanner(index: PfsMacOSNamespaceIndex(rootIdentity: root))
    )

    let eventCount = 1_500
    for version in 1...eventCount {
        daemon.emitInvalidation(
            item: PfsItem(),
            contentVersion: UInt64(version)
        )
    }

    for _ in 0..<200 {
        let counts = await client.testingEventDeliveryCounts()
        if counts.strictV3 == eventCount { break }
        try await Task.sleep(for: .milliseconds(5))
    }
    let counts = await client.testingEventDeliveryCounts()
    #expect(counts.strictV3 == eventCount)
    // Strict events are routed exclusively. They must not accumulate in the
    // legacy stream, whose bounded buffer may have no consumer at all.
    #expect(counts.legacy == 0)
    withExtendedLifetime(transport) {}
}

@Test func strictV3ConnectRequiresAnExactInitialAuthorityLivenessProof() async throws {
    let contract = v3Contract(repairBudgetMillis: 120)
    let daemon = try PfsLocalMockDaemon(configuration: .init(v3Coherence: contract))
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    defer { Task { await client.close() } }

    let resolved = try await client.resolve(attachRef: "mock")
    let root = try v3Identity(1)
    let transport = try await PfsLocalMacOSV3CoherenceTransport.connect(
        client: client,
        resolved: resolved,
        planner: PfsMacOSRepairPlanner(index: PfsMacOSNamespaceIndex(rootIdentity: root))
    )

    // The first proof is complete before connect returns, and subsequent
    // proofs run independently at repairBudget/3 (40 ms here).
    var requests = await daemon.v3LivenessRequests()
    #expect(!requests.isEmpty)
    #expect(requests[0].authorityEpoch == v3Epoch)
    #expect(requests[0].sessionID == v3LocalSession)
    let deadline = ContinuousClock.now + .milliseconds(500)
    while requests.count < 3, ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(5))
        requests = await daemon.v3LivenessRequests()
    }
    #expect(requests.count >= 3)
    #expect(requests.allSatisfy {
        $0.authorityEpoch == v3Epoch && $0.sessionID == v3LocalSession
    })
    #expect(await daemon.stats().syncVolumeRequests == 0)
    withExtendedLifetime(transport) {}
}

@Test func strictV3ConnectFailsClosedWhenTheInitialLivenessProofTimesOut() async throws {
    let contract = v3Contract(repairBudgetMillis: 30)
    let daemon = try PfsLocalMockDaemon(configuration: .init(
        v3Coherence: contract,
        v3LivenessDelayNanoseconds: 250_000_000
    ))
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    defer { Task { await client.close() } }

    let resolved = try await client.resolve(attachRef: "mock")
    let root = try v3Identity(1)
    let started = ContinuousClock.now
    await #expect(throws: PfsMacOSCoherenceError.livenessDeadlineExceeded(10)) {
        _ = try await PfsLocalMacOSV3CoherenceTransport.connect(
            client: client,
            resolved: resolved,
            planner: PfsMacOSRepairPlanner(index: PfsMacOSNamespaceIndex(rootIdentity: root))
        )
    }
    #expect(started.duration(to: .now) < .milliseconds(200))
    #expect(await daemon.stats().v3LivenessRequests == 1)
    #expect(await daemon.stats().syncVolumeRequests == 0)
    await #expect(throws: PfsLocalClientError.shutdown) {
        _ = try await client.request(.statfs(PfsStatfsRequest()))
    }
}
@Test func strictV3PeriodicLivenessMismatchTerminatesWithoutReconnectOrSync() async throws {
    let contract = v3Contract(repairBudgetMillis: 60)
    let daemon = try PfsLocalMockDaemon(configuration: .init(
        v3Coherence: contract,
        v3LivenessSessionOverride: Data(repeating: 0xEE, count: 16),
        // Let the synchronous activation proof pass, then corrupt pulse two.
        v3LivenessOverrideAfterRequestCount: 1
    ))
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    defer { Task { await client.close() } }

    let resolved = try await client.resolve(attachRef: "mock")
    let root = try v3Identity(1)
    let transport = try await PfsLocalMacOSV3CoherenceTransport.connect(
        client: client,
        resolved: resolved,
        planner: PfsMacOSRepairPlanner(index: PfsMacOSNamespaceIndex(rootIdentity: root))
    )

    let terminal = try await withThrowingTaskGroup(of: Bool.self) { group in
        group.addTask { try await transport.nextEvent() == nil }
        group.addTask {
            try await Task.sleep(for: .seconds(1))
            throw PfsLocalClientError.timeout
        }
        guard let result = try await group.next() else {
            throw PfsLocalClientError.timeout
        }
        group.cancelAll()
        return result
    }
    #expect(terminal)
    #expect(await daemon.stats().v3LivenessRequests == 2)
    #expect(await daemon.stats().syncVolumeRequests == 0)
    await #expect(throws: PfsLocalClientError.shutdown) {
        _ = try await client.request(.statfs(PfsStatfsRequest()))
    }
}
}
