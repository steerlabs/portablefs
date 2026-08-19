import Foundation

/// The strict macOS-v3 terms portablefsd returned while resolving this attach.
/// The raw protobuf is validated once and never consulted by the coherence
/// runner again.
public struct PfsMacOSV3LocalContract: Sendable, Equatable {
    public let authorityProtocolMajor: UInt32
    public let epoch: Data
    public let sessionID: Data
    public let cachePolicy: PfsMacOSCachePolicy
    public let repairBudgetMillis: UInt64
    public let initialAcknowledgedCursor: PfsMacOSVisibilityCursor?
}

private actor PfsMacOSV3EventQueue {
    private var queued: [PfsEvent] = []
    private var waiters: [CheckedContinuation<PfsEvent?, Never>] = []
    private var finished = false

    func push(_ event: PfsEvent) {
        guard !finished else { return }
        if !waiters.isEmpty {
            waiters.removeFirst().resume(returning: event)
        } else {
            queued.append(event)
        }
    }

    func finish() {
        guard !finished else { return }
        finished = true
        let pending = waiters
        waiters.removeAll()
        for waiter in pending {
            waiter.resume(returning: nil)
        }
    }

    func next() async -> PfsEvent? {
        if !queued.isEmpty {
            return queued.removeFirst()
        }
        if finished {
            return nil
        }
        return await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }
}

private final class PfsWeakMacOSV3Transport: @unchecked Sendable {
    weak var value: PfsLocalMacOSV3CoherenceTransport?

    init(_ value: PfsLocalMacOSV3CoherenceTransport) {
        self.value = value
    }
}

/// The concrete wire adapter between additive pfslocal minor 15 and the
/// platform-independent `PfsMacOSCoherenceRunner`.
///
/// portablefsd owns the authority connection. This type owns only the local
/// event cursor: it validates every authority-shaped value, derives this
/// mount's concrete repairs from its namespace index, and sends the resulting
/// cursor verdict back over the priority local control lane.
///
/// `VolumeCore` composes this adapter only after the selected FSKit cache policy
/// has supplied its exact index, callback-admission, and repair implementation.
public actor PfsLocalMacOSV3CoherenceTransport: PfsMacOSCoherenceTransport {
    public let contract: PfsMacOSV3LocalContract

    private let client: PfsLocalClient
    private let planner: PfsMacOSRepairPlanner
    private let events: PfsMacOSV3EventQueue
    private let eventPump: Task<Void, Never>
    private var livenessTask: Task<Void, Never>?
    private var lastDeliveredCursor: PfsMacOSVisibilityCursor?

    private init(
        client: PfsLocalClient,
        contract: PfsMacOSV3LocalContract,
        planner: PfsMacOSRepairPlanner,
        events: PfsMacOSV3EventQueue,
        eventPump: Task<Void, Never>
    ) {
        self.client = client
        self.contract = contract
        self.planner = planner
        self.events = events
        self.eventPump = eventPump
    }

    deinit {
        eventPump.cancel()
        livenessTask?.cancel()
    }

    /// Creates a transport only after the resolved attach has supplied a valid
    /// strict-v3 contract and event subscription has succeeded.
    public static func connect(
        client: PfsLocalClient,
        resolved: PfsResolveReply,
        planner: PfsMacOSRepairPlanner
    ) async throws -> PfsLocalMacOSV3CoherenceTransport {
        guard resolved.hasV3Coherence else {
            throw PfsMacOSCoherenceError.missingV3CoherenceContract
        }
        let contract = try parseContract(resolved.v3Coherence)
        let stream = try await client.subscribeStrictV3Events()
        let events = PfsMacOSV3EventQueue()
        let eventPump = Task(priority: .userInitiated) {
            for await event in stream {
                await events.push(event)
            }
            await events.finish()
        }
        let transport = PfsLocalMacOSV3CoherenceTransport(
            client: client,
            contract: contract,
            planner: planner,
            events: events,
            eventPump: eventPump
        )
        try await transport.startLiveness()
        return transport
    }

    private func startLiveness() async throws {
        guard livenessTask == nil else { return }
        let client = client
        let contract = contract
        let cadence = Self.livenessCadence(contract)
        do {
            // Activation cannot outrun its first end-to-end proof. Returning a
            // transport first and probing later leaves a window in which FSKit
            // could serve before the daemon's authority session was known live.
            try await Self.checkLiveness(
                client: client,
                contract: contract,
                deadline: cadence
            )
        } catch {
            await failClosed(
                epoch: contract.epoch,
                cursor: nil,
                reason: String(describing: error)
            )
            throw error
        }

        let weakTransport = PfsWeakMacOSV3Transport(self)
        livenessTask = Task {
            await Self.runLivenessLoop(client: client, contract: contract) { reason in
                guard let transport = weakTransport.value else { return }
                await transport.failClosed(epoch: contract.epoch, cursor: nil, reason: reason)
            }
        }
    }

    private static func livenessCadence(
        _ contract: PfsMacOSV3LocalContract
    ) -> Duration {
        Duration.milliseconds(Int64(contract.repairBudgetMillis)) / 3
    }

    /// This task is independent of event delivery: an open but frozen daemon
    /// socket cannot keep a frontend alive merely because `nextEvent()` is
    /// still waiting. Every successful reply proves an on-demand authority
    /// KeepAlive completed on the daemon's reserved liveness lane.
    private static func runLivenessLoop(
        client: PfsLocalClient,
        contract: PfsMacOSV3LocalContract,
        onFailure: @escaping @Sendable (String) async -> Void
    ) async {
        let cadence = livenessCadence(contract)
        let clock = ContinuousClock()
        var nextPulse = clock.now + cadence
        while !Task.isCancelled {
            do {
                try await clock.sleep(until: nextPulse)
                try await checkLiveness(
                    client: client,
                    contract: contract,
                    deadline: cadence
                )
                nextPulse += cadence
            } catch is CancellationError {
                return
            } catch {
                guard !Task.isCancelled else { return }
                await onFailure(String(describing: error))
                return
            }
        }
    }

    private static func checkLiveness(
        client: PfsLocalClient,
        contract: PfsMacOSV3LocalContract,
        deadline: Duration
    ) async throws {
        var request = PfsV3LivenessRequest()
        request.authorityEpoch = contract.epoch
        request.sessionID = contract.sessionID

        let race = PfsMacOSDeadlineRace()
        let operation = Task {
            do {
                let reply = try await client.checkV3Liveness(request)
                guard reply.authorityEpoch.count == 16 else {
                    throw PfsMacOSCoherenceError.invalidEpochLength(reply.authorityEpoch.count)
                }
                guard reply.sessionID.count == 16 else {
                    throw PfsMacOSCoherenceError.invalidSessionIDLength(reply.sessionID.count)
                }
                guard reply.authorityEpoch == contract.epoch else {
                    throw PfsMacOSCoherenceError.epochChanged
                }
                guard reply.sessionID == contract.sessionID else {
                    throw PfsMacOSCoherenceError.livenessSessionMismatch
                }
                race.resolve(.success(()))
            } catch {
                race.resolve(.failure(error))
            }
        }
        let watchdog = Task {
            do {
                try await Task.sleep(for: deadline)
                operation.cancel()
                race.resolve(.failure(PfsMacOSCoherenceError.livenessDeadlineExceeded(
                    contract.repairBudgetMillis / 3
                )))
            } catch {
                // The authority round trip or caller won the race.
            }
        }
        do {
            try await withTaskCancellationHandler {
                try await race.wait()
            } onCancel: {
                operation.cancel()
                watchdog.cancel()
                race.resolve(.failure(CancellationError()))
            }
            watchdog.cancel()
        } catch {
            operation.cancel()
            watchdog.cancel()
            throw error
        }
    }

    public static func parseContract(
        _ wire: PfsV3CoherenceContract
    ) throws -> PfsMacOSV3LocalContract {
        // This is the authority protocol nested inside pfslocal, not the local
        // UDS major. Protocol 6 names the explicit FSKit synchronous-repair
        // profile; an older authority contract is not negotiated or translated.
        guard wire.authorityProtocolMajor == 6 else {
            throw PfsMacOSCoherenceError.invalidAuthorityProtocolMajor(
                wire.authorityProtocolMajor
            )
        }
        guard wire.authorityEpoch.count == 16 else {
            throw PfsMacOSCoherenceError.invalidEpochLength(wire.authorityEpoch.count)
        }
        guard wire.sessionID.count == 16 else {
            throw PfsMacOSCoherenceError.invalidSessionIDLength(wire.sessionID.count)
        }
        guard let cachePolicy = PfsMacOSCachePolicy(rawValue: wire.cachePolicy) else {
            throw PfsMacOSCoherenceError.invalidCachePolicy(wire.cachePolicy)
        }
        guard wire.repairBudgetMillis > 0 else {
            throw PfsMacOSCoherenceError.invalidRepairBudget(wire.repairBudgetMillis)
        }
        guard wire.repairBudgetMillis <= UInt64(Int64.max) else {
            throw PfsMacOSCoherenceError.invalidRepairBudget(wire.repairBudgetMillis)
        }

        let initialCursor: PfsMacOSVisibilityCursor?
        if !wire.hasInitialCursor {
            initialCursor = nil
        } else {
            initialCursor = try decodeCursor(wire.initialCursor)
            guard initialCursor?.phase == .complete else {
                throw PfsMacOSCoherenceError.initialCursorMustBeComplete
            }
        }
        return PfsMacOSV3LocalContract(
            authorityProtocolMajor: wire.authorityProtocolMajor,
            epoch: wire.authorityEpoch,
            sessionID: wire.sessionID,
            cachePolicy: cachePolicy,
            repairBudgetMillis: wire.repairBudgetMillis,
            initialAcknowledgedCursor: initialCursor
        )
    }

    public func nextEvent() async throws -> PfsMacOSCoherenceEvent? {
        while let event = await events.next() {
            switch event.kind {
            case let .visibility(wire):
                if wire.hasCursor {
                    lastDeliveredCursor = try Self.decodeCursor(wire.cursor)
                }
                return try await Self.decodeEvent(
                    wire,
                    expectedEpoch: contract.epoch,
                    expectedSessionID: contract.sessionID,
                    planner: planner
                )
            case let .attachState(state):
                switch state.state {
                case .degraded, .detaching:
                    throw PfsMacOSCoherenceError.transportClosed
                case .unspecified, .attached, .warming:
                    continue
                case .UNRECOGNIZED:
                    throw PfsMacOSCoherenceError.transportClosed
                }
            case .invalidation:
                // A paired v8 daemon may still publish legacy diagnostic
                // invalidations. They do not discharge a v3 cursor and must
                // never be mistaken for one.
                continue
            case nil:
                throw PfsMacOSCoherenceError.transportClosed
            }
        }
        return nil
    }

    /// Constructs the runner from the already-validated resolved contract so
    /// the authority's per-phase budget cannot be accidentally dropped by a
    /// caller composing the concrete transport.
    public func makeRunner(
        backend: any PfsMacOSCoherenceBackend
    ) throws -> PfsMacOSCoherenceRunner {
        guard backend.policy == contract.cachePolicy else {
            throw PfsMacOSCoherenceError.unsupportedRepair
        }
        return try PfsMacOSCoherenceRunner(
            epoch: contract.epoch,
            initialAcknowledgedCursor: contract.initialAcknowledgedCursor,
            repairBudgetMillis: contract.repairBudgetMillis,
            backend: backend,
            transport: self
        )
    }

    public func acknowledge(
        epoch: Data,
        cursor: PfsMacOSVisibilityCursor
    ) async throws {
        try await acknowledge(
            epoch: epoch,
            cursor: cursor,
            orderedAdmissionContended: false
        )
    }

    public func acknowledge(
        epoch: Data,
        cursor: PfsMacOSVisibilityCursor,
        orderedAdmissionContended: Bool
    ) async throws {
        guard epoch == contract.epoch else {
            throw PfsMacOSCoherenceError.epochChanged
        }
        guard cursor.sequence > 0 else {
            throw PfsMacOSCoherenceError.invalidSequence(cursor.sequence)
        }
        var request = PfsVisibilityAckRequest()
        request.authorityEpoch = epoch
        request.cursor = Self.encodeCursor(cursor)
        request.orderedAdmissionContended = orderedAdmissionContended
        try await client.acknowledgeVisibility(request)
        if lastDeliveredCursor == cursor {
            // A later independent liveness failure has no right to rewrite an
            // already-successful cursor as blocked. Only an outstanding event
            // may be used for the best-effort terminal verdict.
            lastDeliveredCursor = nil
        }
    }

    public func failClosed(
        epoch: Data,
        cursor: PfsMacOSVisibilityCursor?,
        reason: String
    ) async {
        // This is the coherence stack's death sentence for the mount; the
        // reason must reach the unified log from the layer that decided it.
        pfsClientLogger.error(
            "v3 coherence failing closed: \(reason, privacy: .public) at sequence \((self.lastDeliveredCursor ?? cursor)?.sequence ?? 0)"
        )
        guard epoch == contract.epoch,
              let failedCursor = lastDeliveredCursor ?? cursor,
              failedCursor.sequence > 0 else {
            // There is no valid cursor the daemon can bind a blocked verdict
            // to. Closing the subscribed connection is the only truthful
            // signal; the strict bridge treats that disconnect as terminal.
            await client.close()
            return
        }
        var request = PfsVisibilityAckRequest()
        request.authorityEpoch = epoch
        request.cursor = Self.encodeCursor(failedCursor)
        request.blocked = true
        request.reason = Self.boundedReason(reason)
        // Reporting the blocked cursor is best effort. It cannot inherit the
        // ordinary request deadline: this path is also used by the local
        // repair watchdog, and waiting on an unresponsive daemon here would
        // turn a bounded repair failure back into an unbounded mount hang.
        let race = PfsMacOSDeadlineRace()
        let report = Task {
            do {
                try await client.acknowledgeVisibility(request)
                race.resolve(.success(()))
            } catch {
                race.resolve(.failure(error))
            }
        }
        let reportWindow = min(contract.repairBudgetMillis, 100)
        let deadline = Task {
            do {
                try await Task.sleep(for: .milliseconds(Int64(reportWindow)))
                race.resolve(.success(()))
            } catch {
                // The report completed and cancelled this timer.
            }
        }
        _ = try? await race.wait()
        report.cancel()
        deadline.cancel()
        // Success, refusal, disconnect, and timeout all have the same local
        // outcome: retire this participant so no filesystem operation can
        // continue on a mount whose cache state is no longer proven current.
        await client.close()
    }

    public static func decodeEvent(
        _ wire: PfsV3VisibilityEvent,
        expectedEpoch: Data,
        expectedSessionID: Data,
        planner: PfsMacOSRepairPlanner
    ) async throws -> PfsMacOSCoherenceEvent {
        guard expectedEpoch.count == 16 else {
            throw PfsMacOSCoherenceError.invalidEpochLength(expectedEpoch.count)
        }
        guard expectedSessionID.count == 16 else {
            throw PfsMacOSCoherenceError.invalidSessionIDLength(expectedSessionID.count)
        }
        guard wire.authorityEpoch.count == 16 else {
            throw PfsMacOSCoherenceError.invalidEpochLength(wire.authorityEpoch.count)
        }
        guard wire.authorityEpoch == expectedEpoch else {
            throw PfsMacOSCoherenceError.epochChanged
        }
        guard wire.hasCursor else {
            throw PfsMacOSCoherenceError.invalidSequence(0)
        }
        let cursor = try decodeCursor(wire.cursor)
        if wire.hasRoutes {
            guard wire.targets.isEmpty, wire.routes.revision.count == 32 else {
                throw PfsMacOSCoherenceError.invalidRoutesChange
            }
            throw PfsMacOSCoherenceError.routesChangeRequiresRemount
        }
        guard wire.initiatorSessionID != expectedSessionID else {
            throw PfsMacOSCoherenceError.invalidVisibilityTarget
        }
        let initiator = try PfsMacOSMutationInitiator(
            sessionID: wire.initiatorSessionID,
            replaySlot: wire.mutationSlot,
            mutationSequence: wire.mutationSequence
        )

        // A mutation that was definitely refused or proved to be a no-op still
        // sends COMPLETE so mounts reopen their PREPARE gate. It truthfully has
        // no repair targets. PREPARE must always name its intended footprint;
        // otherwise scoped fan-out and publication admission have no basis.
        guard !wire.targets.isEmpty || cursor.phase == .complete else {
            throw PfsMacOSCoherenceError.invalidVisibilityTarget
        }

        var targets: [PfsMacOSVisibilityTarget] = []
        targets.reserveCapacity(wire.targets.count)
        for target in wire.targets {
            // A post-binding is an authority statement about applied XFS truth.
            // PREPARE describes only the intended footprint; attempting to use
            // its not-yet-created coordinate as a repair source would deadlock
            // the mutation on an expected ENOENT.
            guard cursor.phase == .complete || target.postIdentity.isEmpty else {
                throw PfsMacOSCoherenceError.invalidVisibilityTarget
            }
            targets.append(try decodeTarget(target))
        }
        let repairs = try await planner.repairs(
            for: targets,
            authorityNamespaceTruthChanged: cursor.phase == .complete
        )
        return try PfsMacOSCoherenceEvent(
            epoch: wire.authorityEpoch,
            sequence: cursor.sequence,
            phase: cursor.phase,
            initiator: initiator,
            authorityPayloadIdentity: try wire.serializedData(),
            repairs: repairs
        )
    }

    public static func decodeTarget(
        _ wire: PfsVisibilityTarget
    ) throws -> PfsMacOSVisibilityTarget {
        switch wire.scope {
        case .namespace:
            guard wire.identity.isEmpty,
                  wire.parentIdentity.count == 16,
                  wire.name.count <= 255,
                  wire.size == 0 else {
                throw PfsMacOSCoherenceError.invalidVisibilityTarget
            }
            _ = try PfsMacOSRelativePath(components: [wire.name])
            if wire.postIdentity.isEmpty {
                return .namespace(
                    parentIdentity: try PfsMacOSStableIdentity(wire.parentIdentity),
                    name: wire.name
                )
            }
            guard wire.postIdentity.count == 16 else {
                throw PfsMacOSCoherenceError.invalidVisibilityTarget
            }
            return .namespacePost(
                parentIdentity: try PfsMacOSStableIdentity(wire.parentIdentity),
                name: wire.name,
                identity: try PfsMacOSStableIdentity(wire.postIdentity)
            )
        case .data:
            guard wire.identity.count == 16,
                  wire.parentIdentity.isEmpty,
                  wire.name.isEmpty,
                  wire.postIdentity.isEmpty,
                  wire.size >= 0 else {
                throw PfsMacOSCoherenceError.invalidVisibilityTarget
            }
            return .data(
                identity: try PfsMacOSStableIdentity(wire.identity),
                size: UInt64(wire.size)
            )
        case .attributes:
            guard wire.identity.count == 16,
                  wire.parentIdentity.isEmpty,
                  wire.name.isEmpty,
                  wire.postIdentity.isEmpty,
                  wire.size == 0 else {
                throw PfsMacOSCoherenceError.invalidVisibilityTarget
            }
            return .attributes(identity: try PfsMacOSStableIdentity(wire.identity))
        case .unspecified:
            throw PfsMacOSCoherenceError.invalidVisibilityScope(wire.scope.rawValue)
        case .UNRECOGNIZED:
            throw PfsMacOSCoherenceError.invalidVisibilityScope(wire.scope.rawValue)
        }
    }

    private static func decodeCursor(
        _ wire: PfsVisibilityCursor
    ) throws -> PfsMacOSVisibilityCursor {
        guard wire.sequence > 0 else {
            throw PfsMacOSCoherenceError.invalidSequence(wire.sequence)
        }
        let phase: PfsMacOSVisibilityPhase
        switch wire.phase {
        case .prepare:
            phase = .prepare
        case .complete:
            phase = .complete
        case .unspecified, .UNRECOGNIZED:
            throw PfsMacOSCoherenceError.invalidVisibilityPhase(wire.phase.rawValue)
        }
        return PfsMacOSVisibilityCursor(sequence: wire.sequence, phase: phase)
    }

    private static func encodeCursor(
        _ cursor: PfsMacOSVisibilityCursor
    ) -> PfsVisibilityCursor {
        var wire = PfsVisibilityCursor()
        wire.sequence = cursor.sequence
        switch cursor.phase {
        case .prepare:
            wire.phase = .prepare
        case .complete:
            wire.phase = .complete
        }
        return wire
    }

    /// portablefsd bounds the UTF-8 wire representation, not Swift grapheme
    /// count. Preserve whole user-visible characters without exceeding it.
    private static func boundedReason(_ reason: String) -> String {
        guard reason.utf8.count > 1024 else { return reason }
        var end = reason.startIndex
        var byteCount = 0
        while end < reason.endIndex {
            let next = reason.index(after: end)
            let characterBytes = reason[end..<next].utf8.count
            guard byteCount + characterBytes <= 1024 else { break }
            byteCount += characterBytes
            end = next
        }
        return String(reason[..<end])
    }
}
