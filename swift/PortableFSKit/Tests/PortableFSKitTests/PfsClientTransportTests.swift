import Foundation
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

private func transportBytes(_ string: String) -> Data {
    Data(string.utf8)
}

private actor PfsTestAsyncGate {
    private var open = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if open {
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func release() {
        open = true
        let pending = waiters
        waiters.removeAll()
        for continuation in pending {
            continuation.resume()
        }
    }
}

private actor PfsWrittenRequestIDs {
    private var ids: [UInt64] = []

    func append(_ id: UInt64) {
        ids.append(id)
    }

    func snapshot() -> [UInt64] {
        ids
    }
}

private actor PfsWriteOverlapProbe {
    private var active = 0
    private var maximum = 0

    func begin() {
        active += 1
        maximum = max(maximum, active)
    }

    func end() {
        active -= 1
    }

    func maximumConcurrency() -> Int {
        maximum
    }
}

private enum PfsWriterTestError: Error {
    case failed
}

private final class PfsWeakWriteReceiptBox {
    weak var receipt: PfsEnvelopeWriteReceipt?

    init(_ receipt: PfsEnvelopeWriteReceipt) {
        self.receipt = receipt
    }
}

private func writerTestEnvelope(_ requestID: UInt64) -> PfsEnvelope {
    var envelope = PfsEnvelope()
    envelope.requestID = requestID
    envelope.body = .statfs(PfsStatfsRequest())
    return envelope
}

@Test func outboundWriterPreservesRequestIDOrderAcrossDetachedScheduling() async throws {
    let firstWriteGate = PfsTestAsyncGate()
    let written = PfsWrittenRequestIDs()
    let writer = PfsOrderedEnvelopeWriter { envelope in
        if envelope.requestID == 1 {
            await firstWriteGate.wait()
        }
        await written.append(envelope.requestID)
    }

    var firstEnvelope = PfsEnvelope()
    firstEnvelope.requestID = 1
    firstEnvelope.body = .statfs(PfsStatfsRequest())
    var secondEnvelope = PfsEnvelope()
    secondEnvelope.requestID = 2
    secondEnvelope.body = .statfs(PfsStatfsRequest())

    let first = writer.enqueue(firstEnvelope)
    let second = writer.enqueue(secondEnvelope)
    try await Task.sleep(for: .milliseconds(20))
    #expect(await written.snapshot().isEmpty)

    await firstWriteGate.release()
    try await first.wait()
    try await second.wait()
    #expect(await written.snapshot() == [1, 2])
}

@Test func outboundWriterPrioritizesPublicationAfterCurrentFrame() async throws {
    let firstWriteStarted = PfsTestAsyncGate()
    let firstWriteGate = PfsTestAsyncGate()
    let written = PfsWrittenRequestIDs()
    let writer = PfsOrderedEnvelopeWriter { envelope in
        if envelope.requestID == 1 {
            await firstWriteStarted.release()
            await firstWriteGate.wait()
        }
        await written.append(envelope.requestID)
    }

    let first = writer.enqueue(writerTestEnvelope(1))
    await firstWriteStarted.wait()
    let second = writer.enqueue(writerTestEnvelope(2))
    let third = writer.enqueue(writerTestEnvelope(3))
    let publication = writer.enqueue(
        writerTestEnvelope(99),
        lane: .publication
    )

    await firstWriteGate.release()
    try await first.wait()
    try await publication.wait()
    try await second.wait()
    try await third.wait()
    #expect(await written.snapshot() == [1, 99, 2, 3])
}

@Test func outboundWriterReleasesConsumedEntriesWhileBusy() async throws {
    let midpointReached = PfsTestAsyncGate()
    let midpointGate = PfsTestAsyncGate()
    let writer = PfsOrderedEnvelopeWriter { envelope in
        if envelope.requestID == 2_500 {
            await midpointReached.release()
            await midpointGate.wait()
        }
    }
    var consumedReceipts: [PfsWeakWriteReceiptBox] = []
    var finalReceipt: PfsEnvelopeWriteReceipt?

    for requestID in UInt64(1)...5_000 {
        let receipt = writer.enqueue(writerTestEnvelope(requestID))
        if requestID < 2_500 {
            consumedReceipts.append(PfsWeakWriteReceiptBox(receipt))
        }
        if requestID == 5_000 {
            finalReceipt = receipt
        }
    }

    await midpointReached.wait()
    #expect(consumedReceipts.allSatisfy { $0.receipt == nil })
    await midpointGate.release()
    try await finalReceipt?.wait()
}

@Test func outboundWriterSerializesConcurrentEnqueues() async throws {
    let written = PfsWrittenRequestIDs()
    let overlap = PfsWriteOverlapProbe()
    let writer = PfsOrderedEnvelopeWriter { envelope in
        await overlap.begin()
        try await Task.sleep(for: .microseconds(100))
        await written.append(envelope.requestID)
        await overlap.end()
    }
    let workerCount: UInt64 = 8
    let writesPerWorker: UInt64 = 300

    try await withThrowingTaskGroup(of: Void.self) { group in
        for worker in 0..<workerCount {
            group.addTask {
                for index in 0..<writesPerWorker {
                    var envelope = PfsEnvelope()
                    envelope.requestID = worker * writesPerWorker + index + 1
                    envelope.body = .statfs(PfsStatfsRequest())
                    try await writer.enqueue(envelope).wait()
                }
            }
        }
        try await group.waitForAll()
    }

    let ids = await written.snapshot()
    #expect(ids.count == Int(workerCount * writesPerWorker))
    #expect(Set(ids).count == ids.count)
    #expect(await overlap.maximumConcurrency() == 1)
}

@Test func outboundWriterFailsQueuedAndLaterWritesAfterTerminalError() async throws {
    let firstWriteGate = PfsTestAsyncGate()
    let writer = PfsOrderedEnvelopeWriter { envelope in
        if envelope.requestID == 1 {
            await firstWriteGate.wait()
        }
        throw PfsWriterTestError.failed
    }
    let receipts = [
        writer.enqueue(writerTestEnvelope(1)),
        writer.enqueue(writerTestEnvelope(2)),
        writer.enqueue(writerTestEnvelope(3)),
    ]

    await firstWriteGate.release()
    for receipt in receipts {
        do {
            try await receipt.wait()
            Issue.record("expected queued write to fail")
        } catch is PfsWriterTestError {}
    }

    do {
        try await writer.enqueue(writerTestEnvelope(4)).wait()
        Issue.record("expected later write to fail with the terminal error")
    } catch is PfsWriterTestError {}
}

@Test func realReadPathRejectsEOFInMiddleOfFrame() async throws {
    let server = try PfsRawServer { fd in
        _ = try? PfsRawServer.recvSome(fd: fd)
        var length = UInt32(8).littleEndian
        var data = Data()
        withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
        data.append(contentsOf: [0x01, 0x02])
        try? PfsRawServer.sendAll(fd: fd, data: data)
    }
    defer { server.stop() }

    let client = PfsLocalClient(
        socketPath: server.socketPath,
        configuration: .init(maxReconnectAttempts: 1, requestDeadlineNanoseconds: 1_000_000_000)
    )

    do {
        _ = try await client.request(.statfs(PfsStatfsRequest()))
        Issue.record("expected EOF-mid-frame to fail")
    } catch let error as PfsLocalClientError {
        #expect(error == .invalidFrame("EOF before completing frame"))
    }
}

@Test func realReadPathRejectsOversizedFrame() async throws {
    let server = try PfsRawServer { fd in
        _ = try? PfsRawServer.recvSome(fd: fd)
        var length = UInt32(4097).littleEndian
        var data = Data()
        withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
        try? PfsRawServer.sendAll(fd: fd, data: data)
    }
    defer { server.stop() }

    let client = PfsLocalClient(
        socketPath: server.socketPath,
        configuration: .init(maxFrameLength: 4096, maxReconnectAttempts: 1, requestDeadlineNanoseconds: 1_000_000_000)
    )

    do {
        _ = try await client.request(.statfs(PfsStatfsRequest()))
        Issue.record("expected oversized frame to fail")
    } catch let error as PfsLocalClientError {
        #expect(error == .frameTooLarge(length: 4097, max: 4096))
    }
}

@Test func requestTimesOutAndClearsPendingEntry() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(lookupNoReplyNames: ["hung"]))
    defer { daemon.stop() }

    let client = PfsLocalClient(
        socketPath: daemon.socketPath,
        configuration: .init(requestDeadlineNanoseconds: 50_000_000)
    )
    let resolved = try await client.resolve(attachRef: "mock")

    var request = PfsLookupRequest()
    request.dir = resolved.root
    request.name = transportBytes("hung")

    do {
        _ = try await client.request(.lookup(request))
        Issue.record("expected lookup timeout")
    } catch let error as PfsLocalClientError {
        #expect(error == .timeout)
    }

    #expect(await client.testingPendingRequestCount() == 0)
}

@Test func requestCancellationResumesPromptlyAndClearsPendingEntry() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(lookupNoReplyNames: ["hung"]))
    defer { daemon.stop() }

    let client = PfsLocalClient(
        socketPath: daemon.socketPath,
        configuration: .init(requestDeadlineNanoseconds: 5_000_000_000)
    )
    let resolved = try await client.resolve(attachRef: "mock")

    var request = PfsLookupRequest()
    request.dir = resolved.root
    request.name = transportBytes("hung")

    let lookup = Task {
        try await client.request(.lookup(request))
    }
    try await Task.sleep(nanoseconds: 20_000_000)
    let started = ContinuousClock.now
    lookup.cancel()

    do {
        _ = try await lookup.value
        Issue.record("expected cancellation")
    } catch let error as PfsLocalClientError {
        #expect(error == .cancelled)
    }

    #expect(started.duration(to: .now) < .milliseconds(250))
    #expect(await client.testingPendingRequestCount() == 0)
}

@Test func eventsAreResubscribedAfterReconnect() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(
        socketPath: daemon.socketPath,
        attachRef: "mock",
        configuration: .init(maxReconnectAttempts: 10, reconnectBaseDelayNanoseconds: 5_000_000)
    )
    let root = try await core.rootItem()
    _ = try await core.createFile(in: root, name: transportBytes("after"), mode: 0o644)
    let stream = try await core.subscribeEvents()

    daemon.dropConnections()
    do {
        _ = try await core.lookup(in: root, name: transportBytes("after"))
    } catch {}
    _ = try await core.lookup(in: root, name: transportBytes("after"))

    let rootIdentity = await daemon.rootIdentity()
    daemon.emitInvalidation(item: rootIdentity.proto, contentVersion: 9)

    let event = try await nextEvent(from: stream)
    guard case let .invalidation(invalidation)? = event.kind else {
        Issue.record("expected invalidation event")
        return
    }
    #expect(invalidation.contentVersion == 9)
}

@Test func deferredPublicationOperationCannotSpanReplacementConnections() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let client = PfsLocalClient(
        socketPath: daemon.socketPath,
        configuration: .init(
            maxReconnectAttempts: 10,
            reconnectBaseDelayNanoseconds: 5_000_000
        )
    )
    let resolved = try await client.resolve(attachRef: "mock")
    var getattr = PfsGetAttrRequest()
    getattr.item = resolved.root

    let (result, complete) = await client.withDeferredPublication {
        _ = try await client.request(.getAttr(getattr))
        daemon.dropConnections()

        // Let the reader retire connection A before issuing the second
        // ack-producing request on connection B.
        try await Task.sleep(nanoseconds: 20_000_000)
        _ = try await client.request(.getAttr(getattr))
    }
    do {
        try result.get()
        Issue.record("expected a multi-request publication operation to fail across reconnect")
    } catch let error as PfsLocalClientError {
        #expect(error == .connectionClosed)
    }
    await complete()

    var stats = await daemon.stats()
    #expect(stats.publicationAcks == 0)

    // A fresh logical operation uses connection B normally. The stale ticket
    // from A is never replayed onto it.
    _ = try await client.request(.getAttr(getattr))
    let deadline = ContinuousClock.now + .seconds(1)
    while stats.publicationAcks < 1, ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(5))
        stats = await daemon.stats()
    }
    #expect(stats.publicationAcks == 1)
    _ = try await client.request(.statfs(PfsStatfsRequest()))
}

@Test func deferredPublicationNonpublishingContinuationCannotSpanReplacementConnections() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let client = PfsLocalClient(
        socketPath: daemon.socketPath,
        configuration: .init(
            maxReconnectAttempts: 10,
            reconnectBaseDelayNanoseconds: 5_000_000
        )
    )
    let resolved = try await client.resolve(attachRef: "mock")
    var getattr = PfsGetAttrRequest()
    getattr.item = resolved.root

    let (result, complete) = await client.withDeferredPublication {
        _ = try await client.request(.getAttr(getattr))
        daemon.dropConnections()

        // Establish replacement connection B from a detached task, which
        // intentionally does not inherit this callback's task-local
        // publication collector.
        try await Task.detached {
            var lastError: Error = PfsLocalClientError.connectionClosed
            for _ in 0..<20 {
                do {
                    _ = try await client.request(.statfs(PfsStatfsRequest()))
                    return
                } catch {
                    lastError = error
                    try await Task.sleep(for: .milliseconds(5))
                }
            }
            throw lastError
        }.value

        // A nonpublishing continuation still belongs to the publication
        // operation bound to A and must not be issued with operation ID zero
        // on B.
        _ = try await client.request(.statfs(PfsStatfsRequest()))
    }
    do {
        try result.get()
        Issue.record("expected a nonpublishing continuation to fail across reconnect")
    } catch let error as PfsLocalClientError {
        #expect(error == .connectionClosed)
    }
    await complete()

    let stats = await daemon.stats()
    #expect(stats.publicationAcks == 0)

    // The replacement connection remains healthy for a new logical operation.
    _ = try await client.request(.statfs(PfsStatfsRequest()))
}

private func waitForTransportPublicationAcks(
    _ daemon: PfsLocalMockDaemon,
    atLeast expected: Int
) async throws -> PfsLocalMockDaemon.Stats {
    let deadline = ContinuousClock.now + .seconds(1)
    while ContinuousClock.now < deadline {
        let stats = await daemon.stats()
        if stats.publicationAcks >= expected {
            return stats
        }
        try await Task.sleep(for: .milliseconds(5))
    }
    return await daemon.stats()
}

/// Captures an acknowledgement baseline that a later `==` can be trusted
/// against.
///
/// A publication acknowledgement is one-way by design: `PfsLocalClient`
/// returns from a publishing request once the ack has been WRITTEN to the
/// socket, and the daemon counts it whenever it gets round to reading that
/// frame. A bare `stats()` snapshot taken right after a publishing request
/// therefore lands on either side of an ack that is already in flight. The
/// damage never shows up here — it shows up on a LATER assertion, as an
/// off-by-one that reads as if the operation under test acknowledged twice.
///
/// So the baseline is taken by waiting for the counter to reach the number of
/// acks the setup is KNOWN to owe, rather than by sampling it at an arbitrary
/// instant. That is a wait on a specific condition that is guaranteed to
/// become true, not a delay, and it weakens nothing: `owed` is exact, so a
/// setup that starts acknowledging more fails loudly right here instead of
/// flaking somewhere downstream.
private func settledAckBaseline(
    _ daemon: PfsLocalMockDaemon,
    owed: Int,
    sourceLocation: SourceLocation = #_sourceLocation
) async throws -> Int {
    let stats = try await waitForTransportPublicationAcks(daemon, atLeast: owed)
    #expect(
        stats.publicationAcks == owed,
        "setup owed \(owed) publication acks",
        sourceLocation: sourceLocation
    )
    return owed
}

/// A retraction is answered by REISSUING the operation, below userspace.
///
/// The retraction contract itself is unchanged — the crossed attempt's values
/// are never handed back — but the frontend no longer surfaces that as EINTR
/// and hope the kernel restarts the syscall. FSKit on macOS 26 does not restart
/// rmdir(2), so the EINTR reached the application. The extension runs the
/// operation again instead, and only the surviving attempt's values are
/// returned.
@Test func retractedDeferredPublicationIsReissuedAndBothAttemptsAcknowledged() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")
    var getattr = PfsGetAttrRequest()
    getattr.item = resolved.root

    // Nothing before this point publishes, so no ack can be in flight — but
    // say so exactly rather than assuming it.
    let baseline = try await settledAckBaseline(daemon, owed: 0)
    await daemon.retractNextPublications()

    let (result, complete) = await client.withDeferredPublication {
        try await client.request(.getAttr(getattr))
    }
    // The reissue converged, so the caller gets a value rather than an errno.
    _ = try result.get()

    // The daemon's handoff gate is released for EVERY attempt: retraction is
    // about what the FRAMEWORK installs, not about the daemon's bookkeeping.
    // The retracted attempt's ack was sent before the reissue began, so the
    // reissue could not queue behind the handoff waiting for it.
    await complete()
    let stats = try await waitForTransportPublicationAcks(daemon, atLeast: baseline + 2)
    #expect(stats.publicationAcks == baseline + 2)

    // The connection is unaffected — a retraction is the daemon speaking on a
    // healthy connection, not a transport failure.
    _ = try await client.request(.statfs(PfsStatfsRequest()))
}

@Test func retractedPublicationBoundaryIsReissuedAndBothAttemptsAcknowledged() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")
    var getattr = PfsGetAttrRequest()
    getattr.item = resolved.root

    // Nothing before this point publishes, so no ack can be in flight — but
    // say so exactly rather than assuming it.
    let baseline = try await settledAckBaseline(daemon, owed: 0)
    await daemon.retractNextPublications()

    _ = try await client.withPublicationBoundary {
        try await client.request(.getAttr(getattr))
    }

    let stats = try await waitForTransportPublicationAcks(daemon, atLeast: baseline + 2)
    #expect(stats.publicationAcks == baseline + 2)
}

/// A retraction condemns the whole logical operation, not just the reply that
/// carried the bit. The framework installs a callback's result as one unit, so
/// an earlier reply that was individually fine cannot be published on its own.
///
/// Here EVERY attempt is retracted, which is what makes the two halves of the
/// contract visible at once: the reissue is bounded, and a retraction that
/// never stops still reaches the caller as one verdict for the operation rather
/// than as an incidental per-request errno.
@Test func retractionOnLaterReplyCondemnsTheWholeOperationAndReissueIsBounded() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")
    var getattr = PfsGetAttrRequest()
    getattr.item = resolved.root

    // Nothing before this point publishes, so no ack can be in flight — but
    // say so exactly rather than assuming it.
    let baseline = try await settledAckBaseline(daemon, owed: 0)

    let (result, complete) = await client.withDeferredPublication {
        _ = try await client.request(.getAttr(getattr))
        // The handoff crosses here: the first reply is already in hand and
        // uncondemned, and only the parked continuation carries the verdict.
        // Re-arming on every attempt models a mount that keeps crossing.
        await daemon.retractNextPublications()
        return try await client.request(.getAttr(getattr))
    }
    do {
        _ = try result.get()
        Issue.record("expected a late retraction to condemn the whole operation")
    } catch let error as PfsLocalClientError {
        #expect(error == .publicationRetracted)
    }

    await complete()
    // Both requests of an attempt share one operation ID, so each ATTEMPT owes
    // exactly one acknowledgement — and every attempt made is acknowledged.
    let attempts = PfsLocalClient.publicationRetractionReissueLimit
    let stats = try await waitForTransportPublicationAcks(daemon, atLeast: baseline + attempts)
    #expect(stats.publicationAcks == baseline + attempts)
}

@Test func retractionCarriedOnRefusedRequestWithholdsValuesAndLeavesNoMutation() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")

    var create = PfsCreateRequest()
    create.dir = resolved.root
    create.name = transportBytes("doomed")
    create.mode = 0o644
    _ = try await client.request(.create(create))

    var getattr = PfsGetAttrRequest()
    getattr.item = resolved.root
    var remove = PfsRemoveRequest()
    remove.dir = resolved.root
    remove.name = transportBytes("doomed")

    // `create` is itself a publishing operation and owes an ack of its own,
    // which may still be in flight at this point.
    let baseline = try await settledAckBaseline(daemon, owed: 1)

    let (result, complete) = await client.withDeferredPublication {
        // A first reply binds the operation and arrives uncondemned.
        _ = try await client.request(.getAttr(getattr))
        // The handoff crosses. The unlink is the parked request, and the
        // daemon answers it without executing it.
        await daemon.refuseNextPublicationsAsRetracted()
        return try await client.request(.remove(remove))
    }
    do {
        _ = try result.get()
        Issue.record("expected a refused-and-retracted operation to withhold its result")
    } catch let error as PfsLocalClientError {
        // The collector's verdict wins over the refusal's own errno, so the
        // caller sees one retraction for the operation. Re-arming the refusal
        // on every attempt means the reissue can never converge, so the bound
        // is what ends it — and this is the ONLY way the caller sees a
        // retraction at all now.
        #expect(error == .publicationRetracted)
        #expect(error.posixErrno == EINTR)
    }
    await complete()

    // Every attempt is acknowledged; none of them mutated anything.
    let attempts = PfsLocalClient.publicationRetractionReissueLimit
    let stats = try await waitForTransportPublicationAcks(daemon, atLeast: baseline + attempts)
    #expect(stats.publicationAcks == baseline + attempts)

    // The name is still there: the refusal executed no mutation, so the
    // retried syscall will find exactly the state it started from.
    var lookup = PfsLookupRequest()
    lookup.dir = resolved.root
    lookup.name = transportBytes("doomed")
    let survivor = try await client.request(.lookup(lookup))
    guard case .lookupReply? = survivor.body else {
        Issue.record("expected the retracted unlink to have left its target in place")
        return
    }
}

@Test func unretractedPublicationOperationDeliversValuesAndAcknowledges() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")
    var getattr = PfsGetAttrRequest()
    getattr.item = resolved.root

    // Nothing before this point publishes, so no ack can be in flight — but
    // say so exactly rather than assuming it.
    let baseline = try await settledAckBaseline(daemon, owed: 0)

    let (result, complete) = await client.withDeferredPublication {
        try await client.request(.getAttr(getattr))
    }
    let envelope = try result.get()
    guard case let .getAttrReply(reply)? = envelope.body else {
        Issue.record("expected getAttrReply body, got \(String(describing: envelope.body))")
        return
    }
    #expect(reply.attr.item.itemID == resolved.root.itemID)

    await complete()
    let stats = try await waitForTransportPublicationAcks(daemon, atLeast: baseline + 1)
    #expect(stats.publicationAcks == baseline + 1)

    // And the boundary form is equally unaffected.
    _ = try await client.withPublicationBoundary {
        try await client.request(.getAttr(getattr))
    }
    let afterBoundary = try await waitForTransportPublicationAcks(daemon, atLeast: baseline + 2)
    #expect(afterBoundary.publicationAcks == baseline + 2)
}

private func nextEvent(from stream: AsyncStream<PfsEvent>) async throws -> PfsEvent {
    try await withThrowingTaskGroup(of: PfsEvent?.self) { group in
        group.addTask {
            for await event in stream {
                return event
            }
            return nil
        }
        group.addTask {
            try await Task.sleep(nanoseconds: 1_000_000_000)
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

private final class PfsRawServer: @unchecked Sendable {
    let socketPath: String
    private let serverFD: Int32
    private let queue = DispatchQueue(label: "dev.portablefs.tests.rawserver", qos: .utility)
    private let group = DispatchGroup()
    private var stopped = false

    init(onClient: @escaping @Sendable (Int32) -> Void) throws {
        socketPath = "/tmp/pfs-raw-\(UUID().uuidString.prefix(12)).sock"
        serverFD = try PfsUnixSocket.bindAndListen(path: socketPath)
        group.enter()
        queue.async { [serverFD, weak self] in
            defer {
                self?.group.leave()
            }
            do {
                let fd = try PfsUnixSocket.accept(serverFD)
                if self?.stopped == true {
                    PfsUnixSocket.close(fd)
                    return
                }
                onClient(fd)
                PfsUnixSocket.close(fd)
            } catch {
                if self?.stopped != true {}
            }
        }
    }

    func stop() {
        stopped = true
        if let wakeFD = try? PfsUnixSocket.connect(path: socketPath) {
            PfsUnixSocket.close(wakeFD)
        }
        _ = group.wait(timeout: .now() + 2)
        Darwin.shutdown(serverFD, SHUT_RDWR)
        PfsUnixSocket.close(serverFD)
        unlink(socketPath)
    }

    static func sendAll(fd: Int32, data: Data) throws {
        var noSigPipe: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else {
                return
            }
            var offset = 0
            while offset < data.count {
                let sent = Darwin.send(fd, base.advanced(by: offset), data.count - offset, 0)
                if sent > 0 {
                    offset += sent
                    continue
                }
                if sent == 0 {
                    throw PfsLocalClientError.connectionClosed
                }
                if Darwin.errno == EINTR {
                    continue
                }
                throw PfsLocalClientError.system(errno: Darwin.errno, operation: "send")
            }
        }
    }

    static func recvSome(fd: Int32) throws -> Data {
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = buffer.withUnsafeMutableBytes { rawBuffer in
                Darwin.recv(fd, rawBuffer.baseAddress, rawBuffer.count, 0)
            }
            if count > 0 {
                return Data(buffer.prefix(count))
            }
            if count == 0 {
                throw PfsLocalClientError.connectionClosed
            }
            if Darwin.errno == EINTR {
                continue
            }
            throw PfsLocalClientError.system(errno: Darwin.errno, operation: "recv")
        }
    }
}
