import Foundation
import Testing
@testable import PortableFSKit
@testable import PortableFSKitMockDaemon
@preconcurrency import Darwin

private func transportBytes(_ string: String) -> Data {
    Data(string.utf8)
}

private func writeRawTransportFrame(fd: Int32, envelope: PfsEnvelope) throws {
    let frame = try PfsFrameCodec().encode(envelope)
    try frame.withUnsafeBytes { rawBuffer in
        guard let baseAddress = rawBuffer.baseAddress else {
            return
        }
        var offset = 0
        while offset < frame.count {
            let written = Darwin.send(
                fd,
                baseAddress.advanced(by: offset),
                frame.count - offset,
                0
            )
            if written > 0 {
                offset += written
                continue
            }
            if written < 0, errno == EINTR {
                continue
            }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }
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

@Test func mockDaemonUsesPrivateEphemeralSocketStateAndCleansIt() throws {
    let daemon = try PfsLocalMockDaemon()
    let socketPath = daemon.socketPath
    let directory = (socketPath as NSString).deletingLastPathComponent
    var directoryStatus = stat()
    var socketStatus = stat()
    #expect(Darwin.lstat(directory, &directoryStatus) == 0)
    #expect(directoryStatus.st_mode & S_IFMT == S_IFDIR)
    #expect(directoryStatus.st_mode & 0o777 == 0o700)
    #expect(Darwin.lstat(socketPath, &socketStatus) == 0)
    #expect(socketStatus.st_mode & S_IFMT == S_IFSOCK)
    #expect(socketStatus.st_mode & 0o777 == 0o600)

    daemon.stop()

    #expect(Darwin.lstat(socketPath, &socketStatus) != 0 && errno == ENOENT)
    #expect(Darwin.lstat(directory, &directoryStatus) != 0 && errno == ENOENT)
}

@Test func mockDaemonStopOwnsBackpressuredResponseWrites() throws {
    let daemon = try PfsLocalMockDaemon()
    let peerFD = try PfsUnixSocket.connect(path: daemon.socketPath)
    defer { PfsUnixSocket.close(peerFD) }

    // A peer that deliberately does not read creates real socket backpressure.
    // Repeated Hello frames are side-effect-free and each has a definite reply,
    // so the pending-response observation below proves the writer is blocked
    // without relying on a guessed Darwin buffer capacity.
    var receiveBufferBytes: Int32 = 1_024
    #expect(
        setsockopt(
            peerFD,
            SOL_SOCKET,
            SO_RCVBUF,
            &receiveBufferBytes,
            socklen_t(MemoryLayout<Int32>.size)
        ) == 0
    )
    for requestID in 1...4_096 {
        var hello = PfsHello()
        hello.protocolMajor = 1
        hello.protocolMinor = 12
        hello.clientName = "backpressure-owner"
        hello.clientVersion = "1"
        var envelope = PfsEnvelope()
        envelope.requestID = UInt64(requestID)
        envelope.body = .hello(hello)
        try writeRawTransportFrame(fd: peerFD, envelope: envelope)
    }

    let backlogDeadline = ContinuousClock.now + .seconds(2)
    while daemon.testingPendingResponseCount() == 0,
          ContinuousClock.now < backlogDeadline {
        Thread.sleep(forTimeInterval: 0.001)
    }
    #expect(daemon.testingPendingResponseCount() > 0)

    // stop() is the exact ownership boundary: it interrupts the blocking
    // writer, joins every client reader and async handler, then removes the
    // private socket state. There is no timeout or detached cleanup path.
    daemon.stop()
    #expect(daemon.testingPendingResponseCount() == 0)
    var status = stat()
    #expect(Darwin.lstat(daemon.socketPath, &status) != 0 && errno == ENOENT)
}

@Test func mockDaemonStopCancelsAndJoinsDelayedRequestHandlers() async throws {
    let daemon = try PfsLocalMockDaemon(
        configuration: .init(lookupNoReplyNames: ["owned-delay"])
    )
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")

    var request = PfsLookupRequest()
    request.dir = resolved.root
    request.name = transportBytes("owned-delay")
    let delayed = Task {
        try await client.request(.lookup(request))
    }
    let enteredDeadline = ContinuousClock.now + .seconds(2)
    while await daemon.stats().lookupRequests == 0,
          ContinuousClock.now < enteredDeadline {
        try await Task.sleep(for: .milliseconds(1))
    }
    #expect(await daemon.stats().lookupRequests == 1)

    daemon.stop()
    do {
        _ = try await delayed.value
        Issue.record("stopped daemon unexpectedly delivered a delayed reply")
    } catch {
        // The exact error is owned by the client-side socket close race. The
        // invariant under test is that the one-hour mock handler was cancelled
        // and joined before stop returned, not reclassified as a reply.
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

@Test func copiedResourceLeaseCompletesExactlyOnce() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")
    await daemon.resetStats()

    var open = PfsOpenRequest()
    open.item = resolved.root
    open.mode = .read
    let lease = try await client.requestResource(.open(open))
    guard case let .openReply(reply)? = lease.envelope.body else {
        Issue.record("mock open omitted its reply")
        return
    }
    let copiedLease = lease
    lease.acceptHandles()
    await lease.complete(itemsPublished: true)
    await copiedLease.complete(itemsPublished: false)

    for _ in 0..<100 where await daemon.stats().resourceAccepts == 0 {
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    var stats = await daemon.stats()
    #expect(stats.resourceAccepts == 1)
    #expect(stats.resourceAbandons == 0)
    #expect(stats.activeHandles == 1)

    var close = PfsCloseRequest()
    close.handle = reply.handle
    _ = try await client.request(.close(close))
    stats = await daemon.stats()
    #expect(stats.activeHandles == 0)
}

@Test func canceledOpenExplicitlyAbandonsItsLateHandle() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")
    await daemon.delayNextOpen(nanoseconds: 100_000_000)
    await daemon.resetStats()

    var open = PfsOpenRequest()
    open.item = resolved.root
    open.mode = .read
    let request = Task {
        try await client.request(.open(open))
    }
    for _ in 0..<100 where await daemon.stats().openRequests == 0 {
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    request.cancel()
    await #expect(throws: PfsLocalClientError.cancelled) {
        try await request.value
    }
    for _ in 0..<300 where await daemon.stats().resourceAbandons == 0 {
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    let stats = await daemon.stats()
    #expect(stats.resourceAccepts == 0)
    #expect(stats.resourceAbandons == 1)
    #expect(stats.activeHandles == 0)

    // Late resource cleanup is request-scoped; it must not poison the mount.
    _ = try await client.request(.statfs(PfsStatfsRequest()))
}

@available(macOS 26.0, *)
@Test func orderedRequestsStampExactSourcePhaseQueueabilityOnTheWire() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")

    var create = PfsCreateRequest()
    create.dir = resolved.root
    create.name = transportBytes("source-phase-queueability")
    create.mode = 0o644
    create.exclusive = true
    let created = try await client.withPublicationBoundary {
        try await client.request(.create(create))
    }
    guard case let .createReply(createReply)? = created.body else {
        Issue.record("mock create omitted its reply")
        return
    }
    await daemon.resetStats()

    let orderedOnly = PfsMacOSAdmittedCallbackTicket(
        scope: PfsMacOSCallbackScope(selectors: [.orderedMutation])
    )
    var firstWrite = PfsWriteRequest()
    firstWrite.handle = createReply.handle
    firstWrite.data = transportBytes("ordered-only")
    _ = try await PfsMacOSCallbackAdmission.$ticket.withValue(orderedOnly) {
        try await client.withPublicationBoundary {
            try await client.request(.write(firstWrite))
        }
    }

    let mixed = PfsMacOSAdmittedCallbackTicket(
        scope: PfsMacOSCallbackScope(selectors: [.orderedMutation])
    )
    _ = try await PfsMacOSCallbackAdmission.$ticket.withValue(mixed) {
        try await client.withPublicationBoundary {
            // Opening is nonpublishing but still ordinary callback history. The
            // following write must therefore tell the authority not to queue
            // this callback behind a distinct own-source PREPARE.
            var open = PfsOpenRequest()
            open.item = createReply.attr.item
            open.mode = .readWrite
            let opened = try await client.request(.open(open))
            guard case let .openReply(openReply)? = opened.body else {
                throw PfsLocalClientError.unexpectedReply(
                    String(describing: opened.body)
                )
            }
            var write = PfsWriteRequest()
            write.handle = openReply.handle
            write.data = transportBytes("mixed")
            return try await client.request(.write(write))
        }
    }

    let stats = await daemon.stats()
    #expect(stats.openRequests == 1)
    #expect(stats.writeRequests == 2)
    #expect(stats.orderedMutationSourcePhaseQueueable == [true, false])
}

@Test func queueableOrderedRequestWithoutOperationIdentityFailsLocally() throws {
    do {
        try pfsValidateSourcePhaseQueueability(true, operationID: 0)
        Issue.record("queueable request without an operation ID succeeded")
    } catch let error as PfsLocalClientError {
        #expect(error == .invalidFrame(
            "source-phase-queueable ordered mutation requires an operation ID"
        ))
    }
    #expect(throws: Never.self) {
        try pfsValidateSourcePhaseQueueability(false, operationID: 0)
    }
    #expect(throws: Never.self) {
        try pfsValidateSourcePhaseQueueability(true, operationID: 8)
    }
}

@Test func daemonCannotSetRequestOnlySourcePhaseQueueability() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(
        sourcePhaseQueueableOnReplies: true
    ))
    defer { daemon.stop() }
    let client = PfsLocalClient(
        socketPath: daemon.socketPath,
        configuration: .init(maxReconnectAttempts: 1)
    )

    do {
        _ = try await client.resolve(attachRef: "mock")
        Issue.record("client accepted request-only metadata on a daemon reply")
    } catch let error as PfsLocalClientError {
        #expect(error == .invalidFrame(
            "daemon reply/event set request-only source_phase_queueable"
        ))
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

/// FSKit cancels one operation's task when its initiating process is
/// interrupted or dies mid-syscall — a burst of short-lived processes (`git
/// init` copying hook templates) produces this routinely. The cost must be
/// exactly one operation. The old behavior closed the whole connection, which
/// stranded every other in-flight operation's publication, made the daemon
/// treat the disconnect as a kernel-coherence failure, and turned one
/// interrupted process into a permanently fenced mount.
@Test func requestCancellationLeavesTheStrictConnectionAndItsPublicationsIntact() async throws {
    var contract = PfsV3CoherenceContract()
    contract.authorityProtocolMajor = 3
    contract.authorityEpoch = Data(repeating: 0xE1, count: 16)
    contract.sessionID = Data(repeating: 0x51, count: 16)
    contract.cachePolicy = PfsMacOSCachePolicy.synchronousVFSRepairV1.rawValue
    contract.repairBudgetMillis = 2_500
    let daemon = try PfsLocalMockDaemon(
        configuration: .init(lookupNoReplyNames: ["hung"], v3Coherence: contract)
    )
    defer { daemon.stop() }

    let client = PfsLocalClient(
        socketPath: daemon.socketPath,
        configuration: .init(requestDeadlineNanoseconds: 5_000_000_000)
    )
    let resolved = try await client.resolve(attachRef: "mock")

    let hung = Task {
        try await client.withPublicationBoundary {
            var request = PfsLookupRequest()
            request.dir = resolved.root
            request.name = transportBytes("hung")
            return try await client.request(.lookup(request))
        }
    }
    try await Task.sleep(nanoseconds: 20_000_000)
    hung.cancel()
    do {
        _ = try await hung.value
        Issue.record("expected cancellation")
    } catch let error as PfsLocalClientError {
        #expect(error == .cancelled)
    }

    // The cancelled callback's stamped operation is still acknowledged as a
    // whole: the daemon's handoff gate must never wait on a callback that has
    // already given up, and the ack is created by the operation-ID stamp, not
    // by the reply that never came.
    var acks = 0
    for _ in 0..<200 {
        acks = await daemon.stats().publicationAcks
        if acks >= 1 { break }
        try await Task.sleep(nanoseconds: 10_000_000)
    }
    #expect(acks == 1)

    // A strict-v3 client never transparently reconnects, so a follow-up
    // request that reaches the daemon proves the exact connection survived.
    var followUp = PfsLookupRequest()
    followUp.dir = resolved.root
    followUp.name = transportBytes("present-after-cancel")
    do {
        _ = try await client.request(.lookup(followUp))
    } catch let error as PfsLocalClientError {
        guard case .daemon = error else {
            Issue.record("the strict connection did not survive a single cancelled request: \(error)")
            return
        }
    }
}

/// Cancellation after an ordered mutation has crossed the socket cannot be
/// reported as EINTR: the daemon still owns the exact authority request and
/// may commit it. The frontend therefore drains the real result even though
/// the initiating Swift task is cancelled.
@Test func dispatchedMutationCancellationDrainsItsExactOutcome() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let created = try await core.createFile(
        in: root,
        name: transportBytes("cancelled-write"),
        mode: 0o644
    )
    await daemon.resetStats()
    await daemon.delayNextWrite(nanoseconds: 100_000_000)

    let write = Task {
        try await core.write(
            item: created.item,
            offset: 0,
            data: Data("committed".utf8)
        )
    }
    for _ in 0..<200 {
        if await daemon.stats().writeRequests == 1 { break }
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    #expect(await daemon.stats().writeRequests == 1)
    write.cancel()

    let outcome = try await write.value
    #expect(outcome.written == 9)
    #expect(try await core.read(item: created.item, offset: 0, length: 9) == Data("committed".utf8))
    #expect(await daemon.stats().writeRequests == 1)
}

/// A daemon-derived hard deadline is the point at which the exact mutation
/// outcome is no longer recoverable. That is terminal for a strict mount: the
/// client returns EIO and closes the participant instead of exposing a
/// retryable timeout while the daemon may still apply the request.
@Test func dispatchedMutationTimeoutTerminatesStrictMountAsUncertain() async throws {
    var contract = PfsV3CoherenceContract()
    contract.authorityProtocolMajor = 3
    contract.authorityEpoch = Data(repeating: 0xE3, count: 16)
    contract.sessionID = Data(repeating: 0x53, count: 16)
    contract.cachePolicy = PfsMacOSCachePolicy.synchronousVFSRepairV2.rawValue
    contract.repairBudgetMillis = 2_500
    let daemon = try PfsLocalMockDaemon(configuration: .init(v3Coherence: contract))
    defer { daemon.stop() }
    let client = PfsLocalClient(
        socketPath: daemon.socketPath,
        configuration: .init(requestDeadlineNanoseconds: 20_000_000)
    )
    let resolved = try await client.resolve(attachRef: "mock")

    var create = PfsCreateRequest()
    create.dir = resolved.root
    create.name = transportBytes("timed-write")
    create.mode = 0o644
    create.exclusive = true
    let created = try await client.withPublicationBoundary {
        try await client.request(.create(create))
    }
    guard case let .createReply(createReply)? = created.body else {
        Issue.record("mock create omitted its reply")
        return
    }

    await daemon.delayNextWrite(nanoseconds: 100_000_000)
    var write = PfsWriteRequest()
    write.handle = createReply.handle
    write.data = Data("late".utf8)
    do {
        _ = try await client.withPublicationBoundary {
            try await client.request(.write(write))
        }
        Issue.record("expected the strict mutation deadline to terminate the mount")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EIO)
        guard case .system(errno: ETIMEDOUT, operation: "ordered mutation outcome deadline") = error else {
            Issue.record("unexpected terminal mutation error: \(error)")
            return
        }
    }
    #expect(await client.testingPendingRequestCount() == 0)
    do {
        _ = try await client.request(.statfs(PfsStatfsRequest()))
        Issue.record("strict client reconnected after an uncertain mutation")
    } catch let error as PfsLocalClientError {
        #expect(error == .connectionClosed)
    }
}

/// The lane-overtake race, pinned. A publishing request travels the ordinary
/// lane; its operation's acknowledgement travels the priority publication
/// lane, which the writer dequeues first. An immediate cancellation once let
/// the acknowledgement reach the daemon before the request that creates the
/// operation, and the daemon rightly closed the whole strict connection. The
/// mock daemon now keeps the real reader's obligation ledger, so any
/// recurrence kills the connection and fails the follow-up below.
@Test func immediateCancellationNeverLetsTheAckOvertakeItsRequest() async throws {
    var contract = PfsV3CoherenceContract()
    contract.authorityProtocolMajor = 3
    contract.authorityEpoch = Data(repeating: 0xE2, count: 16)
    contract.sessionID = Data(repeating: 0x52, count: 16)
    contract.cachePolicy = PfsMacOSCachePolicy.synchronousVFSRepairV1.rawValue
    contract.repairBudgetMillis = 2_500
    let daemon = try PfsLocalMockDaemon(
        configuration: .init(lookupNoReplyNames: ["hung"], v3Coherence: contract)
    )
    defer { daemon.stop() }
    let client = PfsLocalClient(
        socketPath: daemon.socketPath,
        configuration: .init(requestDeadlineNanoseconds: 5_000_000_000)
    )
    let resolved = try await client.resolve(attachRef: "mock")

    for _ in 0..<25 {
        let hung = Task {
            try await client.withPublicationBoundary {
                var request = PfsLookupRequest()
                request.dir = resolved.root
                request.name = transportBytes("hung")
                return try await client.request(.lookup(request))
            }
        }
        hung.cancel()
        _ = try? await hung.value
    }
    // Give the boundary acknowledgements time to drain through the daemon's
    // ledger before the liveness probe.
    try await Task.sleep(nanoseconds: 100_000_000)

    var followUp = PfsLookupRequest()
    followUp.dir = resolved.root
    followUp.name = transportBytes("alive-after-storm")
    do {
        _ = try await client.request(.lookup(followUp))
    } catch let error as PfsLocalClientError {
        guard case .daemon = error else {
            Issue.record("an immediately-cancelled request cost the strict connection: \(error)")
            return
        }
    }
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
    await complete(false)

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
    await complete(false)

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
    await complete(true)
    let stats = try await waitForTransportPublicationAcks(daemon, atLeast: baseline + 2)
    #expect(stats.publicationAcks == baseline + 2)

    // The connection is unaffected — a retraction is the daemon speaking on a
    // healthy connection, not a transport failure.
    _ = try await client.request(.statfs(PfsStatfsRequest()))
}

/// Retraction creates a fresh logical operation for the transparent retry, but
/// the FSKit framework callback (and therefore its admission ticket) is the
/// same. The barrier must see the surviving attempt's ID; retaining attempt
/// one's already-acknowledged ID lets source COMPLETE pass without awaiting the
/// actual framework publication.
@Test func retractedRetryUpdatesAdmissionTicketToTheSurvivingOperationID() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")
    var getattr = PfsGetAttrRequest()
    getattr.item = resolved.root
    let ticket = PfsMacOSAdmittedCallbackTicket()

    await daemon.retractNextPublications()
    let (result, complete) = await PfsMacOSCallbackAdmission.$ticket.withValue(ticket) {
        await client.withDeferredPublication {
            try await client.request(.getAttr(getattr))
        }
    }
    _ = try result.get()

    // Resolve is nonpublishing, so the retracted attempt owns ID 1 and the
    // surviving retry owns ID 2 on this fresh connection.
    #expect(ticket.currentOperationID() == 2)
    await complete(true)
    let stats = try await waitForTransportPublicationAcks(daemon, atLeast: 2)
    #expect(stats.publicationAcks == 2)
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

    await complete(false)
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
    await complete(false)

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

    await complete(true)
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
    private let socketDirectory: String
    private let serverFD: Int32
    private let queue = DispatchQueue(label: "dev.portablefs.tests.rawserver", qos: .utility)
    private let group = DispatchGroup()
    private var stopped = false

    init(onClient: @escaping @Sendable (Int32) -> Void) throws {
        var template = Array("/tmp/pfs-raw.XXXXXX".utf8CString)
        guard let created = Darwin.mkdtemp(&template) else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let directory = String(cString: created)
        socketDirectory = directory
        socketPath = directory + "/pfs.sock"
        do {
            serverFD = try PfsUnixSocket.bindAndListen(path: socketPath)
            guard Darwin.chmod(socketPath, 0o600) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        } catch {
            unlink(socketPath)
            rmdir(directory)
            throw error
        }
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
        rmdir(socketDirectory)
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
