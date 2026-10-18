import Foundation
import Testing
@testable import PortableFSKit
@testable import PortableFSKitMockDaemon
@preconcurrency import Darwin

private func transportBytes(_ string: String) -> Data {
    Data(string.utf8)
}

/// Re-decodes `envelope` with field 4 set: the deleted publication-retraction
/// bit, which a pfslocal 2.0 decoder retains only as an unknown field.
private func appendingUnknownEnvelopeField(_ envelope: PfsEnvelope) -> PfsEnvelope? {
    guard var bytes = try? envelope.serializedData() else { return nil }
    bytes.append(contentsOf: [0x20, 0x01])
    return try? PfsEnvelope(serializedBytes: bytes)
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

/// Each deadline stays suspended until the test expires that request ID.
/// AsyncStream cancellation retires successful setup requests' waits, even
/// when their detached timer tasks start after the reply has arrived.
private actor PfsTestRequestDeadlines {
    private struct Wait {
        let nanoseconds: UInt64
        let continuation: AsyncStream<Void>.Continuation
    }
    private var waits: [UInt64: Wait] = [:]
    private var observers: [UInt64: CheckedContinuation<Void, Never>] = [:]

    func sleep(requestID: UInt64, nanoseconds: UInt64) async throws {
        try Task.checkCancellation()
        let (stream, continuation) = AsyncStream<Void>.makeStream()
        waits[requestID] = Wait(nanoseconds: nanoseconds, continuation: continuation)
        observers.removeValue(forKey: requestID)?.resume()
        for await _ in stream { break }
        waits.removeValue(forKey: requestID)
        try Task.checkCancellation()
    }

    func expire(_ requestID: UInt64) async throws -> UInt64 {
        if waits[requestID] == nil {
            await withCheckedContinuation { observers[requestID] = $0 }
        }
        let wait = try #require(waits[requestID])
        wait.continuation.yield(())
        wait.continuation.finish()
        return wait.nanoseconds
    }
}

private actor PfsTestHeldReply {
    private let releaseGate = PfsTestAsyncGate()
    private var reply: PfsEnvelope?
    private var observer: CheckedContinuation<PfsEnvelope, Never>?

    func hold(_ reply: PfsEnvelope) async {
        self.reply = reply
        observer?.resume(returning: reply)
        observer = nil
        await releaseGate.wait()
    }

    func waitUntilHeld() async -> PfsEnvelope {
        if let reply { return reply }
        return await withCheckedContinuation { observer = $0 }
    }

    func release() async { await releaseGate.release() }
}

extension PfsLocalMockDaemonTests {
@Test func mockDaemonReleaseStopsAndJoinsItsRuntimeWithoutExplicitStop() throws {
    for _ in 0..<64 {
        weak var daemonReference: PfsLocalMockDaemon?
        var socketPath = ""
        var socketDirectory = ""
        var peerFD: Int32?
        do {
            let daemon = try PfsLocalMockDaemon()
            daemonReference = daemon
            socketPath = daemon.socketPath
            socketDirectory = (socketPath as NSString).deletingLastPathComponent
            peerFD = try PfsUnixSocket.connect(path: socketPath)
        }
        if let peerFD {
            PfsUnixSocket.close(peerFD)
        }

        try #require(daemonReference == nil)
        var status = stat()
        #expect(Darwin.lstat(socketPath, &status) != 0 && errno == ENOENT)
        #expect(Darwin.lstat(socketDirectory, &status) != 0 && errno == ENOENT)
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
    // After the one Hello and Resolve, repeated Statfs frames are
    // side-effect-free and each has a definite reply, so the pending-response
    // observation below proves the writer is blocked without relying on a
    // guessed Darwin buffer capacity.
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
        var envelope = PfsEnvelope()
        envelope.requestID = UInt64(requestID)
        switch requestID {
        case 1:
            var hello = PfsHello()
            hello.protocolMajor = PfsLocalClient.protocolMajor
            hello.protocolMinor = PfsLocalClient.protocolMinor
            hello.clientName = "backpressure-owner"
            hello.clientVersion = "1"
            envelope.body = .hello(hello)
        case 2:
            var resolve = PfsResolveRequest()
            resolve.attachRef = "mock"
            envelope.body = .resolve(resolve)
        default:
            envelope.body = .statfs(PfsStatfsRequest())
        }
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

    let deadlines = PfsTestRequestDeadlines()
    var configuration = PfsLocalClient.Configuration(
        maxConnectAttempts: 1, handshakeDeadlineNanoseconds: 1_000_000_000
    )
    configuration.requestDeadlineSleep = { try await deadlines.sleep(requestID: $0, nanoseconds: $1) }
    let client = PfsLocalClient(socketPath: server.socketPath, configuration: configuration)

    do {
        _ = try await client.resolve(attachRef: "mock")
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

    let deadlines = PfsTestRequestDeadlines()
    var configuration = PfsLocalClient.Configuration(
        maxFrameLength: 4096, maxConnectAttempts: 1, handshakeDeadlineNanoseconds: 1_000_000_000
    )
    configuration.requestDeadlineSleep = { try await deadlines.sleep(requestID: $0, nanoseconds: $1) }
    let client = PfsLocalClient(socketPath: server.socketPath, configuration: configuration)

    do {
        _ = try await client.resolve(attachRef: "mock")
        Issue.record("expected oversized frame to fail")
    } catch let error as PfsLocalClientError {
        #expect(error == .frameTooLarge(length: 4097, max: 4096))
    }
}

@Test func requestTimesOutAndClearsPendingEntry() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(
        requestDeadlineMilliseconds: 50
    ))
    defer { daemon.stop() }

    let deadlines = PfsTestRequestDeadlines()
    var configuration = PfsLocalClient.Configuration()
    configuration.requestDeadlineSleep = { try await deadlines.sleep(requestID: $0, nanoseconds: $1) }
    let client = PfsLocalClient(socketPath: daemon.socketPath, configuration: configuration)
    let resolved = try await client.resolve(attachRef: "mock")

    let heldReply = PfsTestHeldReply()
    await daemon.holdNextReply { await heldReply.hold($0) }

    var request = PfsLookupRequest()
    request.dir = resolved.root
    request.name = transportBytes("hung")

    let lookup = Task { try await client.request(.lookup(request)) }
    let reply = await heldReply.waitUntilHeld()
    #expect(await client.testingPendingRequestCount() == 1)
    #expect(try await deadlines.expire(reply.requestID) == 50_000_000)
    let outcome = await lookup.result
    await heldReply.release()

    do {
        _ = try outcome.get()
        Issue.record("expected lookup timeout")
    } catch let error as PfsLocalClientError {
        #expect(error == .timeout)
    }

    #expect(await client.testingPendingRequestCount() == 0)
    // The late reply and this per-request timeout leave the session usable.
    _ = try await client.request(.statfs(PfsStatfsRequest()))
}

@Test func requestCancellationResumesPromptlyAndClearsPendingEntry() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let deadlines = PfsTestRequestDeadlines()
    var configuration = PfsLocalClient.Configuration()
    configuration.requestDeadlineSleep = { try await deadlines.sleep(requestID: $0, nanoseconds: $1) }
    let client = PfsLocalClient(socketPath: daemon.socketPath, configuration: configuration)
    let resolved = try await client.resolve(attachRef: "mock")

    let heldReply = PfsTestHeldReply()
    await daemon.holdNextReply { await heldReply.hold($0) }
    var request = PfsLookupRequest()
    request.dir = resolved.root
    request.name = transportBytes("hung")

    let lookup = Task {
        try await client.request(.lookup(request))
    }
    _ = await heldReply.waitUntilHeld()
    #expect(await client.testingPendingRequestCount() == 1)
    lookup.cancel()

    // Cancellation must complete while both the reply and deadline are held.
    let outcome = await lookup.result
    await heldReply.release()

    do {
        _ = try outcome.get()
        Issue.record("expected cancellation")
    } catch let error as PfsLocalClientError {
        #expect(error == .cancelled)
    }

    #expect(await client.testingPendingRequestCount() == 0)
}

/// FSKit cancels one operation's task when its initiating process is
/// interrupted or dies mid-syscall — a burst of short-lived processes (`git
/// init` copying hook templates) produces this routinely. The cost must be
/// exactly one operation: closing the bound connection would strand every
/// other in-flight operation's publication and end the whole session.
@Test func requestCancellationLeavesTheBoundConnectionAndItsPublicationsIntact() async throws {
    let daemon = try PfsLocalMockDaemon(
        configuration: .init(lookupNoReplyNames: ["hung"])
    )
    defer { daemon.stop() }

    let client = PfsLocalClient(socketPath: daemon.socketPath)
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

    // A bound client never reconnects, so a follow-up request that reaches
    // the daemon proves the exact connection survived.
    var followUp = PfsLookupRequest()
    followUp.dir = resolved.root
    followUp.name = transportBytes("present-after-cancel")
    do {
        _ = try await client.request(.lookup(followUp))
    } catch let error as PfsLocalClientError {
        guard case .daemon = error else {
            Issue.record("the bound connection did not survive a single cancelled request: \(error)")
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

/// The daemon's request deadline is the point at which the exact mutation
/// outcome is no longer recoverable. That ends the session: the client
/// returns EIO and closes its connection instead of exposing a retryable
/// timeout while the daemon may still apply the request.
@Test func dispatchedMutationTimeoutEndsTheSessionAsUncertain() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(requestDeadlineMilliseconds: 20))
    defer { daemon.stop() }
    let deadlines = PfsTestRequestDeadlines()
    var configuration = PfsLocalClient.Configuration()
    configuration.requestDeadlineSleep = { try await deadlines.sleep(requestID: $0, nanoseconds: $1) }
    let client = PfsLocalClient(socketPath: daemon.socketPath, configuration: configuration)
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

    let heldReply = PfsTestHeldReply()
    await daemon.holdNextReply { await heldReply.hold($0) }
    var write = PfsWriteRequest()
    write.handle = createReply.handle
    write.data = Data("late".utf8)
    let mutation = Task {
        try await client.withPublicationBoundary {
            try await client.request(.write(write))
        }
    }
    let reply = await heldReply.waitUntilHeld()
    // The daemon has applied the mutation, but its exact outcome remains
    // withheld. Expiry cannot race Resolve, CREATE, dispatch or reply delivery.
    #expect(reply.publicationAckRequired)
    #expect(reply.writeReply.written == 4)
    #expect(await daemon.stats().writeRequests == 1)
    #expect(await client.testingPendingRequestCount() == 1)
    #expect(try await deadlines.expire(reply.requestID) == 20_000_000)
    let outcome = await mutation.result
    await heldReply.release()
    do {
        _ = try outcome.get()
        Issue.record("expected the mutation deadline to end the session")
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
        Issue.record("client reconnected after an uncertain mutation")
    } catch let error as PfsLocalClientError {
        #expect(error == .system(errno: ETIMEDOUT, operation: "ordered mutation outcome deadline"))
    }
}

/// The lane-overtake race, pinned. A publishing request travels the ordinary
/// lane; its operation's acknowledgement travels the priority publication
/// lane, which the writer dequeues first. An immediate cancellation once let
/// the acknowledgement reach the daemon before the request that creates the
/// operation, and the daemon rightly closed the whole connection. The mock
/// daemon keeps the real reader's obligation ledger, so any recurrence kills
/// the connection and fails the follow-up below.
@Test func immediateCancellationNeverLetsTheAckOvertakeItsRequest() async throws {
    let daemon = try PfsLocalMockDaemon(
        configuration: .init(lookupNoReplyNames: ["hung"])
    )
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
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
    // ledger before the follow-up probe.
    try await Task.sleep(nanoseconds: 100_000_000)

    var followUp = PfsLookupRequest()
    followUp.dir = resolved.root
    followUp.name = transportBytes("alive-after-storm")
    do {
        _ = try await client.request(.lookup(followUp))
    } catch let error as PfsLocalClientError {
        guard case .daemon = error else {
            Issue.record("an immediately-cancelled request cost the bound connection: \(error)")
            return
        }
    }
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

/// PublicationAck is also a one-way serial-reader transition. A subsequent
/// ordinary reply is therefore an exact acknowledgement barrier, not a timing
/// hint. Suspending the ack makes the former detached-dispatch model allow
/// Statfs to reply while the operation was still unacknowledged.
@Test func publicationAckPrecedesFollowingOrdinaryReply() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")
    await daemon.delayNextPublicationAck(nanoseconds: 250_000_000)

    var getattr = PfsGetAttrRequest()
    getattr.item = resolved.root
    _ = try await client.withPublicationBoundary {
        try await client.request(.getAttr(getattr))
    }
    _ = try await client.request(.statfs(PfsStatfsRequest()))

    #expect(await daemon.stats().publicationAcks == 1)
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

@Test func publicationAckCarriesTheExactCallbackSemanticCommit() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")
    var getattr = PfsGetAttrRequest()
    getattr.item = resolved.root

    _ = try await client.withPublicationBoundary {
        try await client.request(.getAttr(getattr))
    }
    var stats = try await waitForTransportPublicationAcks(daemon, atLeast: 1)
    #expect(stats.publishedPublicationAcks == 1)
    #expect(stats.notPublishedPublicationAcks == 0)

    let (result, complete) = await client.withDeferredPublication {
        _ = try await client.request(.getAttr(getattr))
        throw PfsLocalClientError.cancelled
    }
    #expect(throws: PfsLocalClientError.cancelled) {
        try result.get()
    }
    await complete(false)

    stats = try await waitForTransportPublicationAcks(daemon, atLeast: 2)
    #expect(stats.publishedPublicationAcks == 1)
    #expect(stats.notPublishedPublicationAcks == 1)
}

/// pfslocal 2.0 is an exact grammar. A reply carrying a field this build does
/// not know (here the deleted publication-retraction bit) is a frame defect:
/// no value it carried reaches the caller, every other request in flight fails
/// with the same defect, and the session ends without reconnecting.
@Test func unknownEnvelopeFieldIsAFrameDefectThatEndsTheSession() async throws {
    let daemon = try PfsLocalMockDaemon(
        configuration: .init(lookupNoReplyNames: ["parked"])
    )
    defer { daemon.stop() }

    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")
    let baseline = try await settledAckBaseline(daemon, owed: 0)
    let baselineGetattrs = await daemon.stats().getAttrRequests

    var parkedLookup = PfsLookupRequest()
    parkedLookup.dir = resolved.root
    parkedLookup.name = transportBytes("parked")
    let parked = Task {
        try await client.request(.lookup(parkedLookup))
    }
    for _ in 0..<1_000 {
        if await daemon.stats().lookupRequests == 1 { break }
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    #expect(await daemon.stats().lookupRequests == 1)

    await daemon.transformNextReply { envelope in
        guard case .getAttrReply? = envelope.body else { return nil }
        return appendingUnknownEnvelopeField(envelope)
    }
    var getattr = PfsGetAttrRequest()
    getattr.item = resolved.root
    let (result, complete) = await client.withDeferredPublication {
        try await client.request(.getAttr(getattr))
    }
    do {
        _ = try result.get()
        Issue.record("a reply with an unknown field delivered its values")
    } catch let error as PfsLocalClientError {
        guard case .invalidFrame = error else {
            Issue.record("expected a frame defect, got \(error)")
            return
        }
    }
    await complete(false)
    #expect(await daemon.stats().getAttrRequests == baselineGetattrs + 1)

    do {
        _ = try await parked.value
        Issue.record("a request on the retired connection completed")
    } catch let error as PfsLocalClientError {
        guard case .invalidFrame = error else {
            Issue.record("expected the parked request to fail with the defect, got \(error)")
            return
        }
    }
    // The client is terminal: a later request reports the same defect
    // without connecting again.
    let hellosBeforeFollowUp = await daemon.stats().helloRequests
    do {
        _ = try await client.request(.statfs(PfsStatfsRequest()))
        Issue.record("a terminal client sent another request")
    } catch let error as PfsLocalClientError {
        guard case .invalidFrame = error else {
            Issue.record("expected the original defect after termination, got \(error)")
            return
        }
    }
    #expect(await daemon.stats().helloRequests == hellosBeforeFollowUp)
    #expect(await daemon.stats().getAttrRequests == baselineGetattrs + 1)
    #expect(await daemon.stats().publicationAcks == baseline)
}

/// Unknown fields are refused at every depth, not only on the envelope. A
/// nested deleted field (the old Capabilities.symlinks boolean) inside an
/// otherwise valid ResolveReply is as foreign as a top-level one.
@Test func nestedUnknownFieldIsAFrameDefect() throws {
    var capabilities = try PfsCapabilities(serializedBytes: Data([0x08, 0x01]))
    capabilities.maxNameBytes = 255
    var reply = PfsResolveReply()
    reply.capabilities = capabilities
    var envelope = PfsEnvelope()
    envelope.requestID = 2
    envelope.body = .resolveReply(reply)
    let frame = try PfsFrameCodec().encode(envelope)

    var decoder = PfsFrameDecoder()
    #expect(throws: PfsLocalClientError.invalidFrame("envelope carries a field outside pfslocal 2.0")) {
        _ = try decoder.append(frame)
    }

    var clean = envelope
    clean.resolveReply.capabilities = {
        var known = PfsCapabilities()
        known.maxNameBytes = 255
        return known
    }()
    var cleanDecoder = PfsFrameDecoder()
    #expect(try cleanDecoder.append(try PfsFrameCodec().encode(clean)) == [clean])
}

/// Every client is pre-Resolve when it first connects, so a protocol defect
/// during Hello must be terminal on its own terms. Connection backoff exists
/// for failures to reach the daemon, not for a peer's malformed answer:
/// retrying would consume the defect and hide it behind a later success.
@Test func protocolDefectDuringHelloIsTerminalAndNeverRetried() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    await daemon.transformNextReply { envelope in
        guard case .helloReply? = envelope.body else { return nil }
        return appendingUnknownEnvelopeField(envelope)
    }
    let client = PfsLocalClient(
        socketPath: daemon.socketPath,
        configuration: .init(maxConnectAttempts: 5, connectRetryBaseDelayNanoseconds: 1_000_000)
    )

    for _ in 0..<2 {
        do {
            _ = try await client.resolve(attachRef: "mock")
            Issue.record("a client resolved after a defective HelloReply")
        } catch let error as PfsLocalClientError {
            guard case .invalidFrame = error else {
                Issue.record("expected the original frame defect, got \(error)")
                return
            }
        }
    }
    #expect(await daemon.stats().helloRequests == 1)
}

/// pfslocal is paired by exact major and minor. Any other HelloReply version
/// is the daemon's definite answer, not a connection failure, so it surfaces
/// after exactly one handshake, in either number and in either direction.
@Test func helloVersionMismatchIsNotRetried() async throws {
    for (major, minor) in [(UInt32(2), UInt32(1)), (1, 0), (3, 0)] {
        let daemon = try PfsLocalMockDaemon()
        defer { daemon.stop() }
        await daemon.transformNextReply { envelope in
            guard case var .helloReply(reply)? = envelope.body else { return nil }
            reply.protocolMajor = major
            reply.protocolMinor = minor
            var changed = envelope
            changed.body = .helloReply(reply)
            return changed
        }
        let client = PfsLocalClient(
            socketPath: daemon.socketPath,
            configuration: .init(maxConnectAttempts: 5, connectRetryBaseDelayNanoseconds: 1_000_000)
        )
        await #expect(throws: PfsLocalClientError.protocolMismatch(major: major, minor: minor)) {
            _ = try await client.resolve(attachRef: "mock")
        }
        #expect(await daemon.stats().helloRequests == 1)
    }
}

/// The request deadline is required and positive. A zero has no meaning and
/// no local default replaces it: the handshake fails as a protocol defect.
@Test func helloReplyWithoutItsDeadlineIsAProtocolDefect() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    await daemon.transformNextReply { envelope in
        guard case var .helloReply(reply)? = envelope.body else { return nil }
        reply.requestDeadlineMs = 0
        var changed = envelope
        changed.body = .helloReply(reply)
        return changed
    }
    let client = PfsLocalClient(
        socketPath: daemon.socketPath,
        configuration: .init(maxConnectAttempts: 5, connectRetryBaseDelayNanoseconds: 1_000_000)
    )
    await #expect(throws: PfsLocalClientError.invalidFrame("HelloReply omitted its required request deadline")) {
        _ = try await client.resolve(attachRef: "mock")
    }
    #expect(await daemon.stats().helloRequests == 1)
}

/// Every filesystem request and the event binding follow the one Resolve.
/// The client refuses them locally before sending anything, and a connection
/// resolves exactly once.
@Test func requestsBeforeResolveAndASecondResolveAreRefusedLocally() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)

    await #expect(throws: PfsLocalClientError.unresolved) {
        _ = try await client.request(.statfs(PfsStatfsRequest()))
    }
    await #expect(throws: PfsLocalClientError.unresolved) {
        _ = try await client.subscribeEvents()
    }
    #expect(await daemon.stats().helloRequests == 1)

    // A refused Resolve leaves the connection unbound and may be retried.
    await #expect(throws: PfsLocalClientError.daemon(errno: ENOENT, message: "unknown attachRef")) {
        _ = try await client.resolve(attachRef: "not-this-attach")
    }
    let resolved = try await client.resolve(attachRef: "mock")
    #expect(resolved.root.itemID == 1)
    do {
        _ = try await client.resolve(attachRef: "mock")
        Issue.record("a bound connection resolved a second time")
    } catch let error as PfsLocalClientError {
        guard case .unexpectedReply = error else {
            Issue.record("unexpected second-resolve refusal: \(error)")
            return
        }
    }
    _ = try await client.request(.statfs(PfsStatfsRequest()))
    #expect(await daemon.stats().helloRequests == 1)
}

/// Resolve binds the connection to one attach incarnation. Losing it ends
/// the session: in-flight requests fail, the event stream finishes, and no
/// later request reconnects or re-resolves into a successor.
@Test func boundSessionLossIsTerminalWithoutReconnect() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(lookupNoReplyNames: ["parked"]))
    defer { daemon.stop() }
    let client = PfsLocalClient(
        socketPath: daemon.socketPath,
        configuration: .init(maxConnectAttempts: 10, connectRetryBaseDelayNanoseconds: 1_000_000)
    )
    let resolved = try await client.resolve(attachRef: "mock")
    let events = try await client.subscribeEvents()
    let streamEnded = Task {
        for await _ in events {}
        return true
    }
    var lookup = PfsLookupRequest()
    lookup.dir = resolved.root
    lookup.name = transportBytes("parked")
    let parked = Task { try await client.request(.lookup(lookup)) }
    for _ in 0..<1_000 {
        if await daemon.stats().lookupRequests == 1 { break }
        try await Task.sleep(nanoseconds: 1_000_000)
    }

    daemon.dropConnections()
    await #expect(throws: PfsLocalClientError.self) { _ = try await parked.value }
    #expect(await streamEnded.value)
    for _ in 0..<3 {
        await #expect(throws: PfsLocalClientError.connectionClosed) {
            _ = try await client.request(.statfs(PfsStatfsRequest()))
        }
        await #expect(throws: PfsLocalClientError.connectionClosed) {
            _ = try await client.resolve(attachRef: "mock")
        }
    }
    #expect(await daemon.stats().helloRequests == 1)
    #expect(await client.isDetachingOrStopped)
}

/// The event binding is established once on the bound connection and its
/// stream carries attach state in order.
@Test func eventBindingIsSingleAndDeliversAttachStateInOrder() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    _ = try await client.resolve(attachRef: "mock")
    let events = try await client.subscribeEvents()
    do {
        _ = try await client.subscribeEvents()
        Issue.record("a connection accepted a second event binding")
    } catch let error as PfsLocalClientError {
        guard case .unexpectedReply = error else {
            Issue.record("unexpected second-subscribe refusal: \(error)")
            return
        }
    }
    #expect(await daemon.stats().subscribeRequests == 1)

    daemon.emitAttachState(.attached, detail: "first")
    daemon.emitAttachState(.degraded, detail: "second")
    var details: [String] = []
    for await event in events {
        guard case let .attachState(state)? = event.kind else { continue }
        details.append(state.detail)
        if details.count == 2 { break }
    }
    #expect(details == ["first", "second"])
}

@Test func publicationOperationDeliversValuesAndAcknowledgesOnce() async throws {
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

private final class PfsRawServer: @unchecked Sendable {
    let socketPath: String
    private let socketDirectory: String
    private let serverFD: Int32
    private let queue = DispatchQueue(label: "dev.portablefs.tests.rawserver", qos: .utility)
    private let group = DispatchGroup()
    private let stateLock = NSLock()
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
                if self?.isStopped() == true {
                    PfsUnixSocket.close(fd)
                    return
                }
                onClient(fd)
                PfsUnixSocket.close(fd)
            } catch {}
        }
    }

    func stop() {
        stateLock.lock()
        guard !stopped else {
            stateLock.unlock()
            return
        }
        stopped = true
        stateLock.unlock()
        if let wakeFD = try? PfsUnixSocket.connect(path: socketPath) {
            PfsUnixSocket.close(wakeFD)
        }
        _ = group.wait(timeout: .now() + 2)
        Darwin.shutdown(serverFD, SHUT_RDWR)
        PfsUnixSocket.close(serverFD)
        unlink(socketPath)
        rmdir(socketDirectory)
    }

    private func isStopped() -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return stopped
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
}
