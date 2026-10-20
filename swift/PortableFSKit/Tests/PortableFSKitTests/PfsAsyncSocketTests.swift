import Foundation
import Testing
@testable import PortableFSKit
@preconcurrency import Darwin
@preconcurrency import Dispatch

private final class SocketReceiveLog: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [PfsAsyncSocket.ReceiveEvent] = []
    func append(_ event: PfsAsyncSocket.ReceiveEvent) { lock.withLock { events.append(event) } }
    var all: [PfsAsyncSocket.ReceiveEvent] { lock.withLock { events } }
}

private func socketReceivePair(max: Int = 1024) throws -> (PfsAsyncSocket, Int32, SocketReceiveLog) {
    var fds: [Int32] = [0, 0]
    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw POSIXError(.EIO) }
    let log = SocketReceiveLog()
    let socket = try PfsAsyncSocket(fd: fds[0], maxFrameLength: max, receiveObserver: { log.append($0) })
    var one: Int32 = 1
    setsockopt(fds[1], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    return (socket, fds[1], log)
}

// Blocking fixture writes stay on a Dispatch queue, like the production I/O.
private func socketSend(_ fd: Int32, _ data: Data) async throws {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        DispatchQueue.global().async {
            do {
                try data.withUnsafeBytes { bytes in
                    guard let base = bytes.baseAddress else { return }
                    var offset = 0
                    while offset < bytes.count {
                        let sent = Darwin.send(fd, base.advanced(by: offset), bytes.count - offset, 0)
                        if sent < 0, errno == EINTR { continue }
                        guard sent > 0 else { throw POSIXError(.EIO) }
                        offset += sent
                    }
                }
                continuation.resume()
            } catch { continuation.resume(throwing: error) }
        }
    }
}

private func socketEventually(_ condition: () -> Bool) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(3))
    while !condition() {
        guard ContinuousClock.now < deadline else { throw PfsLocalClientError.timeout }
        try await Task.sleep(for: .milliseconds(1))
    }
}

extension PfsLocalMockDaemonTests {
@Test func asyncSocketCollectsPartialFrameWithOneResumption() async throws {
    let (socket, fd, log) = try socketReceivePair()
    defer { socket.close(); PfsUnixSocket.close(fd) }
    var envelope = PfsEnvelope()
    envelope.requestID = 42
    envelope.body = .statfs(PfsStatfsRequest())
    let frame = try PfsFrameCodec().encode(envelope)
    let receive = Task { try await socket.readFrame() }
    try await socketEventually { log.all == [.readRequested(4)] }
    for byte in frame.prefix(4) { try await socketSend(fd, Data([byte])) }
    try await socketEventually { log.all.contains(.readRequested(frame.count - 4)) }
    #expect(!log.all.contains(.resumed))
    for byte in frame.dropFirst(4).dropLast() { try await socketSend(fd, Data([byte])) }
    #expect(!log.all.contains(.resumed))
    try await socketSend(fd, frame.suffix(1))
    #expect(try await receive.value == envelope)
    #expect(log.all == [.readRequested(4), .readRequested(frame.count - 4), .resumed])
}

@Test func asyncSocketRejectsEOFBeforeHeader() async throws { try await checkInvalidFrame("empty") }
@Test func asyncSocketRejectsEOFMidHeader() async throws { try await checkInvalidFrame("header") }
@Test func asyncSocketRejectsEOFMidPayload() async throws { try await checkInvalidFrame("payload") }
@Test func asyncSocketRejectsOversizedFrameBeforeReadingPayload() async throws { try await checkInvalidFrame("oversized") }
@Test func asyncSocketRejectsUnknownFields() async throws { try await checkInvalidFrame("unknown") }

private func checkInvalidFrame(_ kind: String) async throws {
    let (socket, fd, log) = try socketReceivePair(max: 16)
    defer { socket.close(); PfsUnixSocket.close(fd) }
    let bytes: Data
    switch kind {
    case "empty": bytes = Data()
    case "header": bytes = Data([2, 0])
    case "payload": bytes = Data([2, 0, 0, 0, 8])
    case "oversized": bytes = Data([17, 0, 0, 0])
    default: bytes = Data([2, 0, 0, 0, 0x20, 1])
    }
    try await socketSend(fd, bytes)
    shutdown(fd, SHUT_WR)
    do {
        _ = try await socket.readFrame()
        Issue.record("accepted invalid \(kind) frame")
    } catch let error as PfsLocalClientError {
        switch kind {
        case "empty": #expect(error == .connectionClosed)
        case "oversized": #expect(error == .frameTooLarge(length: 17, max: 16))
        default:
            guard case .invalidFrame = error else { Issue.record("unexpected error \(error)"); return }
        }
    }
    #expect(log.all.filter { $0 == .resumed }.count == 1)
    if kind == "oversized" { #expect(log.all == [.readRequested(4), .resumed]) }
}

@Test func asyncSocketStalledOwnerPreservesOrderingAndBackpressure() async throws {
    let (socket, fd, log) = try socketReceivePair(max: 70_000)
    defer { socket.close(); PfsUnixSocket.close(fd) }
    var envelope = PfsEnvelope()
    envelope.requestID = 1
    var reply = PfsReadReply()
    reply.data = Data(repeating: 7, count: 60_000)
    envelope.body = .readReply(reply)
    let first = Task { try await socket.readFrame() }
    try await socketSend(fd, try PfsFrameCodec(maxFrameLength: 70_000).encode(envelope))
    #expect(try await first.value.requestID == 1)
    // No receive continuation exists while the owner applies the first frame.
    // A nonblocking writer must hit the finite kernel socket buffer.
    #expect(fcntl(fd, F_SETFL, O_NONBLOCK) == 0)
    var queued = Data()
    for id in 2...32 {
        envelope.requestID = UInt64(id)
        queued.append(try PfsFrameCodec(maxFrameLength: 70_000).encode(envelope))
    }
    var sent = 0
    try queued.withUnsafeBytes { bytes in
        let base = try #require(bytes.baseAddress)
        while sent < bytes.count {
            let count = Darwin.send(fd, base.advanced(by: sent), bytes.count - sent, 0)
            if count < 0, errno == EINTR { continue }
            if count < 0, errno == EAGAIN { break }
            try #require(count > 0)
            sent += count
        }
    }
    #expect(sent < queued.count)
    #expect(log.all.filter { $0 == .resumed }.count == 1)
    #expect(log.all.filter { if case .readRequested = $0 { true } else { false } }.count == 2)
    #expect(fcntl(fd, F_SETFL, 0) == 0)
    let remaining = queued.dropFirst(sent)
    let writer = Task { try await socketSend(fd, Data(remaining)) }
    for id in 2...32 { #expect(try await socket.readFrame().requestID == UInt64(id)) }
    try await writer.value
    #expect(log.all.filter { $0 == .resumed }.count == 32)
}
}
