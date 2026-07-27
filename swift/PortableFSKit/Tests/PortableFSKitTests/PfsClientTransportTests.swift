import Foundation
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

private func transportBytes(_ string: String) -> Data {
    Data(string.utf8)
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
