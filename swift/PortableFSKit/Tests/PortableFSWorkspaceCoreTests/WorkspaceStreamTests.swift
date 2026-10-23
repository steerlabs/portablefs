import Foundation
import Darwin
import Testing
import PortableFSWorkspaceCore
@testable import PortableFSWorkspaceVM

private func writeFragments(_ frame: Data, peer: Int32) async throws {
    var offset = 0
    for chunk in [1, 2, 1] + Array(repeating: 1009, count: frame.count / 1009 + 1) {
        let count = min(chunk, frame.count - offset)
        if count == 0 { break }
        var written = 0
        while written < count {
            let n = frame.withUnsafeBytes { raw -> Int in
                guard let base = raw.baseAddress else { return 0 }
                return Darwin.write(peer, base.advanced(by: offset + written), count - written)
            }
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { throw WorkspaceVMError("socket fixture write: \(errno)") }
            written += n
        }
        offset += count
        if offset <= 4 { try await Task.sleep(for: .milliseconds(2)) }
    }
}

@Test @MainActor func workspaceMaximumLegalStatusCrossesFragmentedActualStream() async throws {
    let envelope = try maximumWorkspaceStatus()
    let frame = try WorkspaceControl.encode(envelope)
    #expect(WorkspaceControl.maxFrame == 1 << 20)
    #expect(frame.count <= WorkspaceControl.maxFrame + 4)
    var fds: [Int32] = [-1, -1]
    try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
    defer { close(fds[0]); close(fds[1]) }
    var noSignal: Int32 = 1
    setsockopt(fds[0], SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
    let stream = try WorkspaceStream(fd: fds[1], label: "workspace.maximum-status", onLost: { _ in })
    defer { stream.close() }
    let peer = fds[0]
    let writer = Task.detached { try await writeFragments(frame, peer: peer) }
    let deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + 5_000_000_000
    let header: Data = try await withCheckedThrowingContinuation { c in
        stream.read(count: 4, deadline: deadline) { c.resume(with: $0) }
    }
    let count = header.reduce(0) { ($0 << 8) | Int($1) }
    let body: Data = try await withCheckedThrowingContinuation { c in
        stream.read(count: count, deadline: deadline) { c.resume(with: $0) }
    }
    #expect(header + body == frame)
    #expect(try WorkspaceControl.decode(header + body) == envelope)
    try await writer.value
}

@Test @MainActor func workspaceActualStreamRejectsBufferOverflow() async throws {
    var fds: [Int32] = [-1, -1]
    try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
    defer { close(fds[0]); close(fds[1]) }
    var noSignal: Int32 = 1
    setsockopt(fds[0], SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
    let peer = fds[0]
    let frame = Data(repeating: 1, count: WorkspaceControl.maxFrame + 5)
    // A read beyond the bound must fail buffering, before delivering any bytes.
    var stream: WorkspaceStream?
    var writer: Task<Void, Never>?
    let reason: String = try await withCheckedThrowingContinuation { c in
        do { stream = try WorkspaceStream(fd: fds[1], label: "workspace.overflow", onLost: { c.resume(returning: $0) }) }
        catch { c.resume(throwing: error) }
        let deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + 5_000_000_000
        stream?.read(count: frame.count, deadline: deadline) { _ in }
        writer = Task.detached { try? await writeFragments(frame, peer: peer) }
    }
    await writer?.value
    #expect(reason == "control input exceeds frame limit")
    _ = stream
}
