import Foundation
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

// Each successful chunk reply represents a durable authority mutation. A
// later failure may return that exact prefix; its unacknowledged bytes must
// never contribute to the framework's successful write count.

private func payload(_ count: Int, seed: UInt8) -> Data {
    var data = Data(count: count)
    for index in 0..<count {
        data[index] = seed &+ UInt8(truncatingIfNeeded: index)
    }
    return data
}

/// The mock advertises `preferredIoBytes = 1 MiB`, so a 3 MiB buffer is exactly
/// three daemon write requests inside one `VolumeCore.write`.
private let chunkBytes = 1 << 20

extension PfsLocalMockDaemonTests {
@Test func committedChunksSurviveALaterChunksFailure() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let file = try await core.createFile(in: root, name: Data("flood.bin".utf8), mode: 0o644)

    // The third request is refused after two independently acknowledged chunks.
    let buffer = payload(3 * chunkBytes, seed: 0x11)
    await daemon.failWrite(atIndex: 2, errno: EIO)

    let result = try await core.write(item: file.item, offset: 0, data: buffer)

    #expect(result.written == UInt32(2 * chunkBytes))

    // The bytes the count claims must actually be readable back.
    let readBack = try await core.read(item: file.item, offset: 0, length: UInt32(2 * chunkBytes))
    #expect(readBack == buffer.prefix(2 * chunkBytes))
}

@Test func aWriteThatCommitsNothingStillThrows() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let file = try await core.createFile(in: root, name: Data("refused.bin".utf8), mode: 0o644)

    // The FIRST chunk fails, so nothing is committed and the error is the whole
    // truth. Reporting a short write of zero here would be the other half of the
    // same lie: a successful zero is not a signal any writer loop can act on.
    await daemon.failWrite(atIndex: 0, errno: EIO)

    await #expect(throws: (any Error).self) {
        _ = try await core.write(item: file.item, offset: 0, data: payload(chunkBytes, seed: 0x22))
    }
}

@Test func aShortDaemonCountIsReportedAsAShortWriteNotAsFullSuccess() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let file = try await core.createFile(in: root, name: Data("short.bin".utf8), mode: 0o644)

    // A credit grant covering only a prefix is a healthy, routine outcome under
    // saturation. The count must be the prefix — reporting the full request
    // would advance the application's own offset past bytes nothing admitted,
    // which is precisely how a zero-filled hole appears mid-file.
    let short = chunkBytes / 4
    await daemon.shortenNextWrite(to: short)

    let buffer = payload(2 * chunkBytes, seed: 0x33)
    let result = try await core.write(item: file.item, offset: 0, data: buffer)
    #expect(
        result.written == UInt32(short),
        "a daemon short count of \(short) was reported to the kernel as \(result.written)"
    )
    let readBack = try await core.read(item: file.item, offset: 0, length: UInt32(short) + 16)
    #expect(readBack.count == short)
}
}
