import Foundation
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

// ── THE FRONTEND'S HALF OF THE ACKNOWLEDGEMENT CONTRACT ─────────────────────
//
// One FSKit write callback becomes SEVERAL daemon write requests (VolumeCore
// chunks at the volume's preferredIoBytes), and every one of them is separately
// acknowledged: once the daemon answers a WriteReply, those bytes are in the
// mount's stream WAL or at the authority, and the next attach will replay them.
//
// So the count this layer reports back is a statement about durability, and it
// has exactly two truthful shapes:
//
//   * a count in 0...n, meaning "these bytes are committed, the rest were not
//     attempted"; the kernel reissues the remainder as a fresh callback, and
//     whatever is still wrong surfaces there — and at fsync/synchronize/unmount,
//     which are this mount's drain barriers;
//   * an error with NOTHING committed.
//
// It must never report zero-plus-error over bytes that ARE committed. The
// daemon states the identical rule on its own side of the same wire
// (portablefsd/ops.go, attach.write: "The count is committed progress and
// outranks the error ... reporting zero invites a retry that duplicates an
// append"), and the two ends of one wire cannot be allowed to disagree about
// what a partially completed write looks like.
//
// WIRE DISCIPLINE: none of this changes pfslocal. No message, field, or errno
// is added or reinterpreted; what changes is only which of the daemon's
// existing answers this adapter turns into a throw. The protocol minor is
// therefore unchanged.

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

    // Two chunks commit, the third is refused. This is the fence-mid-callback
    // shape: by the time the daemon says EIO, 2 MiB is already durable. The
    // refusal is placed POSITIONALLY at write request 2 so chunks 0 and 1 reach
    // the mock untouched and really are committed before it fires.
    let buffer = payload(3 * chunkBytes, seed: 0x11)
    await daemon.failWrite(atIndex: 2, errno: EIO)

    let result = try await core.write(item: file.item, offset: 0, data: buffer)

    #expect(
        result.written == UInt32(2 * chunkBytes),
        """
        A write callback whose third chunk failed reported \(result.written) bytes. \
        Two chunks (\(2 * chunkBytes) bytes) were acknowledged by the daemon and are \
        in the mount's WAL. Throwing here tells the kernel that NOTHING was written \
        about bytes that are on media — the exact disagreement between the two ends \
        of one wire that turns a retried append into a duplicate.
        """
    )

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
