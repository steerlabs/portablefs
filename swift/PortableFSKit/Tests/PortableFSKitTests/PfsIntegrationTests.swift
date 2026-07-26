import Foundation
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

private func bytes(_ string: String) -> Data {
    Data(string.utf8)
}

@Test func volumeCoreRoundTripsAgainstMockDaemon() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()

    let created = try await core.createFile(in: root, name: bytes("hello.txt"), mode: 0o644)
    let write = try await core.write(item: created.item, offset: 0, data: bytes("hello"))
    #expect(write.written == 5)
    #expect(try await core.read(item: created.item, offset: 0, length: 5) == bytes("hello"))

    try await core.xattrSet(item: created.item, name: "user.note", value: bytes("note"), createOnly: false, replaceOnly: false)
    #expect(try await core.xattrGet(item: created.item, name: "user.note") == bytes("note"))
    #expect(try await core.xattrList(item: created.item).contains("user.note"))
    try await core.xattrRemove(item: created.item, name: "user.note")

    try await core.rename(
        item: created.item,
        from: root,
        sourceName: bytes("hello.txt"),
        to: root,
        destinationName: bytes("renamed.txt"),
        noReplace: false
    )
    let renamed = try await core.lookup(in: root, name: bytes("renamed.txt"))
    #expect(renamed.attr.size == 5)

    let linkName = try await core.hardLink(item: renamed.item, in: root, name: bytes("renamed.link"))
    #expect(linkName == bytes("renamed.link"))
    let linked = try await core.lookup(in: root, name: linkName)
    #expect(linked.item.identity == renamed.item.identity)
    #expect(linked.attr.nlink == 2)
    try await core.remove(item: renamed.item, named: bytes("renamed.txt"), from: root, isDirectory: false)
    let survivingLink = try await core.lookup(in: root, name: linkName)
    #expect(survivingLink.item.identity == renamed.item.identity)
    #expect(survivingLink.attr.nlink == 1)
    #expect(try await core.read(item: survivingLink.item, offset: 0, length: 5) == bytes("hello"))

    let symlink = try await core.symlink(in: root, name: bytes("sym"), target: linkName)
    #expect(try await core.readlink(item: symlink.item) == linkName)

    var names: [String] = []
    var cookie: UInt64 = 0
    repeat {
        let page = try await core.enumerate(directory: root, startingAt: cookie, wantAttributes: true)
        names.append(contentsOf: page.entries.compactMap { String(data: $0.name, encoding: .utf8) })
        cookie = page.nextCookie
    } while cookie != 0
    #expect(!names.contains("renamed.txt"))
    #expect(names.contains("renamed.link"))
    #expect(names.contains("sym"))

    let stat = try await core.statfs()
    #expect(stat.freeBlocks > 0)

    try await core.reclaim(item: symlink.item)
    do {
        _ = try await core.getattr(item: symlink.item)
        Issue.record("expected reclaimed item to be stale")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == ESTALE)
    }
}

@Test func readWriteChunkingRoundTripsTwentyMiBFile() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: bytes("large.bin"), mode: 0o644)
    await daemon.resetStats()

    let size = 20 * 1024 * 1024
    var payload = Data(count: size)
    payload.withUnsafeMutableBytes { rawBuffer in
        guard let base = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            return
        }
        for index in 0..<size {
            base[index] = UInt8(truncatingIfNeeded: index)
        }
    }

    let written = try await core.write(item: created.item, offset: 0, data: payload)
    #expect(written.written == UInt32(size))
    let readBack = try await core.read(item: created.item, offset: 0, length: UInt32(size))
    #expect(readBack == payload)

    let stats = await daemon.stats()
    #expect(stats.maxWriteLength <= 1_048_576)
    #expect(stats.maxReadLength <= 1_048_576)
}

@Test func volumeCoreGitConfigLockRenameOverRemainsReadable() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let repo = try await core.mkdir(in: root, name: bytes("repo"), mode: 0o755)
    let git = try await core.mkdir(in: repo.item, name: bytes(".git"), mode: 0o755)

    let oldContent = bytes("[core]\n\trepositoryformatversion = 0\n")
    let newContent = bytes("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n")

    let config = try await core.createFile(in: git.item, name: bytes("config"), mode: 0o644, exclusive: true)
    _ = try await core.write(item: config.item, offset: 0, data: oldContent)
    try await core.close(item: config.item)

    let lock = try await core.createFile(in: git.item, name: bytes("config.lock"), mode: 0o644, exclusive: true)
    _ = try await core.write(item: lock.item, offset: 0, data: newContent)
    try await core.close(item: lock.item)

    try await core.rename(
        item: lock.item,
        from: git.item,
        sourceName: bytes("config.lock"),
        to: git.item,
        destinationName: bytes("config"),
        noReplace: false
    )

    let replaced = try await core.lookup(in: git.item, name: bytes("config"))
    try await core.open(item: replaced.item, mode: .read)
    let readBack = try await core.read(item: replaced.item, offset: 0, length: UInt32(newContent.count))
    try await core.close(item: replaced.item)
    #expect(readBack == newContent)
}

@Test func clientMultiplexesOutOfOrderReplies() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(lookupDelaysNanoseconds: ["slow": 200_000_000]))
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    _ = try await core.createFile(in: root, name: bytes("slow"), mode: 0o644)
    _ = try await core.createFile(in: root, name: bytes("fast"), mode: 0o644)

    try await withThrowingTaskGroup(of: String.self) { group in
        group.addTask {
            _ = try await core.lookup(in: root, name: bytes("slow"))
            return "slow"
        }
        group.addTask {
            _ = try await core.lookup(in: root, name: bytes("fast"))
            return "fast"
        }
        let first = try await group.next()
        #expect(first == "fast")
        _ = try await group.next()
    }
}

@Test func connectionDropFailsInflightAndNextOperationReconnects() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(lookupDelaysNanoseconds: ["slow": 500_000_000]))
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(
        socketPath: daemon.socketPath,
        attachRef: "mock",
        configuration: .init(maxReconnectAttempts: 10, reconnectBaseDelayNanoseconds: 5_000_000)
    )
    let root = try await core.rootItem()
    _ = try await core.createFile(in: root, name: bytes("slow"), mode: 0o644)
    _ = try await core.createFile(in: root, name: bytes("fast"), mode: 0o644)

    let slowLookup = Task {
        try await core.lookup(in: root, name: bytes("slow"))
    }
    try await Task.sleep(nanoseconds: 50_000_000)
    daemon.dropConnections()

    do {
        _ = try await slowLookup.value
        Issue.record("expected in-flight lookup to fail on connection drop")
    } catch {
        #expect(PfsErrorMapper.fsKitError(for: error).code == Int(EIO))
    }

    let recovered = try await core.lookup(in: root, name: bytes("fast"))
    #expect(recovered.attr.item.itemID != 0)
}

@Test func eventsAreDeliveredAfterSubscribe() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let stream = try await core.subscribeEvents()
    var iterator = stream.makeAsyncIterator()

    let rootIdentity = await daemon.rootIdentity()
    daemon.emitInvalidation(item: rootIdentity.proto, contentVersion: 7)

    let event = await iterator.next()
    guard case let .invalidation(invalidation)? = event?.kind else {
        Issue.record("expected invalidation event")
        return
    }
    #expect(invalidation.item.itemID == rootIdentity.itemID)
    #expect(invalidation.contentVersion == 7)
}

@Test func detachingAttachStateMakesBoundClientFailWithENXIO() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    _ = try await core.subscribeEvents()

    daemon.emitAttachState(.detaching, detail: "detaching")
    try await Task.sleep(nanoseconds: 50_000_000)

    do {
        _ = try await core.statfs()
        Issue.record("expected detaching attach to fail future operations")
    } catch {
        #expect(PfsErrorMapper.fsKitError(for: error).code == Int(ENXIO))
    }
}

@Test func itemTableDetectsGenerationMismatch() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let stale = await core.testingAdoptItem(identity: PfsItemIdentity(itemID: 99, generation: 1))
    _ = await core.testingAdoptItem(identity: PfsItemIdentity(itemID: 99, generation: 2))

    do {
        _ = try await core.getattr(item: stale)
        Issue.record("expected old generation to be rejected")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == ESTALE)
    }
}
