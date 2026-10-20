import Foundation
import FSKit
import Testing
@testable import PortableFSKit
@testable import PortableFSKitMockDaemon
@preconcurrency import Darwin

private actor ReadAcquisitionPause {
    private(set) var entered = false
    private var continuation: CheckedContinuation<Void, Never>?
    func wait() async {
        entered = true
        await withCheckedContinuation { continuation = $0 }
    }
    func release() { continuation?.resume(); continuation = nil }
}

private func acquisitionEventually(_ check: () async -> Bool) async throws {
    let end = ContinuousClock.now.advanced(by: .seconds(5))
    while !(await check()) {
        guard ContinuousClock.now < end else { throw POSIXError(.ETIMEDOUT) }
        try await Task.sleep(for: .milliseconds(2))
    }
}

@available(macOS 27, *)
private struct ReadAcquisitionFixture {
    let daemon: PfsLocalMockDaemon
    let core: VolumeCore
    let volume: PortableFSVolumeV3
    let cache: PfsKernelCache
    let item: PortableFSItem

    init(mode: UInt32 = 0o600, retainCreation: Bool = false) async throws {
        daemon = try PfsLocalMockDaemon()
        core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
        volume = try #require(try await PortableFSVolume.make(core: core, attachRef: "mock") as? PortableFSVolumeV3)
        cache = try #require(volume.kernelCache)
        cache.install { _, _ in nil }
        item = try await core.createFile(in: core.rootItem(), name: Data("acquisition".utf8), mode: mode).item
        if !retainCreation { try await core.close(item: item) }
        cache.proof(try PfsKernelCache.continuousNanos() + 30_000_000_000)
        await daemon.resetStats()
    }

    func open(_ modes: FSVolume.OpenModes? = [.write], _ requested: FSVolume.DataCacheMode = .readWriteWithCache) async throws -> FSVolume.KernelCacheCoherencyType {
        try await withCheckedThrowingContinuation { continuation in
            volume.cacheOpen(item, modes: modes, cacheMode: requested) { grant, error in
                if let error { continuation.resume(throwing: error) }
                else if let grant { continuation.resume(returning: grant) }
                else { continuation.resume(throwing: POSIXError(.EIO)) }
            }
        }
    }

    func finish() async { await volume.shutdown(); daemon.stop() }
}

extension PfsLocalMockDaemonTests {
@available(macOS 27, *)
@Test func cacheReadFreshWriteOnlyUsesOneCombinedOpen() async throws {
    for mode in [UInt32(0o644), 0o600] {
        let f = try await ReadAcquisitionFixture(mode: mode)
        #expect(try await f.open() == .writeThrough)
        let stats = await f.daemon.stats()
        #expect(stats.openModes == [.readWrite])
        #expect(stats.grantedOpenModes == [.readWrite])
        #expect(stats.openItems == [f.item.identity.proto])
        #expect(stats.openAppendFlags == [false])
        #expect(stats.createRequests == 0 && stats.setAttrRequests == 0)
        #expect(await f.core.testingDebugState().openHandleCount == 1)
        // Deferred V3 close retires the combined description only once.
        await withCheckedContinuation { done in f.volume.finalClose(f.item) { done.resume() } }
        #expect(await f.daemon.stats().closeRequests == 1)
        #expect(await f.daemon.stats().activeHandles == 0)
        try await f.core.reclaim(item: f.item)
        #expect(await f.daemon.stats().closeRequests == 1)
        await f.finish()
    }
}

@available(macOS 27, *)
@Test func cacheReadDenialFallsBackOnceWithoutSideEffects() async throws {
    for acl in [false, true] {
        let f = try await ReadAcquisitionFixture(mode: acl ? 0o600 : 0o200)
        if acl { await f.daemon.denyReadOpen(item: f.item.identity, denied: true) }
        #expect(try await f.open() == .noCache)
        for offset in 0..<4 { _ = try await f.core.write(item: f.item, offset: UInt64(offset), data: Data([65])) }
        let stats = await f.daemon.stats()
        #expect(stats.openModes == [.readWrite, .write])
        #expect(stats.grantedOpenModes == [.write])
        #expect(stats.openItems == [f.item.identity.proto, f.item.identity.proto])
        #expect(stats.openAppendFlags == [false, false])
        #expect(stats.readRequests == 0 && stats.createRequests == 0 && stats.setAttrRequests == 0)
        #expect(stats.activeHandles == 1)
        #expect(stats.writeRequests == 4)
        try await f.core.close(item: f.item)
        #expect(await f.daemon.stats().activeHandles == 0)
        await f.finish()
    }
}

@available(macOS 27, *)
@Test func cacheReadDeniedWriteReturnsOriginalWriteError() async throws {
    let f = try await ReadAcquisitionFixture(mode: 0o000)
    // Distinct errors prove the write retry's refusal is the returned cause.
    await f.daemon.failNextOpen(errno: EACCES)
    await f.daemon.failNextOpen(errno: EROFS)
    do { _ = try await f.open(); Issue.record("denied write succeeded") }
    catch { #expect((error as NSError).code == Int(EROFS)) }
    #expect(await f.daemon.stats().openModes == [.readWrite, .write])
    #expect(await f.daemon.stats().activeHandles == 0)
    await f.finish()
}

@available(macOS 27, *)
@Test func cacheReadUpgradePreservesRetainedWriter() async throws {
    for (denied, upgrade) in [(false, false), (false, true), (true, false), (true, true)] {
        let f = try await ReadAcquisitionFixture()
        #expect(try await f.open([.write], .none) == .noCache)
        // The retained writer survives chmod; only the missing read is checked.
        _ = try await f.core.setattr(item: f.item, attributes: PfsSetAttributes(mode: denied ? 0o000 : 0o400))
        #expect(try await f.open(upgrade ? nil : [.write]) == (denied ? .noCache : .writeThrough))
        let stats = await f.daemon.stats()
        #expect(stats.openModes == [.write, .read])
        #expect(stats.grantedOpenModes == (denied ? [.write] : [.write, .read]))
        #expect(stats.closeRequests == 0)
        #expect(stats.activeHandles == (denied ? 1 : 2))
        _ = try await f.core.write(item: f.item, offset: 0, data: Data([66]))
        try await f.core.close(item: f.item)
        #expect(await f.daemon.stats().closeRequests == (denied ? 1 : 2))
        #expect(await f.daemon.stats().activeHandles == 0)
        await f.finish()
    }
}

@available(macOS 27, *)
@Test func cacheReadUpgradeNeverInventsWriteAndCreationNeedsNoOpen() async throws {
    let reader = try await ReadAcquisitionFixture()
    #expect(try await reader.open([.read], .none) == .noCache)
    #expect(try await reader.open(nil) == .readCache)
    #expect(await reader.daemon.stats().openModes == [.read])
    await reader.finish()
    let created = try await ReadAcquisitionFixture(mode: 0o200, retainCreation: true)
    #expect(try await created.open() == .writeThrough)
    #expect(await created.daemon.stats().openModes.isEmpty)
    await created.finish()
}

@available(macOS 27, *)
@Test func cacheReadNonAccessFailuresNeverRetry() async throws {
    for errno in [Int32(EIO), ENOMEM, EMFILE, EPERM] {
        let f = try await ReadAcquisitionFixture()
        await f.daemon.failNextOpen(errno: errno)
        do { _ = try await f.open(); Issue.record("failed optional OPEN succeeded") }
        catch { #expect((error as NSError).code == Int(errno)) }
        #expect(await f.daemon.stats().openModes == [.readWrite])
        #expect(await f.daemon.stats().activeHandles == 0)
        await f.finish()
    }
}

@available(macOS 27, *)
@Test func cacheReadMalformedReplyNeverRetries() async throws {
    let f = try await ReadAcquisitionFixture()
    await f.daemon.omitNextOpenHandle()
    await #expect(throws: (any Error).self) { _ = try await f.open() }
    #expect(await f.daemon.stats().openModes == [.readWrite])
    let client = await f.core.client
    #expect(client.publicationGate.terminalError != nil)
    await f.finish()
}

@available(macOS 27, *)
@Test func cacheReadPublicationRechecksProofAndTerminal() async throws {
    for terminal in [false, true] {
        let f = try await ReadAcquisitionFixture()
        let pause = ReadAcquisitionPause()
        await f.daemon.holdNextReply { _ in await pause.wait() }
        let opening = Task { try await f.open() }
        try await acquisitionEventually { await pause.entered }
        if terminal {
            let client = await f.core.client
            client.publicationGate.revoke(POSIXError(.EIO))
        } else { f.cache.proof(0) }
        await pause.release()
        if terminal { await #expect(throws: (any Error).self) { _ = try await opening.value } }
        else { #expect(try await opening.value == .noCache) }
        #expect(await f.daemon.stats().openModes == [.readWrite])
        await f.finish()
    }
}

@available(macOS 27, *)
@Test func cacheReadTerminalDenialCannotFallback() async throws {
    let f = try await ReadAcquisitionFixture(mode: 0o200)
    let pause = ReadAcquisitionPause()
    let client = await f.core.client
    await client.testingBeforeReceive { frame in
        if case .error? = frame.body { await pause.wait() }
    }
    let opening = Task { try await f.open() }
    try await acquisitionEventually { await pause.entered }
    client.publicationGate.revoke(POSIXError(.EIO))
    await pause.release()
    await #expect(throws: (any Error).self) { _ = try await opening.value }
    #expect(await f.daemon.stats().openModes == [.readWrite])
    await f.finish()
}

@available(macOS 27, *)
@Test func cacheReadTransportLossCannotFallback() async throws {
    let f = try await ReadAcquisitionFixture()
    let pause = ReadAcquisitionPause()
    await f.daemon.holdNextReply { _ in await pause.wait() }
    let opening = Task { try await f.open() }
    try await acquisitionEventually { await pause.entered }
    f.daemon.dropConnections()
    await pause.release()
    await #expect(throws: (any Error).self) { _ = try await opening.value }
    #expect(await f.daemon.stats().openModes == [.readWrite])
    await f.finish()
}

@available(macOS 27, *)
@Test func cacheReadAcquiredRightsSurviveChmodAndACLUntilRetirement() async throws {
    let f = try await ReadAcquisitionFixture()
    #expect(try await f.open() == .writeThrough)
    _ = try await f.core.setattr(item: f.item, attributes: PfsSetAttributes(mode: 0o000))
    await f.daemon.denyReadOpen(item: f.item.identity, denied: true)
    #expect(try await f.open(nil) == .writeThrough)
    #expect(try await f.core.read(item: f.item, offset: 0, length: 1).isEmpty)
    #expect(await f.daemon.stats().openModes == [.readWrite])
    try await f.core.close(item: f.item)
    // New acquisition observes current storage permission rather than old attrs.
    await #expect(throws: (any Error).self) { _ = try await f.open() }
    #expect(await f.daemon.stats().openModes == [.readWrite, .readWrite, .write])
    await f.finish()
}

@available(macOS 27, *)
@Test func cacheReadNoProofDoesNotAcquireAndRepeatedCyclesStayBounded() async throws {
    let f = try await ReadAcquisitionFixture()
    f.cache.proof(0)
    #expect(try await f.open() == .noCache)
    #expect(await f.daemon.stats().openModes == [.write])
    try await f.core.close(item: f.item)
    for _ in 0..<16 {
        f.cache.proof(try PfsKernelCache.continuousNanos() + 30_000_000_000)
        #expect(try await f.open() == .writeThrough)
        #expect(await f.core.testingDebugState().openHandleCount == 1)
        try await f.core.close(item: f.item)
        #expect(await f.daemon.stats().activeHandles == 0)
    }
    #expect(await f.daemon.stats().closeRequests == 17)
    await f.finish()
}

@available(macOS 27, *)
@Test func cacheReadSeparateDescriptionsStayPinnedAfterAliasesUnlinkAndReplacement() async throws {
    let f = try await ReadAcquisitionFixture()
    #expect(try await f.open([.write], .none) == .noCache)
    #expect(try await f.open(nil) == .writeThrough)
    let root = try await f.core.rootItem()
    _ = try await f.core.hardLink(item: f.item, in: root, name: Data("alias".utf8))
    let alias = try await f.core.lookup(in: root, name: Data("alias".utf8))
    #expect(alias.item === f.item)
    let target = try await f.core.createFile(in: root, name: Data("target".utf8), mode: 0o600)
    _ = try await f.core.rename(item: f.item, from: root, sourceName: Data("alias".utf8),
                                to: root, destinationName: Data("target".utf8), noReplace: false)
    // Both replaced and source descriptions remain valid on their old inodes.
    _ = try await f.core.write(item: target.item, offset: 0, data: Data([84]))
    try await f.core.close(item: target.item)
    try await f.core.remove(item: f.item, named: Data("acquisition".utf8), from: root, isDirectory: false)
    try await f.core.remove(item: f.item, named: Data("target".utf8), from: root, isDirectory: false)
    _ = try await f.core.write(item: f.item, offset: 0, data: Data([87]))
    await f.daemon.resetStats()
    f.cache.install { item, transition in
        guard item === f.item, transition.action == .push else { return nil }
        let done = DispatchSemaphore(value: 0)
        Task {
            do {
                try await f.core.close(item: item)
                try await f.core.reclaim(item: item)
                #expect(await f.core.testingDebugState().openHandleCount == 2)
                #expect(await f.daemon.stats().activeHandles == 2)
                #expect(!item.reclaimed)
            } catch { Issue.record("pinned cleanup failed: \(error)") }
            done.signal()
        }
        return done.wait(timeout: .now() + 3) == .success ? nil : POSIXError(.EDEADLK)
    }
    try await f.cache.push([f.item])
    try await acquisitionEventually { await f.core.testingDebugState().openHandleCount == 0 && f.item.reclaimed }
    #expect(await f.daemon.stats().closeRequests == 2)
    #expect(await f.daemon.stats().activeHandles == 0)
    await f.finish()
}


@available(macOS 27, *)
@Test func cacheReadUncachedReadCacheAndReadOnlyRequestsAcquireOnlyCallerAccess() async throws {
    for requested in [FSVolume.DataCacheMode.none, .readWithCache] {
        let f = try await ReadAcquisitionFixture()
        #expect(try await f.open([.write], requested) == .noCache)
        #expect(await f.daemon.stats().openModes == [.write])
        await f.finish()
    }
    let reader = try await ReadAcquisitionFixture()
    #expect(try await reader.open([.read]) == .readCache)
    #expect(await reader.daemon.stats().openModes == [.read])
    await reader.finish()
}

}
