import Foundation
import FSKit
import Testing
@testable import PortableFSKit
@testable import PortableFSKitMockDaemon
@preconcurrency import Darwin

private final class CacheBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: T
    init(_ value: T) { stored = value }
    var value: T { lock.withLock { stored } }
    func change(_ operation: (inout T) -> Void) { lock.withLock { operation(&stored) } }
}

private func cacheItem(_ id: UInt64 = 2) -> PortableFSItem {
    PortableFSItem(identity: PfsItemIdentity(itemID: id, generation: 1), fileID: id, kind: .file)
}

private func cacheEventually(_ check: () async -> Bool, line: UInt = #line) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while !(await check()) {
        guard ContinuousClock.now < deadline else {
            throw NSError(domain: "cacheEventually source line \(line)", code: Int(ETIMEDOUT))
        }
        try await Task.sleep(for: .milliseconds(2))
    }
}

@Test func kernelCacheGrantRequiresProofRequestedModeAndOwnedRead() async throws {
    let now = CacheBox<UInt64>(100)
    let gate = PfsSessionPublicationGate()
    let cache = PfsKernelCache(gate: gate, clock: { now.value }, failure: { _ in })
    cache.install { _, _ in nil }
    let item = cacheItem()
    cache.retain(item)
    cache.ownership(item, access: .readWrite)
    #expect(try !cache.grant(item, requested: true, ownsRead: true))
    cache.proof(1_000_000_000_100)
    #expect(try cache.grant(item, requested: true, ownsRead: true))
    #expect(try !cache.grant(item, requested: false, ownsRead: true))
    #expect(try !cache.grant(item, requested: true, ownsRead: false))
    cache.ownership(item, access: .write)
    #expect(try !cache.grant(item, requested: true, ownsRead: true))
    cache.ownership(item, access: .read)
    now.change { $0 = 1_000_000_000_100 }
    #expect(try !cache.grant(item, requested: true, ownsRead: true))
    await cache.withdraw(.revoke)
}

@Test func kernelCacheExpiryInvalidatesButDoesNotEndSession() async throws {
    let now = CacheBox<UInt64>(0)
    let actions = CacheBox<[PfsKernelCache.Action]>([])
    let gate = PfsSessionPublicationGate()
    let cache = PfsKernelCache(gate: gate, clock: { now.value }, failure: { _ in Issue.record("unexpected terminal failure") })
    cache.install { _, action in actions.change { $0.append(action) }; return nil }
    let item = cacheItem()
    cache.retain(item)
    cache.ownership(item, access: .read)
    cache.proof(1_000_000_000_000)
    #expect(try cache.grant(item, requested: true, ownsRead: true))
    now.change { $0 = 1_000_000_000_000 }
    await cache.withdraw(.invalidate, expiredDeadline: now.value)
    #expect(actions.value == [.invalidate])
    #expect(gate.terminalError == nil)
    #expect(try !cache.grant(item, requested: true, ownsRead: true))
    cache.proof(2_000_000_000_000)
    #expect(try cache.grant(item, requested: true, ownsRead: true))
    await cache.withdraw(.revoke)
}

@Test func kernelCacheWithdrawalFailureRevokesAndRetainsFirstCause() async throws {
    let actions = CacheBox<[PfsKernelCache.Action]>([])
    let failures = CacheBox<[Int]>([])
    let gate = PfsSessionPublicationGate()
    let cache = PfsKernelCache(gate: gate, clock: { 1 }, failure: { error in failures.change { $0.append((error as NSError).code) } })
    cache.install { _, action in
        actions.change { $0.append(action) }
        return action == .invalidate ? POSIXError(.EIO) : nil
    }
    let item = cacheItem()
    cache.retain(item)
    cache.ownership(item, access: .read)
    cache.proof(1_000_000_000_000)
    #expect(try cache.grant(item, requested: true, ownsRead: true))
    await cache.withdraw(.invalidate)
    #expect(actions.value == [.invalidate, .revoke])
    #expect((gate.terminalError as NSError?)?.code == Int(EIO))
    #expect(failures.value == [Int(EIO)])
    cache.proof(2_000_000_000_000)
    #expect(try !cache.grant(item, requested: true, ownsRead: true))
}

@Test func kernelCacheReentrantCloseKeepsOwnershipThroughKernelCompletion() async throws {
    let gate = PfsSessionPublicationGate()
    let cache = PfsKernelCache(gate: gate, clock: { 1 }, failure: { _ in })
    let item = cacheItem()
    let cleaned = CacheBox(false)
    cache.retain(item)
    cache.ownership(item, access: .read)
    cache.proof(1_000_000_000_000)
    #expect(try cache.grant(item, requested: true, ownsRead: true))
    cache.install { retained, action in
        if action == .revoke { return nil }
        // These calls reacquire both module locks. A lock held across the
        // actuator would deadlock, as would waiting for deferred cleanup here.
        gate.synchronized { #expect(retained === item) }
        #expect(cache.deferCleanup(item) { cleaned.change { $0 = true } })
        #expect(!cleaned.value)
        #expect((try? cache.grant(item, requested: true, ownsRead: true)) == false)
        return nil
    }
    await cache.withdraw(.invalidate)
    try await cacheEventually { cleaned.value }
    await cache.withdraw(.revoke)
}

@Test func kernelCacheAuthorizationLossFailsGrantAndRevokes() async throws {
    let actions = CacheBox<[PfsKernelCache.Action]>([])
    let gate = PfsSessionPublicationGate()
    let cache = PfsKernelCache(gate: gate, clock: { 1 }, failure: { _ in })
    cache.install { _, action in actions.change { $0.append(action) }; return nil }
    let item = cacheItem()
    cache.retain(item)
    cache.ownership(item, access: .read)
    cache.proof(1_000_000_000_000, authorization: 1)
    #expect(throws: (any Error).self) { try cache.grant(item, requested: false, ownsRead: true) }
    await cache.withdraw(.revoke)
    #expect(actions.value == [.revoke])
}

extension PfsLocalMockDaemonTests {
@available(macOS 27, *)
@Test func v3CacheOpenUpgradeAndFinalCloseUseBoundedDescriptionsAndExpectedTrips() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let volume = try #require(try await PortableFSVolume.make(core: core, attachRef: "mock") as? PortableFSVolumeV3)
    let cache = try #require(volume.kernelCache)
    cache.install { _, _ in nil }
    #expect(!(volume is any FSVolume.OpenCloseOperations))
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: Data("v3-open".utf8), mode: 0o600)
    cache.proof(try PfsKernelCache.continuousNanos() + 30_000_000_000)
    await daemon.resetStats()
    let first = CacheBox<FSVolume.KernelCacheCoherencyType?>(nil)
    volume.cacheOpen(created.item, modes: [.read], cacheMode: .readWithCache) { grant, error in
        #expect(error == nil); first.change { $0 = grant }
    }
    try await cacheEventually { first.value != nil }
    #expect(first.value == .readCache)
    #expect(await daemon.stats().openRequests == 0)
    let upgraded = CacheBox<FSVolume.KernelCacheCoherencyType?>(nil)
    volume.cacheOpen(created.item, modes: nil, cacheMode: .readWriteWithCache) { grant, error in
        #expect(error == nil); upgraded.change { $0 = grant }
    }
    try await cacheEventually { upgraded.value != nil }
    #expect(upgraded.value == .readCache)
    #expect(await daemon.stats().openRequests == 0)
    #expect(await core.testingDebugState().openHandleCount == 1)
    let data = try await core.read(item: created.item, offset: 0, length: 1)
    #expect(data.isEmpty)
    #expect(await daemon.stats().readRequests == 1)
    let closed = CacheBox(false)
    volume.finalClose(created.item) { closed.change { $0 = true } }
    try await cacheEventually { closed.value }
    #expect(await daemon.stats().closeRequests == 1)
    #expect(await core.testingDebugState().openHandleCount == 0)
    // A cold open acquires exactly one new description; an access upgrade
    // acquires only the missing right, preserving already granted access.
    let cold = CacheBox<FSVolume.KernelCacheCoherencyType?>(nil)
    volume.cacheOpen(created.item, modes: [.read], cacheMode: .none) { grant, error in
        #expect(error == nil); cold.change { $0 = grant }
    }
    try await cacheEventually { cold.value != nil }
    #expect(cold.value == .noCache)
    #expect(await daemon.stats().openModes == [.read])
    let writable = CacheBox<FSVolume.KernelCacheCoherencyType?>(nil)
    volume.cacheOpen(created.item, modes: [.read, .write], cacheMode: .readWriteWithCache) { grant, error in
        #expect(error == nil); writable.change { $0 = grant }
    }
    try await cacheEventually { writable.value != nil }
    #expect(writable.value == .readCache)
    #expect(await daemon.stats().openModes == [.read, .write])
    #expect(await core.testingDebugState().openHandleCount == 2)
    await volume.shutdown()
}

@available(macOS 27, *)
@Test func v3CacheOpenUnlinkedStaysAccessibleAndTerminalRevokesRetainedItems() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let volume = try #require(try await PortableFSVolume.make(core: core, attachRef: "mock") as? PortableFSVolumeV3)
    let cache = try #require(volume.kernelCache)
    let actions = CacheBox<[PfsKernelCache.Action]>([])
    cache.install { _, action in actions.change { $0.append(action) }; return nil }
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: Data("unlinked".utf8), mode: 0o600)
    _ = try await core.write(item: created.item, offset: 0, data: Data("retained".utf8))
    try await core.remove(item: created.item, named: Data("unlinked".utf8), from: root, isDirectory: false)
    #expect(try await core.read(item: created.item, offset: 0, length: 8) == Data("retained".utf8))
    #expect(actions.value.isEmpty)
    daemon.emitAttachState(.degraded)
    try await cacheEventually { actions.value.count >= 2 }
    #expect(actions.value.allSatisfy { $0 == .revoke })
    let error = CacheBox<Error?>(nil)
    volume.cacheOpen(created.item, modes: [.read], cacheMode: .readWithCache) { grant, failure in
        #expect(grant == nil); error.change { $0 = failure }
    }
    try await cacheEventually { error.value != nil }
    await volume.shutdown()
}

@available(macOS 27, *)
@Test func v3FinalCloseFailureTerminatesButStillCompletes() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let volume = try #require(try await PortableFSVolume.make(core: core, attachRef: "mock") as? PortableFSVolumeV3)
    volume.kernelCache?.install { _, _ in nil }
    let created = try await core.createFile(in: core.rootItem(), name: Data("close-error".utf8), mode: 0o600)
    await daemon.failNextClose()
    let closed = CacheBox(false)
    volume.finalClose(created.item) { closed.change { $0 = true } }
    try await cacheEventually { closed.value }
    let terminal = await core.client.publicationGate.terminalError
    #expect(terminal != nil)
    await volume.shutdown()
}
}

extension PfsLocalMockDaemonTests {
@available(macOS 27, *)
@Test func v3KernelCallCanReenterFinalCloseAndReclaimBeforeReturning() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let volume = try #require(try await PortableFSVolume.make(core: core, attachRef: "mock") as? PortableFSVolumeV3)
    let cache = try #require(volume.kernelCache)
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: Data("reentrant".utf8), mode: 0o600)
    cache.proof(try PfsKernelCache.continuousNanos() + 30_000_000_000)
    #expect(try cache.grant(created.item, requested: true, ownsRead: true))
    cache.install { item, action in
        guard item === created.item, action == .invalidate else { return nil }
        let completed = DispatchSemaphore(value: 0)
        Task {
            // The callback must complete while setCacheState is still on the
            // stack, yet its authority ownership must not be released yet.
            try await core.close(item: item)
            try await core.reclaim(item: item)
            #expect(await core.testingDebugState().openHandleCount == 1)
            #expect(!item.reclaimed)
            completed.signal()
        }
        return completed.wait(timeout: .now() + 3) == .success ? nil : POSIXError(.EDEADLK)
    }
    await cache.withdraw(.invalidate)
    try await cacheEventually { await core.testingDebugState().openHandleCount == 0 && created.item.reclaimed }
    let terminal = await core.client.publicationGate.terminalError
    #expect(terminal == nil)
    await volume.shutdown()
}

@available(macOS 27, *)
@Test func v3ProofEventExpiresKernelDataAndDaemonDeathRevokesIt() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let volume = try #require(try await PortableFSVolume.make(core: core, attachRef: "mock") as? PortableFSVolumeV3)
    let cache = try #require(volume.kernelCache)
    let actions = CacheBox<[PfsKernelCache.Action]>([])
    cache.install { _, action in actions.change { $0.append(action) }; return nil }
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: Data("wire-proof".utf8), mode: 0o600)
    daemon.emitCacheProof(horizon: try PfsKernelCache.continuousNanos() + 500_000_000)
    try await cacheEventually { (try? cache.grant(created.item, requested: true, ownsRead: true)) == true }
    try await cacheEventually { actions.value.contains(.invalidate) }
    let terminal = await core.client.publicationGate.terminalError
    #expect(terminal == nil)
    daemon.stop()
    try await cacheEventually { actions.value.contains(.revoke) }
    await volume.shutdown()
}
}

@Test func kernelCacheTerminalRevocationWaitsForInflightInvalidation() async throws {
    let gate = PfsSessionPublicationGate()
    let cache = PfsKernelCache(gate: gate, clock: { 1 }, failure: { _ in })
    let item = cacheItem()
    let entered = CacheBox(false)
    let released = DispatchSemaphore(value: 0)
    let actions = CacheBox<[PfsKernelCache.Action]>([])
    cache.retain(item)
    cache.ownership(item, access: .read)
    cache.proof(1_000_000_000_000)
    #expect(try cache.grant(item, requested: true, ownsRead: true))
    cache.install { _, action in
        actions.change { $0.append(action) }
        if action == .invalidate {
            entered.change { $0 = true }
            return released.wait(timeout: .now() + 3) == .success ? nil : POSIXError(.ETIMEDOUT)
        }
        return nil
    }
    let invalidation = Task { await cache.withdraw(.invalidate) }
    try await cacheEventually { entered.value }
    let revocation = Task { await cache.withdraw(.revoke) }
    await cache.withdraw(.invalidate) // Duplicate expiry must not run again.
    #expect(actions.value == [.invalidate])
    released.signal()
    await invalidation.value
    await revocation.value
    #expect(actions.value == [.invalidate, .revoke])
}

@Test func kernelCacheClockFailureCannotGrantAndTerminates() async throws {
    let gate = PfsSessionPublicationGate()
    let cache = PfsKernelCache(gate: gate, clock: { throw POSIXError(.EIO) }, failure: { _ in })
    cache.install { _, _ in nil }
    let item = cacheItem()
    cache.retain(item)
    cache.ownership(item, access: .read)
    #expect(throws: PfsKernelCache.AdmissionFailure.self) {
        try cache.grant(item, requested: true, ownsRead: true)
    }
    cache.proof(100)
    try await cacheEventually { gate.terminalError != nil }
    #expect((gate.terminalError as NSError?)?.code == Int(EIO))
    await cache.withdraw(.revoke)
}

extension PfsLocalMockDaemonTests {
@available(macOS 27, *)
@Test func v3ReentrantOperationFailureRepliesBeforeTerminalCleanupWaitsForKernel() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let volume = try #require(try await PortableFSVolume.make(core: core, attachRef: "mock") as? PortableFSVolumeV3)
    let cache = try #require(volume.kernelCache)
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: Data("before-error".utf8), mode: 0o600)
    cache.proof(try PfsKernelCache.continuousNanos() + 30_000_000_000)
    #expect(try cache.grant(created.item, requested: true, ownsRead: true))
    await daemon.omitNextCreateHandle()
    cache.install { item, action in
        guard item === created.item, action == .invalidate else { return nil }
        let completed = DispatchSemaphore(value: 0)
        Task {
            do {
                _ = try await core.createFile(in: root, name: Data("reentrant-error".utf8), mode: 0o600)
                Issue.record("malformed creation unexpectedly succeeded")
            } catch {}
            completed.signal()
        }
        return completed.wait(timeout: .now() + 3) == .success ? nil : POSIXError(.EDEADLK)
    }
    await cache.withdraw(.invalidate)
    await volume.shutdown()
    #expect(created.item.reclaimed)
    #expect(await core.testingDebugState().openHandleCount == 0)
}
}

extension PfsLocalMockDaemonTests {
@Test func cacheProofEventBufferKeepsLatestProofAndTerminalWithoutGrowing() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    _ = try await client.resolve(attachRef: "mock")
    let events = try await client.subscribeEvents()
    for horizon in UInt64(1)...128 { daemon.emitCacheProof(horizon: horizon) }
    // The reply follows every emitted proof on this one socket.
    _ = try await client.request(.statfs(PfsStatfsRequest()))
    daemon.emitAttachState(.degraded)
    try await cacheEventually { client.publicationGate.terminalError != nil }
    // Join the actor after its synchronous terminal receive turn, so the
    // stream is finished before inspecting its coalesced buffered contents.
    #expect(await client.isDetachingOrStopped)
    var horizons: [UInt64] = []
    var terminal = false
    var count = 0
    for await event in events {
        count += 1
        switch event.kind {
        case let .cacheProof(proof)?: horizons.append(proof.horizonNanos)
        case let .attachState(state)?: terminal = state.state == .degraded
        case nil: Issue.record("empty event")
        }
    }
    #expect(count == 2)
    #expect(horizons == [128])
    #expect(terminal)
}
}

private actor CachePause {
    private(set) var entered = false
    private var released = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        entered = true
        if released { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        released = true
        let pending = waiters
        waiters.removeAll()
        for waiter in pending { waiter.resume() }
    }
}

@Test func kernelCacheFinalDecisionSettlesOrdinaryAndTerminalErrorsAsUnpublished() async throws {
    let gate = PfsSessionPublicationGate()
    let window = PfsCallbackWindow(capacity: 2, publicationGate: gate)
    let fault = CacheBox(false)
    let cache = PfsKernelCache(gate: gate, clock: { if fault.value { throw POSIXError(.EIO) }; return 1 }, failure: { _ in })
    let item = cacheItem()
    let ordinary = try await window.admit()
    let ordinaryPublished = await window.settle(ordinary, decision: { try cache.grant(item, requested: true, ownsRead: true) }, terminalCause: { ($0 as? PfsKernelCache.AdmissionFailure)?.cause }) { result in
        if case let .failure(error) = result { #expect((error as NSError).code == Int(EBADF)) }
        else { Issue.record("ordinary grant refusal published success") }
    }
    #expect(!ordinaryPublished)
    #expect(gate.terminalError == nil)
    let terminal = try await window.admit()
    let held = try await window.admit()
    fault.change { $0 = true }
    let terminalPublished = await window.settle(terminal, decision: { try cache.grant(item, requested: true, ownsRead: true) }, terminalCause: {
        ($0 as? PfsKernelCache.AdmissionFailure)?.cause
    }) { result in
        if case let .failure(error) = result { #expect((error as NSError).code == Int(EIO)) }
        else { Issue.record("terminal grant refusal published success") }
    }
    #expect(!terminalPublished)
    let heldPublished = await window.settle(held) { error in #expect((error as NSError?)?.code == Int(EIO)) }
    #expect(!heldPublished)
}

extension PfsLocalMockDaemonTests {
@available(macOS 27, *)
@Test func v3FailedFinalGrantLatchesBeforeDelayedCleanupAndHeldPublication() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let records = CacheBox<[PfsTraceRecord]>([])
    var configuration = PfsLocalClient.Configuration()
    configuration.traceObserver = { record in records.change { $0.append(record) } }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock", configuration: configuration)
    let fault = CacheBox(false)
    let volume = try #require(try await PortableFSVolume.make(
        core: core, attachRef: "mock", adapter: PortableFSVolumeV3.self,
        cacheClock: { if fault.value { throw POSIXError(.EIO) }; return 1 }
    ) as? PortableFSVolumeV3)
    volume.kernelCache?.install { _, _ in nil }
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: Data("final-grant".utf8), mode: 0o600)
    try await core.close(item: created.item)
    records.change { $0.removeAll() }
    await daemon.resetStats()
    let cleanup = CachePause()
    volume.testingBeforePublicationFailureCleanup { await cleanup.wait() }
    let heldBody = CachePause()
    defer { Task { await cleanup.release(); await heldBody.release() } }
    let heldReply = CacheBox<Error?>(nil)
    volume.testOnlyPublishAfterReply(operation: {
        let attr = try await core.getattr(item: created.item)
        await heldBody.wait()
        return attr
    }, reply: { result in
        if case let .failure(error) = result { heldReply.change { $0 = error } }
        else { Issue.record("held callback served after final grant failure") }
    })
    try await cacheEventually { await heldBody.entered }
    fault.change { $0 = true }
    let openReply = CacheBox<Error?>(nil)
    volume.cacheOpen(created.item, modes: [.read], cacheMode: .readWithCache) { grant, error in
        #expect(grant == nil)
        openReply.change { $0 = error }
    }
    try await cacheEventually { let entered = await cleanup.entered; return openReply.value != nil && entered }
    #expect((openReply.value as NSError?)?.code == Int(EIO))
    // A real OPEN body succeeded; only its final cache admission failed.
    #expect(await daemon.stats().openRequests == 1)
    #expect(await core.testingDebugState().openHandleCount == 1)
    let client = await core.client
    #expect((client.publicationGate.terminalError as NSError?)?.code == Int(EIO))
    try await cacheEventually { records.value.contains { $0.event == .callbackFinished } }
    #expect(records.value.filter { $0.event == .callbackFinished }.allSatisfy { $0.value("outcome") == "revoked" })
    // A plain OPEN has no semantic-ack obligation. In particular it must
    // never manufacture a published ack for this failed framework reply.
    #expect(records.value.filter { $0.event == .publicationAck }.isEmpty)
    await heldBody.release()
    try await cacheEventually { heldReply.value != nil }
    #expect((heldReply.value as NSError?)?.code == Int(EIO))
    // A transient clock recovery cannot revive final serving or admission.
    fault.change { $0 = false }
    let laterReply = CacheBox<Error?>(nil)
    volume.cacheOpen(created.item, modes: [.read], cacheMode: .none) { grant, error in
        #expect(grant == nil)
        laterReply.change { $0 = error }
    }
    try await cacheEventually { laterReply.value != nil }
    #expect((laterReply.value as NSError?)?.code == Int(EIO))
    try await cacheEventually { records.value.filter { $0.event == .publicationAck }.count == 1 }
    #expect(records.value.filter { $0.event == .publicationAck }.allSatisfy { $0.value("published") == "false" })
    #expect(await daemon.stats().openRequests == 1)
    await cleanup.release()
    await volume.shutdown()
}

@Test func cacheIngressBackpressuresBeforeProofCoalescingAndTerminal() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    _ = try await client.resolve(attachRef: "mock")
    let events = try await client.subscribeEvents()
    let first = CachePause()
    let seen = CacheBox<[String]>([])
    await client.testingBeforeReceive { frame in
        guard case let .event(event)? = frame.body else { return }
        switch event.kind {
        case let .cacheProof(proof)?:
            if proof.horizonNanos == 1 { await first.wait() }
            seen.change { $0.append("proof-\(proof.horizonNanos)") }
        case .attachState?: seen.change { $0.append("terminal") }
        case nil: break
        }
    }
    daemon.emitCacheProof(horizon: 1, authorization: 100)
    try await cacheEventually { await first.entered }
    // These socket writes happen while ingress delivery of proof 1 is held.
    daemon.emitCacheProof(horizon: 2, authorization: 200)
    daemon.emitAttachState(.degraded)
    daemon.emitCacheProof(horizon: 3, authorization: 300)
    try await cacheEventually { daemon.testingPendingResponseCount() == 0 }
    #expect(seen.value.isEmpty)
    #expect(client.publicationGate.terminalError == nil)
    await first.release()
    try await cacheEventually { client.publicationGate.terminalError != nil }
    #expect(await client.isDetachingOrStopped)
    var retained: [UInt64] = []
    var authorizations: [UInt64] = []
    var terminal = false
    for await event in events {
        switch event.kind {
        case let .cacheProof(proof)?:
            retained.append(proof.horizonNanos)
            authorizations.append(proof.authorizationDeadlineUnixNanos)
        case .attachState?: terminal = true
        case nil: break
        }
    }
    #expect(seen.value == ["proof-1", "proof-2", "terminal"])
    #expect(retained == [2])
    #expect(authorizations == [200])
    #expect(terminal)
    let cause = client.publicationGate.terminalError
    await #expect(throws: (any Error).self) { _ = try await client.request(.statfs(PfsStatfsRequest())) }
    #expect(String(describing: client.publicationGate.terminalError) == String(describing: cause))
    await client.close()
}
}

private func checkAuthorizationExpiryCommit(renewalWins: Bool) async throws {
    let gate = PfsSessionPublicationGate()
    let wake = CachePause()
    let actions = CacheBox<[PfsKernelCache.Action]>([])
    let failures = CacheBox<[Int]>([])
    let cache = PfsKernelCache(gate: gate, clock: { 1 }, authorizationNow: { 200 }, beforeAuthorizationExpiry: {
        await wake.wait()
    }, failure: { error in failures.change { $0.append((error as NSError).code) } })
    cache.install { _, action in actions.change { $0.append(action) }; return nil }
    let item = cacheItem()
    cache.retain(item)
    cache.ownership(item, access: .read)
    cache.proof(1_000_000_000_000, authorization: 100)
    let old = try #require(cache.testingExpiryTask())
    try await cacheEventually { await wake.entered }
    if renewalWins { cache.proof(2_000_000_000_000, authorization: 1_000_000_000_000) }
    await wake.release()
    await old.value
    if renewalWins {
        #expect(gate.terminalError == nil)
        #expect(actions.value.isEmpty)
        #expect(failures.value.isEmpty)
        #expect(try cache.grant(item, requested: true, ownsRead: true))
    } else {
        // The terminal commit wins before the renewal tries to install.
        cache.proof(2_000_000_000_000, authorization: 1_000_000_000_000)
        #expect((gate.terminalError as NSError?)?.code == Int(EACCES))
        #expect(actions.value == [.revoke])
        #expect(failures.value == [Int(EACCES)])
        #expect(throws: PfsKernelCache.AdmissionFailure.self) { try cache.grant(item, requested: true, ownsRead: true) }
    }
    await cache.withdraw(.revoke)
}

@Test func kernelCacheRenewalSupersedesAWokenAuthorizationExpiry() async throws {
    try await checkAuthorizationExpiryCommit(renewalWins: true)
}

@Test func kernelCacheAuthorizationExpiryCommitsBeforeRenewal() async throws {
    try await checkAuthorizationExpiryCommit(renewalWins: false)
}
