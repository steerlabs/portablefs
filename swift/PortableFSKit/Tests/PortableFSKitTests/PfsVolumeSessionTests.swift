import Foundation
import FSKit
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

// The bounded callback window and the volume's single terminal path: one
// event binding per pfslocal session, whose end or terminal attach state
// closes the client and fails the window.

private actor WindowProgress {
    private var done = false
    private var order: [Int] = []
    func mark() { done = true }
    func value() -> Bool { done }
    func record(_ index: Int) { order.append(index) }
    func recorded() -> [Int] { order }
}

private func waitForWindowWaiters(
    _ window: PfsCallbackWindow,
    count: Int
) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(5))
    while await window.waiterCount() != count {
        try Task.checkCancellation()
        guard clock.now < deadline else { throw PfsLocalClientError.timeout }
        await Task.yield()
    }
}

private func waitUntil(
    _ deadline: Duration = .seconds(5),
    _ condition: () async -> Bool
) async throws -> Bool {
    let clock = ContinuousClock()
    let end = clock.now + deadline
    while clock.now < end {
        if await condition() { return true }
        try await Task.sleep(for: .milliseconds(2))
    }
    return await condition()
}

private final class SessionReplyBox<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value?
    private var replies = 0
    private var waiters: [CheckedContinuation<Value, Never>] = []

    func set(_ value: Value) {
        lock.lock()
        replies += 1
        stored = value
        let pending = waiters
        waiters.removeAll()
        lock.unlock()
        for waiter in pending { waiter.resume(returning: value) }
    }

    func wait() async -> Value {
        await withCheckedContinuation { continuation in
            lock.lock()
            if let stored {
                lock.unlock()
                continuation.resume(returning: stored)
            } else {
                waiters.append(continuation)
                lock.unlock()
            }
        }
    }

    func get() -> Value? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    func count() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return replies
    }
}

/// Holds an injected callback operation inside its window slot until the
/// test releases it.
private actor SessionGate {
    private var open = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var entered = 0
    private var observers: [(Int, CheckedContinuation<Void, Never>)] = []

    func enter() async {
        entered += 1
        let ready = observers.filter { $0.0 <= entered }
        observers.removeAll { $0.0 <= entered }
        for (_, observer) in ready { observer.resume() }
        if open { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func enteredCount() -> Int { entered }

    func waitForEntries(_ count: Int) async {
        if entered >= count { return }
        await withCheckedContinuation { observers.append((count, $0)) }
    }

    func release() {
        open = true
        let pending = waiters
        waiters.removeAll()
        for waiter in pending { waiter.resume() }
    }
}

/// Settles a ticket whose reply the test does not inspect.
@discardableResult
private func settle(_ window: PfsCallbackWindow, _ ticket: PfsCallbackTicket) async -> Bool {
    await window.settle(ticket) { _ in }
}

// MARK: - Window

@Test func callbackWindowBoundsABurstToItsCapacity() async throws {
    let window = PfsCallbackWindow(capacity: 3)
    let counts = try await withThrowingTaskGroup(of: Int.self) { group in
        for _ in 0..<2_000 {
            group.addTask {
                let ticket = try await window.admit()
                let count = await window.admittedCount()
                await Task.yield()
                await settle(window, ticket)
                return count
            }
        }
        var values: [Int] = []
        for try await count in group { values.append(count) }
        return values
    }
    #expect(counts.count == 2_000)
    #expect(counts.allSatisfy { $0 <= 3 })
    #expect(await window.admittedCount() == 0)
    #expect(await window.waiterCount() == 0)
}

@Test func callbackWindowDefaultsToOneHundredTwentyEightCallbacks() async throws {
    let window = PfsCallbackWindow()
    var tickets: [PfsCallbackTicket] = []
    for _ in 0..<PfsCallbackWindow.defaultCapacity {
        tickets.append(try await window.admit())
    }
    #expect(PfsCallbackWindow.defaultCapacity == 128)
    let queued = Task { try await window.admit() }
    try await waitForWindowWaiters(window, count: 1)
    await settle(window, tickets.removeLast())
    tickets.append(try await queued.value)
    #expect(await window.admittedCount() == 128)
    for ticket in tickets { await settle(window, ticket) }
    #expect(await window.admittedCount() == 0)
}

/// A freed slot goes to the oldest waiter, never to a later arrival.
@Test func callbackWindowHandsFreedSlotsToWaitersInArrivalOrder() async throws {
    let window = PfsCallbackWindow(capacity: 1)
    let progress = WindowProgress()
    let first = try await window.admit()
    var queued: [Task<Void, Error>] = []
    for index in 0..<4 {
        queued.append(Task {
            let ticket = try await window.admit()
            await progress.record(index)
            await settle(window, ticket)
        })
        try await waitForWindowWaiters(window, count: index + 1)
    }
    await settle(window, first)
    for task in queued { try await task.value }
    #expect(await progress.recorded() == [0, 1, 2, 3])
    #expect(await window.admittedCount() == 0)
}

@Test func cancellingAQueuedCallbackCannotLeakItsSlot() async throws {
    let window = PfsCallbackWindow(capacity: 1)
    let first = try await window.admit()
    let queued = Task { try await window.admit() }
    try await waitForWindowWaiters(window, count: 1)
    queued.cancel()
    await #expect(throws: PfsLocalClientError.cancelled) { _ = try await queued.value }
    #expect(await window.waiterCount() == 0)
    await settle(window, first)
    let next = try await window.admit()
    await settle(window, next)
    #expect(await window.admittedCount() == 0)
}

@Test func cancellationRacingAHandOffCannotStrandTheNextCallback() async throws {
    for _ in 0..<100 {
        let window = PfsCallbackWindow(capacity: 1)
        let first = try await window.admit()
        let cancelling = Task {
            let ticket = try await window.admit()
            await settle(window, ticket)
        }
        try await waitForWindowWaiters(window, count: 1)
        let finished = WindowProgress()
        let following = Task {
            let ticket = try await window.admit()
            await settle(window, ticket)
            await finished.mark()
        }
        try await waitForWindowWaiters(window, count: 2)
        await settle(window, first)
        cancelling.cancel()
        let madeProgress = try await waitUntil { await finished.value() }
        if !madeProgress { await window.fail(PfsLocalClientError.timeout) }
        _ = await cancelling.result
        _ = await following.result
        #expect(madeProgress)
        #expect(await window.admittedCount() == 0)
        #expect(await window.waiterCount() == 0)
        if !madeProgress { return }
    }
}

@Test func aTicketReleasesItsSlotExactlyOnce() async throws {
    let window = PfsCallbackWindow(capacity: 1)
    let first = try await window.admit()
    #expect(await settle(window, first))
    let second = try await window.admit()
    // A duplicate settlement of the first ticket must neither reply again
    // nor free the second's slot.
    let duplicateReplies = SessionReplyBox<Int>()
    #expect(!(await window.settle(first) { _ in duplicateReplies.set(1) }))
    #expect(duplicateReplies.get() == nil)
    #expect(await window.admittedCount() == 1)
    let queued = Task { try await window.admit() }
    try await waitForWindowWaiters(window, count: 1)
    await settle(window, second)
    await settle(window, try await queued.value)
    #expect(await window.admittedCount() == 0)
}

@Test func terminalFailureWakesQueuedCallbacksAndRefusesLaterAdmission() async throws {
    let window = PfsCallbackWindow(capacity: 1)
    let first = try await window.admit()
    let queued = (0..<3).map { _ in Task { try await window.admit() } }
    try await waitForWindowWaiters(window, count: 3)
    await window.fail(PfsLocalClientError.connectionClosed)
    for task in queued {
        await #expect(throws: PfsLocalClientError.connectionClosed) { _ = try await task.value }
    }
    await #expect(throws: PfsLocalClientError.connectionClosed) { _ = try await window.admit() }
    // A second terminal transition keeps the first cause.
    await window.fail(PfsLocalClientError.shutdown)
    await #expect(throws: PfsLocalClientError.connectionClosed) { _ = try await window.admit() }
    // The admitted callback's publication lost to the terminal transition:
    // it replies with the first terminal cause, not its own outcome.
    let lateVerdict = SessionReplyBox<PfsLocalClientError>()
    #expect(!(await window.settle(first) { terminal in
        lateVerdict.set(terminal as? PfsLocalClientError ?? .timeout)
    }))
    #expect(lateVerdict.get() == .connectionClosed)
    #expect(await window.isFailed())
    #expect(await window.admittedCount() == 0)
    #expect(await window.waiterCount() == 0)
}

/// Termination cannot split the final decision from a synchronous reply that
/// already won. Conversely, every serving reply after revocation sees the first cause.
@Test func sessionTerminationWaitsForTheWinningSynchronousReply() async {
    let gate = PfsSessionPublicationGate()
    let entered = SessionReplyBox<Bool>()
    let release = DispatchSemaphore(value: 0)
    let publication = Task.detached {
        gate.decide { terminal in
            #expect(terminal == nil)
            entered.set(true)
            release.wait()
        }
    }
    _ = await entered.wait()
    let revoking = SessionReplyBox<Bool>()
    let revoked = SessionReplyBox<Bool>()
    let termination = Task.detached {
        revoking.set(true)
        gate.revoke(PfsLocalClientError.connectionClosed)
        revoked.set(true)
    }
    _ = await revoking.wait()
    #expect(revoked.get() == nil)
    release.signal()
    #expect(await publication.value)
    await termination.value
    gate.revoke(PfsLocalClientError.shutdown)
    let published = gate.decide { terminal in
        #expect(terminal as? PfsLocalClientError == .connectionClosed)
    }
    #expect(!published)
}

@Test func attachEventsSelectTheTerminalCause() {
    func event(_ state: PfsAttachState.State, detail: String = "") -> PfsEvent {
        var attachState = PfsAttachState()
        attachState.state = state
        attachState.detail = detail
        var event = PfsEvent()
        event.kind = .attachState(attachState)
        return event
    }
    #expect(PfsAttachEventMonitor.terminalCause(of: event(.attached)) == nil)
    #expect(PfsAttachEventMonitor.terminalCause(of: event(.degraded, detail: "authority lost"))
        == .daemon(errno: EIO, message: "attach degraded: authority lost"))
    #expect(PfsAttachEventMonitor.terminalCause(of: event(.detaching))
        == .daemon(errno: ENXIO, message: "attach is detaching"))
    for undefined in [PfsAttachState.State.unspecified, .UNRECOGNIZED(99)] {
        #expect(PfsAttachEventMonitor.terminalCause(of: event(undefined))
            == .invalidFrame("attach state event names no defined state"))
    }
    #expect(PfsAttachEventMonitor.terminalCause(of: PfsEvent())
        == .invalidFrame("event has no body"))
}

// MARK: - Volume session

@available(macOS 26.0, *)
private struct SessionHarness {
    let daemon: PfsLocalMockDaemon
    let core: VolumeCore
    let volume: PortableFSVolume
    let root: PortableFSItem
}

@available(macOS 26.0, *)
private func makeSessionHarness(
    daemonConfiguration: PfsLocalMockDaemon.Configuration = .init(),
    windowCapacity: Int = PfsCallbackWindow.defaultCapacity,
    clientConfiguration: PfsLocalClient.Configuration = .init()
) async throws -> SessionHarness {
    let daemon = try PfsLocalMockDaemon(configuration: daemonConfiguration)
    let core = try await VolumeCore.connect(
        socketPath: daemon.socketPath, attachRef: "mock", configuration: clientConfiguration
    )
    let volume = try await PortableFSVolume.make(
        core: core,
        attachRef: "mock",
        windowCapacity: windowCapacity
    )
    return SessionHarness(
        daemon: daemon,
        core: core,
        volume: volume,
        root: try await core.rootItem()
    )
}

// MARK: - Native local-teardown contract

private enum NativeTeardown: CaseIterable, Sendable {
    case deactivate, forceDeactivate, unload, unmount
}

@available(macOS 26.0, *)
private struct LoadedSession: @unchecked Sendable {
    let harness: SessionHarness
    let fileSystem: PortableFSFileSystem
    let resource: FSGenericURLResource
    let options: FSTaskOptions
    let file: PortableFSItem
    let factories: SessionReplyBox<Bool>

    func teardown(_ entry: NativeTeardown) -> SessionReplyBox<Int> {
        let reply = SessionReplyBox<Int>()
        let operations: any FSVolume.Operations = harness.volume
        switch entry {
        case .deactivate, .forceDeactivate:
            operations.deactivate(options: entry == .forceDeactivate ? .force : []) { error in
                reply.set((error as NSError?)?.code ?? 0)
            }
        case .unload:
            fileSystem.unloadResource(resource: resource, options: options) { error in
                reply.set((error as NSError?)?.code ?? 0)
            }
        case .unmount:
            operations.unmount { reply.set(0) }
        }
        return reply
    }
}

@available(macOS 26.0, *)
private func loadSession(
    clientConfiguration: PfsLocalClient.Configuration = .init()
) async throws -> LoadedSession {
    let harness = try await makeSessionHarness(clientConfiguration: clientConfiguration)
    let socketPath = harness.daemon.socketPath
    let factories = SessionReplyBox<Bool>()
    let fileSystem = PortableFSFileSystem(
        moduleIdentity: PortableFSIdentity.moduleIdentity,
        resolverFactory: { PfsSocketPathResolver(infoDictionary: ["PFSDaemonSocketPath": socketPath]) },
        volumeFactory: { _, _, _ in
            factories.set(true)
            return harness.volume
        }
    )
    let options = try #require(class_createInstance(FSTaskOptions.self, 0) as? FSTaskOptions)
    let resource = FSGenericURLResource(url: try #require(URL(string: "dev.portablefs.oss://mock")))
    let loaded = SessionReplyBox<Int>()
    fileSystem.loadResource(resource: resource, options: options) { volume, error in
        #expect(volume === harness.volume)
        loaded.set((error as NSError?)?.code ?? 0)
    }
    #expect(await loaded.wait() == 0)
    #expect(loaded.count() == 1)
    let created = try await harness.core.createFile(in: harness.root, name: Data("owned".utf8), mode: 0o644)
    #expect(await harness.core.testingDebugState().openHandleCount == 1)
    return LoadedSession(
        harness: harness, fileSystem: fileSystem, resource: resource, options: options,
        file: created.item, factories: factories
    )
}

@available(macOS 26.0, *)
private func expectLocalCleanup(_ fixture: LoadedSession, cause: PfsLocalClientError) async {
    let core = fixture.harness.core
    #expect(fixture.harness.root.reclaimed)
    #expect(fixture.file.reclaimed)
    #expect(await core.testingDebugState() == VolumeCoreDebugState(
        itemCount: 0, objectIdentityCount: 0, publishedItemCount: 0,
        provisionalItemCount: 0, retiringItemCount: 0, retirementWaiterCount: 0, openHandleCount: 0
    ))
    #expect(await core.client.isDetachingOrStopped)
    let client = await core.client
    #expect(client.publicationGate.terminalError as? PfsLocalClientError == cause)
    #expect(fixture.factories.count() == 1)
}

@available(macOS 26.0, *)
private func expectNativeServingRefused(_ fixture: LoadedSession, errno: Int) async {
    let operations: any FSVolume.Operations = fixture.harness.volume
    let activate = SessionReplyBox<Int>()
    operations.activate(options: fixture.options) { item, error in
        #expect(item == nil)
        activate.set((error as NSError?)?.code ?? 0)
    }
    let mount = SessionReplyBox<Int>()
    operations.mount(options: fixture.options) { error in mount.set((error as NSError?)?.code ?? 0) }
    let sync = SessionReplyBox<Int>()
    operations.synchronize(flags: .wait) { error in sync.set((error as NSError?)?.code ?? 0) }
    #expect(await activate.wait() == errno)
    #expect(await mount.wait() == errno)
    #expect(await sync.wait() == errno)
    #expect(activate.count() == 1)
    #expect(mount.count() == 1)
    #expect(sync.count() == 1)
}

extension PfsLocalMockDaemonTests {
/// Regression port of review-p5-r4-astra-probes/lifecycle.swift. r3d accepts
/// ENXIO for serving and nil for completed local teardown; both keep ENXIO.
/// Each entry point owns a fresh loaded fixture, including force deactivation.
@available(macOS 26.0, *)
@Test func nativeLifecycleProbeAcknowledgesCompletedCleanupAfterENXIO() async throws {
    for first in [NativeTeardown.deactivate, .forceDeactivate, .unload] {
        try await checkNativeLifecycleProbe(first: first)
    }
}

@available(macOS 26.0, *)
private func checkNativeLifecycleProbe(first: NativeTeardown) async throws {
    let fixture = try await loadSession()
    defer { fixture.harness.daemon.stop() }
    let cause = PfsLocalClientError.daemon(errno: ENXIO, message: "terminal before native lifecycle callbacks")
    await fixture.harness.core.client.close(error: cause)
    await expectNativeServingRefused(fixture, errno: Int(ENXIO))
    let reply = fixture.teardown(first)
    #expect(await reply.wait() == 0)
    #expect(reply.count() == 1)
    await expectLocalCleanup(fixture, cause: cause)
    for entry in [first, .deactivate, .unload] {
        let repeated = fixture.teardown(entry)
        #expect(await repeated.wait() == 0)
        #expect(repeated.count() == 1)
    }
    #expect(fixture.fileSystem.testingRegisteredVolume(attachRef: "mock") == nil)
    await expectNativeServingRefused(fixture, errno: Int(ENXIO))
    let stats = await fixture.harness.daemon.stats()
    #expect(stats.helloRequests == 1)
    #expect(stats.syncVolumeRequests == 0)
    #expect(stats.closeRequests == 0)
    #expect(stats.reclaimRequests == 0)
}

/// Native unmount's void completion and the error-bearing teardown replies
/// certify the same local boundary. Repeat all completed entry points.
@available(macOS 26.0, *)
@Test func nativeOrdinaryTeardownAndRepeatsCompleteLocally() async throws {
    for first in [NativeTeardown.unmount, .deactivate, .forceDeactivate, .unload] {
        try await checkNativeOrdinaryTeardown(first: first)
    }
}

@available(macOS 26.0, *)
private func checkNativeOrdinaryTeardown(first: NativeTeardown) async throws {
    let fixture = try await loadSession()
    defer { fixture.harness.daemon.stop() }
    let firstReply = fixture.teardown(first)
    #expect(await firstReply.wait() == 0)
    #expect(firstReply.count() == 1)
    await expectLocalCleanup(fixture, cause: .shutdown)
    for entry in [first] + NativeTeardown.allCases + NativeTeardown.allCases {
        let reply = fixture.teardown(entry)
        #expect(await reply.wait() == 0)
        #expect(reply.count() == 1)
        await expectLocalCleanup(fixture, cause: .shutdown)
    }
    #expect(fixture.fileSystem.testingRegisteredVolume(attachRef: "mock") == nil)
    await expectNativeServingRefused(fixture, errno: Int(EIO))
    #expect(await fixture.harness.daemon.stats().helloRequests == 1)
    #expect(await fixture.harness.daemon.stats().syncVolumeRequests == 0)
}

@available(macOS 26.0, *)
@Test func nativeUnloadPreservesMalformedResourceError() async throws {
    let fixture = try await loadSession()
    defer { fixture.harness.daemon.stop() }
    let malformed = FSGenericURLResource(url: try #require(URL(string: "https://mock")))
    let reply = SessionReplyBox<Int>()
    fixture.fileSystem.unloadResource(resource: malformed, options: fixture.options) { error in
        reply.set((error as NSError?)?.code ?? 0)
    }
    #expect(await reply.wait() == Int(ENXIO))
    #expect(reply.count() == 1)
    #expect(fixture.fileSystem.testingRegisteredVolume(attachRef: "mock") === fixture.harness.volume)
    #expect(!fixture.harness.root.reclaimed)
    #expect(await fixture.teardown(.unload).wait() == 0)
}

/// Hold the single owned cleanup and observe every caller joining it. No reply
/// can run before release, even an overlapping unload or a cancelled requester.
@available(macOS 26.0, *)
@Test func nativeTeardownWaitsForCleanupDespiteOverlapAndCancellation() async throws {
    for first in NativeTeardown.allCases {
        try await checkNativeTeardownWaits(first: first)
    }
}

@available(macOS 26.0, *)
private func checkNativeTeardownWaits(first: NativeTeardown) async throws {
    let fixture = try await loadSession()
    defer { fixture.harness.daemon.stop() }
    let cleanup = SessionGate()
    let joined = SessionGate()
    await joined.release()
    fixture.harness.volume.testingShutdown(
        beforeCleanup: { await cleanup.enter() }, onWait: { await joined.enter() }
    )
    let requested = SessionReplyBox<SessionReplyBox<Int>>()
    let requester = Task {
        let reply = fixture.teardown(first)
        requested.set(reply)
        return await reply.wait()
    }
    let firstReply = await requested.wait()
    await cleanup.waitForEntries(1)
    await joined.waitForEntries(1)
    requester.cancel()
    #expect(firstReply.get() == nil)
    #expect(!fixture.harness.root.reclaimed)
    #expect(fixture.fileSystem.testingRegisteredVolume(attachRef: "mock") === fixture.harness.volume)

    let overlapping = fixture.teardown(.unload)
    // Dictionary absence used to produce a synchronous early reply here.
    // Record that regression without waiting for a join that never happens.
    if overlapping.get() != nil {
        Issue.record("overlapping unload replied before local cleanup completed")
        await cleanup.release()
        _ = await requester.value
        return
    }
    await joined.waitForEntries(2)
    #expect(firstReply.get() == nil)
    #expect(overlapping.get() == nil)
    await cleanup.release()
    #expect(await firstReply.wait() == 0)
    #expect(await overlapping.wait() == 0)
    #expect(await requester.value == 0)
    #expect(firstReply.count() == 1)
    #expect(overlapping.count() == 1)
    #expect(await cleanup.enteredCount() == 1)
    #expect(fixture.fileSystem.testingRegisteredVolume(attachRef: "mock") == nil)
    await expectLocalCleanup(fixture, cause: .shutdown)
}

/// Cancelling an async caller that is still awaiting owned cleanup cannot
/// shorten that cleanup or strand the native completion joining it.
@available(macOS 26.0, *)
@Test func cancelledDeactivationStillWaitsForOwnedCleanup() async throws {
    let fixture = try await loadSession()
    defer { fixture.harness.daemon.stop() }
    let cleanup = SessionGate()
    let joined = SessionGate()
    await joined.release()
    fixture.harness.volume.testingShutdown(
        beforeCleanup: { await cleanup.enter() }, onWait: { await joined.enter() }
    )
    let finished = SessionReplyBox<Int>()
    let requester = Task {
        do { try await fixture.harness.volume.deactivate(); finished.set(0) }
        catch { finished.set((error as NSError).code) }
    }
    await cleanup.waitForEntries(1)
    requester.cancel()
    let nativeReply = fixture.teardown(.deactivate)
    await joined.waitForEntries(2)
    #expect(finished.get() == nil)
    #expect(nativeReply.get() == nil)
    await cleanup.release()
    await requester.value
    #expect(await nativeReply.wait() == 0)
    #expect(finished.get() == 0)
    #expect(nativeReply.count() == 1)
    await expectLocalCleanup(fixture, cause: .shutdown)
    #expect(await fixture.teardown(.unload).wait() == 0)
}
}

extension PfsLocalMockDaemonTests {
/// The event binding is the daemon's witness that this frontend observes its
/// attach. It exists before the volume can serve a single callback.
@available(macOS 26.0, *)
@Test func volumeBindsItsEventStreamBeforeItCanServe() async throws {
    let harness = try await makeSessionHarness()
    defer { harness.daemon.stop() }
    let stats = await harness.daemon.stats()
    #expect(stats.helloRequests == 1)
    #expect(stats.subscribeRequests == 1)
    #expect(!(await harness.volume.window.isFailed()))
    #expect(harness.volume.maximumXattrSize == 64 * 1024)
    let capabilities = harness.volume.supportedVolumeCapabilities
    #expect(capabilities.supportsSymbolicLinks)
    #expect(capabilities.supportsHardLinks)
    #expect(capabilities.caseFormat == .sensitive)
    #expect(!capabilities.doesNotSupportImmutableFiles)

    // A healthy attach-state event keeps the session serving.
    harness.daemon.emitAttachState(.attached)
    let request = FSItem.GetAttributesRequest()
    request.wantedAttributes = [.type]
    let attributes = try await harness.volume.attributes(request, of: harness.root)
    #expect(attributes.type == .directory)
    #expect(!(await harness.volume.window.isFailed()))
}

/// A volume whose connection cannot establish its event binding never reaches
/// FSKit, and its session is closed rather than left serving unobserved.
@available(macOS 26.0, *)
@Test func failedEventBindingEndsTheSessionBeforeTheVolumeExists() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    await daemon.transformNextReply { envelope in
        guard case .subscribeEventsReply? = envelope.body else { return nil }
        var refused = envelope
        var error = PfsErrorReply()
        error.errno = EIO
        error.message = "binding refused"
        refused.body = .error(error)
        return refused
    }
    do {
        _ = try await PortableFSVolume.make(core: core, attachRef: "mock")
        Issue.record("a volume was built without its event binding")
    } catch {}
    #expect(await core.client.isDetachingOrStopped)
    await #expect(throws: PfsLocalClientError.self) { _ = try await core.statfs() }
    #expect(await daemon.stats().helloRequests == 1)
}

/// The FSKit errno a callback reply carried, or zero for success.
private func replyErrno<Value>(_ result: Result<Value, Error>) -> Int {
    switch result {
    case .success: 0
    case let .failure(error): (error as NSError).code
    }
}

/// Two admitted callbacks that already hold their daemon results and are
/// parked before their FSKit reply: a cacheable read (getattr of the root)
/// and a resource-bearing lookup whose fresh item is still provisional.
@available(macOS 26.0, *)
private struct HeldCallbacks {
    let gate: SessionGate
    let readReply: SessionReplyBox<Int>
    let lookupReply: SessionReplyBox<Int>
    let lookedUp: SessionReplyBox<PortableFSItem>
    let readSettled: SessionReplyBox<Bool>
    let lookupSettled: SessionReplyBox<Bool>
}

@available(macOS 26.0, *)
private func holdCompletedCallbacks(_ harness: SessionHarness) async throws -> HeldCallbacks {
    // The daemon keeps this file after the core reclaims its item, so the
    // held lookup adopts a new provisional item rather than an interned one.
    let (created, _) = try await harness.volume.createItem(
        named: FSFileName(string: "held"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    try await harness.core.reclaim(item: try #require(created as? PortableFSItem))

    let held = HeldCallbacks(
        gate: SessionGate(),
        readReply: SessionReplyBox(),
        lookupReply: SessionReplyBox(),
        lookedUp: SessionReplyBox(),
        readSettled: SessionReplyBox(),
        lookupSettled: SessionReplyBox()
    )
    let core = harness.core
    let root = harness.root
    // Park completed publications on the window actor, before its final
    // synchronous gate/reply decision. No scheduler delay guesses are needed.
    await harness.volume.window.testingBeforeSettlement { await held.gate.enter() }
    harness.volume.testOnlyPublishAfterReply(operation: {
        try await core.getattr(item: root)
    }, reply: { result in held.readReply.set(replyErrno(result)) },
    settled: { held.readSettled.set(true) })
    harness.volume.testOnlyPublishAfterReply(operation: {
        let found = try await core.lookup(in: root, name: Data("held".utf8))
        held.lookedUp.set(found.item)
        return found.item
    }, reply: { result in held.lookupReply.set(replyErrno(result)) },
    settled: { held.lookupSettled.set(true) })
    await held.gate.waitForEntries(2)
    #expect(await harness.core.testingDebugState().provisionalItemCount == 1)
    return held
}

/// Releases held callbacks after the session's terminal transition and
/// requires the terminal verdict: neither result reaches FSKit, the lookup's
/// provisional item settles as unpublished, and every slot is released.
@available(macOS 26.0, *)
private func expectHeldCallbacksRevoked(
    _ held: HeldCallbacks,
    _ harness: SessionHarness,
    errno expected: Int32
) async throws {
    #expect(await harness.volume.window.isFailed())
    #expect(held.readReply.get() == nil)
    #expect(held.lookupReply.get() == nil)
    await held.gate.release()
    #expect(await held.readReply.wait() == Int(expected))
    #expect(await held.lookupReply.wait() == Int(expected))
    _ = await held.readSettled.wait()
    _ = await held.lookupSettled.wait()
    #expect(await harness.volume.window.admittedCount() == 0)
    let item = try #require(held.lookedUp.get())
    #expect(item.reclaimed)
    #expect(await harness.core.testingDebugState().provisionalItemCount == 0)
}

/// Teardown's successful cleanup acknowledgement cannot authorize successful
/// publication by a read or provisional lookup already awaiting settlement.
@available(macOS 26.0, *)
@Test func nativeTeardownRevokesHeldServingResults() async throws {
    for entry in [NativeTeardown.deactivate, .unload] {
        try await checkNativeTeardownRevokesHeldServingResults(entry: entry)
    }
}

@available(macOS 26.0, *)
private func checkNativeTeardownRevokesHeldServingResults(entry: NativeTeardown) async throws {
    let fixture = try await loadSession()
    defer { fixture.harness.daemon.stop() }
    let held = try await holdCompletedCallbacks(fixture.harness)
    let reply = fixture.teardown(entry)
    #expect(await reply.wait() == 0)
    await expectLocalCleanup(fixture, cause: .shutdown)
    try await expectHeldCallbacksRevoked(held, fixture.harness, errno: EIO)
    #expect(held.readReply.count() == 1)
    #expect(held.lookupReply.count() == 1)
    #expect(held.readSettled.count() == 1)
    #expect(held.lookupSettled.count() == 1)
    #expect(await fixture.teardown(.unload).wait() == 0)
}

/// Both authority operations have succeeded before this native synchronize
/// reaches final settlement. Actual teardown wins the same gate afterwards.
@available(macOS 26.0, *)
@Test func nativeTeardownRevokesSuccessfulSynchronize() async throws {
    for entry in [NativeTeardown.deactivate, .unload] {
        try await checkNativeTeardownRevokesSuccessfulSynchronize(entry: entry)
    }
}

@available(macOS 26.0, *)
private func checkNativeTeardownRevokesSuccessfulSynchronize(entry: NativeTeardown) async throws {
    let fixture = try await loadSession()
    defer { fixture.harness.daemon.stop() }
    let settlement = SessionGate()
    await fixture.harness.volume.window.testingBeforeSettlement { await settlement.enter() }
    let reply = SessionReplyBox<Int>()
    let operations: any FSVolume.Operations = fixture.harness.volume
    operations.synchronize(flags: .wait) { error in reply.set((error as NSError?)?.code ?? 0) }
    await settlement.waitForEntries(1)
    #expect(await fixture.harness.daemon.stats().syncVolumeRequests == 1)
    #expect(reply.get() == nil)
    #expect(await fixture.teardown(entry).wait() == 0)
    await expectLocalCleanup(fixture, cause: .shutdown)
    #expect(reply.get() == nil)
    await settlement.release()
    #expect(await reply.wait() == Int(EIO))
    #expect(reply.count() == 1)
    #expect(await fixture.harness.volume.window.admittedCount() == 0)
    #expect(await fixture.teardown(.unload).wait() == 0)
}

private enum TeardownTerminalSource: CaseIterable, Sendable {
    case socketLoss, protocolDefect, explicitShutdown
}

/// Real socket and malformed-wire failures retain their exact first cause,
/// as does explicit shutdown. Native serving remains refused after cleanup.
@available(macOS 26.0, *)
@Test func nativeTeardownPreservesEachTerminalSource() async throws {
    for source in TeardownTerminalSource.allCases {
        for entry in [NativeTeardown.deactivate, .unload] {
            try await checkNativeTeardownPreservesTerminalSource(source: source, entry: entry)
        }
    }
}

@available(macOS 26.0, *)
private func checkNativeTeardownPreservesTerminalSource(
    source: TeardownTerminalSource, entry: NativeTeardown
) async throws {
    let fixture = try await loadSession()
    defer { fixture.harness.daemon.stop() }
    let ended = SessionReplyBox<Bool>()
    await fixture.harness.volume.window.testingBeforeTerminalDrain { ended.set(true) }
    let cause: PfsLocalClientError
    switch source {
    case .socketLoss:
        cause = .connectionClosed
        fixture.harness.daemon.dropConnections()
    case .protocolDefect:
        cause = .invalidFrame("envelope carries a field outside pfslocal 2.0")
        await fixture.harness.daemon.transformNextReply { envelope in
            guard case .statfsReply? = envelope.body,
                  var bytes = try? envelope.serializedData() else { return nil }
            bytes.append(contentsOf: [0x20, 0x01])
            return try? PfsEnvelope(serializedBytes: bytes)
        }
        await #expect(throws: cause) { _ = try await fixture.harness.core.statfs() }
    case .explicitShutdown:
        cause = .shutdown
        await fixture.harness.core.client.close()
    }
    _ = await ended.wait()
    let reply = fixture.teardown(entry)
    #expect(await reply.wait() == 0)
    #expect(reply.count() == 1)
    await expectLocalCleanup(fixture, cause: cause)
    #expect(await fixture.teardown(.deactivate).wait() == 0)
    #expect(await fixture.teardown(.unload).wait() == 0)
    await expectNativeServingRefused(fixture, errno: Int(cause.posixErrno))
    #expect(await fixture.harness.daemon.stats().helloRequests == 1)
    #expect(await fixture.harness.daemon.stats().syncVolumeRequests == 0)
}

/// An unanswered remote reclaim and a local retirement waiter cannot hold
/// local disposal hostage. Cleanup wakes both without issuing a remote drain.
@available(macOS 26.0, *)
@Test func nativeTeardownDoesNotAwaitRemoteReclaim() async throws {
    for entry in [NativeTeardown.deactivate, .unload] {
        try await checkNativeTeardownDoesNotAwaitRemoteReclaim(entry: entry)
    }
}

@available(macOS 26.0, *)
private func checkNativeTeardownDoesNotAwaitRemoteReclaim(entry: NativeTeardown) async throws {
    let dispatched = SessionReplyBox<Bool>()
    var configuration = PfsLocalClient.Configuration()
    configuration.traceObserver = { record in
        if record.event == .dispatched, record.value("kind") == "reclaim" { dispatched.set(true) }
    }
    let fixture = try await loadSession(clientConfiguration: configuration)
    defer { fixture.harness.daemon.stop() }
    await fixture.harness.daemon.pauseReclaims()
    let retiring = Task { try await fixture.harness.core.reclaim(item: fixture.file) }
    _ = await dispatched.wait()
    let waiting = Task { try await fixture.harness.core.reclaim(item: fixture.file) }
    while await fixture.harness.core.testingDebugState().retirementWaiterCount != 1 { await Task.yield() }
    #expect(await fixture.harness.core.testingDebugState().retiringItemCount == 1)
    let reply = fixture.teardown(entry)
    #expect(await reply.wait() == 0)
    #expect(reply.count() == 1)
    await expectLocalCleanup(fixture, cause: .shutdown)
    if case .success = await retiring.result { Issue.record("unanswered reclaim unexpectedly succeeded") }
    if case .success = await waiting.result { Issue.record("retirement waiter unexpectedly succeeded") }
    // Resume only after the cleanup acknowledgement and local waiters settled.
    await fixture.harness.daemon.resumeReclaims()
    #expect(await fixture.teardown(.unload).wait() == 0)
    await expectNativeServingRefused(fixture, errno: Int(EIO))
    #expect(await fixture.harness.daemon.stats().syncVolumeRequests == 0)
    #expect(await fixture.harness.daemon.stats().helloRequests == 1)
}

/// Degraded attach state is terminal: the client closes, a callback queued
/// for a window slot wakes with the cause instead of waiting forever, nothing
/// later is admitted, and callbacks that already hold results lose their
/// publication to the terminal decision.
@available(macOS 26.0, *)
@Test func degradedAttachStateEndsTheSessionAndWakesQueuedCallbacks() async throws {
    let harness = try await makeSessionHarness(windowCapacity: 2)
    defer { harness.daemon.stop() }
    let held = try await holdCompletedCallbacks(harness)
    await harness.daemon.resetStats()

    let queuedReply = SessionReplyBox<Int>()
    harness.volume.getAttributes(FSItem.GetAttributesRequest(), of: harness.root) { _, error in
        queuedReply.set((error as NSError?)?.code ?? 0)
    }
    while await harness.volume.window.waiterCount() != 1 { await Task.yield() }
    #expect(queuedReply.get() == nil)

    let drain = SessionGate()
    await harness.volume.window.testingBeforeTerminalDrain { await drain.enter() }
    harness.daemon.emitAttachState(.degraded, detail: "authority unreachable")
    await drain.waitForEntries(1)
    #expect(await harness.core.client.isDetachingOrStopped)
    #expect(await harness.volume.window.waiterCount() == 1)
    #expect(queuedReply.get() == nil)
    #expect(await harness.daemon.stats().getAttrRequests == 0)

    // The event consumer has not failed/drained the window. Already completed
    // publications still lose to the client's terminal transition itself.
    try await expectHeldCallbacksRevoked(held, harness, errno: EIO)
    #expect(await harness.volume.window.waiterCount() == 1)
    await drain.release()
    #expect(await queuedReply.wait() == Int(EIO))

    let laterReply = SessionReplyBox<Int>()
    harness.volume.getAttributes(FSItem.GetAttributesRequest(), of: harness.root) { _, error in
        laterReply.set((error as NSError?)?.code ?? 0)
    }
    #expect(await laterReply.wait() == Int(EIO))
}

/// Loss of the bound socket revokes the publication of callbacks that
/// already hold their results, exactly as a degraded attach does.
@available(macOS 26.0, *)
@Test func connectionLossRevokesCompletedCallbacksBeforeTheirReply() async throws {
    let harness = try await makeSessionHarness(windowCapacity: 2)
    defer { harness.daemon.stop() }
    let held = try await holdCompletedCallbacks(harness)
    let drain = SessionGate()
    await harness.volume.window.testingBeforeTerminalDrain { await drain.enter() }
    harness.daemon.dropConnections()
    await drain.waitForEntries(1)
    #expect(await harness.core.client.isDetachingOrStopped)
    try await expectHeldCallbacksRevoked(held, harness, errno: EIO)
    await drain.release()
}

/// Volume teardown is the same terminal decision.
@available(macOS 26.0, *)
@Test func shutdownRevokesCompletedCallbacksBeforeTheirReply() async throws {
    let harness = try await makeSessionHarness(windowCapacity: 2)
    defer { harness.daemon.stop() }
    let held = try await holdCompletedCallbacks(harness)
    let drain = SessionGate()
    await harness.volume.window.testingBeforeTerminalDrain { await drain.enter() }
    let shutdown = Task { await harness.volume.shutdown() }
    await drain.waitForEntries(1)
    try await expectHeldCallbacksRevoked(held, harness, errno: EIO)
    await drain.release()
    await shutdown.value
}

/// Core teardown does not pass through PortableFSVolume.shutdown. It must
/// revoke synchronously before its first actor hop to close the client.
@available(macOS 26.0, *)
@Test func coreShutdownRevokesCompletedCallbacksBeforeTheMonitorDrains() async throws {
    let harness = try await makeSessionHarness(windowCapacity: 2)
    defer { harness.daemon.stop() }
    let held = try await holdCompletedCallbacks(harness)
    let drain = SessionGate()
    await harness.volume.window.testingBeforeTerminalDrain { await drain.enter() }
    await harness.core.shutdown()
    await drain.waitForEntries(1)
    try await expectHeldCallbacksRevoked(held, harness, errno: EIO)
    await drain.release()
}

/// A malformed wire reply ends the same session, without waiting for the
/// event consumer. Later shutdown must retain the original defect.
@available(macOS 26.0, *)
@Test func protocolDefectRevokesCompletedCallbacksBeforeTheMonitorDrains() async throws {
    let harness = try await makeSessionHarness(windowCapacity: 2)
    defer { harness.daemon.stop() }
    let held = try await holdCompletedCallbacks(harness)
    let drain = SessionGate()
    await harness.volume.window.testingBeforeTerminalDrain { await drain.enter() }
    await harness.daemon.transformNextReply { envelope in
        guard case .statfsReply? = envelope.body,
              var bytes = try? envelope.serializedData() else { return nil }
        bytes.append(contentsOf: [0x20, 0x01]) // Removed envelope field 4.
        return try? PfsEnvelope(serializedBytes: bytes)
    }
    await #expect(throws: PfsLocalClientError.invalidFrame(
        "envelope carries a field outside pfslocal 2.0"
    )) { _ = try await harness.core.statfs() }
    await drain.waitForEntries(1)
    await harness.core.client.close()
    try await expectHeldCallbacksRevoked(held, harness, errno: EINVAL)
    await drain.release()
}

/// The native synchronize probe, with continuation handshakes in place of
/// sleeps: hold its Statfs dispatch after a successful authority barrier,
/// start real volume shutdown, then release the dispatch after revocation.
@available(macOS 26.0, *)
@Test func nativeSynchronizeCannotSucceedAfterShutdownWinsItsReply() async throws {
    let armed = SessionReplyBox<Bool>()
    let statfsReached = SessionReplyBox<Bool>()
    let releaseStatfs = DispatchSemaphore(value: 0)
    var configuration = PfsLocalClient.Configuration()
    configuration.traceObserver = { record in
        if record.event == .dispatched, record.value("kind") == "statfs", armed.get() == true {
            statfsReached.set(true)
            releaseStatfs.wait()
        }
    }
    let harness = try await makeSessionHarness(clientConfiguration: configuration)
    defer { harness.daemon.stop() }
    armed.set(true)
    let synchronize = Task { () -> Int in
        do { try await harness.volume.synchronize(flags: .wait); return 0 }
        catch { return (error as NSError).code }
    }
    _ = await statfsReached.wait()
    #expect(await harness.daemon.stats().syncVolumeRequests == 1)
    let shuttingDown = SessionReplyBox<Bool>()
    await harness.volume.window.testingBeforeTerminalDrain { shuttingDown.set(true) }
    let shutdown = Task { await harness.volume.shutdown() }
    _ = await shuttingDown.wait()
    #expect(await harness.volume.window.isFailed())
    releaseStatfs.signal()
    #expect(await synchronize.value == Int(EIO))
    await shutdown.value
    #expect(await harness.core.client.isDetachingOrStopped)
    #expect(await harness.volume.window.admittedCount() == 0)
}

/// Removing try? alone cannot close the native publication race. This
/// variant holds an actual successful Statfs response before returning it
/// to synchronize, so only its final gated reply can reject the result.
@available(macOS 26.0, *)
@Test func nativeSynchronizeRevokesItsSuccessfulStatfsResultAtFinalReply() async throws {
    let armed = SessionReplyBox<Bool>()
    let statfsID = SessionReplyBox<String>()
    let statfsReplied = SessionReplyBox<Bool>()
    let releaseStatfs = DispatchSemaphore(value: 0)
    var configuration = PfsLocalClient.Configuration()
    configuration.traceObserver = { record in
        guard armed.get() == true else { return }
        if record.event == .dispatched, record.value("kind") == "statfs",
           let requestID = record.value("request_id") {
            statfsID.set(requestID)
        }
        if record.event == .replied, let requestID = statfsID.get(),
           record.value("request_id") == requestID {
            #expect(record.value("errno") == "0")
            statfsReplied.set(true)
            releaseStatfs.wait()
        }
    }
    let harness = try await makeSessionHarness(clientConfiguration: configuration)
    defer { harness.daemon.stop() }
    armed.set(true)
    let synchronize = Task { () -> Int in
        do { try await harness.volume.synchronize(flags: .wait); return 0 }
        catch { return (error as NSError).code }
    }
    _ = await statfsReplied.wait()
    #expect(await harness.daemon.stats().syncVolumeRequests == 1)
    await harness.volume.window.fail(PfsLocalClientError.daemon(
        errno: ENXIO, message: "session ended before synchronize reply"
    ))
    releaseStatfs.signal()
    #expect(await synchronize.value == Int(ENXIO))
    #expect(await harness.volume.window.admittedCount() == 0)
    await harness.volume.shutdown()
}

/// Statfs failure is part of synchronize's outcome, even after the durable
/// barrier succeeded. It must not become an optional statistics refresh.
@available(macOS 26.0, *)
@Test func nativeSynchronizePropagatesItsPostBarrierStatfsError() async throws {
    let harness = try await makeSessionHarness()
    defer { harness.daemon.stop() }
    await harness.daemon.transformNextReply { envelope in
        guard case .statfsReply? = envelope.body else { return nil }
        var response = envelope
        var error = PfsErrorReply()
        error.errno = EACCES
        error.message = "statfs refused"
        response.body = .error(error)
        return response
    }
    let reply = SessionReplyBox<Int>()
    harness.volume.synchronize(flags: .wait) { error in
        reply.set((error as NSError?)?.code ?? 0)
    }
    #expect(await reply.wait() == Int(EACCES))
    #expect(await harness.daemon.stats().syncVolumeRequests == 1)
    #expect(!(await harness.core.client.isDetachingOrStopped))
    try await harness.volume.synchronize(flags: .wait)
    #expect(await harness.daemon.stats().syncVolumeRequests == 2)
    await harness.volume.shutdown()
}

/// Construction saves a root but does not authorize later activation or
/// mounting. Both native reply handlers must reenter the publication gate.
@available(macOS 26.0, *)
@Test func nativeLifecycleCallbacksRejectTerminationBeforeActivation() async throws {
    let harness = try await makeSessionHarness()
    defer { harness.daemon.stop() }
    let options = try #require(class_createInstance(FSTaskOptions.self, 0) as? FSTaskOptions)
    #expect(try await harness.volume.activate(options: options) === harness.root)
    try await harness.volume.mount(options: options)

    let cause = PfsLocalClientError.daemon(errno: ENXIO, message: "session ended before activation")
    await harness.core.client.close(error: cause)
    await #expect(throws: cause) { _ = try await harness.core.rootItem() }
    let activate = SessionReplyBox<Int>()
    harness.volume.activate(options: options) { item, error in
        #expect(item == nil)
        activate.set((error as NSError?)?.code ?? 0)
    }
    let mount = SessionReplyBox<Int>()
    harness.volume.mount(options: options) { error in
        mount.set((error as NSError?)?.code ?? 0)
    }
    let synchronize = SessionReplyBox<Int>()
    harness.volume.synchronize(flags: .wait) { error in
        synchronize.set((error as NSError?)?.code ?? 0)
    }
    #expect(await activate.wait() == Int(ENXIO))
    #expect(await mount.wait() == Int(ENXIO))
    #expect(await synchronize.wait() == Int(ENXIO))
    #expect(await harness.daemon.stats().syncVolumeRequests == 0)
    await harness.volume.shutdown()
    let client = await harness.core.client
    #expect(client.publicationGate.terminalError as? PfsLocalClientError == cause)
}

/// loadResource may resume its factory after the constructed volume has
/// ended. Its final framework reply shares the session gate too.
@available(macOS 26.0, *)
@Test func loadResourceRejectsTerminationAfterVolumeConstruction() async throws {
    let harness = try await makeSessionHarness()
    defer { harness.daemon.stop() }
    let factory = SessionGate()
    let socketPath = harness.daemon.socketPath
    let fileSystem = PortableFSFileSystem(
        moduleIdentity: PortableFSIdentity.moduleIdentity,
        resolverFactory: {
            PfsSocketPathResolver(infoDictionary: ["PFSDaemonSocketPath": socketPath])
        },
        volumeFactory: { _, _, _ in
            await factory.enter()
            return harness.volume
        }
    )
    let options = try #require(class_createInstance(FSTaskOptions.self, 0) as? FSTaskOptions)
    let resource = FSGenericURLResource(url: try #require(URL(string: "dev.portablefs.oss://mock")))
    let reply = SessionReplyBox<Int>()
    fileSystem.loadResource(resource: resource, options: options) { volume, error in
        #expect(volume == nil)
        reply.set((error as NSError?)?.code ?? 0)
    }
    await factory.waitForEntries(1)
    await harness.core.client.close()
    await factory.release()
    #expect(await reply.wait() == Int(EIO))
    await harness.volume.shutdown()
}

/// The terminal decision alone settles the losing callback's publication
/// unit as unpublished. The window is failed here with the session still
/// connected, so the daemon itself observes the verdicts: a not-published
/// acknowledgement for each operation and zero accepted items for the
/// provisional lookup result. A callback settled while the window is live
/// publishes as before.
@available(macOS 26.0, *)
@Test func aPublicationThatLosesToTerminalFailureSettlesUnpublished() async throws {
    let harness = try await makeSessionHarness(windowCapacity: 2)
    defer { harness.daemon.stop() }
    let core = harness.core
    let root = harness.root

    await harness.daemon.resetStats()
    let liveReply = SessionReplyBox<Int>()
    harness.volume.testOnlyPublishAfterReply(operation: {
        try await core.getattr(item: root)
    }, reply: { result in liveReply.set(replyErrno(result)) })
    #expect(try await waitUntil { liveReply.get() != nil })
    #expect(liveReply.get() == 0)
    #expect(try await waitUntil { await harness.daemon.stats().publicationAcks == 1 })
    #expect(await harness.daemon.stats().publishedPublicationAcks == 1)

    let held = try await holdCompletedCallbacks(harness)
    await harness.daemon.resetStats()
    await harness.volume.window.fail(PfsLocalClientError.shutdown)
    // The socket remains connected so the daemon can observe unpublished verdicts.
    try await expectHeldCallbacksRevoked(held, harness, errno: EIO)

    #expect(try await waitUntil { await harness.daemon.stats().publicationAcks == 2 })
    let stats = await harness.daemon.stats()
    #expect(stats.publishedPublicationAcks == 0)
    #expect(stats.notPublishedPublicationAcks == 2)
    #expect(stats.resourceAcceptedItemCounts == [0])
}

@available(macOS 26.0, *)
@Test func detachingAttachStateRefusesLaterCallbacksWithENXIO() async throws {
    let harness = try await makeSessionHarness()
    defer { harness.daemon.stop() }
    harness.daemon.emitAttachState(.detaching)
    #expect(try await waitUntil { await harness.volume.window.isFailed() })
    let reply = SessionReplyBox<Int>()
    harness.volume.lookupItem(named: FSFileName(string: "any"), inDirectory: harness.root) { _, _, error in
        reply.set((error as NSError?)?.code ?? 0)
    }
    #expect(try await waitUntil { reply.get() != nil })
    #expect(reply.get() == Int(ENXIO))
    #expect(await harness.daemon.stats().lookupRequests == 0)
}

/// Loss of the bound connection is the terminal signal: in-flight callbacks
/// fail, the window fails, and the volume never reconnects to a successor.
@available(macOS 26.0, *)
@Test func connectionLossEndsTheVolumeSessionWithoutReconnect() async throws {
    let harness = try await makeSessionHarness(
        daemonConfiguration: .init(lookupNoReplyNames: ["parked"])
    )
    defer { harness.daemon.stop() }
    let parkedReply = SessionReplyBox<Int>()
    harness.volume.lookupItem(named: FSFileName(string: "parked"), inDirectory: harness.root) { _, _, error in
        parkedReply.set((error as NSError?)?.code ?? 0)
    }
    #expect(try await waitUntil { await harness.daemon.stats().lookupRequests == 1 })

    harness.daemon.dropConnections()
    #expect(try await waitUntil { parkedReply.get() != nil })
    #expect(parkedReply.get() == Int(EIO))
    #expect(try await waitUntil { await harness.volume.window.isFailed() })

    let laterReply = SessionReplyBox<Int>()
    harness.volume.getAttributes(FSItem.GetAttributesRequest(), of: harness.root) { _, error in
        laterReply.set((error as NSError?)?.code ?? 0)
    }
    #expect(try await waitUntil { laterReply.get() != nil })
    #expect(laterReply.get() == Int(EIO))
    #expect(await harness.daemon.stats().helloRequests == 1)
}

/// Volume teardown takes the same terminal path.
@available(macOS 26.0, *)
@Test func unmountFailsTheWindowAndClosesTheSession() async throws {
    let harness = try await makeSessionHarness()
    defer { harness.daemon.stop() }
    await harness.volume.unmount()
    #expect(await harness.volume.window.isFailed())
    #expect(await harness.core.client.isDetachingOrStopped)
    #expect(harness.root.reclaimed)
}

/// Names the deleted repair machinery once reserved are ordinary names now:
/// they reach the daemon like any other legal component.
@available(macOS 26.0, *)
@Test func formerlyReservedRepairNamesAreOrdinaryNames() async throws {
    let harness = try await makeSessionHarness()
    defer { harness.daemon.stop() }
    let name = FSFileName(string: ".portablefs-v3-r1-0123456789abcdef")
    let (item, created) = try await harness.volume.createItem(
        named: name,
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    #expect(created.data == name.data)
    let (found, _) = try await harness.volume.lookupItem(named: name, inDirectory: harness.root)
    #expect(found === item)
    let renamed = FSFileName(string: ".portablefs-v3-r1-renamed")
    _ = try await harness.volume.renameItem(
        item,
        inDirectory: harness.root,
        named: name,
        to: renamed,
        inDirectory: harness.root,
        overItem: nil
    )
    try await harness.volume.removeItem(item, named: renamed, fromDirectory: harness.root)
    let stats = await harness.daemon.stats()
    #expect(stats.createRequests == 1)
    #expect(stats.lookupRequests == 1)
    #expect(stats.renameRequests == 1)
    #expect(stats.removeRequests == 1)
}

/// The fixed xattr-set refusal never enters the window or ordered
/// publication: it replies even while every window slot is held, sends no
/// request and owes no publication acknowledgement. Its precedence is
/// malformed (EINVAL), then stale item (ESTALE), then Darwin's EOPNOTSUPP.
@available(macOS 26.0, *)
@Test func xattrSetRefusalRepliesOutsideTheWindowWithFixedPrecedence() async throws {
    let harness = try await makeSessionHarness(windowCapacity: 1)
    defer { harness.daemon.stop() }
    let (created, _) = try await harness.volume.createItem(
        named: FSFileName(string: "xattr-read-only"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let item = try #require(created as? PortableFSItem)
    let (staleCreated, _) = try await harness.volume.createItem(
        named: FSFileName(string: "xattr-stale"),
        type: .file,
        inDirectory: harness.root,
        attributes: FSItem.SetAttributesRequest()
    )
    let staleItem = try #require(staleCreated as? PortableFSItem)
    try await harness.core.reclaim(item: staleItem)
    #expect(try await waitUntil { await harness.daemon.stats().publicationAcks >= 2 })
    await harness.daemon.resetStats()

    let gate = SessionGate()
    harness.volume.testOnlyPublishAfterReply(operation: { await gate.enter() }, reply: { _ in })
    #expect(try await waitUntil { await gate.enteredCount() == 1 })

    func setXattrErrno(
        _ name: FSFileName,
        on target: FSItem,
        policy: FSVolume.SetXattrPolicy
    ) async throws -> Int? {
        let reply = SessionReplyBox<Int>()
        harness.volume.setXattr(named: name, to: Data("value".utf8), on: target, policy: policy) { error in
            reply.set((error as NSError?)?.code ?? 0)
        }
        _ = try await waitUntil { reply.get() != nil }
        return reply.get()
    }

    for policy: FSVolume.SetXattrPolicy in [.mustCreate, .mustReplace, .alwaysSet] {
        #expect(try await setXattrErrno(FSFileName(string: "user.test"), on: item, policy: policy)
            == Int(EOPNOTSUPP))
        #expect(try await setXattrErrno(FSFileName(string: "user.test"), on: staleItem, policy: policy)
            == Int(ESTALE))
    }
    // A foreign FSItem is stale too, and still loses to malformed syntax.
    let foreignItem = FSItem()
    #expect(try await setXattrErrno(FSFileName(string: "user.test"), on: foreignItem, policy: .alwaysSet)
        == Int(ESTALE))
    for target in [staleItem, foreignItem] {
        #expect(try await setXattrErrno(FSFileName(data: Data([0xff])), on: target, policy: .alwaysSet)
            == Int(EINVAL))
        #expect(try await setXattrErrno(
            FSFileName(string: String(repeating: "x", count: 256)),
            on: target,
            policy: .alwaysSet
        ) == Int(EINVAL))
    }

    #expect(await harness.volume.window.waiterCount() == 0)
    #expect(await harness.volume.window.admittedCount() == 1)
    await gate.release()
    #expect(try await waitUntil { await harness.volume.window.admittedCount() == 0 })
    let stats = await harness.daemon.stats()
    #expect(stats.publicationAcks == 0)
    #expect(stats.getAttrRequests == 0)
    #expect(stats.xattrGetRequests == 0)
    #expect(stats.xattrRemoveRequests == 0)
}
}
