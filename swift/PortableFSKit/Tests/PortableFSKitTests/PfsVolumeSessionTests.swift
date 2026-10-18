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

private final class SessionReplyBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value?

    func set(_ value: Value) {
        lock.lock()
        stored = value
        lock.unlock()
    }

    func get() -> Value? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }
}

/// Holds an injected callback operation inside its window slot until the
/// test releases it.
private actor SessionGate {
    private var open = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var entered = 0

    func enter() async {
        entered += 1
        if open { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func enteredCount() -> Int { entered }

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
    windowCapacity: Int = PfsCallbackWindow.defaultCapacity
) async throws -> SessionHarness {
    let daemon = try PfsLocalMockDaemon(configuration: daemonConfiguration)
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
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
        lookedUp: SessionReplyBox()
    )
    let core = harness.core
    let root = harness.root
    harness.volume.testOnlyPublishAfterReply(operation: {
        let attr = try await core.getattr(item: root)
        await held.gate.enter()
        return attr
    }, reply: { result in held.readReply.set(replyErrno(result)) })
    harness.volume.testOnlyPublishAfterReply(operation: {
        let found = try await core.lookup(in: root, name: Data("held".utf8))
        held.lookedUp.set(found.item)
        await held.gate.enter()
        return found.item
    }, reply: { result in held.lookupReply.set(replyErrno(result)) })
    #expect(try await waitUntil { await held.gate.enteredCount() == 2 })
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
    #expect(try await waitUntil { held.readReply.get() != nil && held.lookupReply.get() != nil })
    #expect(held.readReply.get() == Int(expected))
    #expect(held.lookupReply.get() == Int(expected))
    #expect(try await waitUntil { await harness.volume.window.admittedCount() == 0 })
    let item = try #require(held.lookedUp.get())
    #expect(try await waitUntil { item.reclaimed })
    #expect(await harness.core.testingDebugState().provisionalItemCount == 0)
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
    #expect(try await waitUntil { await harness.volume.window.waiterCount() == 1 })
    #expect(queuedReply.get() == nil)

    harness.daemon.emitAttachState(.degraded, detail: "authority unreachable")
    #expect(try await waitUntil { queuedReply.get() != nil })
    #expect(queuedReply.get() == Int(EIO))
    #expect(await harness.volume.window.isFailed())
    #expect(try await waitUntil { await harness.core.client.isDetachingOrStopped })
    #expect(await harness.daemon.stats().getAttrRequests == 0)

    let laterReply = SessionReplyBox<Int>()
    harness.volume.getAttributes(FSItem.GetAttributesRequest(), of: harness.root) { _, error in
        laterReply.set((error as NSError?)?.code ?? 0)
    }
    #expect(try await waitUntil { laterReply.get() != nil })
    #expect(laterReply.get() == Int(EIO))

    try await expectHeldCallbacksRevoked(held, harness, errno: EIO)
}

/// Loss of the bound socket revokes the publication of callbacks that
/// already hold their results, exactly as a degraded attach does.
@available(macOS 26.0, *)
@Test func connectionLossRevokesCompletedCallbacksBeforeTheirReply() async throws {
    let harness = try await makeSessionHarness(windowCapacity: 2)
    defer { harness.daemon.stop() }
    let held = try await holdCompletedCallbacks(harness)
    harness.daemon.dropConnections()
    #expect(try await waitUntil { await harness.volume.window.isFailed() })
    #expect(try await waitUntil { await harness.core.client.isDetachingOrStopped })
    try await expectHeldCallbacksRevoked(held, harness, errno: EIO)
}

/// Volume teardown is the same terminal decision.
@available(macOS 26.0, *)
@Test func shutdownRevokesCompletedCallbacksBeforeTheirReply() async throws {
    let harness = try await makeSessionHarness(windowCapacity: 2)
    defer { harness.daemon.stop() }
    let held = try await holdCompletedCallbacks(harness)
    await harness.volume.shutdown()
    try await expectHeldCallbacksRevoked(held, harness, errno: EIO)
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
    #expect(!(await harness.core.client.isDetachingOrStopped))
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
