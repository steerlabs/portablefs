import Foundation
import FSKit
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

// The request trace joins FSKit callbacks to pfslocal requests by explicit
// labels. Two volume sessions in one process restart request and operation
// numbering at 1, so a join on bare numbers would be ambiguous; these tests
// read every record through one process-wide sink and require each join to
// be exact.

private final class TraceLog: @unchecked Sendable {
    private let lock = NSLock()
    private var records: [PfsTraceRecord] = []

    func append(_ record: PfsTraceRecord) {
        lock.lock()
        records.append(record)
        lock.unlock()
    }

    func all() -> [PfsTraceRecord] {
        lock.lock()
        defer { lock.unlock() }
        return records
    }
}

private final class TraceReplyBox<Value>: @unchecked Sendable {
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

private func waitForReply<Value>(_ box: TraceReplyBox<Value>) async throws -> Value {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(10))
    while clock.now < deadline {
        if let value = box.get() { return value }
        try await Task.sleep(for: .milliseconds(2))
    }
    throw PfsLocalClientError.timeout
}

/// Drives one volume through real FSKit callback entry points: a create
/// (resource-bearing), an open that reuses the creation description (an OPEN
/// decision) and a burst of concurrent getattr callbacks.
@available(macOS 26.0, *)
private func driveTracedCallbacks(_ volume: PortableFSVolume, root: FSItem, getattrs: Int) async throws {
    let created = TraceReplyBox<(item: FSItem?, errno: Int)>()
    volume.createItem(
        named: FSFileName(string: "traced"),
        type: .file,
        inDirectory: root,
        attributes: FSItem.SetAttributesRequest()
    ) { item, _, error in
        created.set((item, (error as NSError?)?.code ?? 0))
    }
    let item = try #require(try await waitForReply(created).item)

    let opened = TraceReplyBox<Int>()
    volume.openItem(item, modes: [.read]) { error in
        opened.set((error as NSError?)?.code ?? 0)
    }
    #expect(try await waitForReply(opened) == 0)

    let replies = (0..<getattrs).map { _ in TraceReplyBox<Int>() }
    let request = FSItem.GetAttributesRequest()
    request.wantedAttributes = [.type, .fileID]
    for reply in replies {
        volume.getAttributes(request, of: item) { _, error in
            reply.set((error as NSError?)?.code ?? 0)
        }
    }
    for reply in replies {
        #expect(try await waitForReply(reply) == 0)
    }
}

private struct RequestKey: Hashable {
    let connection: String
    let id: String
}

extension PfsLocalMockDaemonTests {
@available(macOS 26.0, *)
@Test func requestTraceJoinsCallbacksAcrossConcurrentSessionsWithOverlappingIDs() async throws {
    let log = TraceLog()
    var configuration = PfsLocalClient.Configuration(clientName: "portablefskit-trace-test")
    configuration.traceObserver = { log.append($0) }
    let refs = ["trace-a", "trace-b"]
    let daemons = try refs.map { ref in
        try PfsLocalMockDaemon(configuration: .init(attachRef: ref))
    }
    defer { for daemon in daemons { daemon.stop() } }
    var volumes: [PortableFSVolume] = []
    for (daemon, ref) in zip(daemons, refs) {
        let core = try await VolumeCore.connect(
            socketPath: daemon.socketPath,
            attachRef: ref,
            configuration: configuration
        )
        volumes.append(try await PortableFSVolume.make(core: core, attachRef: ref))
    }
    let getattrs = 4
    let callbacksPerVolume = 2 + getattrs
    try await withThrowingTaskGroup(of: Void.self) { group in
        for volume in volumes {
            let root = try await volume.core.rootItem()
            group.addTask { try await driveTracedCallbacks(volume, root: root, getattrs: getattrs) }
        }
        try await group.waitForAll()
    }
    // Publication verdicts follow the FSKit replies; let them land.
    let clock = ContinuousClock()
    let settle = clock.now.advanced(by: .seconds(5))
    while clock.now < settle {
        let finished = log.all().filter { $0.event == .callbackFinished }.count
        let acks = log.all().filter { $0.event == .publicationAck }.count
        let operations = log.all().filter { $0.event == .callbackOperation }.count
        if finished == 2 * callbacksPerVolume, acks >= operations { break }
        try await Task.sleep(for: .milliseconds(2))
    }
    for volume in volumes { await volume.shutdown() }

    let records = log.all()
    func of(_ event: PfsTraceRecord.Event) -> [PfsTraceRecord] {
        records.filter { $0.event == event }
    }

    // Every record names its connection, and exactly the two sessions appear.
    #expect(records.allSatisfy { !$0.connection.isEmpty })
    let connections = Set(records.map(\.connection))
    #expect(connections.count == 2)

    // The bare numbers collide across sessions, so only labels can join them.
    let dispatched = of(.dispatched)
    // The daemon join is explicit and uses the exact Hello client_name.
    // Hello precedes Resolve and therefore has no attach_ref yet. Resolve
    // itself and every subsequent request carry the requested attachment.
    let requestRecords = dispatched + of(.replied) + of(.disposition) + of(.publicationAck)
    for record in requestRecords {
        #expect(record.value("frontend_pid") == String(getpid()))
        #expect(record.value("conn_role") == configuration.clientName)
        #expect(record.value("request_id") != nil)
        if record.value("attach_ref") == "" {
            let hello = dispatched.first {
                $0.connection == record.connection && $0.value("kind") == "hello"
            }
            #expect(record.value("request_id") == hello?.value("request_id"))
        } else {
            #expect(refs.contains(record.value("attach_ref") ?? ""))
        }
    }
    let resolved = dispatched.filter { $0.value("kind") == "resolve" }
    #expect(Set(resolved.compactMap { $0.value("attach_ref") }) == Set(refs))
    // Ignore the pre-Resolve handshake when checking the cross-process key.
    let daemonKeys = dispatched.filter { $0.value("attach_ref") != "" }.map { record in
        ["frontend_pid", "attach_ref", "conn_role", "request_id"].map { key in
            record.value(key) ?? ""
        }.joined(separator: "/")
    }
    #expect(Set(daemonKeys).count == daemonKeys.count)
    func numbers(_ records: [PfsTraceRecord], _ key: String, on connection: String) -> Set<String> {
        Set(records.filter { $0.connection == connection }.compactMap { $0.value(key) })
    }
    let labels = Array(connections)
    #expect(!numbers(dispatched, "request_id", on: labels[0])
        .intersection(numbers(dispatched, "request_id", on: labels[1])).isEmpty)
    #expect(!numbers(of(.callbackOperation), "operation", on: labels[0])
        .intersection(numbers(of(.callbackOperation), "operation", on: labels[1])).isEmpty)

    // Requests are unique per (connection, request); replies and dispositions
    // join to exactly one of them.
    var requests: [RequestKey: PfsTraceRecord] = [:]
    for record in dispatched {
        let key = RequestKey(connection: record.connection, id: record.value("request_id") ?? "")
        #expect(requests.updateValue(record, forKey: key) == nil, "duplicate request \(key)")
    }
    for record in of(.replied) + of(.disposition) {
        let key = RequestKey(connection: record.connection, id: record.value("request_id") ?? "")
        #expect(requests[key] != nil, "unjoined \(record.message)")
    }

    // Callback labels are process-unique, each callback began and finished on
    // its own connection, and each binds at most one operation.
    let began = of(.callbackBegan)
    var callbackConnection: [String: String] = [:]
    for record in began {
        let label = try #require(record.value("callback"))
        #expect(label != "0")
        #expect(callbackConnection.updateValue(record.connection, forKey: label) == nil)
    }
    #expect(began.count == 2 * callbacksPerVolume)
    for connection in connections {
        #expect(began.filter { $0.connection == connection }.count == callbacksPerVolume)
    }
    for record in of(.callbackFinished) {
        #expect(callbackConnection[record.value("callback") ?? ""] == record.connection)
        #expect(record.value("outcome") == "success")
    }
    var operationCallback: [RequestKey: String] = [:]
    var boundCallbacks = Set<String>()
    for record in of(.callbackOperation) {
        let label = record.value("callback") ?? ""
        #expect(callbackConnection[label] == record.connection, "operation of a foreign callback")
        #expect(boundCallbacks.insert(label).inserted, "callback bound twice")
        let key = RequestKey(connection: record.connection, id: record.value("operation") ?? "")
        #expect(operationCallback.updateValue(label, forKey: key) == nil)
    }

    // Each callback request joins to its callback on the same connection and,
    // when it carries an operation, to that callback's single association.
    for record in dispatched where record.value("callback") != "0" {
        let label = record.value("callback") ?? ""
        #expect(callbackConnection[label] == record.connection)
        if let operation = record.value("operation"), operation != "0" {
            #expect(operationCallback[RequestKey(connection: record.connection, id: operation)] == label)
        }
    }
    // Every getattr callback reached exactly one getattr request.
    for record in began where record.value("kind")?.hasPrefix("getAttributes") == true {
        let label = record.value("callback") ?? ""
        #expect(dispatched.filter { $0.value("callback") == label && $0.value("kind") == "getattr" }.count == 1)
    }
    // Every acknowledgement joins to one operation dispatched on its own
    // connection; a callback's acknowledgement joins to that callback.
    for record in of(.publicationAck) {
        let operation = record.value("operation") ?? ""
        let carriers = dispatched.filter { $0.connection == record.connection && $0.value("operation") == operation }
        #expect(!carriers.isEmpty, "unjoined \(record.message)")
        if carriers.contains(where: { $0.value("callback") != "0" }) {
            #expect(operationCallback[RequestKey(connection: record.connection, id: operation)] != nil)
        }
    }
    // OPEN decisions name their connection and their callback.
    let openDecisions = of(.openDecision)
    for connection in connections {
        #expect(!openDecisions.filter { $0.connection == connection }.isEmpty)
    }
    for record in openDecisions {
        #expect(callbackConnection[record.value("callback") ?? ""] == record.connection)
    }
}
}

// This boundary counts every pfslocal request emitted by a real callback.
// v3trips_test.go reconciles lookup/getattr with the daemon's 0/1 authority
// paths, and close/reclaim with held background authority releases. The mock
// does not model authority caching: a local lookup/getattr is still one local
// request. Keeping both boundaries explicit catches an extra Swift OPEN or
// STATFS without inventing an authority simulator here.
@available(macOS 26.0, *)
private final class CallbackTripFixture {
    let log: TraceLog
    let daemon: PfsLocalMockDaemon
    let volume: PortableFSVolume
    let root: FSItem

    init(adapter: PortableFSVolume.Type = PortableFSVolumeV2.self) async throws {
        let log = TraceLog()
        var configuration = PfsLocalClient.Configuration(clientName: "callback-trips")
        configuration.traceObserver = { log.append($0) }
        let daemon = try PfsLocalMockDaemon(configuration: .init(attachRef: "callback-trips"))
        self.log = log
        self.daemon = daemon
        let core = try await VolumeCore.connect(
            socketPath: daemon.socketPath, attachRef: "callback-trips", configuration: configuration
        )
        volume = try await PortableFSVolume.make(core: core, attachRef: "callback-trips", adapter: adapter)
        // No mounted kernel participates in this socket test. Withdrawal calls
        // are covered separately by PfsKernelCacheTests.
        volume.kernelCache?.install { _, _ in nil }
        root = try await core.rootItem()
    }

    // Associate the exact ordered request list with one callback label, including
    // requests with operation 0. Filtering by operation alone would miss STATFS.
    func step<Value>(
        _ expected: [String],
        invoke: (@escaping (Result<Value, Error>) -> Void) -> Void
    ) async throws -> Value {
        let before = log.all().count
        let reply = TraceReplyBox<Result<Value, Error>>()
        invoke { reply.set($0) }
        let result = try await waitForReply(reply).get()
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while ContinuousClock.now < deadline {
            if log.all().dropFirst(before).contains(where: { $0.event == .callbackFinished }) { break }
            try await Task.sleep(for: .milliseconds(2))
        }
        let records = Array(log.all().dropFirst(before))
        let began = records.filter { $0.event == .callbackBegan }
        #expect(began.count == 1)
        let label = try #require(began.first?.value("callback"))
        let requests = records.filter { $0.event == .dispatched }
        #expect(requests.allSatisfy { $0.value("callback") == label })
        #expect(requests.compactMap { $0.value("kind") } == expected)
        #expect(records.contains { $0.event == .callbackFinished && $0.value("callback") == label && $0.value("outcome") == "success" })
        return result
    }

    func create(_ name: String, type: FSItem.ItemType = .file) async throws -> FSItem {
        try await step([type == .directory ? "mkdir" : "create"]) { finish in
            volume.createItem(named: FSFileName(string: name), type: type, inDirectory: root,
                              attributes: FSItem.SetAttributesRequest()) { item, _, error in
                if let error { finish(.failure(error)) }
                else if let item { finish(.success(item)) }
                else { finish(.failure(PfsLocalClientError.unexpectedReply("create omitted item"))) }
            }
        }
    }

    func lookup(_ name: String) async throws -> FSItem {
        try await step(["lookup"]) { finish in
            volume.lookupItem(named: FSFileName(string: name), inDirectory: root) { item, _, error in
                if let error { finish(.failure(error)) }
                else if let item { finish(.success(item)) }
                else { finish(.failure(PfsLocalClientError.unexpectedReply("lookup omitted item"))) }
            }
        }
    }

    func open(_ item: FSItem, expected: [String]) async throws {
        try await step(expected) { finish in
            if #available(macOS 27, *), let v3 = volume as? PortableFSVolumeV3 {
                v3.cacheOpen(item, modes: [.read], cacheMode: .none) { grant, error in
                    #expect(grant == .noCache)
                    finish(error.map { .failure($0) } ?? .success(()))
                }
            } else {
                volume.openItem(item, modes: [.read]) { error in
                    finish(error.map { .failure($0) } ?? .success(()))
                }
            }
        }
    }

    func close(_ item: FSItem, expected: [String] = ["close"]) async throws {
        try await step(expected) { finish in
            if #available(macOS 27, *), let v3 = volume as? PortableFSVolumeV3 {
                v3.finalClose(item) { finish(.success(())) }
            } else {
                volume.closeItem(item, modes: []) { error in
                    finish(error.map { .failure($0) } ?? .success(()))
                }
            }
        }
    }
}

extension PfsLocalMockDaemonTests {
@available(macOS 26.0, *)
@Test func callbackTripCountsAndGitObjectChain() async throws {
    try await checkCallbackTripCountsAndGitObjectChain(adapter: PortableFSVolumeV2.self)
}

@available(macOS 27.0, *)
@Test func v3CallbackTripCountsAndGitObjectChain() async throws {
    try await checkCallbackTripCountsAndGitObjectChain(adapter: PortableFSVolumeV3.self)
}

@available(macOS 26.0, *)
private func checkCallbackTripCountsAndGitObjectChain(adapter: PortableFSVolume.Type) async throws {
    let f = try await CallbackTripFixture(adapter: adapter)
    #expect(type(of: f.volume) == adapter)
    defer { f.daemon.stop() }
    let item = try await f.create("temporary")
    // CREATE's description covers this open; no request of any kind is allowed.
    try await f.open(item, expected: [])
    let request = FSItem.GetAttributesRequest()
    request.wantedAttributes = [.type, .fileID]
    try await f.step(["getattr"]) { finish in
        f.volume.getAttributes(request, of: item) { _, error in
            finish(error.map { .failure($0) } ?? .success(()))
        }
    }
    let written: Int = try await f.step(["write"]) { finish in
        f.volume.write(contents: Data("abc".utf8), to: item, at: 0) { count, error in
            finish(error.map { .failure($0) } ?? .success(count))
        }
    }
    #expect(written == 3)
    // Exercise the adapter's shared request body and publication path; only
    // copying into FSKit's unconstructible buffer stays outside this seam.
    let read: Data = try await f.step(["read"]) { finish in
        f.volume.testOnlyPublishAfterReply(operation: {
            try await f.volume.readData(from: item, at: 0, length: 3)
        }, reply: finish)
    }
    #expect(read == Data("abc".utf8))
    try await f.close(item)
    try await f.step(["link"]) { finish in
        f.volume.createLink(to: item, named: FSFileName(string: "object"), inDirectory: f.root) { _, error in
            finish(error.map { .failure($0) } ?? .success(()))
        }
    }
    // Both local requests map to zero authority trips in TestV3GitObjectAuthorityChain.
    let temporary = try await f.lookup("temporary")
    let alias = try await f.lookup("object")
    #expect(temporary === alias)
    try await f.step(["remove"]) { finish in
        f.volume.removeItem(item, named: FSFileName(string: "temporary"), fromDirectory: f.root) { error in
            finish(error.map { .failure($0) } ?? .success(()))
        }
    }
    _ = try await f.lookup("object")
    // No retained description after close: exactly one real OPEN is required.
    try await f.open(alias, expected: ["open"])
    if f.volume.kernelCache == nil { try await f.close(alias) }
    try await f.step(["rename"]) { finish in
        f.volume.renameItem(alias, inDirectory: f.root, named: FSFileName(string: "object"),
                            to: FSFileName(string: "renamed"), inDirectory: f.root, overItem: nil) { _, error in
            finish(error.map { .failure($0) } ?? .success(()))
        }
    }
    _ = try await f.create("directory", type: .directory)
    try await f.step(["sync-volume", "statfs"]) { finish in
        f.volume.synchronize(flags: .wait) { error in
            finish(error.map { .failure($0) } ?? .success(()))
        }
    }
    let portable = try #require(alias as? PortableFSItem)
    if #available(macOS 27, *), f.volume is PortableFSVolumeV3 {
        // Direct callbacks do not pass through FSKit's kernel-count bookkeeping.
        // The real tryReclaim refuses this attempt. It must retain canonical
        // identity and the open description, with no CLOSE or RECLAIM request.
        try await f.step([]) { finish in
            f.volume.reclaimItem(alias) { error in
                finish(error.map { .failure($0) } ?? .success(()))
            }
        }
        #expect(!portable.reclaimed)
        #expect(await f.volume.core.testingDebugState().openHandleCount == 1)
        #expect(try await f.lookup("renamed") === alias)
        let retained: Data = try await f.step(["read"]) { finish in
            f.volume.testOnlyPublishAfterReply(operation: {
                try await f.volume.readData(from: alias, at: 0, length: 3)
            }, reply: finish)
        }
        #expect(retained == Data("abc".utf8))
        // Final close releases the retained description exactly once, even if
        // cleanup is reentered. The item capability still awaits agreed reclaim.
        try await f.close(alias)
        try await f.close(alias, expected: [])
        #expect(await f.volume.core.testingDebugState().openHandleCount == 0)
        #expect(!portable.reclaimed)
        // Model the later kernel/user count agreement at the sole SDK seam.
        // All core retirement and real socket requests remain under test.
        await f.volume.core.testingNativeReclaimCheck { item, retire in
            #expect(item === portable)
            #expect(!item.reclaimed)
            retire()
            return true
        }
    }
    try await f.step(["reclaim"]) { finish in
        f.volume.reclaimItem(alias) { error in
            finish(error.map { .failure($0) } ?? .success(()))
        }
    }
    #expect(portable.reclaimed)
    #expect(await f.daemon.stats().closeRequests == 2)
    #expect(await f.daemon.stats().reclaimRequests == 1)
    await f.volume.shutdown()
    #expect(await f.daemon.stats().closeRequests == 2)
    #expect(await f.daemon.stats().reclaimRequests == 1)
}
}

extension PfsLocalMockDaemonTests {
@available(macOS 26.0, *)
@Test func disjointCallbackTripsReachDaemonBeforeEitherReply() async throws {
    try await checkDisjointCallbackTrips(adapter: PortableFSVolumeV2.self)
}

@available(macOS 27.0, *)
@Test func v3DisjointCallbackTripsReachDaemonBeforeEitherReply() async throws {
    try await checkDisjointCallbackTrips(adapter: PortableFSVolumeV3.self)
}

@available(macOS 26.0, *)
private func checkDisjointCallbackTrips(adapter: PortableFSVolume.Type) async throws {
    let f = try await CallbackTripFixture(adapter: adapter)
    defer { f.daemon.stop() }
    let a = try #require(try await f.create("a") as? PortableFSItem)
    let b = try #require(try await f.create("b") as? PortableFSItem)
    let before = f.log.all().count
    let readsBefore = await f.daemon.stats().readRequests
    await f.daemon.pauseReads()
    let replies = [TraceReplyBox<Result<Data, Error>>(), TraceReplyBox<Result<Data, Error>>()]
    for (item, reply) in zip([a, b], replies) {
        f.volume.testOnlyPublishAfterReply(operation: {
            try await f.volume.readData(from: item, at: 0, length: 3)
        }, reply: { reply.set($0) })
    }
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    var arrived = 0
    while ContinuousClock.now < deadline {
        arrived = await f.daemon.stats().readRequests - readsBefore
        if arrived == 2 { break }
        try await Task.sleep(for: .milliseconds(2))
    }
    // The second request must reach real socket dispatch while the first is
    // still waiting. Time is only a deadlock bound, never a latency assertion.
    #expect(arrived == 2)
    #expect(replies.allSatisfy { $0.get() == nil })
    await f.daemon.resumeReads()
    for reply in replies {
        #expect(try await waitForReply(reply).get().isEmpty)
    }
    let records = Array(f.log.all().dropFirst(before))
    let requests = records.filter { $0.event == .dispatched }
    #expect(requests.compactMap { $0.value("kind") } == ["read", "read"])
    #expect(Set(requests.compactMap { $0.value("callback") }).count == 2)
    #expect(records.filter { $0.event == .callbackBegan }.count == 2)
    await f.volume.shutdown()
}
}

extension PfsLocalMockDaemonTests {
@available(macOS 26.0, *)
@Test func fixedXattrRefusalsHaveZeroCallbackTripsAndBoundedIdentityTrace() async throws {
    try await checkFixedXattrRefusals(adapter: PortableFSVolumeV2.self)
}

@available(macOS 27.0, *)
@Test func v3FixedXattrRefusalsHaveZeroCallbackTripsAndBoundedIdentityTrace() async throws {
    try await checkFixedXattrRefusals(adapter: PortableFSVolumeV3.self)
}

@available(macOS 26.0, *)
private func checkFixedXattrRefusals(adapter: PortableFSVolume.Type) async throws {
    let f = try await CallbackTripFixture(adapter: adapter)
    defer { f.daemon.stop() }
    let item = try await f.create("private-diagnostic-file")
    let portable = try #require(item as? PortableFSItem)
    // Use the real native entry points, including delete's setXattr entry.
    for name in ["com.apple.FinderInfo", "security.capability", "user.portablefs.secret"] {
        for deleting in [false, true] {
            let before = f.log.all().count
            let reply = TraceReplyBox<Int>()
            if deleting {
                f.volume.setXattr(named: FSFileName(string: name), to: nil, on: item, policy: .delete) { error in
                    reply.set((error as NSError?)?.code ?? 0)
                }
            } else {
                f.volume.getXattr(named: FSFileName(string: name), of: item) { _, error in
                    reply.set((error as NSError?)?.code ?? 0)
                }
            }
            #expect(try await waitForReply(reply) == Int(EOPNOTSUPP))
            let deadline = ContinuousClock.now.advanced(by: .seconds(5))
            while !f.log.all().dropFirst(before).contains(where: { $0.event == .callbackFinished }) {
                try #require(ContinuousClock.now < deadline)
                try await Task.sleep(for: .milliseconds(1))
            }
            let records = Array(f.log.all().dropFirst(before))
            #expect(records.filter { $0.event == .dispatched }.isEmpty)
            #expect(records.filter { $0.event == .callbackOperation }.isEmpty)
            let began = try #require(records.first { $0.event == .callbackBegan })
            #expect(began.value("item_local") == String(portable.identity.itemID))
            #expect(began.value("item_generation") == String(portable.identity.generation))
            #expect(began.value("item_file") == String(portable.fileID))
            #expect(began.value("pid") == "unavailable")
            #expect(began.value("name_token")?.count == 32)
            #expect(began.value("name_bytes") == String(name.utf8.count))
            #expect(records.allSatisfy { !$0.message.contains(name) })
            #expect(records.contains { $0.event == .callbackFinished && $0.value("outcome") == "preflight-refused" && $0.value("errno") == String(EOPNOTSUPP) })
        }
    }
    for policy: FSVolume.SetXattrPolicy in [.mustCreate, .mustReplace, .alwaysSet] {
        let before = f.log.all().count
        let reply = TraceReplyBox<Int>()
        f.volume.setXattr(named: FSFileName(string: "user.test"), to: Data([1]), on: item, policy: policy) { error in
            reply.set((error as NSError?)?.code ?? 0)
        }
        #expect(try await waitForReply(reply) == Int(EOPNOTSUPP))
        #expect(f.log.all().dropFirst(before).filter { $0.event == .dispatched }.isEmpty)
    }
    // Permitted names still use one local request for each native callback.
    try await f.daemon.seedXattr(named: "user.test", value: Data([7]), on: portable.identity)
    let value: Data = try await f.step(["xattr-get"]) { finish in
        f.volume.getXattr(named: FSFileName(string: "user.test"), of: item) { value, error in
            finish(error.map { .failure($0) } ?? .success(value ?? Data()))
        }
    }
    #expect(value == Data([7]))
    let _: [FSFileName] = try await f.step(["xattr-list"]) { finish in
        f.volume.listXattrs(of: item) { names, error in
            finish(error.map { .failure($0) } ?? .success(names ?? []))
        }
    }
    try await f.step(["xattr-remove"]) { finish in
        f.volume.setXattr(named: FSFileName(string: "user.test"), to: nil, on: item, policy: .delete) { error in
            finish(error.map { .failure($0) } ?? .success(()))
        }
    }
    _ = try await f.lookup("private-diagnostic-file")
    let before = f.log.all().count
    let _: FSItem.Attributes = try await f.step(["getattr"]) { finish in
        let request = FSItem.GetAttributesRequest()
        request.wantedAttributes = [.fileID, .type]
        f.volume.getAttributes(request, of: item) { attributes, error in
            if let error { finish(.failure(error)) }
            else if let attributes { finish(.success(attributes)) }
        }
    }
    let getattr = try #require(f.log.all().dropFirst(before).first { $0.event == .callbackBegan })
    #expect(getattr.value("item_file") == String(portable.fileID))
    #expect(getattr.value("wanted") != nil)
    let lookup = try #require(f.log.all().last { $0.event == .callbackBegan && $0.value("kind")?.hasPrefix("lookupItem") == true })
    #expect(lookup.value("parent_file") == String((f.root as? PortableFSItem)?.fileID ?? 0))
    #expect(lookup.value("name_token")?.count == 32)
    #expect(lookup.value("pid") == "unavailable")
    #expect(!lookup.message.contains("private-diagnostic-file"))
    let lookupResult = try #require(f.log.all().last { $0.event == .callbackFinished && $0.value("callback") == lookup.value("callback") })
    #expect(lookupResult.value("returned_local") == String(portable.identity.itemID))
    #expect(lookupResult.value("returned_generation") == String(portable.identity.generation))
    #expect(lookupResult.value("returned_file") == String(portable.fileID))
    await f.volume.shutdown()
}
}

@Test func metadataNameTokensAreBoundedAndStableWithinTheProcess() {
    let a = PfsMetadataTrace.name(Data("a b\nprivate".utf8))
    #expect(a == PfsMetadataTrace.name(Data("a b\nprivate".utf8)))
    #expect(a != PfsMetadataTrace.name(Data("different".utf8)))
    #expect(a.first?.value.count == 32)
    #expect(PfsMetadataTrace.name(Data(repeating: 65, count: 100_000)).first?.value.count == 32)
}
