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
