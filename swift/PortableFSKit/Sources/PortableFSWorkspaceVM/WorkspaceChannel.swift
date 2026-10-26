import Foundation
import Darwin
import CryptoKit
@preconcurrency import Virtualization
import PortableFSWorkspaceCore

@MainActor public final class WorkspaceVsockChannel: WorkspaceGuestChannel {
    private struct Request {
        let body: WorkspaceEnvelope.OneOf_Body
        let desiredBody: WorkspaceEnvelope.OneOf_Body?
        let deadline: UInt64
        let completion: (Result<WorkspaceEnvelope, Error>) -> Void
    }
    private let vm: WorkspaceMachine?
    private var connection: VZVirtioSocketConnection?
    private var stream: WorkspaceStream?
    private var requestID: UInt64 = 0
    private var queue: [Request] = []
    private var active: Request?
    private var failed = false
    private var ready = false
    private var pendingHello: (() -> Void)?
    public var isIdle: Bool { active == nil && queue.isEmpty && pendingHello == nil }
    public var statusObserver: ((WorkspaceStatusReply) throws -> Void)?
    public var onFailure: ((String) -> Void)?
    public init(vm: WorkspaceMachine) { self.vm = vm }
    init(fd: Int32) throws {
        self.vm = nil
        self.stream = try WorkspaceStream(fd: fd, label: "portablefs.workspace.control", onLost: { [weak self] in self?.lost($0) })
    }
    public func controlReady() { ready = true; let start = pendingHello; pendingHello = nil; start?() }
    public func hello(_ host: WorkspaceHello, deadline: UInt64, completion: @escaping (Result<WorkspaceHello, Error>) -> Void) {
        let start = { [weak self] in
            guard let self, !self.failed, let vm = self.vm else { completion(.failure(WorkspaceVMError("control startup unavailable"))); return }
            vm.connect(port: 1023) { [self] result in
                do {
                    let connection = try result.get(); self.connection = connection
                    let stream = try WorkspaceStream(fd: connection.fileDescriptor, label: "portablefs.workspace.control", onLost: { [weak self] in self?.lost($0) })
                    self.stream = stream
                    stream.read(count: 32, deadline: deadline) { result in
                        do {
                            let proof = try result.get()
                            let expected = Data(HMAC<SHA256>.authenticationCode(for: Data("portablefs-workspace-control-8".utf8) + host.hostServiceID, using: SymmetricKey(data: host.bootID)))
                            guard proof == expected else { throw WorkspaceVMError("guest seeded-nonce proof refused") }
                            self.exchange(.hello(host), deadline: deadline) { result in completion(result.flatMap { envelope in
                                guard case .helloAck(let ack) = envelope.body else { return .failure(WorkspaceVMError("expected HelloAck")) }
                                return .success(ack) // The coordinator performs the one release pairing check.
                            }) }
                        } catch { self.lost(String(describing: error)); completion(.failure(error)) }
                    }
                } catch { self.lost(String(describing: error)); completion(.failure(error)) }
            }
        }
        if ready { start() } else { pendingHello = start }
    }
    private func exchange(_ body: WorkspaceEnvelope.OneOf_Body, desired: Bool = false, deadline: UInt64, completion: @escaping (Result<WorkspaceEnvelope, Error>) -> Void) {
        guard !failed, queue.count < 128 else { completion(.failure(WorkspaceVMError("control queue unavailable"))); return }
        queue.append(Request(body: body, desiredBody: desired ? body : nil, deadline: deadline, completion: completion)); advance()
    }
    private func advance() {
        guard active == nil, !failed, !queue.isEmpty, stream != nil else { return }
        dispatch(queue.removeFirst())
    }
    private func dispatch(_ request: Request) {
        guard let stream else { return }
        active = request
        guard clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) < request.deadline, requestID < UInt64.max else { active = nil; request.completion(.failure(WorkspaceVMError("queued control deadline expired"))); advance(); return }
        requestID += 1; let expected = requestID
        do {
            // Stamp after FIFO residence, immediately before encoding. The
            // original host deadline still bounds transport and pause.
            let frame = try Self.encodeRequest(request.body, requestID: expected, deadline: request.deadline, now: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW))
            stream.write(frame, deadline: request.deadline) { result in
                switch result {
                case .failure(let error): self.finish(.failure(error))
                case .success:
                    stream.read(count: 4, deadline: request.deadline) { result in
                        do {
                            let header = try result.get(); let size = header.reduce(0) { ($0 << 8) | Int($1) }
                            guard size > 0, size <= WorkspaceControl.maxFrame else { throw WorkspaceVMError("invalid frame length") }
                            stream.read(count: size, deadline: request.deadline) { result in
                                do {
                                    let reply = try WorkspaceControl.decode(header + result.get())
                                    guard reply.requestID == expected else { throw WorkspaceVMError("control response correlation failed") }
                                    if case .resume = request.body, case .result(let refusal) = reply.body, refusal.code == "refused" {
                                        throw WorkspaceVMError("guest refused resume: " + refusal.reason)
                                    }
                                    switch (request.body, reply.body) {
                                    case (.identityRequest, .result): throw WorkspaceVMError("guest identity refused")
                                    case (.identityRequest, .identityReply), (.hello, .helloAck), (.status, .statusReply), (.suspend, .suspendAck), (.resume, .resumeAck), (.awakeRecover, .resumeAck), (.retireAck, .result), (.provision, .result), (.mount, .result), (.umount, .result): break
                                    default: throw WorkspaceVMError("unexpected control reply")
                                    }
                                    self.finish(.success(reply))
                                } catch { self.finish(.failure(error)) }
                            }
                        } catch { self.finish(.failure(error)) }
                    }
                }
            }
        } catch { finish(.failure(error)) }
    }
    static func encodeRequest(_ body: WorkspaceEnvelope.OneOf_Body, requestID: UInt64, deadline: UInt64, now: UInt64) throws -> Data {
        guard now < deadline else { throw WorkspaceVMError("queued control deadline expired") }
        var envelope = WorkspaceEnvelope(); envelope.version = 8; envelope.requestID = requestID; envelope.body = body
        if case .suspend = body { envelope.drainBudgetNanos = deadline - now }
        return try WorkspaceControl.encode(envelope)
    }
    private func finish(_ result: Result<WorkspaceEnvelope, Error>) {
        guard let current = active else { return }
        var consumed = result
        if case .success(let envelope) = result, case .statusReply(let status) = envelope.body {
            do {
                guard let statusObserver else { throw WorkspaceVMError("Status observation owner missing") }
                try statusObserver(status)
            } catch { consumed = .failure(error) }
        }
        guard !failed else { return }
        if case .failure(let error) = consumed { lost(String(describing: error)); return }
        // Observation and retry are steps of the active logical operation.
        // Keep later callers queued, with fresh wire IDs and one absolute deadline.
        if let desiredBody = current.desiredBody, case .success(let envelope) = consumed {
            if case .statusReply = envelope.body {
                dispatch(Request(body: desiredBody, desiredBody: desiredBody, deadline: current.deadline, completion: current.completion))
                return
            }
            if envelope.result.code == "predecessor-unobserved" {
                dispatch(Request(body: .status(WorkspaceStatusRequest()), desiredBody: desiredBody, deadline: current.deadline, completion: current.completion))
                return
            }
        }
        active = nil
        current.completion(consumed)
        advance()
    }
    private func lost(_ reason: String) {
        guard !failed else { return }; failed = true
        stream?.close(); connection?.close(); connection = nil
        let waiting = queue; queue = []; let current = active; active = nil
        current?.completion(.failure(WorkspaceVMError(reason)))
        for request in waiting { request.completion(.failure(WorkspaceVMError(reason))) }
        onFailure?(reason)
    }
    public func status(deadline: UInt64, completion: @escaping (Result<WorkspaceStatusReply, Error>) -> Void) {
        exchange(.status(WorkspaceStatusRequest()), deadline: deadline) { completion($0.map { $0.statusReply }) }
    }
    public func identity(_ request: WorkspaceIdentityRequest, deadline: UInt64, completion: @escaping (Result<WorkspaceIdentityReply, Error>) -> Void) {
        exchange(.identityRequest(request), desired: true, deadline: deadline) { completion($0.map { $0.identityReply }) }
    }
    public func provision(_ request: WorkspaceProvision, deadline: UInt64, completion: @escaping (Result<WorkspaceResult, Error>) -> Void) {
        exchange(.provision(request), desired: true, deadline: deadline) { completion($0.map { $0.result }) }
    }
    public func mount(_ mount: WorkspaceMountID, deadline: UInt64, completion: @escaping (Result<WorkspaceResult, Error>) -> Void) {
        var request = WorkspaceMountRequest(); request.mount = mount
        exchange(.mount(request), desired: true, deadline: deadline) { completion($0.map { $0.result }) }
    }
    public func umount(_ mount: WorkspaceMountID, force: Bool = false, deadline: UInt64, completion: @escaping (Result<WorkspaceResult, Error>) -> Void) {
        var request = WorkspaceUmountRequest(); request.mount = mount; request.force = force
        exchange(.umount(request), desired: true, deadline: deadline) { completion($0.map { $0.result }) }
    }
    public func suspend(_ request: WorkspaceSuspension, deadline: UInt64, completion: @escaping (Result<WorkspaceSuspendAck, Error>) -> Void) {
        exchange(.suspend(request), deadline: deadline) { completion($0.map { $0.suspendAck }) }
    }
    public func recoverAwake(_ token: WorkspaceResumeToken, deadline: UInt64, completion: @escaping (Result<WorkspaceResumeAck, Error>) -> Void) {
        exchange(.awakeRecover(token), deadline: deadline) { completion($0.map { $0.resumeAck }) }
    }
    public func resume(_ token: WorkspaceResumeToken, deadline: UInt64, completion: @escaping (Result<WorkspaceResumeAck, Error>) -> Void) {
        exchange(.resume(token), deadline: deadline) { completion($0.map { $0.resumeAck }) }
    }
    public func acknowledgeRetired(through sequence: UInt64, deadline: UInt64, completion: @escaping (Result<Void, Error>) -> Void) {
        var ack = WorkspaceRetireAck(); ack.throughSequence = sequence
        exchange(.retireAck(ack), deadline: deadline) { result in completion(result.flatMap { $0.result.code == "accepted" ? .success(()) : .failure(WorkspaceVMError("retirement refused")) }) }
    }
    public func close() { onFailure = nil; lost("owner closed channel") }
}
