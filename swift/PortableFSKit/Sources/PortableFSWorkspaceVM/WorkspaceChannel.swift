import Foundation
import Darwin
import CryptoKit
@preconcurrency import Virtualization
import PortableFSWorkspaceCore

@MainActor public final class WorkspaceVsockChannel: WorkspaceGuestChannel {
    private struct Request {
        let body: WorkspaceEnvelope.OneOf_Body
        let deadline: UInt64
        let completion: (Result<WorkspaceEnvelope, Error>) -> Void
    }
    private let vm: WorkspaceMachine
    private var connection: VZVirtioSocketConnection?
    private var stream: WorkspaceStream?
    private var requestID: UInt64 = 0
    private var queue: [Request] = []
    private var active: Request?
    private var failed = false
    private var ready = false
    private var pendingHello: (() -> Void)?
    public private(set) var lastResume: WorkspaceResumeToken?
    public var onFailure: ((String) -> Void)?
    public init(vm: WorkspaceMachine) { self.vm = vm }
    public func controlReady() { ready = true; let start = pendingHello; pendingHello = nil; start?() }
    public func hello(_ host: WorkspaceHello, deadline: UInt64, completion: @escaping (Result<WorkspaceHello, Error>) -> Void) {
        let start = { [weak self] in
            guard let self, !self.failed else { completion(.failure(WorkspaceVMError("control startup unavailable"))); return }
            self.vm.connect(port: 1023) { result in
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
    private func exchange(_ body: WorkspaceEnvelope.OneOf_Body, deadline: UInt64, completion: @escaping (Result<WorkspaceEnvelope, Error>) -> Void) {
        guard !failed, queue.count < 128 else { completion(.failure(WorkspaceVMError("control queue unavailable"))); return }
        queue.append(Request(body: body, deadline: deadline, completion: completion)); advance()
    }
    private func advance() {
        guard active == nil, !failed, !queue.isEmpty, let stream else { return }
        let request = queue.removeFirst()
        guard clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) < request.deadline, requestID < UInt64.max else { request.completion(.failure(WorkspaceVMError("queued control deadline expired"))); advance(); return }
        requestID += 1; let expected = requestID; active = request
        var envelope = WorkspaceEnvelope(); envelope.version = 8; envelope.requestID = expected; envelope.body = request.body
        do {
            try stream.write(WorkspaceControl.encode(envelope), deadline: request.deadline) { result in
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
                                    case (.hello, .helloAck), (.status, .statusReply), (.suspend, .suspendAck), (.resume, .resumeAck), (.retireAck, .result): break
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
    private func finish(_ result: Result<WorkspaceEnvelope, Error>) {
        guard let current = active else { return }; active = nil
        current.completion(result)
        if case .failure(let error) = result { lost(String(describing: error)) } else { advance() }
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
    public func suspend(_ request: WorkspaceSuspension, deadline: UInt64, completion: @escaping (Result<WorkspaceSuspendAck, Error>) -> Void) {
        exchange(.suspend(request), deadline: deadline) { completion($0.map { $0.suspendAck }) }
    }
    public func resume(_ token: WorkspaceResumeToken, deadline: UInt64, completion: @escaping (Result<WorkspaceResumeAck, Error>) -> Void) {
        lastResume = token
        exchange(.resume(token), deadline: deadline) { completion($0.map { $0.resumeAck }) }
    }
    public func acknowledgeRetired(_ outcomes: [WorkspaceMountStatus], deadline: UInt64, completion: @escaping (Result<Void, Error>) -> Void) {
        var ack = WorkspaceRetireAck(); ack.outcomes = outcomes
        exchange(.retireAck(ack), deadline: deadline) { result in completion(result.flatMap { $0.result.code == "ok" ? .success(()) : .failure(WorkspaceVMError("retirement refused")) }) }
    }
    public func close() { onFailure = nil; lost("owner closed channel") }
}
