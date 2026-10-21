import Foundation
import Darwin
@preconcurrency import Virtualization
import PortableFSWorkspaceCore

@MainActor public final class WorkspaceVsockChannel: WorkspaceGuestChannel {
    private let vm: WorkspaceMachine
    private var connection: VZVirtioSocketConnection?
    private var requestID: UInt64 = 0
    private var busy = false
    private var failed = false
    private var idleMonitor: DispatchSourceRead?
    public var onFailure: (() -> Void)?
    public init(vm: WorkspaceMachine) { self.vm = vm }
    public func hello(_ host: WorkspaceHello, completion: @escaping (Result<WorkspaceHello, Error>) -> Void) {
        let deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + 120_000_000_000
        connect(deadline: deadline) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success:
                self.exchange(.hello(host)) { result in
                    completion(result.flatMap { e in
                        guard case .helloAck(let ack) = e.body else { return .failure(WorkspaceVMError("expected HelloAck")) }
                        do { try WorkspaceControl.pair(host: host, guest: ack); return .success(ack) } catch { return .failure(error) }
                    })
                }
            }
        }
    }
    private func connect(deadline: UInt64, completion: @escaping (Result<Void, Error>) -> Void) {
        guard !failed, clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) < deadline else { completion(.failure(WorkspaceVMError("guest control startup timed out"))); return }
        vm.connect(port: 1024) { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let connection):
                self.connection = connection
                let fd = connection.fileDescriptor
                var flag: Int32 = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &flag, socklen_t(MemoryLayout.size(ofValue: flag)))
                _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
                completion(.success(()))
            case .failure:
                // Only pre-pair listener discovery retries. A paired stream is
                // never replaced and a token is never resent.
                DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(100)) { self.connect(deadline: deadline, completion: completion) }
            }
        }
    }
    private func exchange(_ body: WorkspaceEnvelope.OneOf_Body, completion: @escaping (Result<WorkspaceEnvelope, Error>) -> Void) {
        guard !failed, !busy, requestID < UInt64.max, let connection else { completion(.failure(WorkspaceVMError("control channel unavailable or busy"))); return }
        idleMonitor?.cancel(); idleMonitor = nil
        requestID += 1; busy = true
        let expected = requestID
        var request = WorkspaceEnvelope(); request.version = 8; request.requestID = expected; request.body = body
        let outgoing = request
        let fd = connection.fileDescriptor
        WorkspaceIO({
            let deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + 10_000_000_000
            try WorkspaceSocket.write(fd, data: WorkspaceControl.encode(outgoing), deadline: deadline)
            let header = try WorkspaceSocket.read(fd, count: 4, deadline: deadline)
            let size = header.reduce(0) { ($0 << 8) | Int($1) }
            guard size > 0, size <= WorkspaceControl.maxFrame else { throw WorkspaceVMError("invalid frame length") }
            let reply = try WorkspaceControl.decode(header + WorkspaceSocket.read(fd, count: size, deadline: deadline))
            guard reply.requestID == expected else { throw WorkspaceVMError("control response correlation failed") }
            switch (body, reply.body) {
            case (.hello, .helloAck), (.status, .statusReply), (.suspend, .suspendAck), (.resume, .resumeAck): break
            default: throw WorkspaceVMError("unexpected control reply")
            }
            return reply
        }, completion: { [weak self] result in
            guard let self else { return }; self.busy = false
            if case .failure = result { self.failed = true }
            if self.failed { self.connection?.close(); self.connection = nil }
            if !self.failed { self.monitorIdle() }
            completion(result)
            if self.failed { self.onFailure?() }
        }).start()
    }
    private func monitorIdle() {
        guard !failed, !busy, let connection else { return }
        let fd = connection.fileDescriptor
        let monitor = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .main)
        monitor.setEventHandler { [weak self] in
            guard let self, !self.busy else { return }
            var byte: UInt8 = 0
            let count = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
            if count >= 0 || (errno != EAGAIN && errno != EINTR) {
                self.close(); self.onFailure?()
            }
        }
        idleMonitor = monitor; monitor.resume()
    }
    public func status(completion: @escaping (Result<WorkspaceStatusReply, Error>) -> Void) {
        exchange(.status(WorkspaceStatusRequest())) { result in completion(result.flatMap { e in
            guard case .statusReply(let value) = e.body else { return .failure(WorkspaceVMError("expected status")) }; return .success(value)
        }) }
    }
    public func suspend(_ request: WorkspaceSuspension, completion: @escaping (Result<WorkspaceSuspendAck, Error>) -> Void) {
        exchange(.suspend(request)) { result in completion(result.flatMap { e in
            guard case .suspendAck(let value) = e.body else { return .failure(WorkspaceVMError("expected SuspendAck")) }; return .success(value)
        }) }
    }
    public func resume(_ token: WorkspaceResumeToken, completion: @escaping (Result<WorkspaceResumeAck, Error>) -> Void) {
        exchange(.resume(token)) { result in completion(result.flatMap { e in
            guard case .resumeAck(let value) = e.body else { return .failure(WorkspaceVMError("expected ResumeAck")) }; return .success(value)
        }) }
    }
    public func close() {
        failed = true; idleMonitor?.cancel(); idleMonitor = nil
        // Wake an in-flight worker before closing. Its captured descriptor may
        // not be reused until the worker has finished its last system call.
        if busy, let connection { shutdown(connection.fileDescriptor, SHUT_RDWR) }
        else { connection?.close(); connection = nil }
    }
}
