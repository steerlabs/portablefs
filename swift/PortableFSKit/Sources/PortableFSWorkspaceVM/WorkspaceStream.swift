import Foundation
import Darwin

// Descriptor and bounded buffers belong to one dedicated serial queue. Dispatch
// sources do no blocking I/O and cancellation owns the final descriptor close.
final class WorkspaceStream: @unchecked Sendable {
    private let queue: DispatchQueue
    private let fd: Int32
    private let reader: DispatchSourceRead
    private let writer: DispatchSourceWrite
    private var writerActive = false
    private var closed = false
    private var incoming = Data()
    private var outgoing = Data()
    private var readCount = 0
    private var readCompletion: (@MainActor (Result<Data, Error>) -> Void)?
    private var writeCompletion: (@MainActor (Result<Void, Error>) -> Void)?
    private var serial: UInt64 = 0
    private let onLost: @MainActor (String) -> Void

    init(fd original: Int32, label: String, onLost: @escaping @MainActor (String) -> Void) throws {
        fd = dup(original)
        guard fd >= 0 else { throw WorkspaceVMError("duplicate stream: \(errno)") }
        queue = DispatchQueue(label: label)
        self.onLost = onLost
        guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0 else { Darwin.close(fd); throw WorkspaceVMError("nonblocking stream: \(errno)") }
        reader = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        writer = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: queue)
        var flag: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &flag, socklen_t(MemoryLayout.size(ofValue: flag)))
        let group = DispatchGroup(); group.enter(); group.enter()
        reader.setCancelHandler { group.leave() }; writer.setCancelHandler { group.leave() }
        let descriptor = fd
        group.notify(queue: queue) { Darwin.close(descriptor) }
        reader.setEventHandler { [weak self] in self?.readReady() }
        writer.setEventHandler { [weak self] in self?.writeReady() }
        reader.resume()
    }
    func read(count: Int, deadline: UInt64, completion: @escaping @MainActor (Result<Data, Error>) -> Void) {
        queue.async { [self] in
            guard !closed, readCompletion == nil, clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) < deadline else { DispatchQueue.main.async { completion(.failure(WorkspaceVMError("stream unavailable"))) }; return }
            readCount = count; readCompletion = completion
            arm(deadline)
            deliverRead()
        }
    }
    func write(_ data: Data, deadline: UInt64, completion: @escaping @MainActor (Result<Void, Error>) -> Void) {
        queue.async { [self] in
            guard !closed, writeCompletion == nil, clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) < deadline else { DispatchQueue.main.async { completion(.failure(WorkspaceVMError("stream unavailable"))) }; return }
            outgoing = data; writeCompletion = completion
            arm(deadline)
            writerActive = true; writer.resume()
        }
    }
    private func arm(_ deadline: UInt64) {
        serial += 1
        let current = serial
        Task {
            let now = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
            if now < deadline { try? await Task.sleep(for: .nanoseconds(Int64(min(deadline - now, UInt64(Int64.max)))), clock: .continuous) }
            queue.async { [self] in
                if serial == current, readCompletion != nil || writeCompletion != nil { fail("control operation deadline expired") }
            }
        }
    }
    private func readReady() {
        var bytes = [UInt8](repeating: 0, count: 65536)
        while !closed {
            let n = Darwin.read(fd, &bytes, bytes.count)
            if n < 0 && errno == EINTR { continue }
            if n < 0 && errno == EAGAIN { return }
            guard n > 0 else { fail(n == 0 ? "control peer closed" : "control read failed: \(errno)"); return }
            incoming.append(contentsOf: bytes.prefix(n))
            guard incoming.count <= 1_048_580 else { fail("control input exceeds frame limit"); return }
            deliverRead()
        }
    }
    private func deliverRead() {
        guard let completion = readCompletion, incoming.count >= readCount else { return }
        let data = Data(incoming.prefix(readCount)); incoming.removeFirst(readCount)
        readCompletion = nil; serial += 1
        DispatchQueue.main.async { completion(.success(data)) }
    }
    private func writeReady() {
        while !outgoing.isEmpty, !closed {
            let n = outgoing.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
            if n < 0 && errno == EINTR { continue }
            if n < 0 && errno == EAGAIN { return }
            guard n > 0 else { fail("control write failed: \(errno)"); return }
            outgoing.removeFirst(n)
        }
        if !closed, writerActive {
            writer.suspend(); writerActive = false
            let completion = writeCompletion; writeCompletion = nil; serial += 1
            DispatchQueue.main.async { completion?(.success(())) }
        }
    }
    private func fail(_ reason: String) {
        guard !closed else { return }; closed = true
        shutdown(fd, SHUT_RDWR)
        if !writerActive { writer.resume(); writerActive = true }
        reader.cancel(); writer.cancel()
        let read = readCompletion; let write = writeCompletion
        readCompletion = nil; writeCompletion = nil
        DispatchQueue.main.async { [onLost] in
            let error = WorkspaceVMError(reason)
            read?(.failure(error)); write?(.failure(error)); onLost(reason)
        }
    }
    func close() { queue.async { [self] in fail("control channel closed by owner") } }
}
