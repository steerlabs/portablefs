import Foundation
import Darwin

final class WorkspaceRelay: @unchecked Sendable {
    private final class Direction {
        let input: Int32; let output: Int32
        let reader: DispatchSourceRead; let writer: DispatchSourceWrite
        var readActive = true; var writeActive = false
        var buffer = Data(); var eof = false; var done = false
        init(input: Int32, output: Int32, queue: DispatchQueue) {
            self.input = input; self.output = output
            reader = DispatchSource.makeReadSource(fileDescriptor: input, queue: queue)
            writer = DispatchSource.makeWriteSource(fileDescriptor: output, queue: queue)
        }
    }
    private let queue = DispatchQueue(label: "portablefs.workspace.ssh.relay")
    private let directions: [Direction]
    private var closed = false
    private let completion: @MainActor () -> Void
    init(client: Int32, guest: Int32, completion: @escaping @MainActor () -> Void) throws {
        let copy = dup(guest)
        guard copy >= 0 else { throw WorkspaceVMError("duplicate SSH vsock: \(errno)") }
        self.completion = completion
        directions = [Direction(input: client, output: copy, queue: queue), Direction(input: copy, output: client, queue: queue)]
        for fd in [client, copy] {
            _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
            var flag: Int32 = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &flag, socklen_t(MemoryLayout.size(ofValue: flag)))
        }
        let group = DispatchGroup()
        for direction in directions {
            group.enter(); group.enter()
            direction.reader.setCancelHandler { group.leave() }
            direction.writer.setCancelHandler { group.leave() }
            direction.reader.setEventHandler { [weak self] in self?.read(direction) }
            direction.writer.setEventHandler { [weak self] in self?.write(direction) }
            direction.reader.resume()
        }
        group.notify(queue: queue) {
            Darwin.close(client); Darwin.close(copy)
            DispatchQueue.main.async { completion() }
        }
    }
    private func read(_ d: Direction) {
        guard !closed else { return }
        var bytes = [UInt8](repeating: 0, count: 65536)
        let n = Darwin.read(d.input, &bytes, bytes.count)
        if n < 0 && [EAGAIN, EINTR].contains(errno) { return }
        if n < 0 { finish(); return }
        d.reader.suspend(); d.readActive = false
        if n == 0 { d.eof = true; finishDirection(d); return }
        d.buffer = Data(bytes.prefix(n)); d.writer.resume(); d.writeActive = true
    }
    private func write(_ d: Direction) {
        guard !closed else { return }
        let n = d.buffer.withUnsafeBytes { Darwin.write(d.output, $0.baseAddress, $0.count) }
        if n < 0 && [EAGAIN, EINTR].contains(errno) { return }
        guard n > 0 else { finish(); return }
        d.buffer.removeFirst(n)
        if d.buffer.isEmpty {
            d.writer.suspend(); d.writeActive = false
            d.reader.resume(); d.readActive = true
        }
    }
    private func finishDirection(_ d: Direction) {
        shutdown(d.output, SHUT_WR); d.done = true
        if directions.allSatisfy(\.done) { finish() }
    }
    private func finish() {
        guard !closed else { return }; closed = true
        for d in directions {
            shutdown(d.input, SHUT_RDWR)
            if !d.readActive { d.reader.resume() }
            if !d.writeActive { d.writer.resume() }
            d.reader.cancel(); d.writer.cancel()
        }
    }
    func close() { queue.async { [self] in finish() } }
}
