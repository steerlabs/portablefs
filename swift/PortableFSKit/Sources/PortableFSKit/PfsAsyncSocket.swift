import Foundation
import SwiftProtobuf
@preconcurrency import Dispatch
@preconcurrency import Darwin

private final class PfsContinuationBox<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Error>?

    init(_ continuation: CheckedContinuation<T, Error>) {
        self.continuation = continuation
    }

    func resume(returning value: T) {
        lock.lock()
        let continuation = continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(returning: value)
    }

    func resume(throwing error: Error) {
        lock.lock()
        let continuation = continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(throwing: error)
    }
}

final class PfsAsyncSocket: @unchecked Sendable {
    private static let connectQueue = DispatchQueue(label: "dev.portablefs.pfslocal.connect", qos: .userInitiated)

    private let io: DispatchIO
    private let queue: DispatchQueue
    private let maxFrameLength: Int
    private let closeLock = NSLock()
    private var closed = false

    private init(fd: Int32, maxFrameLength: Int) throws {
        self.maxFrameLength = maxFrameLength
        self.queue = DispatchQueue(label: "dev.portablefs.pfslocal.io.\(UUID().uuidString)", qos: .userInitiated)
        let ioFD = dup(fd)
        guard ioFD >= 0 else {
            let error = Darwin.errno
            PfsUnixSocket.close(fd)
            throw PfsLocalClientError.system(errno: error, operation: "dup")
        }
        PfsUnixSocket.close(fd)
        self.io = DispatchIO(type: .stream, fileDescriptor: ioFD, queue: queue) { _ in }
        io.setLimit(lowWater: 1)
    }

    static func connect(path: String, maxFrameLength: Int) async throws -> PfsAsyncSocket {
        try await withCheckedThrowingContinuation { continuation in
            connectQueue.async {
                do {
                    let fd = try PfsUnixSocket.connect(path: path)
                    continuation.resume(returning: try PfsAsyncSocket(fd: fd, maxFrameLength: maxFrameLength))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// The single receive owner asks for another frame only after applying
    /// this one. At most one bounded frame crosses the actor hop; a stalled
    /// receiver leaves later bytes in the socket and backpressures the sender.
    func readFrame() async throws -> PfsEnvelope {
        let header = try await readExactly(4, frameStart: true)
        let length = header.enumerated().reduce(UInt32(0)) { $0 | (UInt32($1.element) << ($1.offset * 8)) }
        guard length <= maxFrameLength else {
            throw PfsLocalClientError.frameTooLarge(length: length, max: maxFrameLength)
        }
        let payload = try await readExactly(Int(length), frameStart: false)
        let envelope = try PfsEnvelope(serializedBytes: payload)
        try PfsUnknownFieldGuard.requireKnownFields(envelope)
        return envelope
    }

    private func readExactly(_ count: Int, frameStart: Bool) async throws -> Data {
        if count == 0 { return Data() }
        return try await withCheckedThrowingContinuation { continuation in
            let box = PfsContinuationBox<Data>(continuation)
            queue.async { [io, queue] in
                var bytes = Data()
                io.read(offset: 0, length: count, queue: queue) { done, data, error in
                    if error != 0 {
                        box.resume(throwing: PfsLocalClientError.system(errno: error, operation: "read"))
                        return
                    }
                    if let data { bytes.append(Data(data)) }
                    guard done else { return }
                    if bytes.count == count { box.resume(returning: bytes) }
                    else if frameStart, bytes.isEmpty { box.resume(throwing: PfsLocalClientError.connectionClosed) }
                    else { box.resume(throwing: PfsLocalClientError.invalidFrame("EOF before completing frame")) }
                }
            }
        }
    }

    func write(_ envelope: PfsEnvelope) async throws {
        let data = try PfsFrameCodec(maxFrameLength: maxFrameLength).encode(envelope)
        try await write(data)
    }

    func close() {
        closeLock.lock()
        let shouldClose = !closed
        closed = true
        closeLock.unlock()
        if shouldClose {
            io.close(flags: .stop)
        }
    }

    private func write(_ data: Data) async throws {
        let dispatchData = data.withUnsafeBytes { rawBuffer -> DispatchData in
            DispatchData(bytes: rawBuffer)
        }

        try await withCheckedThrowingContinuation { continuation in
            let box = PfsContinuationBox<Void>(continuation)
            io.write(offset: 0, data: dispatchData, queue: queue) { done, _, error in
                if error != 0 {
                    box.resume(throwing: PfsLocalClientError.system(errno: error, operation: "write"))
                } else if done {
                    box.resume(returning: ())
                }
            }
        }
    }
}
