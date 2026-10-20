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

    enum ReceiveEvent: Sendable, Equatable {
        case readRequested(Int)
        case resumed
    }

    private let receiveObserver: (@Sendable (ReceiveEvent) -> Void)?

    init(fd: Int32, maxFrameLength: Int, receiveObserver: (@Sendable (ReceiveEvent) -> Void)? = nil) throws {
        self.receiveObserver = receiveObserver
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
        try await withCheckedThrowingContinuation { continuation in
            let box = PfsContinuationBox<PfsEnvelope>(continuation)
            queue.async { [self] in
                readExactly(4, frameStart: true) { [self] headerResult in
                    switch headerResult {
                    case let .failure(error):
                        receiveObserver?(.resumed)
                        box.resume(throwing: error)
                    case let .success(header):
                        let length = header.enumerated().reduce(UInt32(0)) {
                            $0 | (UInt32($1.element) << ($1.offset * 8))
                        }
                        guard length <= maxFrameLength else {
                            receiveObserver?(.resumed)
                            box.resume(throwing: PfsLocalClientError.frameTooLarge(length: length, max: maxFrameLength))
                            return
                        }
                        readExactly(Int(length), frameStart: false) { [self] payloadResult in
                            let result = payloadResult.flatMap { payload in
                                Result {
                                    let envelope = try PfsEnvelope(serializedBytes: payload)
                                    try PfsUnknownFieldGuard.requireKnownFields(envelope)
                                    return envelope
                                }
                            }
                            receiveObserver?(.resumed)
                            switch result {
                            case let .success(envelope): box.resume(returning: envelope)
                            case let .failure(error): box.resume(throwing: error)
                            }
                        }
                    }
                }
            }
        }
    }

    // Header and payload collection stay on the I/O queue. No second frame is
    // requested until the ordered receive owner has applied this frame.
    private func readExactly(
        _ count: Int,
        frameStart: Bool,
        completion: @escaping @Sendable (Result<Data, Error>) -> Void
    ) {
        receiveObserver?(.readRequested(count))
        if count == 0 {
            completion(.success(Data()))
            return
        }
        var bytes = Data()
        var completed = false
        io.read(offset: 0, length: count, queue: queue) { done, data, error in
            guard !completed else { return }
            if error != 0 {
                completed = true
                completion(.failure(PfsLocalClientError.system(errno: error, operation: "read")))
                return
            }
            if let data { bytes.append(Data(data)) }
            guard done else { return }
            completed = true
            if bytes.count == count { completion(.success(bytes)) }
            else if frameStart, bytes.isEmpty { completion(.failure(PfsLocalClientError.connectionClosed)) }
            else { completion(.failure(PfsLocalClientError.invalidFrame("EOF before completing frame"))) }
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
