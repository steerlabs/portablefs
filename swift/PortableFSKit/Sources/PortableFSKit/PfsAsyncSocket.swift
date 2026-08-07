import Foundation
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

    func startReading(
        onFrame: @escaping @Sendable (PfsEnvelope) -> Void,
        onClose: @escaping @Sendable (Error) -> Void
    ) {
        queue.async { [io, queue, maxFrameLength] in
            var decoder = PfsFrameDecoder(maxFrameLength: maxFrameLength)
            let closeOnce = PfsCloseCallback(onClose)
            io.read(offset: 0, length: Int.max, queue: queue) { done, dispatchData, error in
                if error != 0 {
                    closeOnce.call(PfsLocalClientError.system(errno: error, operation: "read"))
                    return
                }

                if let dispatchData, dispatchData.count > 0 {
                    do {
                        let frames = try decoder.append(Data(dispatchData))
                        for frame in frames {
                            onFrame(frame)
                        }
                    } catch {
                        closeOnce.call(error)
                        return
                    }
                }

                if done {
                    if decoder.bufferedByteCount == 0 {
                        closeOnce.call(PfsLocalClientError.connectionClosed)
                    } else {
                        closeOnce.call(PfsLocalClientError.invalidFrame("EOF before completing frame"))
                    }
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

private final class PfsCloseCallback: @unchecked Sendable {
    private let lock = NSLock()
    private var callback: (@Sendable (Error) -> Void)?

    init(_ callback: @escaping @Sendable (Error) -> Void) {
        self.callback = callback
    }

    func call(_ error: Error) {
        lock.lock()
        let callback = callback
        self.callback = nil
        lock.unlock()
        callback?(error)
    }
}
