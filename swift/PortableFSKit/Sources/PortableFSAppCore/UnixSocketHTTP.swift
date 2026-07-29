import Foundation
import PortableFSKit
@preconcurrency import Darwin

public enum UnixSocketHTTPError: Error, Equatable, CustomStringConvertible {
    case connect(path: String, errno: Int32)
    case io(operation: String, errno: Int32)
    case timeout(path: String)
    case malformedResponse(String)

    public var description: String {
        switch self {
        case let .connect(path, errnoValue):
            return "connect \(path): \(String(cString: strerror(errnoValue)))"
        case let .io(operation, errnoValue):
            return "\(operation): \(String(cString: strerror(errnoValue)))"
        case let .timeout(path):
            return "request to \(path) timed out"
        case let .malformedResponse(detail):
            return "malformed HTTP response: \(detail)"
        }
    }
}

public struct UnixSocketHTTPResponse: Equatable, Sendable {
    public var status: Int
    /// Header names lowercased; duplicate headers keep the last value.
    public var headers: [String: String]
    public var body: Data

    public init(status: Int, headers: [String: String] = [:], body: Data = Data()) {
        self.status = status
        self.headers = headers
        self.body = body
    }
}

/// Parses a complete HTTP/1.x response captured off a `Connection: close`
/// exchange. Supports Content-Length, chunked transfer encoding, and
/// EOF-delimited bodies.
public enum HTTPResponseParser {
    public static func parse(_ raw: Data) throws -> UnixSocketHTTPResponse {
        guard let headerEnd = raw.range(of: Data("\r\n\r\n".utf8)) else {
            throw UnixSocketHTTPError.malformedResponse("missing header terminator")
        }
        let headerData = raw[raw.startIndex..<headerEnd.lowerBound]
        guard let headerText = String(data: headerData, encoding: .utf8) else {
            throw UnixSocketHTTPError.malformedResponse("headers are not valid UTF-8")
        }
        var lines = headerText.components(separatedBy: "\r\n")
        guard !lines.isEmpty else {
            throw UnixSocketHTTPError.malformedResponse("empty header block")
        }
        let statusLine = lines.removeFirst()
        let statusParts = statusLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard statusParts.count >= 2,
              statusParts[0].hasPrefix("HTTP/"),
              let status = Int(statusParts[1]) else {
            throw UnixSocketHTTPError.malformedResponse("bad status line \(statusLine)")
        }

        var headers: [String: String] = [:]
        for line in lines where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else {
                throw UnixSocketHTTPError.malformedResponse("bad header line \(line)")
            }
            let name = line[line.startIndex..<colon].lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[name] = value
        }

        let rawBody = Data(raw[headerEnd.upperBound...])
        let body: Data
        if headers["transfer-encoding"]?.lowercased().contains("chunked") == true {
            body = try decodeChunked(rawBody)
        } else if let lengthText = headers["content-length"], let length = Int(lengthText) {
            guard rawBody.count >= length else {
                throw UnixSocketHTTPError.malformedResponse("body truncated: expected \(length) bytes, got \(rawBody.count)")
            }
            body = rawBody.prefix(length)
        } else {
            body = rawBody
        }
        return UnixSocketHTTPResponse(status: status, headers: headers, body: body)
    }

    static func decodeChunked(_ raw: Data) throws -> Data {
        var decoded = Data()
        var cursor = raw.startIndex
        let crlf = Data("\r\n".utf8)
        while true {
            guard let lineEnd = raw.range(of: crlf, in: cursor..<raw.endIndex) else {
                throw UnixSocketHTTPError.malformedResponse("chunked body missing size line")
            }
            let sizeText = String(data: raw[cursor..<lineEnd.lowerBound], encoding: .utf8) ?? ""
            let sizeToken = sizeText.split(separator: ";").first.map(String.init) ?? sizeText
            guard let size = Int(sizeToken.trimmingCharacters(in: .whitespaces), radix: 16) else {
                throw UnixSocketHTTPError.malformedResponse("bad chunk size \(sizeText)")
            }
            cursor = lineEnd.upperBound
            if size == 0 {
                return decoded
            }
            guard raw.distance(from: cursor, to: raw.endIndex) >= size + 2 else {
                throw UnixSocketHTTPError.malformedResponse("chunk truncated")
            }
            let chunkEnd = raw.index(cursor, offsetBy: size)
            decoded.append(raw[cursor..<chunkEnd])
            cursor = raw.index(chunkEnd, offsetBy: 2)
        }
    }
}

/// Minimal HTTP/1.1 client over a Unix domain socket. One connection per
/// request (`Connection: close`), which is exactly how the Go CLI drives the
/// portablefsd control socket via curl in the integration harness.
public struct UnixSocketHTTPClient: Sendable {
    public var socketPath: String
    public var timeout: TimeInterval

    public init(socketPath: String, timeout: TimeInterval = 10) {
        self.socketPath = socketPath
        self.timeout = timeout
    }

    public func send(
        method: String,
        path: String,
        body: Data? = nil,
        contentType: String = "application/json"
    ) async throws -> UnixSocketHTTPResponse {
        let socketPath = self.socketPath
        let timeout = self.timeout
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Result {
                    try Self.blockingSend(
                        socketPath: socketPath,
                        timeout: timeout,
                        method: method,
                        path: path,
                        body: body,
                        contentType: contentType
                    )
                })
            }
        }
    }

    private static func blockingSend(
        socketPath: String,
        timeout: TimeInterval,
        method: String,
        path: String,
        body: Data?,
        contentType: String
    ) throws -> UnixSocketHTTPResponse {
        let fd: Int32
        do {
            fd = try PfsUnixSocket.connect(path: socketPath)
        } catch let error as PfsLocalClientError {
            if case let .system(errnoValue, _) = error {
                throw UnixSocketHTTPError.connect(path: socketPath, errno: errnoValue)
            }
            throw UnixSocketHTTPError.connect(path: socketPath, errno: EINVAL)
        }
        defer { PfsUnixSocket.close(fd) }
        applyTimeout(fd: fd, seconds: timeout)

        var request = "\(method) \(path) HTTP/1.1\r\n"
        request += "Host: portablefsd\r\n"
        request += "Connection: close\r\n"
        request += "X-PortableFS-Control-Protocol: 1\r\n"
        if let body {
            request += "Content-Type: \(contentType)\r\n"
            request += "Content-Length: \(body.count)\r\n"
        }
        request += "\r\n"
        var outgoing = Data(request.utf8)
        if let body {
            outgoing.append(body)
        }

        try writeAll(fd: fd, data: outgoing, socketPath: socketPath)
        let raw = try readToEOF(fd: fd, socketPath: socketPath)
        return try HTTPResponseParser.parse(raw)
    }

    private static func applyTimeout(fd: Int32, seconds: TimeInterval) {
        var value = timeval(
            tv_sec: Int(seconds),
            tv_usec: Int32((seconds - floor(seconds)) * 1_000_000)
        )
        let size = socklen_t(MemoryLayout<timeval>.size)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &value, size)
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &value, size)
    }

    private static func writeAll(fd: Int32, data: Data, socketPath: String) throws {
        var remaining = data
        while !remaining.isEmpty {
            let written = remaining.withUnsafeBytes { buffer -> Int in
                guard let base = buffer.baseAddress else {
                    return 0
                }
                return Darwin.write(fd, base, buffer.count)
            }
            if written > 0 {
                remaining.removeFirst(written)
                continue
            }
            let errnoValue = errno
            if errnoValue == EINTR {
                continue
            }
            if errnoValue == EAGAIN || errnoValue == EWOULDBLOCK {
                throw UnixSocketHTTPError.timeout(path: socketPath)
            }
            throw UnixSocketHTTPError.io(operation: "write", errno: errnoValue)
        }
    }

    private static func readToEOF(fd: Int32, socketPath: String) throws -> Data {
        var collected = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count > 0 {
                collected.append(contentsOf: buffer[0..<count])
                continue
            }
            if count == 0 {
                return collected
            }
            let errnoValue = errno
            if errnoValue == EINTR {
                continue
            }
            if errnoValue == EAGAIN || errnoValue == EWOULDBLOCK {
                throw UnixSocketHTTPError.timeout(path: socketPath)
            }
            throw UnixSocketHTTPError.io(operation: "read", errno: errnoValue)
        }
    }
}
