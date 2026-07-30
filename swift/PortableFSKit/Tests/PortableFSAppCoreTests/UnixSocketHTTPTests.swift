import Foundation
import Testing
import PortableFSKit
@testable import PortableFSAppCore
@preconcurrency import Darwin

// MARK: Response parser

@Test func parserHandlesContentLengthBody() throws {
    let raw = Data("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"ok\":\"yes\"}\nTRAILING-GARBAGE".utf8)
    let response = try HTTPResponseParser.parse(raw)
    #expect(response.status == 200)
    #expect(response.headers["content-type"] == "application/json")
    #expect(String(data: response.body, encoding: .utf8) == "{\"ok\":\"yes\"}\n")
}

@Test func parserHandlesChunkedBody() throws {
    let raw = Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n7\r\n, world\r\n0\r\n\r\n".utf8)
    let response = try HTTPResponseParser.parse(raw)
    #expect(String(data: response.body, encoding: .utf8) == "hello, world")
}

@Test func parserHandlesEOFDelimitedBody() throws {
    let raw = Data("HTTP/1.1 204 No Content\r\n\r\n".utf8)
    let response = try HTTPResponseParser.parse(raw)
    #expect(response.status == 204)
    #expect(response.body.isEmpty)

    let withBody = Data("HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nplain".utf8)
    #expect(String(data: try HTTPResponseParser.parse(withBody).body, encoding: .utf8) == "plain")
}

@Test func parserRejectsMalformedResponses() {
    #expect(throws: UnixSocketHTTPError.self) {
        _ = try HTTPResponseParser.parse(Data("garbage with no header end".utf8))
    }
    #expect(throws: UnixSocketHTTPError.self) {
        _ = try HTTPResponseParser.parse(Data("NOT-HTTP 200\r\n\r\n".utf8))
    }
    #expect(throws: UnixSocketHTTPError.self) {
        _ = try HTTPResponseParser.parse(Data("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort".utf8))
    }
}

// MARK: In-process control-socket server

/// Tiny sequential HTTP-over-UDS server: reads one request per connection,
/// hands it to the route table, writes the response, closes.
private final class MockControlServer: @unchecked Sendable {
    struct Request {
        var method: String
        var path: String
        var body: Data
    }

    struct Response {
        var status: Int
        var body: Data
        var chunked = false

        init(status: Int, json: String, chunked: Bool = false) {
            self.status = status
            self.body = Data(json.utf8)
            self.chunked = chunked
        }
    }

    let socketPath: String
    private let listener: Int32
    private let handler: @Sendable (Request) -> Response
    private let lock = NSLock()
    private var seen: [Request] = []
    private var stopping = false
    private let finished = DispatchSemaphore(value: 0)

    init(socketPath: String, handler: @escaping @Sendable (Request) -> Response) throws {
        self.socketPath = socketPath
        self.handler = handler
        listener = try PfsUnixSocket.bindAndListen(path: socketPath)
        let listenerCopy = listener
        let thread = Thread { [weak self] in
            while let client = try? PfsUnixSocket.accept(listenerCopy) {
                guard let self, !self.isStopping else {
                    PfsUnixSocket.close(client)
                    break
                }
                self.serve(client: client)
            }
            // The accept thread owns the listener fd: closing it from stop()
            // while accept() is still blocked would let the kernel recycle the
            // fd number into other tests' sockets mid-syscall.
            PfsUnixSocket.close(listenerCopy)
            self?.finished.signal()
        }
        thread.name = "mock-control-server"
        thread.start()
    }

    private var isStopping: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopping
    }

    func stop() {
        lock.lock()
        let alreadyStopping = stopping
        stopping = true
        lock.unlock()
        guard !alreadyStopping else {
            return
        }
        // Wake the blocked accept with a throwaway connection.
        if let wake = try? PfsUnixSocket.connect(path: socketPath) {
            PfsUnixSocket.close(wake)
        }
        _ = finished.wait(timeout: .now() + 5)
        unlink(socketPath)
    }

    var requests: [Request] {
        lock.lock()
        defer { lock.unlock() }
        return seen
    }

    private func serve(client: Int32) {
        defer { PfsUnixSocket.close(client) }
        guard let request = Self.readRequest(client: client) else {
            return
        }
        lock.lock()
        seen.append(request)
        lock.unlock()
        let response = handler(request)

        var head = "HTTP/1.1 \(response.status) X\r\nContent-Type: application/json\r\nConnection: close\r\n"
        var payload = Data()
        if response.chunked {
            head += "Transfer-Encoding: chunked\r\n\r\n"
            payload = Data(head.utf8)
            // Split the body into two chunks to exercise reassembly.
            let half = response.body.count / 2
            for part in [response.body.prefix(half), response.body.suffix(response.body.count - half)] where !part.isEmpty {
                payload.append(Data(String(format: "%x\r\n", part.count).utf8))
                payload.append(part)
                payload.append(Data("\r\n".utf8))
            }
            payload.append(Data("0\r\n\r\n".utf8))
        } else {
            head += "Content-Length: \(response.body.count)\r\n\r\n"
            payload = Data(head.utf8)
            payload.append(response.body)
        }
        payload.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else {
                return
            }
            var offset = 0
            while offset < buffer.count {
                let written = Darwin.write(client, base + offset, buffer.count - offset)
                if written <= 0 {
                    break
                }
                offset += written
            }
        }
    }

    private static func readRequest(client: Int32) -> Request? {
        var collected = Data()
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        let headerEndMarker = Data("\r\n\r\n".utf8)
        var headerEnd: Range<Data.Index>?
        while headerEnd == nil {
            let count = Darwin.read(client, &buffer, buffer.count)
            guard count > 0 else {
                return nil
            }
            collected.append(contentsOf: buffer[0..<count])
            headerEnd = collected.range(of: headerEndMarker)
        }
        guard let headerRange = headerEnd,
              let headerText = String(data: collected[collected.startIndex..<headerRange.lowerBound], encoding: .utf8) else {
            return nil
        }
        var lines = headerText.components(separatedBy: "\r\n")
        let requestLine = lines.removeFirst().split(separator: " ")
        guard requestLine.count >= 2 else {
            return nil
        }
        var contentLength = 0
        for line in lines {
            let parts = line.split(separator: ":", maxSplits: 1)
            if parts.count == 2, parts[0].lowercased() == "content-length" {
                contentLength = Int(parts[1].trimmingCharacters(in: .whitespaces)) ?? 0
            }
        }
        var body = Data(collected[headerRange.upperBound...])
        while body.count < contentLength {
            let count = Darwin.read(client, &buffer, buffer.count)
            guard count > 0 else {
                break
            }
            body.append(contentsOf: buffer[0..<count])
        }
        return Request(method: String(requestLine[0]), path: String(requestLine[1]), body: body)
    }
}

private func shortSocketPath(_ name: String) -> String {
    "/tmp/pfs-t-\(getpid())-\(name).sock"
}

@Test func daemonControlClientRoundTripsAgainstMockServer() async throws {
    let socketPath = shortSocketPath("ctl")
    let server = try MockControlServer(socketPath: socketPath) { request in
        switch (request.method, request.path) {
        case ("GET", "/healthz"):
            return .init(status: 200, json: "ok\n")
        case ("POST", "/v1/attaches"):
            return .init(status: 200, json: #"{"attachRef":"att_test123","volumeName":"vol-a@main"}"#)
        case ("GET", "/v1/attaches"):
            // Chunked to mirror Go's encoder behavior on larger payloads.
            return .init(status: 200, json: """
            {"attaches":[{"attachRef":"att_test123","volumeId":"vol-a","branch":"main",
             "mountPath":"/Users/u/PortableFS/vol-a","state":"attached",
             "prefetch":{"done":true,"entriesWalked":10},
             "cache":{"attrEntries":5,"diskBytes":100,"diskCapBytes":1000}}]}
            """, chunked: true)
        case ("GET", "/v1/attaches/att_test123"):
            return .init(status: 200, json: #"{"attachRef":"att_test123","volumeId":"vol-a","branch":"main","mountPath":"/m","state":"degraded","lastError":"credentials required after daemon restart","prefetch":{"done":false,"entriesWalked":0},"cache":{"attrEntries":0,"diskBytes":0,"diskCapBytes":0}}"#)
        case ("POST", "/v1/attaches/att_test123/unmount"):
            return .init(status: 204, json: "")
        case ("POST", "/v1/attaches/att_test123/credential"):
            return .init(status: 204, json: "")
        default:
            return .init(status: 404, json: #"{"error":"unknown attach endpoint"}"#)
        }
    }
    defer { server.stop() }

    let client = DaemonControlClient(socketPath: socketPath, timeout: 5)
    #expect(await client.healthz())

    let ensured = try await client.ensureAttach(DaemonEnsureAttachRequest(
        volumeId: "vol-a",
        branch: "main",
        authorityUrl: "127.0.0.1:9999",
        authToken: "tok",
        dataPlaneTransport: "plaintext",
        mountPath: "/Users/u/PortableFS/vol-a"
    ))
    #expect(ensured.attachRef == "att_test123")
    #expect(ensured.volumeName == "vol-a@main")

    let attaches = try await client.listAttaches()
    #expect(attaches.count == 1)
    #expect(attaches[0].state == "attached")
    #expect(attaches[0].prefetch.done)
    #expect(attaches[0].cache.diskCapBytes == 1000)

    let status = try await client.attachStatus(ref: "att_test123")
    #expect(status.state == "degraded")
    #expect(status.lastError == "credentials required after daemon restart")

    try await client.setCredential(ref: "att_test123", authToken: "fresh")
    try await client.unmountAttach(ref: "att_test123")

    // Exact unmount is idempotent: a lost successful reply followed by 404
    // has already converged to the requested state.
    try await client.unmountAttach(ref: "att_missing")

    // The attach request body must carry the exact Go JSON keys.
    let attachRequest = server.requests.first { $0.method == "POST" && $0.path == "/v1/attaches" }
    let bodyObject = try JSONSerialization.jsonObject(with: attachRequest?.body ?? Data()) as? [String: Any]
    #expect(bodyObject?["volumeId"] as? String == "vol-a")
    #expect(bodyObject?["authorityUrl"] as? String == "127.0.0.1:9999")
    #expect(bodyObject?["mountPath"] as? String == "/Users/u/PortableFS/vol-a")
    let options = bodyObject?["options"] as? [String: Any]
    #expect(options?["writePolicy"] == nil)
    #expect(options?["fsyncPolicy"] == nil)
    #expect(options?["negativeCache"] as? Bool == true)
}

@Test func daemonControlClientReportsUnreachableSocket() async {
    let client = DaemonControlClient(socketPath: "/tmp/pfs-t-no-such-socket.sock", timeout: 1)
    #expect(await !client.healthz())
    do {
        _ = try await client.listAttaches()
        Issue.record("expected connect error")
    } catch let error as UnixSocketHTTPError {
        if case .connect = error {
        } else {
            Issue.record("expected connect error, got \(error)")
        }
    } catch {
        Issue.record("unexpected error type: \(error)")
    }
}

@Test func daemonControlClientRejectsMissingAttachCollection() async throws {
    let socketPath = shortSocketPath("missing-list")
    let server = try MockControlServer(socketPath: socketPath) { _ in
        .init(status: 200, json: "{}")
    }
    defer { server.stop() }

    let client = DaemonControlClient(socketPath: socketPath, timeout: 5)
    do {
        _ = try await client.listAttaches()
        Issue.record("expected missing attaches array to fail")
    } catch let error as DaemonControlError {
        #expect(error.message.contains("no attaches array"))
    } catch {
        Issue.record("unexpected error type: \(error)")
    }
}
