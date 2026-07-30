import Foundation

/// Attach tuning knobs, JSON-compatible with portablefsd's `AttachOptions`
/// (`vcs/internal/portablefsd/registry.go`).
public struct DaemonAttachOptions: Codable, Equatable, Sendable {
    public var prefetch: Bool
    public var diskCacheDir: String
    public var diskCacheMb: Int64
    public var negativeCache: Bool

    public init(
        prefetch: Bool = false,
        diskCacheDir: String = "",
        diskCacheMb: Int64 = 0,
        negativeCache: Bool = true
    ) {
        self.prefetch = prefetch
        self.diskCacheDir = diskCacheDir
        self.diskCacheMb = diskCacheMb
        self.negativeCache = negativeCache
    }
}

/// Body of `POST /v1/attaches`, matching portablefsd's `ensureAttachRequest`.
public struct DaemonEnsureAttachRequest: Codable, Equatable, Sendable {
    public var volumeId: String
    public var branch: String
    public var authorityUrl: String
    public var authToken: String
    public var dataPlaneTransport: String
    public var dataPlaneServerName: String
    public var tlsCaPem: String
    public var tlsCaSha256: String
    public var mountPath: String
    public var options: DaemonAttachOptions

    public init(
        volumeId: String,
        branch: String,
        authorityUrl: String,
        authToken: String,
        dataPlaneTransport: String,
        dataPlaneServerName: String = "",
        tlsCaPem: String = "",
        tlsCaSha256: String = "",
        mountPath: String,
        options: DaemonAttachOptions = DaemonAttachOptions()
    ) {
        self.volumeId = volumeId
        self.branch = branch
        self.authorityUrl = authorityUrl
        self.authToken = authToken
        self.dataPlaneTransport = dataPlaneTransport
        self.dataPlaneServerName = dataPlaneServerName
        self.tlsCaPem = tlsCaPem
        self.tlsCaSha256 = tlsCaSha256
        self.mountPath = mountPath
        self.options = options
    }
}

/// One attach as reported by the daemon, matching `attachStatus`.
public struct DaemonAttachStatus: Codable, Equatable, Sendable {
    public struct Prefetch: Codable, Equatable, Sendable {
        public var done: Bool
        public var entriesWalked: Int64

        public init(done: Bool = false, entriesWalked: Int64 = 0) {
            self.done = done
            self.entriesWalked = entriesWalked
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            done = try container.decodeIfPresent(Bool.self, forKey: .done) ?? false
            entriesWalked = try container.decodeIfPresent(Int64.self, forKey: .entriesWalked) ?? 0
        }
    }

    public struct Cache: Codable, Equatable, Sendable {
        public var attrEntries: Int
        public var diskBytes: Int64
        public var diskCapBytes: Int64

        public init(attrEntries: Int = 0, diskBytes: Int64 = 0, diskCapBytes: Int64 = 0) {
            self.attrEntries = attrEntries
            self.diskBytes = diskBytes
            self.diskCapBytes = diskCapBytes
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            attrEntries = try container.decodeIfPresent(Int.self, forKey: .attrEntries) ?? 0
            diskBytes = try container.decodeIfPresent(Int64.self, forKey: .diskBytes) ?? 0
            diskCapBytes = try container.decodeIfPresent(Int64.self, forKey: .diskCapBytes) ?? 0
        }
    }

    public var attachRef: String
    public var volumeId: String
    public var branch: String
    public var mountPath: String
    public var state: String
    public var prefetch: Prefetch
    public var cache: Cache
    public var lastError: String
    public var volumeName: String

    public init(
        attachRef: String,
        volumeId: String,
        branch: String,
        mountPath: String,
        state: String,
        prefetch: Prefetch = Prefetch(),
        cache: Cache = Cache(),
        lastError: String = "",
        volumeName: String = ""
    ) {
        self.attachRef = attachRef
        self.volumeId = volumeId
        self.branch = branch
        self.mountPath = mountPath
        self.state = state
        self.prefetch = prefetch
        self.cache = cache
        self.lastError = lastError
        self.volumeName = volumeName
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        attachRef = try container.decodeIfPresent(String.self, forKey: .attachRef) ?? ""
        volumeId = try container.decodeIfPresent(String.self, forKey: .volumeId) ?? ""
        branch = try container.decodeIfPresent(String.self, forKey: .branch) ?? ""
        mountPath = try container.decodeIfPresent(String.self, forKey: .mountPath) ?? ""
        state = try container.decodeIfPresent(String.self, forKey: .state) ?? ""
        prefetch = try container.decodeIfPresent(Prefetch.self, forKey: .prefetch) ?? Prefetch()
        cache = try container.decodeIfPresent(Cache.self, forKey: .cache) ?? Cache()
        lastError = try container.decodeIfPresent(String.self, forKey: .lastError) ?? ""
        volumeName = try container.decodeIfPresent(String.self, forKey: .volumeName) ?? ""
    }
}

public struct DaemonControlError: Error, Equatable, CustomStringConvertible {
    public var status: Int
    public var message: String

    public init(status: Int, message: String) {
        self.status = status
        self.message = message
    }

    public var description: String {
        message.isEmpty ? "portablefsd control error (HTTP \(status))" : "\(message) (HTTP \(status))"
    }
}

public struct DaemonIdentity: Decodable, Equatable, Sendable {
    public var schemaVersion: Int
    public var controlProtocol: Int
    public var daemonVersion: String
    public var executableSha256: String
    public var pfslocalMajor: UInt32
    public var pfslocalMinor: UInt32
}

/// Client for the portablefsd control socket (HTTP over UDS; see
/// `vcs/internal/portablefsd/control.go`).
public struct DaemonControlClient: Sendable {
    public var http: UnixSocketHTTPClient

    public init(socketPath: String, timeout: TimeInterval = 10) {
        http = UnixSocketHTTPClient(socketPath: socketPath, timeout: timeout)
    }

    public var socketPath: String {
        http.socketPath
    }

    public func healthz() async -> Bool {
        do {
            let response = try await http.send(method: "GET", path: "/healthz")
            return (200..<300).contains(response.status)
        } catch {
            return false
        }
    }

    public func identity() async throws -> DaemonIdentity {
        let response = try await http.send(method: "GET", path: "/v1/identity")
        try Self.check(response)
        return try Self.decode(DaemonIdentity.self, from: response.body)
    }

    public func ensureAttach(_ request: DaemonEnsureAttachRequest) async throws -> (attachRef: String, volumeName: String) {
        struct Reply: Decodable {
            var attachRef: String?
            var volumeName: String?
        }
        let body = try JSONEncoder().encode(request)
        let response = try await http.send(method: "POST", path: "/v1/attaches", body: body)
        try Self.check(response)
        let reply = try Self.decode(Reply.self, from: response.body)
        guard let ref = reply.attachRef, !ref.isEmpty else {
            throw DaemonControlError(status: response.status, message: "POST /v1/attaches returned no attachRef")
        }
        return (ref, reply.volumeName ?? "")
    }

    public func listAttaches() async throws -> [DaemonAttachStatus] {
        struct Reply: Decodable {
            var attaches: [DaemonAttachStatus]?
        }
        let response = try await http.send(method: "GET", path: "/v1/attaches")
        try Self.check(response)
        let reply = try Self.decode(Reply.self, from: response.body)
        guard let attaches = reply.attaches else {
            throw DaemonControlError(status: response.status, message: "GET /v1/attaches returned no attaches array")
        }
        guard attaches.allSatisfy({ !$0.attachRef.isEmpty && !$0.volumeId.isEmpty }) else {
            throw DaemonControlError(status: response.status, message: "GET /v1/attaches returned an incomplete attach identity")
        }
        return attaches
    }

    public func attachStatus(ref: String) async throws -> DaemonAttachStatus {
        let response = try await http.send(method: "GET", path: "/v1/attaches/\(Self.escape(ref))")
        try Self.check(response)
        return try Self.decode(DaemonAttachStatus.self, from: response.body)
    }

    /// Atomically drains the attach, proves and removes its exact FSKit
    /// kernel mount, then durably removes the daemon attach.
    public func unmountAttach(ref: String) async throws {
        let response = try await http.send(
            method: "POST",
            path: "/v1/attaches/\(Self.escape(ref))/unmount",
            body: Data("{}".utf8)
        )
        // Exact unmount converges state. If a prior request committed but its
        // reply was lost, the retry sees 404 and is already complete.
        if response.status == 404 {
            return
        }
        try Self.check(response)
    }

    public func setCredential(ref: String, authToken: String) async throws {
        let body = try JSONEncoder().encode(["authToken": authToken])
        let response = try await http.send(method: "POST", path: "/v1/attaches/\(Self.escape(ref))/credential", body: body)
        try Self.check(response)
    }

    public func flush(ref: String) async throws {
        let response = try await http.send(method: "POST", path: "/v1/attaches/\(Self.escape(ref))/flush", body: Data("{}".utf8))
        try Self.check(response)
    }

    /// Full authority durability barrier used before a normal kernel unmount.
    public func sync(ref: String) async throws {
        let response = try await http.send(method: "POST", path: "/v1/attaches/\(Self.escape(ref))/sync", body: Data("{}".utf8))
        try Self.check(response)
    }

    private static func escape(_ ref: String) -> String {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: "/")
        return ref.addingPercentEncoding(withAllowedCharacters: allowed) ?? ref
    }

    private static func check(_ response: UnixSocketHTTPResponse) throws {
        guard !(200..<300).contains(response.status) else {
            return
        }
        struct ErrorEnvelope: Decodable {
            var error: String?
        }
        var message = ""
        if let envelope = try? JSONDecoder().decode(ErrorEnvelope.self, from: response.body) {
            message = envelope.error ?? ""
        }
        if message.isEmpty, let text = String(data: response.body, encoding: .utf8) {
            message = text.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        throw DaemonControlError(status: response.status, message: message)
    }

    private static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw DaemonControlError(status: 0, message: "parse control response: \(error.localizedDescription)")
        }
    }
}
