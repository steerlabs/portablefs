import Foundation

/// Transport seam so tests can exercise the client against canned responses.
public protocol HTTPDataTransport: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

public struct URLSessionTransport: HTTPDataTransport {
    private let session: URLSession

    public init(requestTimeout: TimeInterval = 30) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = requestTimeout
        configuration.timeoutIntervalForResource = requestTimeout * 2
        configuration.waitsForConnectivity = false
        session = URLSession(configuration: configuration)
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw ControlPlaneError(status: 0, code: "", message: "non-HTTP response from \(request.url?.absoluteString ?? "?")")
        }
        return (data, http)
    }
}

/// A failed control-plane request. `status == 0` means the request never got
/// an HTTP response (network failure, bad URL).
public struct ControlPlaneError: Error, Equatable, CustomStringConvertible {
    public var status: Int
    public var code: String
    public var message: String

    public init(status: Int, code: String = "", message: String = "") {
        self.status = status
        self.code = code
        self.message = message
    }

    public var description: String {
        var text = message.isEmpty ? HTTPURLResponse.localizedString(forStatusCode: status) : message
        if !code.isEmpty {
            text += " (\(code), HTTP \(status))"
        } else if status != 0 {
            text += " (HTTP \(status))"
        }
        return text
    }

    /// Accepts both server error envelopes: the volume-api's
    /// `{"error":{"code","message"}}` and the authority manager's `{"error":"..."}`.
    public static func parse(status: Int, body: Data) -> ControlPlaneError {
        struct NestedEnvelope: Decodable {
            struct Inner: Decodable {
                var code: String?
                var message: String?
            }
            var error: Inner
        }
        if let nested = try? JSONDecoder().decode(NestedEnvelope.self, from: body),
           (nested.error.code ?? "").isEmpty == false || (nested.error.message ?? "").isEmpty == false {
            return ControlPlaneError(status: status, code: nested.error.code ?? "", message: nested.error.message ?? "")
        }
        struct FlatEnvelope: Decodable {
            var error: String
        }
        if let flat = try? JSONDecoder().decode(FlatEnvelope.self, from: body), !flat.error.isEmpty {
            return ControlPlaneError(status: status, message: flat.error)
        }
        if let text = String(data: body, encoding: .utf8) {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty && trimmed.count < 300 {
                return ControlPlaneError(status: status, message: trimmed)
            }
        }
        return ControlPlaneError(status: status)
    }
}

public struct ListedVolumeBranch: Codable, Equatable, Sendable {
    public var name: String
    public var headCommitId: String

    public init(name: String, headCommitId: String = "") {
        self.name = name
        self.headCommitId = headCommitId
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        headCommitId = try container.decodeIfPresent(String.self, forKey: .headCommitId) ?? ""
    }
}

public struct ListedVolume: Codable, Equatable, Sendable, Identifiable {
    public var volumeId: String
    public var tenantId: String
    public var createdAtMs: Int64
    public var branches: [ListedVolumeBranch]

    public var id: String { volumeId }

    public init(volumeId: String, tenantId: String = "", createdAtMs: Int64 = 0, branches: [ListedVolumeBranch] = []) {
        self.volumeId = volumeId
        self.tenantId = tenantId
        self.createdAtMs = createdAtMs
        self.branches = branches
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        volumeId = try container.decodeIfPresent(String.self, forKey: .volumeId) ?? ""
        tenantId = try container.decodeIfPresent(String.self, forKey: .tenantId) ?? ""
        createdAtMs = try container.decodeIfPresent(Int64.self, forKey: .createdAtMs) ?? 0
        branches = try container.decodeIfPresent([ListedVolumeBranch].self, forKey: .branches) ?? []
    }

    /// Branch the app mounts by default: `main` when present, else the first.
    public var defaultBranch: String {
        if branches.contains(where: { $0.name == "main" }) {
            return "main"
        }
        return branches.first?.name ?? "main"
    }
}

public struct DeviceCodeResponse: Codable, Equatable, Sendable {
    public var deviceCode: String
    public var userCode: String
    public var verificationUri: String
    public var expiresInSeconds: Int
    public var intervalSeconds: Int

    public init(deviceCode: String, userCode: String, verificationUri: String, expiresInSeconds: Int = 0, intervalSeconds: Int = 0) {
        self.deviceCode = deviceCode
        self.userCode = userCode
        self.verificationUri = verificationUri
        self.expiresInSeconds = expiresInSeconds
        self.intervalSeconds = intervalSeconds
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        deviceCode = try container.decodeIfPresent(String.self, forKey: .deviceCode) ?? ""
        userCode = try container.decodeIfPresent(String.self, forKey: .userCode) ?? ""
        verificationUri = try container.decodeIfPresent(String.self, forKey: .verificationUri) ?? ""
        expiresInSeconds = try container.decodeIfPresent(Int.self, forKey: .expiresInSeconds) ?? 0
        intervalSeconds = try container.decodeIfPresent(Int.self, forKey: .intervalSeconds) ?? 0
    }

    public var pollInterval: TimeInterval {
        intervalSeconds > 0 ? TimeInterval(intervalSeconds) : 5
    }

    public var expiry: TimeInterval {
        expiresInSeconds > 0 ? TimeInterval(expiresInSeconds) : 15 * 60
    }
}

public enum DeviceTokenPollResult: Equatable, Sendable {
    case ready(apiKey: String, managerUrl: String)
    case pending
    case denied(message: String)
}

public enum CredentialVerification: Equatable, Sendable {
    case accepted
    case rejected(status: Int)
    case unreachable(message: String)
}

public enum AccessLeaseFailureDisposition: Equatable, Sendable {
    /// The manager may have committed the operation. Retry only with the
    /// exact same operation ID and request body.
    case retrySameOperation
    /// The response is definitive or says the lease can never advance.
    case terminal
}

/// Resolved data-plane endpoint + credential for one mount, as minted by the
/// authority manager's access-lease route.
public struct AccessSessionInfo: Equatable, Sendable {
    public var authorityUrl: String
    public var host: String
    public var port: Int
    public var token: String
    public var expiresAtMs: Int64
    public var authorityInstanceId: String
    public var accessLeaseId: String
    public var controlSeq: String

    public init(
        authorityUrl: String,
        host: String = "",
        port: Int = 0,
        token: String = "",
        expiresAtMs: Int64 = 0,
        authorityInstanceId: String = "",
        accessLeaseId: String = "",
        controlSeq: String = ""
    ) {
        self.authorityUrl = authorityUrl
        self.host = host
        self.port = port
        self.token = token
        self.expiresAtMs = expiresAtMs
        self.authorityInstanceId = authorityInstanceId
        self.accessLeaseId = accessLeaseId
        self.controlSeq = controlSeq
    }
}

/// Bearer-authenticated JSON client against one PortableFS control-plane base
/// URL. Mirrors the request/response shapes of the Go CLI
/// (`vcs/cmd/portablefs/internal/cli/{api,login,manager}.go`).
public struct ControlPlaneClient: Sendable {
    public var baseURL: String
    public var token: String
    public var transport: HTTPDataTransport

    public init(baseURL: String, token: String, transport: HTTPDataTransport = URLSessionTransport()) {
        self.baseURL = Self.normalizeServerURL(baseURL)
        self.token = token
        self.transport = transport
    }

    public static func normalizeServerURL(_ raw: String) -> String {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.isEmpty {
            return ""
        }
        if !value.contains("://") {
            value = "https://" + value
        }
        while value.hasSuffix("/") {
            value.removeLast()
        }
        return value
    }

    // MARK: Volumes

    public func listVolumes(limit: Int = 0) async throws -> [ListedVolume] {
        struct Envelope: Decodable {
            var volumes: [ListedVolume]?
        }
        var path = "/v1/volumes"
        if limit > 0 {
            path += "?limit=\(limit)"
        }
        let envelope: Envelope = try await sendJSON(method: "GET", path: path, body: nil)
        guard let volumes = envelope.volumes else {
            throw ControlPlaneError(status: 0, message: "list-volumes response omitted the volumes array")
        }
        guard volumes.allSatisfy({ !$0.volumeId.isEmpty }) else {
            throw ControlPlaneError(status: 0, message: "list-volumes response contained a volume without volumeId")
        }
        return volumes
    }

    /// Mirrors the CLI's `verifyCredential`: the server authenticates before
    /// routing, so any HTTP response other than 401/403 proves the token was
    /// accepted (404 from older builds, 400 from admin tokens included).
    public func verifyCredential() async -> CredentialVerification {
        do {
            let (status, _) = try await sendRaw(method: "GET", path: "/v1/volumes", body: nil)
            switch status {
            case 401, 403:
                return .rejected(status: status)
            default:
                return .accepted
            }
        } catch {
            return .unreachable(message: friendlyTransportMessage(error))
        }
    }

    // MARK: Device flow

    public func startDeviceFlow() async throws -> DeviceCodeResponse {
        let empty = Data("{}".utf8)
        let (status, body) = try await sendRaw(method: "POST", path: "/v1/auth/device/code", body: empty)
        switch status {
        case 200..<300:
            break
        case 404:
            throw ControlPlaneError(status: status, message: "this server does not support device login; paste a token instead")
        case 401, 403:
            throw ControlPlaneError(status: status, message: "this server requires a pre-issued token for login; paste a token instead")
        default:
            throw ControlPlaneError.parse(status: status, body: body)
        }
        let code = try decodeJSON(DeviceCodeResponse.self, from: body, context: "device login response")
        guard !code.deviceCode.isEmpty, !code.verificationUri.isEmpty else {
            throw ControlPlaneError(status: status, message: "this server returned an incomplete device-login response; paste a token instead")
        }
        return code
    }

    public func pollDeviceToken(deviceCode: String) async throws -> DeviceTokenPollResult {
        let body = try JSONEncoder().encode(["deviceCode": deviceCode])
        let (status, data) = try await sendRaw(method: "POST", path: "/v1/auth/device/token", body: body)
        switch status {
        case 200:
            struct TokenResponse: Decodable {
                var apiKey: String?
                var managerUrl: String?
                var status: String?
            }
            let response = try decodeJSON(TokenResponse.self, from: data, context: "device token response")
            if let apiKey = response.apiKey, !apiKey.isEmpty {
                return .ready(apiKey: apiKey, managerUrl: response.managerUrl ?? "")
            }
            if response.status == "pending" {
                return .pending
            }
            throw ControlPlaneError(status: status, message: "device login returned no apiKey; start over or paste a token")
        case 202:
            return .pending
        case 400, 410:
            return .denied(message: ControlPlaneError.parse(status: status, body: data).description)
        default:
            throw ControlPlaneError.parse(status: status, body: data)
        }
    }

    // MARK: Access sessions (authority manager surface)

    /// Resolves a live mount endpoint + credential for volumeID+branch by
    /// creating an access lease — the manager's only resolution route (the
    /// retired mount-session/authority-session routes answer 410).
    public func accessSession(volumeID: String, branch: String) async throws -> AccessSessionInfo {
        try await accessSession(
            volumeID: volumeID,
            branch: branch,
            operationID: UUID().uuidString.lowercased()
        )
    }

    /// Operation-ID-explicit create used by long-lived clients. An ambiguous
    /// response must be retried with the same value.
    public func accessSession(
        volumeID: String,
        branch: String,
        operationID: String
    ) async throws -> AccessSessionInfo {
        struct Authority: Decodable {
            var authorityUrl: String?
            var host: String?
            var port: Int?
            var authorityInstanceId: String?
        }
        struct Lease: Decodable {
            var accessLeaseId: String?
            var controlSeq: String?
            var expiresAt: Int64?
        }
        struct Envelope: Decodable {
            var authority: Authority?
            var lease: Lease?
            var accessToken: String?
        }

        let host = ProcessInfo.processInfo.hostName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty else {
            throw ControlPlaneError(
                status: 0,
                message: "cannot create an access lease because macOS returned an empty machine hostname"
            )
        }
        let request = try JSONEncoder().encode([
            "operationId": operationID,
            "volumeId": volumeID,
            "branch": branch,
            "consumerId": "app:" + host,
        ])
        let (status, body) = try await sendRaw(method: "POST", path: "/v1/access-leases/create", body: request)
        guard (200..<300).contains(status) else {
            throw ControlPlaneError.parse(status: status, body: body)
        }
        let envelope = try decodeJSON(Envelope.self, from: body, context: "access lease response")
        guard let authorityUrl = envelope.authority?.authorityUrl, !authorityUrl.isEmpty else {
            throw ControlPlaneError(status: status, message: "manager returned an access lease without an authority endpoint")
        }
        guard let token = envelope.accessToken, !token.isEmpty,
              let leaseId = envelope.lease?.accessLeaseId, !leaseId.isEmpty,
              let controlSeq = envelope.lease?.controlSeq, !controlSeq.isEmpty,
              let expiresAt = envelope.lease?.expiresAt, expiresAt > 0 else {
            throw ControlPlaneError(status: status, message: "manager returned an incomplete access lease for \(volumeID)@\(branch)")
        }
        return AccessSessionInfo(
            authorityUrl: authorityUrl,
            host: envelope.authority?.host ?? "",
            port: envelope.authority?.port ?? 0,
            token: token,
            expiresAtMs: expiresAt,
            authorityInstanceId: envelope.authority?.authorityInstanceId ?? "",
            accessLeaseId: leaseId,
            controlSeq: controlSeq
        )
    }

    /// Renews exactly one existing lease. The caller owns `operationID` and
    /// must reuse it when a response is ambiguous; this method never creates
    /// a replacement lease or probes another route.
    public func renewAccessSession(
        _ session: AccessSessionInfo,
        operationID: String,
        rotateToken: Bool = false
    ) async throws -> AccessSessionInfo {
        struct Request: Encodable {
            var operationId: String
            var accessLeaseId: String
            var accessToken: String
            var expectedControlSeq: String
            var rotateToken: Bool
        }
        struct Lease: Decodable {
            var accessLeaseId: String?
            var controlSeq: String?
            var expiresAt: Int64?
        }
        struct Envelope: Decodable {
            var lease: Lease?
            var accessToken: String?
        }

        let request = try JSONEncoder().encode(Request(
            operationId: operationID,
            accessLeaseId: session.accessLeaseId,
            accessToken: session.token,
            expectedControlSeq: session.controlSeq,
            rotateToken: rotateToken
        ))
        let (status, body) = try await sendRaw(method: "POST", path: "/v1/access-leases/renew", body: request)
        guard (200..<300).contains(status) else {
            throw ControlPlaneError.parse(status: status, body: body)
        }
        let envelope = try decodeJSON(Envelope.self, from: body, context: "access lease renewal response")
        guard let leaseId = envelope.lease?.accessLeaseId, leaseId == session.accessLeaseId,
              let controlSeq = envelope.lease?.controlSeq, !controlSeq.isEmpty,
              let expiresAt = envelope.lease?.expiresAt, expiresAt > 0 else {
            throw ControlPlaneError(status: status, message: "manager returned an incomplete access lease renewal")
        }
        var renewed = session
        renewed.controlSeq = controlSeq
        renewed.expiresAtMs = expiresAt
        if let token = envelope.accessToken, !token.isEmpty {
            renewed.token = token
        } else if rotateToken {
            throw ControlPlaneError(status: status, message: "manager renewed without the requested rotated access token")
        }
        return renewed
    }

    /// Classifies access-lease failures without inventing a recovery path.
    /// Terminal typed lease codes win even when carried by a 5xx status.
    public static func accessLeaseFailureDisposition(_ error: Error) -> AccessLeaseFailureDisposition {
        guard let controlError = error as? ControlPlaneError else {
            return .retrySameOperation
        }
        let terminalCodes: Set<String> = [
            "ACCESS_LEASE_EPOCH_SUPERSEDED",
            "ACCESS_LEASE_NOT_FOUND",
            "ACCESS_LEASE_EXPIRED",
            "ACCESS_LEASE_REVOKED",
            "ACCESS_LEASE_RELEASED",
            "ACCESS_LEASE_UNAUTHORIZED",
        ]
        if terminalCodes.contains(controlError.code) {
            return .terminal
        }
        if controlError.status == 0 || controlError.status == 408 ||
            controlError.status == 429 || controlError.status >= 500 {
            return .retrySameOperation
        }
        return .terminal
    }

    /// Releases exactly one existing lease. No alternate cleanup route is
    /// attempted; callers surface an ambiguous result and let expiry remain
    /// the manager's terminal backstop.
    public func releaseAccessSession(
        _ session: AccessSessionInfo,
        operationID: String
    ) async throws {
        let request = try JSONEncoder().encode([
            "operationId": operationID,
            "accessLeaseId": session.accessLeaseId,
            "accessToken": session.token,
        ])
        let (status, body) = try await sendRaw(method: "POST", path: "/v1/access-leases/release", body: request)
        guard (200..<300).contains(status) else {
            throw ControlPlaneError.parse(status: status, body: body)
        }
    }

    // MARK: Plumbing

    private func decodeJSON<T: Decodable>(_ type: T.Type, from data: Data, context: String) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw ControlPlaneError(status: 0, message: "parse \(context): \(error.localizedDescription)")
        }
    }

    private func sendJSON<T: Decodable>(method: String, path: String, body: Data?) async throws -> T {
        let (status, data) = try await sendRaw(method: method, path: path, body: body)
        guard (200..<300).contains(status) else {
            throw ControlPlaneError.parse(status: status, body: data)
        }
        return try decodeJSON(T.self, from: data, context: "\(method) \(path) response")
    }

    private func sendRaw(method: String, path: String, body: Data?) async throws -> (Int, Data) {
        guard let url = URL(string: baseURL + path) else {
            throw ControlPlaneError(status: 0, message: "invalid URL \(baseURL + path)")
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        if !token.isEmpty {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        do {
            let (data, response) = try await transport.send(request)
            return (response.statusCode, data)
        } catch let error as ControlPlaneError {
            throw error
        } catch {
            throw ControlPlaneError(status: 0, message: "\(method) \(baseURL + path): \(friendlyTransportMessage(error))")
        }
    }

    private func friendlyTransportMessage(_ error: Error) -> String {
        let nsError = error as NSError
        if nsError.domain == NSURLErrorDomain {
            switch nsError.code {
            case NSURLErrorTimedOut:
                return "request timed out"
            case NSURLErrorCannotConnectToHost, NSURLErrorCannotFindHost:
                return "cannot reach the server"
            case NSURLErrorNotConnectedToInternet:
                return "no network connection"
            case NSURLErrorSecureConnectionFailed, NSURLErrorServerCertificateUntrusted:
                return "TLS connection failed"
            default:
                break
            }
        }
        return nsError.localizedDescription
    }
}
