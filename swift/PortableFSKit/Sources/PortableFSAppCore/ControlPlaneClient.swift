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

/// Resolved data-plane endpoint + credential for one mount, as minted by the
/// authority manager.
public struct MountSessionInfo: Equatable, Sendable {
    public var authorityUrl: String
    public var host: String
    public var port: Int
    public var nfsPort: Int
    public var token: String
    public var expiresAtMs: Int64
    public var authorityInstanceId: String

    public init(
        authorityUrl: String,
        host: String = "",
        port: Int = 0,
        nfsPort: Int = 0,
        token: String = "",
        expiresAtMs: Int64 = 0,
        authorityInstanceId: String = ""
    ) {
        self.authorityUrl = authorityUrl
        self.host = host
        self.port = port
        self.nfsPort = nfsPort
        self.token = token
        self.expiresAtMs = expiresAtMs
        self.authorityInstanceId = authorityInstanceId
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
        return envelope.volumes ?? []
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

    // MARK: Mount sessions (authority manager surface)

    /// Resolves a live mount endpoint for volumeID+branch, mirroring the Go
    /// CLI: the canonical volume-scoped route first, the flat alias on
    /// 404/405, then the legacy ensure+session pair when the unified route is
    /// entirely absent.
    public func mountSession(volumeID: String, branch: String) async throws -> MountSessionInfo {
        struct Endpoint: Decodable {
            var authorityUrl: String?
            var host: String?
            var port: Int?
            var nfsPort: Int?
        }
        struct NewStyleSession: Decodable {
            var endpoint: Endpoint?
            var token: String?
            var expiresAtMs: Int64?
            var authorityInstanceId: String?
        }
        struct NewStyleEnvelope: Decodable {
            var mountSession: NewStyleSession?
        }

        let ref = try JSONEncoder().encode(["volumeId": volumeID, "branch": branch])
        let escapedVolume = volumeID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? volumeID

        var (status, body) = try await sendRaw(
            method: "POST",
            path: "/v1/volumes/\(escapedVolume)/mount-sessions",
            body: ref
        )
        if status == 404 || status == 405 {
            (status, body) = try await sendRaw(method: "POST", path: "/v1/mount-sessions", body: ref)
        }
        if (200..<300).contains(status) {
            let envelope = try decodeJSON(NewStyleEnvelope.self, from: body, context: "mount session response")
            guard let session = envelope.mountSession,
                  let authorityUrl = session.endpoint?.authorityUrl,
                  !authorityUrl.isEmpty else {
                throw ControlPlaneError(status: status, message: "manager returned a mount session without an authority endpoint")
            }
            return MountSessionInfo(
                authorityUrl: authorityUrl,
                host: session.endpoint?.host ?? "",
                port: session.endpoint?.port ?? 0,
                nfsPort: session.endpoint?.nfsPort ?? 0,
                token: session.token ?? "",
                expiresAtMs: session.expiresAtMs ?? 0,
                authorityInstanceId: session.authorityInstanceId ?? ""
            )
        }
        if status != 404 {
            throw ControlPlaneError.parse(status: status, body: body)
        }

        // Older manager: ensure the authority exists, then mint the session token.
        struct AuthorityPayload: Decodable {
            var authorityUrl: String?
            var host: String?
            var port: Int?
            var nfsPort: Int?
            var authorityInstanceId: String?
            var authorityAuthToken: String?
            var authorityExpiresAt: Int64?
        }
        struct AuthorityEnvelope: Decodable {
            var authority: AuthorityPayload?
        }
        let (ensureStatus, ensureBody) = try await sendRaw(method: "POST", path: "/v1/authorities/ensure", body: ref)
        guard (200..<300).contains(ensureStatus) else {
            throw ControlPlaneError.parse(status: ensureStatus, body: ensureBody)
        }
        let ensure = try decodeJSON(AuthorityEnvelope.self, from: ensureBody, context: "authority ensure response")
        let (sessionStatus, sessionBody) = try await sendRaw(method: "POST", path: "/v1/authorities/session", body: ref)
        guard (200..<300).contains(sessionStatus) else {
            throw ControlPlaneError.parse(status: sessionStatus, body: sessionBody)
        }
        let session = try decodeJSON(AuthorityEnvelope.self, from: sessionBody, context: "authority session response")
        var authority = session.authority ?? AuthorityPayload()
        if (authority.authorityUrl ?? "").isEmpty {
            authority.authorityUrl = ensure.authority?.authorityUrl
        }
        if (authority.authorityInstanceId ?? "").isEmpty {
            authority.authorityInstanceId = ensure.authority?.authorityInstanceId
        }
        guard let authorityUrl = authority.authorityUrl, !authorityUrl.isEmpty else {
            throw ControlPlaneError(status: sessionStatus, message: "manager returned no authority endpoint for \(volumeID)@\(branch)")
        }
        return MountSessionInfo(
            authorityUrl: authorityUrl,
            host: authority.host ?? "",
            port: authority.port ?? 0,
            nfsPort: authority.nfsPort ?? 0,
            token: authority.authorityAuthToken ?? "",
            expiresAtMs: authority.authorityExpiresAt ?? 0,
            authorityInstanceId: authority.authorityInstanceId ?? ""
        )
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
