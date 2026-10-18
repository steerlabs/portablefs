import Darwin
import Foundation

/// Decodes one strict JSON object with exactly `keys`: no missing, unknown,
/// duplicate (including escaped spellings) or null member, no nested value,
/// no trailing data, and no body larger than `maximumBytes`.
///
/// Numbers are judged on their token text with the grammar Go's
/// encoding/json applies to the peer field's type, so the Swift and Go
/// decoders of one sealed resource or lifecycle identity accept exactly the
/// same bodies. An unsigned field accepts only digits: `-0` is refused, as Go
/// refuses it for uint32. A signed field also takes an optional minus sign.
/// Fractions, exponents and out-of-range values are refused for both.
enum PortableFSDStrictObject {
    static func decode(
        _ data: Data,
        maximumBytes: Int,
        keys: Set<String>
    ) throws -> [String: PortableFSDStrictJSON.Scalar] {
        guard data.count <= maximumBytes else { throw PortableFSDStrictJSONError.invalid }
        let members = try PortableFSDStrictJSON.flatObject(data)
        guard Set(members.keys) == keys,
              !members.values.contains(.null) else {
            throw PortableFSDStrictJSONError.invalid
        }
        return members
    }

    static func string(_ value: PortableFSDStrictJSON.Scalar?) -> String? {
        guard case let .string(string)? = value else { return nil }
        return string
    }

    /// Go `uint32`: an unsigned integer token, never signed.
    static func uint32(_ value: PortableFSDStrictJSON.Scalar?) -> UInt32? {
        guard case let .number(token)? = value,
              let first = token.utf8.first,
              (0x30...0x39).contains(first) else {
            return nil
        }
        return UInt32(token)
    }

    /// Go `int` (64-bit), then required positive. `-0` decodes to zero and
    /// is refused by the positivity rule, as in Go.
    static func positiveInt(_ value: PortableFSDStrictJSON.Scalar?) -> Int? {
        guard case let .number(token)? = value,
              let integer = Int64(token),
              integer > 0 else {
            return nil
        }
        return Int(integer)
    }
}

/// The protocol numbers a daemon release seals into its service bundle's
/// signed resources. Read only after the bundle's code signature validated.
/// The executable hash and daemon version come from the signed executable and
/// bundle themselves: an executable's hash cannot sit inside the resources
/// its own signature covers.
struct PortableFSDSealedProtocols: Equatable, Sendable {
    static let relativePath = "Contents/Resources/PortableFSProtocol.json"
    static let maximumBytes = 4_096

    let identitySchema: Int
    let controlProtocol: Int
    let pfslocalMajor: UInt32
    let pfslocalMinor: UInt32

    static func decode(_ data: Data) throws -> PortableFSDSealedProtocols {
        let object = try PortableFSDStrictObject.decode(
            data,
            maximumBytes: maximumBytes,
            keys: ["identitySchema", "controlProtocol", "pfslocalMajor", "pfslocalMinor"]
        )
        guard let identitySchema = PortableFSDStrictObject.positiveInt(object["identitySchema"]),
              identitySchema == PortableFSDLifecycle.identitySchemaVersion,
              let controlProtocol = PortableFSDStrictObject.positiveInt(object["controlProtocol"]),
              let pfslocalMajor = PortableFSDStrictObject.uint32(object["pfslocalMajor"]),
              pfslocalMajor > 0,
              let pfslocalMinor = PortableFSDStrictObject.uint32(object["pfslocalMinor"]) else {
            throw PortableFSDStrictJSONError.invalid
        }
        return PortableFSDSealedProtocols(
            identitySchema: identitySchema,
            controlProtocol: controlProtocol,
            pfslocalMajor: pfslocalMajor,
            pfslocalMinor: pfslocalMinor
        )
    }
}

/// The identity a live daemon reports on the lifecycle endpoint: identity
/// schema 1, the serving release's actual protocol numbers and its executable
/// hash. Its claims are never authority by themselves; they must equal the
/// sealed release of the app whose signed daemon the socket peer proved to be.
struct PortableFSDLiveIdentity: Equatable, Sendable {
    let schemaVersion: Int
    let controlProtocol: Int
    let daemonVersion: String
    let executableSha256: String
    let pfslocalMajor: UInt32
    let pfslocalMinor: UInt32

    func matches(_ sealed: PortableFSDReleaseIdentity) -> Bool {
        schemaVersion == sealed.identitySchema
            && controlProtocol == sealed.controlProtocol
            && daemonVersion == sealed.daemonVersion
            && executableSha256 == sealed.executableSHA256
            && pfslocalMajor == sealed.pfslocalMajor
            && pfslocalMinor == sealed.pfslocalMinor
    }

    static func decode(_ data: Data) throws -> PortableFSDLiveIdentity {
        let object = try PortableFSDStrictObject.decode(
            data,
            maximumBytes: PortableFSDLifecycle.maximumBodyBytes,
            keys: [
                "schemaVersion", "controlProtocol", "daemonVersion",
                "executableSha256", "pfslocalMajor", "pfslocalMinor",
            ]
        )
        guard let schemaVersion = PortableFSDStrictObject.positiveInt(object["schemaVersion"]),
              schemaVersion == PortableFSDLifecycle.identitySchemaVersion,
              let controlProtocol = PortableFSDStrictObject.positiveInt(object["controlProtocol"]),
              let daemonVersion = PortableFSDStrictObject.string(object["daemonVersion"]),
              (1...128).contains(daemonVersion.utf8.count),
              daemonVersion.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }),
              let executableSha256 = PortableFSDStrictObject.string(object["executableSha256"]),
              executableSha256.utf8.count == 64,
              executableSha256.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }),
              let pfslocalMajor = PortableFSDStrictObject.uint32(object["pfslocalMajor"]),
              pfslocalMajor > 0,
              let pfslocalMinor = PortableFSDStrictObject.uint32(object["pfslocalMinor"]) else {
            throw PortableFSDStrictJSONError.invalid
        }
        return PortableFSDLiveIdentity(
            schemaVersion: schemaVersion,
            controlProtocol: controlProtocol,
            daemonVersion: daemonVersion,
            executableSha256: executableSha256,
            pfslocalMajor: pfslocalMajor,
            pfslocalMinor: pfslocalMinor
        )
    }
}

enum PortableFSDLifecycleError: Error, Equatable {
    /// HTTP 409 from stop-if-idle: the daemon still has registered attaches.
    /// Its admission, serving state and registrations are unchanged.
    case busy
    /// Any lifecycle status other than the one success its route defines.
    case refused(status: Int)
    case malformedResponse
}

/// The authenticated cross-release lifecycle API, version 1. It is fixed
/// across operational control versions, so an incoming app can quiesce an
/// authenticated outgoing release whatever that release's operational and
/// pfslocal numbers are, without ever speaking its attach protocol. It rides
/// the same owner-private control socket and carries no operational version
/// header.
enum PortableFSDLifecycle {
    static let identitySchemaVersion = 1
    static let identityPath = "/lifecycle/v1/identity"
    static let stopIfIdlePath = "/lifecycle/v1/stop-if-idle"
    static let maximumBodyBytes = 4_096
    /// Status line and headers of a lifecycle reply stay far below this.
    private static let maximumHeaderBytes = 16 * 1_024

    struct Response: Equatable {
        let status: Int
        let body: Data
    }

    static func requestBytes(method: String, path: String) -> Data {
        var request = "\(method) \(path) HTTP/1.1\r\nHost: portablefsd\r\nConnection: close\r\n"
        if method == "POST" {
            request += "Content-Length: 0\r\n"
        }
        request += "\r\n"
        return Data(request.utf8)
    }

    /// One request/reply on an already authenticated control connection.
    /// The caller owns the descriptor and its timeouts.
    static func exchange(_ fd: Int32, method: String, path: String) throws -> Response {
        let request = requestBytes(method: method, path: path)
        var sent = 0
        while sent < request.count {
            let count = request.withUnsafeBytes { bytes in
                Darwin.write(fd, bytes.baseAddress!.advanced(by: sent), request.count - sent)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw PortableFSDLifecycleError.malformedResponse }
            sent += count
        }
        var response = Data()
        var buffer = [UInt8](repeating: 0, count: 4_096)
        let limit = maximumHeaderBytes + maximumBodyBytes
        while response.count <= limit {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0, errno == EINTR { continue }
            if count == 0 { break }
            guard count > 0 else { throw PortableFSDLifecycleError.malformedResponse }
            response.append(buffer, count: count)
        }
        guard response.count <= limit else { throw PortableFSDLifecycleError.malformedResponse }
        return try parseResponse(response)
    }

    /// Parses one complete `Connection: close` reply. The body must be exactly
    /// the declared Content-Length when one is present; chunked transfer and
    /// oversized bodies are refused rather than reassembled.
    static func parseResponse(_ data: Data) throws -> Response {
        guard let boundary = data.range(of: Data("\r\n\r\n".utf8)),
              boundary.lowerBound <= maximumHeaderBytes,
              let header = String(data: data[..<boundary.lowerBound], encoding: .utf8) else {
            throw PortableFSDLifecycleError.malformedResponse
        }
        var lines = header.components(separatedBy: "\r\n")
        let statusLine = lines.removeFirst().split(separator: " ", maxSplits: 2)
        guard statusLine.count >= 2,
              statusLine[0] == "HTTP/1.1",
              statusLine[1].count == 3,
              let status = Int(statusLine[1]), (100...599).contains(status) else {
            throw PortableFSDLifecycleError.malformedResponse
        }
        var contentLength: Int?
        for line in lines {
            guard let colon = line.firstIndex(of: ":") else {
                throw PortableFSDLifecycleError.malformedResponse
            }
            let name = line[..<colon].lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            switch name {
            case "transfer-encoding":
                throw PortableFSDLifecycleError.malformedResponse
            case "content-length":
                guard contentLength == nil, let length = Int(value), length >= 0 else {
                    throw PortableFSDLifecycleError.malformedResponse
                }
                contentLength = length
            default:
                continue
            }
        }
        let body = Data(data[boundary.upperBound...])
        guard body.count <= maximumBodyBytes,
              contentLength == nil || contentLength == body.count else {
            throw PortableFSDLifecycleError.malformedResponse
        }
        return Response(status: status, body: body)
    }

    /// Identity is HTTP 200 with its strict schema-1 body; no other status is
    /// an identity, and a missing endpoint is never answered by falling back
    /// to an operational route.
    static func identity(from response: Response) throws -> PortableFSDLiveIdentity {
        guard response.status == 200 else {
            throw PortableFSDLifecycleError.refused(status: response.status)
        }
        return try PortableFSDLiveIdentity.decode(response.body)
    }

    /// Stop-if-idle succeeds only with HTTP 204 and no body. HTTP 409 is the
    /// definite busy refusal. Everything else, including 200, redirects and a
    /// missing endpoint, is a failure that proves nothing.
    static func stopIfIdleOutcome(_ response: Response) throws {
        switch response.status {
        case 204 where response.body.isEmpty:
            return
        case 409:
            throw PortableFSDLifecycleError.busy
        default:
            throw PortableFSDLifecycleError.refused(status: response.status)
        }
    }
}
