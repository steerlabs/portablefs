import Foundation
import CryptoKit
import Security
import Testing
@testable import PortableFSAppCore

/// Serves queued responses and records the requests it saw.
private final class StubTransport: HTTPDataTransport, @unchecked Sendable {
    struct Exchange {
        var status: Int
        var body: Data
    }

    private let lock = NSLock()
    private var queue: [Exchange]
    private(set) var requests: [URLRequest] = []

    init(_ responses: [Exchange]) {
        queue = responses
    }

    convenience init(status: Int, json: String) {
        self.init([Exchange(status: status, body: Data(json.utf8))])
    }

    private func record(_ request: URLRequest) -> Exchange {
        lock.lock()
        defer { lock.unlock() }
        requests.append(request)
        return queue.isEmpty ? Exchange(status: 599, body: Data()) : queue.removeFirst()
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let exchange = record(request)
        let response = HTTPURLResponse(
            url: request.url ?? URL(string: "https://stub")!,
            statusCode: exchange.status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        return (exchange.body, response)
    }

    var recordedPaths: [String] {
        lock.lock()
        defer { lock.unlock() }
        return requests.map { $0.url?.path(percentEncoded: false) ?? "" }
    }
}

private func systemCertificatePEM() throws -> String {
    var anchors: CFArray?
    let status = SecTrustCopyAnchorCertificates(&anchors)
    #expect(status == errSecSuccess)
    let certificate = try #require((anchors as? [SecCertificate])?.first)
    let der = SecCertificateCopyData(certificate) as Data
    return "-----BEGIN CERTIFICATE-----\n" +
        der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]) +
        "-----END CERTIFICATE-----\n"
}

private struct FailingTransport: HTTPDataTransport {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        throw URLError(.cannotConnectToHost)
    }
}

@Test func normalizeServerURLMatchesGoCLI() {
    #expect(ControlPlaneClient.normalizeServerURL("  api.example.com ") == "https://api.example.com")
    #expect(ControlPlaneClient.normalizeServerURL("http://x/") == "http://x")
    #expect(ControlPlaneClient.normalizeServerURL("https://x///") == "https://x")
    #expect(ControlPlaneClient.normalizeServerURL("") == "")
}

@Test func listVolumesDecodesGoShape() async throws {
    let fixture = """
    {"volumes":[
      {"volumeId":"vol-a","tenantId":"t1","createdAtMs":1751500000000,
       "branches":[{"name":"main","headCommitId":"c1"},{"name":"dev","headCommitId":"c2"}]},
      {"volumeId":"vol-b","tenantId":"t1","createdAtMs":1751500000001,"branches":[]}
    ]}
    """
    let transport = StubTransport(status: 200, json: fixture)
    let client = ControlPlaneClient(baseURL: "https://api", token: "tok", transport: transport)
    let volumes = try await client.listVolumes()
    #expect(volumes.count == 2)
    #expect(volumes[0].volumeId == "vol-a")
    #expect(volumes[0].branches.map(\.name) == ["main", "dev"])
    #expect(volumes[0].defaultBranch == "main")
    #expect(volumes[1].defaultBranch == "main")

    let request = transport.requests.first
    #expect(request?.value(forHTTPHeaderField: "Authorization") == "Bearer tok")
    #expect(request?.url?.absoluteString == "https://api/v1/volumes")
}

@Test func listVolumesSurfacesServerErrorEnvelope() async {
    let transport = StubTransport(status: 403, json: #"{"error":{"code":"FORBIDDEN","message":"tenant mismatch"}}"#)
    let client = ControlPlaneClient(baseURL: "https://api", token: "tok", transport: transport)
    do {
        _ = try await client.listVolumes()
        Issue.record("expected error")
    } catch let error as ControlPlaneError {
        #expect(error.status == 403)
        #expect(error.code == "FORBIDDEN")
        #expect(error.message == "tenant mismatch")
    } catch {
        Issue.record("unexpected error type: \(error)")
    }
}

@Test func listVolumesRejectsMissingCollectionOrIdentity() async {
    for json in [#"{}"#, #"{"volumes":[{"branches":[]}]}"#] {
        let client = ControlPlaneClient(
            baseURL: "https://api",
            token: "tok",
            transport: StubTransport(status: 200, json: json)
        )
        do {
            _ = try await client.listVolumes()
            Issue.record("expected incomplete list-volumes response to fail")
        } catch let error as ControlPlaneError {
            #expect(error.message.contains("list-volumes response"))
        } catch {
            Issue.record("unexpected error type: \(error)")
        }
    }
}

@Test func verifyCredentialMirrorsGoSemantics() async {
    // 401/403 = rejected.
    let rejected = ControlPlaneClient(
        baseURL: "https://api", token: "bad",
        transport: StubTransport(status: 401, json: "{}")
    )
    #expect(await rejected.verifyCredential() == .rejected(status: 401))

    // 404 (older build without the listing route) still proves auth passed.
    let accepted404 = ControlPlaneClient(
        baseURL: "https://api", token: "tok",
        transport: StubTransport(status: 404, json: "{}")
    )
    #expect(await accepted404.verifyCredential() == .accepted)

    let unreachable = ControlPlaneClient(baseURL: "https://api", token: "tok", transport: FailingTransport())
    if case .unreachable = await unreachable.verifyCredential() {
    } else {
        Issue.record("expected unreachable")
    }
}

@Test func deviceFlowStartAndPoll() async throws {
    let code = """
    {"deviceCode":"dc-1","userCode":"WDJB-MJHT","verificationUri":"https://api/activate",
     "expiresInSeconds":900,"intervalSeconds":5}
    """
    let client = ControlPlaneClient(
        baseURL: "https://api", token: "",
        transport: StubTransport(status: 200, json: code)
    )
    let started = try await client.startDeviceFlow()
    #expect(started.deviceCode == "dc-1")
    #expect(started.userCode == "WDJB-MJHT")
    #expect(started.pollInterval == 5)

    let pending202 = ControlPlaneClient(
        baseURL: "https://api", token: "",
        transport: StubTransport(status: 202, json: "")
    )
    #expect(try await pending202.pollDeviceToken(deviceCode: "dc-1") == .pending)

    let pending200 = ControlPlaneClient(
        baseURL: "https://api", token: "",
        transport: StubTransport(status: 200, json: #"{"status":"pending"}"#)
    )
    #expect(try await pending200.pollDeviceToken(deviceCode: "dc-1") == .pending)

    let ready = ControlPlaneClient(
        baseURL: "https://api", token: "",
        transport: StubTransport(status: 200, json: #"{"apiKey":"key-1","managerUrl":"https://mgr"}"#)
    )
    #expect(try await ready.pollDeviceToken(deviceCode: "dc-1") == .ready(apiKey: "key-1", managerUrl: "https://mgr"))

    let denied = ControlPlaneClient(
        baseURL: "https://api", token: "",
        transport: StubTransport(status: 410, json: #"{"error":"code expired"}"#)
    )
    if case .denied = try await denied.pollDeviceToken(deviceCode: "dc-1") {
    } else {
        Issue.record("expected denied")
    }
}

@Test func deviceFlowStartExplainsUnsupportedServers() async {
    let client = ControlPlaneClient(
        baseURL: "https://api", token: "",
        transport: StubTransport(status: 404, json: "")
    )
    do {
        _ = try await client.startDeviceFlow()
        Issue.record("expected error")
    } catch let error as ControlPlaneError {
        #expect(error.message.contains("does not support device login"))
    } catch {
        Issue.record("unexpected error type: \(error)")
    }
}

private let accessLeaseJSON = """
{"authority":{"authorityUrl":"tcp://10.0.0.5:7443","host":"10.0.0.5","port":7443,"authorityInstanceId":"auth-1",
 "dataPlaneTransport":{"mode":"tls-system-pki","serverName":"router.example"}},
 "lease":{"accessLeaseId":"pfal_1","controlSeq":"7","expiresAt":1751505000000,"state":"active"},
 "accessToken":"lease-token","serverTimeMs":1751504000000}
"""

private func accessLeaseResponse(transport: [String: Any]?) throws -> Data {
    var authority: [String: Any] = ["authorityUrl": "router.example:2050"]
    if let transport {
        authority["dataPlaneTransport"] = transport
    }
    return try JSONSerialization.data(withJSONObject: [
        "authority": authority,
        "lease": [
            "accessLeaseId": "pfal_1",
            "controlSeq": "1",
            "expiresAt": 1_751_505_000_000,
            "state": "active",
        ],
        "accessToken": "lease-token",
    ])
}

@Test func accessSessionAcceptsPrivateCAAndExplicitPlaintext() async throws {
    let pem = try systemCertificatePEM()
    let digest = SHA256.hash(data: Data(pem.utf8)).map { String(format: "%02x", $0) }.joined()
    let privateClient = ControlPlaneClient(
        baseURL: "https://mgr",
        token: "mtok",
        transport: StubTransport([.init(status: 200, body: try accessLeaseResponse(transport: [
            "mode": "tls-private-ca",
            "serverName": "router.example",
            "caPem": pem,
            "caSha256": digest,
        ]))])
    )
    #expect(
        try await privateClient.accessSession(volumeID: "vol-a", branch: "main").dataPlaneTransport ==
            .tlsPrivateCA(serverName: "router.example", caPEM: pem, caSHA256: digest)
    )

    let plaintextClient = ControlPlaneClient(
        baseURL: "https://mgr",
        token: "mtok",
        transport: StubTransport([.init(
            status: 200,
            body: try accessLeaseResponse(transport: ["mode": "plaintext"])
        )])
    )
    #expect(
        try await plaintextClient.accessSession(volumeID: "vol-a", branch: "main").dataPlaneTransport ==
            .plaintext
    )
}

@Test func accessSessionRejectsMissingConflictingAndFingerprintMismatchedTransport() async throws {
    let pem = try systemCertificatePEM()
    let cases: [([String: Any]?, String)] = [
        (nil, "upgrade the authority manager"),
        (["mode": "plaintext", "serverName": "router.example"], "conflicting"),
        (["mode": "tls-system-pki"], "incomplete"),
        ([
            "mode": "tls-private-ca",
            "serverName": "router.example",
            "caPem": pem,
            "caSha256": String(repeating: "0", count: 64),
        ], "fingerprint mismatch"),
        (["mode": "future"], "unsupported"),
    ]
    for (wire, expected) in cases {
        let client = ControlPlaneClient(
            baseURL: "https://mgr",
            token: "mtok",
            transport: StubTransport([.init(
                status: 200,
                body: try accessLeaseResponse(transport: wire)
            )])
        )
        do {
            _ = try await client.accessSession(volumeID: "vol-a", branch: "main")
            Issue.record("accepted invalid transport \(String(describing: wire))")
        } catch let error as ControlPlaneError {
            #expect(error.message.contains(expected))
        } catch {
            Issue.record("unexpected error type: \(error)")
        }
    }
}

@Test func accessSessionUsesAccessLeaseRoute() async throws {
    let transport = StubTransport([.init(status: 200, body: Data(accessLeaseJSON.utf8))])
    let client = ControlPlaneClient(baseURL: "https://mgr", token: "mtok", transport: transport)
    let session = try await client.accessSession(volumeID: "vol-a", branch: "main")
    #expect(session.authorityUrl == "tcp://10.0.0.5:7443")
    #expect(session.token == "lease-token")
    #expect(session.expiresAtMs == 1751505000000)
    #expect(session.accessLeaseId == "pfal_1")
    #expect(session.controlSeq == "7")
    #expect(session.dataPlaneTransport == .tlsSystemPKI(serverName: "router.example"))
    #expect(transport.recordedPaths == ["/v1/access-leases/create"])
}

@Test func accessSessionRenewsAndRotatesOnlyTheSameLease() async throws {
    let renewedJSON = """
    {"lease":{"accessLeaseId":"pfal_1","controlSeq":"8","expiresAt":1751506000000,"state":"active"},
     "accessToken":"rotated-token","serverTimeMs":1751505000000}
    """
    let transport = StubTransport(status: 200, json: renewedJSON)
    let client = ControlPlaneClient(baseURL: "https://mgr", token: "mtok", transport: transport)
    let initial = AccessSessionInfo(
        authorityUrl: "tcp://10.0.0.5:7443",
        token: "lease-token",
        expiresAtMs: 1751505000000,
        authorityInstanceId: "auth-1",
        accessLeaseId: "pfal_1",
        controlSeq: "7",
        dataPlaneTransport: .plaintext
    )
    let renewed = try await client.renewAccessSession(
        initial,
        operationID: "op-renew-1",
        rotateToken: true
    )
    #expect(renewed.authorityUrl == initial.authorityUrl)
    #expect(renewed.accessLeaseId == initial.accessLeaseId)
    #expect(renewed.controlSeq == "8")
    #expect(renewed.expiresAtMs == 1751506000000)
    #expect(renewed.token == "rotated-token")
    #expect(transport.recordedPaths == ["/v1/access-leases/renew"])

    let body = try #require(transport.requests.first?.httpBody)
    let payload = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
    #expect(payload["operationId"] as? String == "op-renew-1")
    #expect(payload["accessLeaseId"] as? String == "pfal_1")
    #expect(payload["expectedControlSeq"] as? String == "7")
    #expect(payload["rotateToken"] as? Bool == true)
}

@Test func accessLeaseFailureClassificationNeverReacquires() {
    #expect(
        ControlPlaneClient.accessLeaseFailureDisposition(
            ControlPlaneError(status: 0, message: "connection lost")
        ) == .retrySameOperation
    )
    #expect(
        ControlPlaneClient.accessLeaseFailureDisposition(
            ControlPlaneError(status: 503, code: "ACCESS_LEASE_EPOCH_SUPERSEDED", message: "old epoch")
        ) == .terminal
    )
    #expect(
        ControlPlaneClient.accessLeaseFailureDisposition(
            ControlPlaneError(status: 409, code: "ACCESS_LEASE_CONTROL_CONFLICT", message: "conflict")
        ) == .terminal
    )
}

@Test func accessSessionRenewRejectsIncompleteRotationWithoutFallback() async {
    let transport = StubTransport(
        status: 200,
        json: #"{"lease":{"accessLeaseId":"pfal_1","controlSeq":"8","expiresAt":1751506000000,"state":"active"}}"#
    )
    let client = ControlPlaneClient(baseURL: "https://mgr", token: "mtok", transport: transport)
    let initial = AccessSessionInfo(
        authorityUrl: "tcp://authority",
        token: "lease-token",
        expiresAtMs: 1751505000000,
        accessLeaseId: "pfal_1",
        controlSeq: "7",
        dataPlaneTransport: .plaintext
    )
    do {
        _ = try await client.renewAccessSession(
            initial,
            operationID: "op-renew-1",
            rotateToken: true
        )
        Issue.record("expected error")
    } catch let error as ControlPlaneError {
        #expect(error.message.contains("without the requested rotated access token"))
    } catch {
        Issue.record("unexpected error type: \(error)")
    }
    #expect(transport.recordedPaths == ["/v1/access-leases/renew"])
}

@Test func accessSessionReleaseUsesExactLeaseRouteAndOperation() async throws {
    let transport = StubTransport(
        status: 200,
        json: #"{"lease":{"accessLeaseId":"pfal_1"},"receipt":{"operationId":"op-release-1"},"serverTimeMs":1}"#
    )
    let client = ControlPlaneClient(baseURL: "https://mgr", token: "mtok", transport: transport)
    let session = AccessSessionInfo(
        authorityUrl: "tcp://authority",
        token: "lease-token",
        accessLeaseId: "pfal_1",
        controlSeq: "7",
        dataPlaneTransport: .plaintext
    )
    try await client.releaseAccessSession(session, operationID: "op-release-1")
    #expect(transport.recordedPaths == ["/v1/access-leases/release"])
    let body = try #require(transport.requests.first?.httpBody)
    let payload = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
    #expect(payload["operationId"] as? String == "op-release-1")
    #expect(payload["accessLeaseId"] as? String == "pfal_1")
    #expect(payload["accessToken"] as? String == "lease-token")
}

@Test func accessSessionNeverFallsBack() async {
    // The retired mount-session/authority-session routes answer 410; a
    // manager without the access-lease route is a hard error, never a probe
    // of retired paths.
    let transport = StubTransport([.init(status: 404, body: Data(#"{"error":"unknown route"}"#.utf8))])
    let client = ControlPlaneClient(baseURL: "https://mgr", token: "mtok", transport: transport)
    do {
        _ = try await client.accessSession(volumeID: "vol-a", branch: "main")
        Issue.record("expected error")
    } catch let error as ControlPlaneError {
        #expect(error.status == 404)
    } catch {
        Issue.record("unexpected error type: \(error)")
    }
    #expect(transport.recordedPaths == ["/v1/access-leases/create"])
}

@Test func accessSessionRejectsMissingEndpoint() async {
    let transport = StubTransport(status: 200, json: #"{"lease":{"accessLeaseId":"pfal_1"},"accessToken":"t"}"#)
    let client = ControlPlaneClient(baseURL: "https://mgr", token: "mtok", transport: transport)
    do {
        _ = try await client.accessSession(volumeID: "vol-a", branch: "main")
        Issue.record("expected error")
    } catch let error as ControlPlaneError {
        #expect(error.message.contains("without an authority endpoint"))
    } catch {
        Issue.record("unexpected error type: \(error)")
    }
}

@Test func accessSessionRejectsIncompleteLease() async {
    let transport = StubTransport(status: 200, json: #"{"authority":{"authorityUrl":"tcp://10.0.0.5:7443"},"lease":{},"accessToken":""}"#)
    let client = ControlPlaneClient(baseURL: "https://mgr", token: "mtok", transport: transport)
    do {
        _ = try await client.accessSession(volumeID: "vol-a", branch: "main")
        Issue.record("expected error")
    } catch let error as ControlPlaneError {
        #expect(error.message.contains("incomplete access lease"))
    } catch {
        Issue.record("unexpected error type: \(error)")
    }
}

@Test func accessSessionSurfacesErrors() async {
    let transport = StubTransport([.init(status: 502, body: Data(#"{"error":"no capacity"}"#.utf8))])
    let client = ControlPlaneClient(baseURL: "https://mgr", token: "mtok", transport: transport)
    do {
        _ = try await client.accessSession(volumeID: "vol-a", branch: "main")
        Issue.record("expected error")
    } catch let error as ControlPlaneError {
        #expect(error.status == 502)
        #expect(error.message == "no capacity")
    } catch {
        Issue.record("unexpected error type: \(error)")
    }
}
