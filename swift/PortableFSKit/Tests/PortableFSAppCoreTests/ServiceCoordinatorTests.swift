import Darwin
import Foundation
import PortableFSKit
import Testing
@testable import PortableFSAppCore

@_silgen_name("flock")
private func serviceCoordinatorTestFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

@Test func serviceCoordinatorDerivesEveryIdentityFromTheSignedHost() throws {
    let configuration = try PortableFSDServiceCoordinator.deriveConfiguration(
        bundleIdentifier: "dev.portablefs.PortableFSApp",
        teamIdentifier: "B47U2LLKHW",
        appGroupIdentifier: "B47U2LLKHW.pfsoss",
        shortVersion: "0.2.3",
        buildVersion: "42"
    )
    #expect(configuration.plistName == "dev.portablefs.PortableFSApp.portablefsd.plist")
    #expect(configuration.label == "dev.portablefs.PortableFSApp.portablefsd")
    #expect(configuration.serviceBundleIdentifier == "dev.portablefs.PortableFSApp.PortableFSDService")
    #expect(configuration.teamIdentifier == "B47U2LLKHW")
    #expect(configuration.appGroupIdentifier == "B47U2LLKHW.pfsoss")
    #expect(configuration.shortVersion == "0.2.3")
    #expect(configuration.buildVersion == "42")
}

@Test func serviceCoordinatorRejectsACrossTeamOrEmptyAppGroup() {
    #expect(throws: (any Error).self) {
        _ = try PortableFSDServiceCoordinator.deriveConfiguration(
            bundleIdentifier: "dev.portablefs.PortableFSApp",
            teamIdentifier: "B47U2LLKHW",
            appGroupIdentifier: "OTHERTEAM.pfsoss",
            shortVersion: "0.2.3",
            buildVersion: "42"
        )
    }
    #expect(throws: (any Error).self) {
        _ = try PortableFSDServiceCoordinator.deriveConfiguration(
            bundleIdentifier: "dev.portablefs.PortableFSApp",
            teamIdentifier: "B47U2LLKHW",
            appGroupIdentifier: "B47U2LLKHW.",
            shortVersion: "0.2.3",
            buildVersion: "42"
        )
    }
}

@Test func releaseIdentityContractUsesExactFrozenFieldsAndValues() throws {
    let identity = PortableFSDReleaseIdentity(
        codeDirectoryHash: String(repeating: "a", count: 40),
        executableSHA256: String(repeating: "b", count: 64),
        daemonVersion: "0.2.3",
        identitySchema: 1,
        controlProtocol: 2,
        pfslocalMajor: 2,
        pfslocalMinor: 0
    )
    try identity.validate()
    let object = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(identity))
            as? [String: Any]
    )
    #expect(Set(object.keys) == [
        "codeDirectoryHash", "executableSHA256", "daemonVersion",
        "identitySchema", "controlProtocol", "pfslocalMajor", "pfslocalMinor",
    ])

    #expect(throws: (any Error).self) {
        try PortableFSDReleaseIdentity(
            codeDirectoryHash: String(repeating: "A", count: 40),
            executableSHA256: String(repeating: "b", count: 64),
            daemonVersion: "0.2.3",
            identitySchema: 1,
            controlProtocol: 2,
            pfslocalMajor: 2,
            pfslocalMinor: 0
        ).validate()
    }

    try PortableFSDReleaseIdentity(
        codeDirectoryHash: String(repeating: "a", count: 40),
        executableSHA256: String(repeating: "b", count: 64),
        daemonVersion: "0.2.3",
        identitySchema: 1,
        controlProtocol: 77,
        pfslocalMajor: 91,
        pfslocalMinor: 0
    ).validate()
}

@Test func failedRegistrationMustFenceAndSurfacesAnAmbiguousFenceFailure() {
    struct ExpectedFailure: LocalizedError {
        let name: String
        var errorDescription: String? { name }
    }

    var fenced = 0
    #expect(throws: ExpectedFailure.self) {
        try PortableFSDServiceCoordinator.completeRegisteredRelease(
            operation: { throw ExpectedFailure(name: "identity mismatch") },
            fence: { fenced += 1 }
        )
    }
    #expect(fenced == 1)

    do {
        try PortableFSDServiceCoordinator.completeRegisteredRelease(
            operation: { throw ExpectedFailure(name: "identity mismatch") },
            fence: { throw ExpectedFailure(name: "socket still present") }
        )
        Issue.record("registration unexpectedly succeeded")
    } catch {
        #expect(error.localizedDescription.contains("identity mismatch"))
        #expect(error.localizedDescription.contains("socket still present"))
        #expect(error.localizedDescription.contains("state is ambiguous"))
    }
}

@Test func serviceFenceRequiresAllThreeIndependentProofs() {
    for status in [false, true] {
        for paths in [false, true] {
            for process in [false, true] {
                #expect(
                    PortableFSDServiceCoordinator.serviceFenceReady(
                        statusNotRegistered: status,
                        runtimePathsAbsent: paths,
                        processDeparted: process
                    ) == (status && paths && process)
                )
            }
        }
    }
}

@Test func daemonOwnershipRequiresTheCanonicalNestedServicePath() throws {
    let suffix = "/Contents/Library/LaunchAgents/PortableFSDService.app/Contents/MacOS/portablefsd"
    for app in ["/Applications/PortableFS.app", "/tmp/build/PortableFSKitDev.app"] {
        #expect(try PortableFSDServiceCoordinator.daemonOwningBundle(
            executableURL: URL(fileURLWithPath: app + suffix)
        ).path == app)
    }
    for path in [
        "/tmp/portablefsd",
        "/Applications/PortableFS.app/Contents/MacOS/portablefsd",
        "/Applications/PortableFS.app/Contents/Library/LaunchAgents/Other.app/Contents/MacOS/portablefsd",
        "/Applications/PortableFS.app" + suffix + ".other",
        "/tmp/not-an-app" + suffix,
    ] {
        #expect(throws: (any Error).self) {
            try PortableFSDServiceCoordinator.daemonOwningBundle(
                executableURL: URL(fileURLWithPath: path)
            )
        }
    }
    let networkURL = try #require(URL(string: "https://example.com/PortableFS.app" + suffix))
    #expect(throws: (any Error).self) {
        try PortableFSDServiceCoordinator.daemonOwningBundle(executableURL: networkURL)
    }
}

@Test func serviceOwnershipAdmitsAReleaseUpdateWithinTheSameSignedProduct() throws {
    let incoming = try PortableFSDServiceCoordinator.deriveConfiguration(
        bundleIdentifier: "dev.portablefs.oss.KitDev",
        teamIdentifier: "B47U2LLKHW",
        appGroupIdentifier: "B47U2LLKHW.pfsoss",
        shortVersion: "0.4.1",
        buildVersion: "42"
    )
    let running = try PortableFSDServiceCoordinator.deriveConfiguration(
        bundleIdentifier: "dev.portablefs.oss.KitDev",
        teamIdentifier: "B47U2LLKHW",
        appGroupIdentifier: "B47U2LLKHW.pfsoss",
        shortVersion: "0.3.0",
        buildVersion: "1"
    )
    try PortableFSDServiceCoordinator.validateServiceOwner(running, expected: incoming)
}

@Test func serviceOwnershipRejectsOtherProductsTeamsAndAppGroups() throws {
    let expected = try PortableFSDServiceCoordinator.deriveConfiguration(
        bundleIdentifier: "dev.portablefs.oss.KitDev",
        teamIdentifier: "B47U2LLKHW",
        appGroupIdentifier: "B47U2LLKHW.pfsoss",
        shortVersion: "0.4.1",
        buildVersion: "42"
    )
    for (product, team, group) in [
        ("dev.portablefs.Other", "B47U2LLKHW", "B47U2LLKHW.pfsoss"),
        ("dev.portablefs.oss.KitDev", "OTHERTEAM", "OTHERTEAM.pfsoss"),
        ("dev.portablefs.oss.KitDev", "B47U2LLKHW", "B47U2LLKHW.other"),
    ] {
        let owner = try PortableFSDServiceCoordinator.deriveConfiguration(
            bundleIdentifier: product,
            teamIdentifier: team,
            appGroupIdentifier: group,
            shortVersion: "0.3.0",
            buildVersion: "1"
        )
        #expect(throws: (any Error).self) {
            try PortableFSDServiceCoordinator.validateServiceOwner(owner, expected: expected)
        }
    }
}

/// A live daemon's reported identity is accepted only as an exact match of
/// the release sealed into the app whose signed daemon the socket peer
/// proved to be. An arbitrary outgoing release keeps its own operational and
/// pfslocal numbers; this build's pairing is never expected of it, and any
/// single deviation from the seal, including a spoofed protocol number, is
/// refused.
@Test func liveIdentityMustEqualTheSealedReleaseExactly() {
    for (control, major, minor) in [(77, UInt32(91), UInt32(18)), (2, 2, 0), (1, UInt32.max, UInt32.max)] {
        let sealed = PortableFSDReleaseIdentity(
            codeDirectoryHash: String(repeating: "a", count: 40),
            executableSHA256: String(repeating: "b", count: 64),
            daemonVersion: "0.3.0",
            identitySchema: 1,
            controlProtocol: control,
            pfslocalMajor: major,
            pfslocalMinor: minor
        )
        let exact = PortableFSDLiveIdentity(
            schemaVersion: 1, controlProtocol: control, daemonVersion: "0.3.0",
            executableSha256: sealed.executableSHA256,
            pfslocalMajor: major, pfslocalMinor: minor
        )
        #expect(exact.matches(sealed))

        let deviations = [
            PortableFSDLiveIdentity(schemaVersion: 2, controlProtocol: control, daemonVersion: "0.3.0",
                executableSha256: sealed.executableSHA256, pfslocalMajor: major, pfslocalMinor: minor),
            PortableFSDLiveIdentity(schemaVersion: 1, controlProtocol: control + 1, daemonVersion: "0.3.0",
                executableSha256: sealed.executableSHA256, pfslocalMajor: major, pfslocalMinor: minor),
            PortableFSDLiveIdentity(schemaVersion: 1, controlProtocol: control, daemonVersion: "0.4.1",
                executableSha256: sealed.executableSHA256, pfslocalMajor: major, pfslocalMinor: minor),
            PortableFSDLiveIdentity(schemaVersion: 1, controlProtocol: control, daemonVersion: "0.3.0",
                executableSha256: String(repeating: "c", count: 64), pfslocalMajor: major, pfslocalMinor: minor),
            PortableFSDLiveIdentity(schemaVersion: 1, controlProtocol: control, daemonVersion: "0.3.0",
                executableSha256: sealed.executableSHA256, pfslocalMajor: major &- 1, pfslocalMinor: minor),
            PortableFSDLiveIdentity(schemaVersion: 1, controlProtocol: control, daemonVersion: "0.3.0",
                executableSha256: sealed.executableSHA256, pfslocalMajor: major, pfslocalMinor: minor &+ 1),
        ]
        for deviation in deviations {
            #expect(!deviation.matches(sealed))
        }
    }
}

/// The daemon sealed into this app's own bundle must be exactly paired with
/// this build. That requirement is applied to the incoming release only.
@Test func incomingReleaseRequiresExactPairing() {
    func release(_ schema: Int, _ control: Int, _ major: UInt32, _ minor: UInt32) -> PortableFSDReleaseIdentity {
        PortableFSDReleaseIdentity(
            codeDirectoryHash: String(repeating: "a", count: 40),
            executableSHA256: String(repeating: "b", count: 64),
            daemonVersion: "0.5.0",
            identitySchema: schema,
            controlProtocol: control,
            pfslocalMajor: major,
            pfslocalMinor: minor
        )
    }
    #expect(PortableFSDServiceCoordinator.pairedControlProtocol == 2)
    #expect(PortableFSDServiceCoordinator.pairedPFSLocalMajor == 2)
    #expect(PortableFSDServiceCoordinator.pairedPFSLocalMinor == 0)
    #expect(PortableFSDServiceCoordinator.isPaired(release(1, 2, 2, 0)))
    for unpaired in [release(2, 2, 2, 0), release(1, 1, 2, 0), release(1, 3, 2, 0),
                     release(1, 2, 1, 16), release(1, 2, 2, 1), release(1, 2, 3, 0)] {
        #expect(!PortableFSDServiceCoordinator.isPaired(unpaired))
    }
}

@Test func sealedProtocolResourceDecodesStrictly() throws {
    for (control, major, minor) in [(2, UInt32(2), UInt32(0)), (77, 91, 18), (1, UInt32.max, UInt32.max)] {
        let data = Data(#"{"identitySchema":1,"controlProtocol":\#(control),"pfslocalMajor":\#(major),"pfslocalMinor":\#(minor)}"#.utf8)
        #expect(try PortableFSDSealedProtocols.decode(data) == PortableFSDSealedProtocols(
            identitySchema: 1, controlProtocol: control, pfslocalMajor: major, pfslocalMinor: minor
        ))
    }
    let valid = #"{"identitySchema":1,"controlProtocol":2,"pfslocalMajor":2,"pfslocalMinor":0}"#
    // Whitespace, key order and escaped key spellings are JSON, not grammar.
    _ = try PortableFSDSealedProtocols.decode(Data(#" { "pfslocalMinor" : 0, "pfslocalMajor":2, "controlProtocol":2, "identitySchema":1 } "#.utf8))
    var invalid = [
        "", "null", "[]", valid + "{}", valid + " x", String(repeating: " ", count: 4_096) + valid,
        #"{"identitySchema":2,"controlProtocol":2,"pfslocalMajor":2,"pfslocalMinor":0}"#,
        #"{"identitySchema":1,"controlProtocol":0,"pfslocalMajor":2,"pfslocalMinor":0}"#,
        #"{"identitySchema":1,"controlProtocol":-2,"pfslocalMajor":2,"pfslocalMinor":0}"#,
        #"{"identitySchema":1,"controlProtocol":2,"pfslocalMajor":0,"pfslocalMinor":0}"#,
        #"{"identitySchema":1,"controlProtocol":2,"pfslocalMajor":4294967296,"pfslocalMinor":0}"#,
        #"{"identitySchema":1,"controlProtocol":2,"pfslocalMajor":2,"pfslocalMinor":-1}"#,
        #"{"identitySchema":1,"controlProtocol":2.0,"pfslocalMajor":2,"pfslocalMinor":0}"#,
        #"{"identitySchema":1,"controlProtocol":2e0,"pfslocalMajor":2,"pfslocalMinor":0}"#,
        #"{"identitySchema":1,"controlProtocol":"2","pfslocalMajor":2,"pfslocalMinor":0}"#,
        #"{"identitySchema":1,"controlProtocol":true,"pfslocalMajor":2,"pfslocalMinor":0}"#,
        #"{"identitySchema":1,"controlProtocol":2,"pfslocalMajor":2,"pfslocalMinor":0,"executableSHA256":"b"}"#,
        #"{"identitySchema":1,"controlProtocol":2,"pfslocalMajor":2,"pfslocalMinor":{"x":0}}"#,
    ]
    for key in ["identitySchema", "controlProtocol", "pfslocalMajor", "pfslocalMinor"] {
        let member = #"""# + key + #"":"#
        invalid.append(valid.replacingOccurrences(of: member, with: #""unknown":"#))
        invalid.append(valid.replacingOccurrences(of: member, with: member + "null," + member))
        invalid.append(valid.replacingOccurrences(of: member, with: member + "1," + member))
    }
    for data in invalid {
        #expect(throws: (any Error).self, "accepted \(data)") {
            _ = try PortableFSDSealedProtocols.decode(Data(data.utf8))
        }
    }
}

/// Lifecycle identity is schema 1 with exactly six members and bounded
/// scalar shapes, decoded without any expectation of this build's numbers.
@Test func lifecycleIdentityDecodesStrictly() throws {
    let digest = String(repeating: "d", count: 64)
    let valid = #"{"schemaVersion":1,"controlProtocol":77,"daemonVersion":"0.9.1","executableSha256":"\#(digest)","pfslocalMajor":91,"pfslocalMinor":0}"#
    let decoded = try PortableFSDLiveIdentity.decode(Data(valid.utf8))
    #expect(decoded == PortableFSDLiveIdentity(
        schemaVersion: 1, controlProtocol: 77, daemonVersion: "0.9.1",
        executableSha256: digest, pfslocalMajor: 91, pfslocalMinor: 0
    ))
    // Trailing JSON whitespace is not trailing data.
    #expect(try PortableFSDLiveIdentity.decode(Data((valid + "\n").utf8)) == decoded)

    var invalid = [
        valid.replacingOccurrences(of: #""schemaVersion":1"#, with: #""schemaVersion":2"#),
        valid.replacingOccurrences(of: #""controlProtocol":77"#, with: #""controlProtocol":0"#),
        valid.replacingOccurrences(of: #""controlProtocol":77"#, with: #""controlProtocol":7.5"#),
        valid.replacingOccurrences(of: #""pfslocalMajor":91"#, with: #""pfslocalMajor":0"#),
        valid.replacingOccurrences(of: #""pfslocalMinor":0"#, with: #""pfslocalMinor":4294967296"#),
        valid.replacingOccurrences(of: #""0.9.1""#, with: #""""#),
        valid.replacingOccurrences(of: #""0.9.1""#, with: #""0.9 1""#),
        valid.replacingOccurrences(of: #""0.9.1""#, with: #"""# + String(repeating: "v", count: 129) + #"""#),
        valid.replacingOccurrences(of: digest, with: String(repeating: "D", count: 64)),
        valid.replacingOccurrences(of: digest, with: String(repeating: "d", count: 63)),
        valid.replacingOccurrences(of: #""pfslocalMinor":0"#, with: #""pfslocalMinor":0,"pid":1"#),
        valid + "{}",
        "[" + valid + "]",
    ]
    for key in ["schemaVersion", "controlProtocol", "daemonVersion", "executableSha256", "pfslocalMajor", "pfslocalMinor"] {
        let member = #"""# + key + #"":"#
        invalid.append(valid.replacingOccurrences(of: member, with: #""Unknown":"#))
        invalid.append(valid.replacingOccurrences(of: member, with: member + "null," + member))
        invalid.append(valid.replacingOccurrences(of: member, with: #""A":0,"# + member))
    }
    for data in invalid {
        #expect(throws: (any Error).self, "accepted \(data)") {
            _ = try PortableFSDLiveIdentity.decode(Data(data.utf8))
        }
    }
}

/// Parity vectors with Go's `daemonctl.DecodeSealedProtocols` and
/// `DecodeIdentity`, which decode through encoding/json into `int` and
/// `uint32` fields. Each value replaces one member of an otherwise valid
/// body, and the verdict is Go's: an unsigned field takes digits only (Go
/// refuses `-0` for uint32), a signed field takes an optional minus sign and
/// must then be positive, and neither takes a fraction, an exponent or an
/// out-of-range value. The same table was run against the Go decoders.
private let sealedNumberParityVectors: [(key: String, value: String, accepted: Bool)] = [
    ("pfslocalMinor", "0", true),
    ("pfslocalMinor", "4294967295", true),
    ("pfslocalMinor", "-0", false),
    ("pfslocalMinor", "-1", false),
    ("pfslocalMinor", "0.0", false),
    ("pfslocalMinor", "0e0", false),
    ("pfslocalMinor", "0E+0", false),
    ("pfslocalMinor", "4294967296", false),
    ("pfslocalMinor", "00", false),
    ("pfslocalMinor", "+0", false),
    ("pfslocalMinor", "-", false),
    ("pfslocalMajor", "-0", false),
    ("pfslocalMajor", "-2", false),
    ("pfslocalMajor", "2.0", false),
    ("controlProtocol", "-0", false),
    ("controlProtocol", "-2", false),
    ("controlProtocol", "9223372036854775807", true),
    ("controlProtocol", "9223372036854775808", false),
    ("controlProtocol", "2.5", false),
    ("identitySchema", "-1", false),
    ("identitySchema", "1.0", false),
]

@Test func sealedAndLiveProtocolNumbersFollowGoFieldGrammar() throws {
    let sealed = ["identitySchema": "1", "controlProtocol": "2", "pfslocalMajor": "2", "pfslocalMinor": "0"]
    func sealedBody(_ key: String, _ value: String) -> String {
        "{" + ["identitySchema", "controlProtocol", "pfslocalMajor", "pfslocalMinor"].map {
            #"""# + $0 + #"":"# + ($0 == key ? value : sealed[$0]!)
        }.joined(separator: ",") + "}"
    }
    for vector in sealedNumberParityVectors {
        let body = sealedBody(vector.key, vector.value)
        let decoded = try? PortableFSDSealedProtocols.decode(Data(body.utf8))
        #expect((decoded != nil) == vector.accepted, "sealed \(body)")
    }
    // An escaped key spelling is the same key in both decoders.
    #expect(try PortableFSDSealedProtocols.decode(Data(
        #"{"identitySchema":1,"controlProtocol":2,"pfslocalMajor":2,"pfslocal\u004dinor":0}"#.utf8
    )).pfslocalMinor == 0)

    // The live identity shares the accessor and therefore the grammar.
    let digest = String(repeating: "d", count: 64)
    let live = [
        "schemaVersion": "1", "controlProtocol": "2", "daemonVersion": #""0.9.1""#,
        "executableSha256": #"""# + digest + #"""#, "pfslocalMajor": "2", "pfslocalMinor": "0",
    ]
    let liveKeys = ["schemaVersion", "controlProtocol", "daemonVersion", "executableSha256", "pfslocalMajor", "pfslocalMinor"]
    for vector in sealedNumberParityVectors {
        let key = vector.key == "identitySchema" ? "schemaVersion" : vector.key
        let body = "{" + liveKeys.map {
            #"""# + $0 + #"":"# + ($0 == key ? vector.value : live[$0]!)
        }.joined(separator: ",") + "}"
        let decoded = try? PortableFSDLiveIdentity.decode(Data(body.utf8))
        #expect((decoded != nil) == vector.accepted, "live \(body)")
    }
}

private func lifecycleResponse(_ status: String, headers: [String] = [], body: String = "") -> Data {
    var text = "HTTP/1.1 \(status)\r\n"
    for header in headers { text += header + "\r\n" }
    text += "\r\n" + body
    return Data(text.utf8)
}

/// Identity is exactly HTTP 200 with its strict body; stop-if-idle is exactly
/// HTTP 204 with no body, 409 is the definite busy refusal, and every other
/// status, a missing endpoint included, proves nothing. Chunked transfer,
/// oversized bodies and a mismatched Content-Length are refused.
@Test func lifecycleResponsesAreClassifiedExactly() throws {
    let digest = String(repeating: "e", count: 64)
    let body = #"{"schemaVersion":1,"controlProtocol":2,"daemonVersion":"0.5.0","executableSha256":"\#(digest)","pfslocalMajor":2,"pfslocalMinor":0}"#
    let identity = try PortableFSDLifecycle.identity(from: PortableFSDLifecycle.parseResponse(
        lifecycleResponse("200 OK", headers: ["Content-Type: application/json", "Content-Length: \(body.utf8.count)"], body: body)
    ))
    #expect(identity.executableSha256 == digest)
    for status in ["404 Not Found", "426 Upgrade Required", "500 Internal Server Error", "301 Moved Permanently", "204 No Content"] {
        #expect(throws: PortableFSDLifecycleError.self) {
            _ = try PortableFSDLifecycle.identity(from: PortableFSDLifecycle.parseResponse(
                lifecycleResponse(status, body: status.hasPrefix("204") ? "" : body)
            ))
        }
    }

    try PortableFSDLifecycle.stopIfIdleOutcome(PortableFSDLifecycle.parseResponse(lifecycleResponse("204 No Content")))
    #expect(throws: PortableFSDLifecycleError.busy) {
        try PortableFSDLifecycle.stopIfIdleOutcome(PortableFSDLifecycle.parseResponse(
            lifecycleResponse("409 Conflict", headers: ["Content-Length: 11"], body: "busy detail")
        ))
    }
    for (status, responseBody) in [("204 No Content", "{}"), ("200 OK", ""), ("202 Accepted", ""),
                                   ("404 Not Found", ""), ("307 Temporary Redirect", ""), ("500 Internal Server Error", "")] {
        #expect(throws: PortableFSDLifecycleError.self) {
            try PortableFSDLifecycle.stopIfIdleOutcome(PortableFSDLifecycle.parseResponse(
                lifecycleResponse(status, body: responseBody)
            ))
        }
    }
    do {
        try PortableFSDLifecycle.stopIfIdleOutcome(PortableFSDLifecycle.parseResponse(lifecycleResponse("404 Not Found")))
    } catch let error as PortableFSDLifecycleError {
        #expect(error == .refused(status: 404))
    }

    for malformed in [
        lifecycleResponse("200 OK", headers: ["Transfer-Encoding: chunked"], body: "5\r\nhello\r\n0\r\n\r\n"),
        lifecycleResponse("200 OK", headers: ["Content-Length: 3"], body: body),
        lifecycleResponse("200 OK", headers: ["Content-Length: 1", "Content-Length: 1"], body: "x"),
        lifecycleResponse("200 OK", body: String(repeating: " ", count: 4_097)),
        lifecycleResponse("2000 OK"),
        Data("HTTP/1.0 200 OK\r\n\r\n".utf8),
        Data("HTTP/1.1 200 OK\r\nno-colon-header\r\n\r\n".utf8),
        Data("HTTP/1.1 200 OK\r\n".utf8),
    ] {
        #expect(throws: PortableFSDLifecycleError.malformedResponse) {
            _ = try PortableFSDLifecycle.parseResponse(malformed)
        }
    }
}

/// The exchange speaks the fixed lifecycle request grammar: exact method and
/// path, no operational control-protocol header, an empty POST body.
@Test func lifecycleExchangeSpeaksTheFixedRequestGrammar() throws {
    for (method, path, response) in [
        ("GET", PortableFSDLifecycle.identityPath, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"),
        ("POST", PortableFSDLifecycle.stopIfIdlePath, "HTTP/1.1 204 No Content\r\n\r\n"),
    ] {
        var pair: [Int32] = [-1, -1]
        try #require(Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        let server = pair[1]
        let received = DispatchSemaphore(value: 0)
        final class Captured: @unchecked Sendable { var request = Data() }
        let captured = Captured()
        let thread = Thread {
            var buffer = [UInt8](repeating: 0, count: 1_024)
            while captured.request.range(of: Data("\r\n\r\n".utf8)) == nil {
                let count = Darwin.read(server, &buffer, buffer.count)
                if count <= 0 { break }
                captured.request.append(buffer, count: count)
            }
            _ = response.withCString { Darwin.write(server, $0, strlen($0)) }
            Darwin.close(server)
            received.signal()
        }
        thread.start()
        let reply = try PortableFSDLifecycle.exchange(pair[0], method: method, path: path)
        Darwin.close(pair[0])
        received.wait()
        let request = String(decoding: captured.request, as: UTF8.self)
        var expected = "\(method) \(path) HTTP/1.1\r\nHost: portablefsd\r\nConnection: close\r\n"
        if method == "POST" { expected += "Content-Length: 0\r\n" }
        expected += "\r\n"
        #expect(request == expected)
        #expect(!request.contains("X-PortableFS-Control-Protocol"))
        #expect(reply.status == (method == "GET" ? 200 : 204))
    }
}

@Test func pfsLocalTransportErrorsSurfaceTheirOwnDescription() {
    let failure = PfsLocalClientError.system(errno: ENOENT, operation: "connect")
    #expect(failure.localizedDescription == failure.description)
    #expect(failure.localizedDescription.contains("connect"))
    #expect(!failure.localizedDescription.contains("error 6"))
}

@Test func daemonProcessWitnessRemainsBoundToTheObservedExecution() throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sleep")
    process.arguments = ["30"]
    try process.run()
    defer {
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
    }

    let witness = try PortableFSDServiceCoordinator.DaemonProcessWitness(
        pid: process.processIdentifier,
        pidVersion: 1
    )
    #expect(try !witness.hasExited())

    process.terminate()
    let deadline = Date().addingTimeInterval(5)
    while try !witness.hasExited(), Date() < deadline {
        Thread.sleep(forTimeInterval: 0.01)
    }
    #expect(try witness.hasExited())

    // A later unrelated process cannot change the terminal verdict. The
    // kqueue registration is bound to the exited execution, not a PID lookup.
    let unrelated = Process()
    unrelated.executableURL = URL(fileURLWithPath: "/usr/bin/true")
    try unrelated.run()
    unrelated.waitUntilExit()
    #expect(try witness.hasExited())
}

@Test func unpublishedDaemonFenceProvesThePinnedStateSingleton() throws {
    let fileManager = FileManager.default
    let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent("pfs-state-fence-\(UUID().uuidString)", isDirectory: true)
    #expect(try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root))

    try fileManager.createDirectory(
        at: root,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    defer { try? fileManager.removeItem(at: root) }

    #expect(try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root))

    let lock = root.appendingPathComponent(".portablefsd-state.lock")
    #expect(fileManager.createFile(
        atPath: lock.path,
        contents: Data("owner\n".utf8),
        attributes: [.posixPermissions: 0o600]
    ))
    #expect(try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root))

    let descriptor = Darwin.open(lock.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    #expect(descriptor >= 0)
    guard descriptor >= 0 else { return }
    defer { Darwin.close(descriptor) }
    #expect(serviceCoordinatorTestFlock(descriptor, LOCK_EX | LOCK_NB) == 0)
    defer { _ = serviceCoordinatorTestFlock(descriptor, LOCK_UN) }
    #expect(try !PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root))
}

@Test func unpublishedDaemonFenceRejectsUnsafeLockEntries() throws {
    let fileManager = FileManager.default

    func withRoot(_ body: (URL) throws -> Void) throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("pfs-state-fence-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? fileManager.removeItem(at: root) }
        try body(root)
    }

    try withRoot { root in
        try fileManager.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: root.path
        )
        #expect(throws: (any Error).self) {
            _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root)
        }
    }
    try withRoot { root in
        let alias = root.appendingPathExtension("alias")
        try fileManager.createSymbolicLink(at: alias, withDestinationURL: root)
        defer { try? fileManager.removeItem(at: alias) }
        #expect(throws: (any Error).self) {
            _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: alias)
        }
    }
    try withRoot { root in
        let lock = root.appendingPathComponent(".portablefsd-state.lock")
        #expect(fileManager.createFile(
            atPath: lock.path,
            contents: Data(),
            attributes: [.posixPermissions: 0o644]
        ))
        #expect(throws: (any Error).self) {
            _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root)
        }
    }
    try withRoot { root in
        let target = root.appendingPathComponent("target")
        #expect(fileManager.createFile(
            atPath: target.path,
            contents: Data(),
            attributes: [.posixPermissions: 0o600]
        ))
        let lock = root.appendingPathComponent(".portablefsd-state.lock")
        try fileManager.createSymbolicLink(at: lock, withDestinationURL: target)
        #expect(throws: (any Error).self) {
            _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root)
        }
    }
    try withRoot { root in
        let lock = root.appendingPathComponent(".portablefsd-state.lock")
        let alias = root.appendingPathComponent("alias")
        #expect(fileManager.createFile(
            atPath: lock.path,
            contents: Data(),
            attributes: [.posixPermissions: 0o600]
        ))
        guard Darwin.link(lock.path, alias.path) == 0 else {
            Issue.record("create hard link: \(String(cString: strerror(errno)))")
            return
        }
        #expect(throws: (any Error).self) {
            _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root)
        }
    }
    try withRoot { root in
        let lock = root.appendingPathComponent(".portablefsd-state.lock")
        guard Darwin.mkfifo(lock.path, 0o600) == 0 else {
            Issue.record("create FIFO: \(String(cString: strerror(errno)))")
            return
        }
        #expect(throws: (any Error).self) {
            _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(at: root)
        }
    }
}

@Test func unpublishedDaemonFenceRejectsLockAndDirectoryReplacementRaces() throws {
    let fileManager = FileManager.default

    let lockRoot = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent("pfs-lock-race-\(UUID().uuidString)", isDirectory: true)
    try fileManager.createDirectory(
        at: lockRoot,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    defer { try? fileManager.removeItem(at: lockRoot) }
    let lock = lockRoot.appendingPathComponent(".portablefsd-state.lock")
    #expect(fileManager.createFile(
        atPath: lock.path,
        contents: Data(),
        attributes: [.posixPermissions: 0o600]
    ))
    #expect(throws: (any Error).self) {
        _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(
            at: lockRoot,
            beforeFinalRecheck: {
                try fileManager.removeItem(at: lock)
                guard fileManager.createFile(
                    atPath: lock.path,
                    contents: Data(),
                    attributes: [.posixPermissions: 0o600]
                ) else {
                    throw CocoaError(.fileWriteUnknown)
                }
            }
        )
    }

    let directoryRoot = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent("pfs-dir-race-\(UUID().uuidString)", isDirectory: true)
    let displaced = directoryRoot.appendingPathExtension("old")
    try fileManager.createDirectory(
        at: directoryRoot,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    defer {
        try? fileManager.removeItem(at: directoryRoot)
        try? fileManager.removeItem(at: displaced)
    }
    #expect(throws: (any Error).self) {
        _ = try PortableFSDServiceCoordinator.stateSingletonIsUnlocked(
            at: directoryRoot,
            beforeFinalRecheck: {
                try fileManager.moveItem(at: directoryRoot, to: displaced)
                try fileManager.createDirectory(
                    at: directoryRoot,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
            }
        )
    }
}

// MARK: - Live service owner decision flow

private typealias Coordinator = PortableFSDServiceCoordinator

private func ownerTestConfiguration() throws -> Coordinator.Configuration {
    try Coordinator.deriveConfiguration(
        bundleIdentifier: "dev.portablefs.oss.KitDev",
        teamIdentifier: "B47U2LLKHW",
        appGroupIdentifier: "B47U2LLKHW.pfsoss",
        shortVersion: "0.4.2",
        buildVersion: "42"
    )
}

private func ownerTestRelease(
    version: String,
    digit: Character,
    controlProtocol: Int = 2,
    pfslocalMajor: UInt32 = 2,
    pfslocalMinor: UInt32 = 0
) -> PortableFSDReleaseIdentity {
    PortableFSDReleaseIdentity(
        codeDirectoryHash: String(repeating: digit, count: 40),
        executableSHA256: String(repeating: digit, count: 64),
        daemonVersion: version,
        identitySchema: 1,
        controlProtocol: controlProtocol,
        pfslocalMajor: pfslocalMajor,
        pfslocalMinor: pfslocalMinor
    )
}

/// Unix socket paths must fit sockaddr_un, so fixtures live under /tmp rather
/// than the much longer per-user temporary directory.
private func withOwnerFixtureDirectory(_ body: (URL) throws -> Void) throws {
    var template = Array("/tmp/pfs-owner.XXXXXX".utf8CString)
    guard let created = Darwin.mkdtemp(&template) else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    let root = URL(fileURLWithPath: String(cString: created), isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try body(root)
}

private func makeOwnerBundle(at url: URL, identifier: String) throws -> Bundle {
    let contents = url.appendingPathComponent("Contents", isDirectory: true)
    try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
    let plist: [String: Any] = [
        "CFBundleIdentifier": identifier,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "0.4.1",
        "CFBundleVersion": "41",
        "PFSAppGroupIdentifier": "B47U2LLKHW.pfsoss",
    ]
    let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    try data.write(to: contents.appendingPathComponent("Info.plist"))
    return try #require(Bundle(url: url))
}

private func ownerRefusal(
    _ operation: () throws -> Void
) -> Coordinator.UnauthenticatedServiceOwner? {
    do {
        try operation()
    } catch Coordinator.RegistrationError.unauthenticatedServiceOwner(let owner) {
        return owner
    } catch {
        Issue.record("expected an unauthenticated-owner refusal, got \(error.localizedDescription)")
        return nil
    }
    Issue.record("expected an unauthenticated-owner refusal")
    return nil
}

private func ownProcessExecutablePath() throws -> String {
    var buffer = [CChar](repeating: 0, count: 4 * 1_024)
    let length = proc_pidpath(getpid(), &buffer, UInt32(buffer.count))
    guard length > 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
    return URL(fileURLWithPath: String(decoding: bytes, as: UTF8.self)).standardizedFileURL.path
}

/// A valid older release, or this release from another copy of the app, is
/// replaced, and every later step binds to its authenticated identity: the
/// empty-inventory guard reads that exact daemon's attaches and the fence
/// waits for that exact execution. The state singleton is never consulted.
@Test func liveOwnerDecisionReplacesAValidOlderReleaseThroughItsOwnIdentity() throws {
    try withOwnerFixtureDirectory { root in
        let incoming = ownerTestRelease(version: "0.4.2", digit: "b")
        // An arbitrary distinct release: its own operational and pfslocal
        // numbers are carried through, never this build's pairing.
        let older = ownerTestRelease(
            version: "0.4.1",
            digit: "c",
            controlProtocol: 7,
            pfslocalMajor: 3,
            pfslocalMinor: 15
        )
        let incomingURL = root.appendingPathComponent("New.app", isDirectory: true)
        let oldBundle = try makeOwnerBundle(
            at: root.appendingPathComponent("Old.app", isDirectory: true),
            identifier: "dev.portablefs.oss.KitDev"
        )
        let running = Coordinator.RunningDaemon(bundle: oldBundle, releaseIdentity: older)

        guard case .replace(let outgoing?) = Coordinator.registrationStep(
            for: .authenticated(running),
            incoming: incoming,
            bundleURL: incomingURL
        ) else {
            Issue.record("a valid older release must be replaced through its identity")
            return
        }
        #expect(outgoing.releaseIdentity == older)
        #expect(Coordinator.inventoryGuardArguments(outgoing: outgoing.releaseIdentity) == [
            "lifecycle", "hold-install-exclusive", "--json",
            "--expected-daemon-version", "0.4.1",
            "--expected-daemon-sha256", String(repeating: "c", count: 64),
            "--expected-pfslocal-major", "3",
            "--expected-pfslocal-minor", "15",
        ])

        var probed: [PortableFSDReleaseIdentity] = []
        var singletonConsulted = false
        let witness = try Coordinator.replacementWitness(
            outgoing: outgoing,
            probe: { daemon in
                probed.append(daemon.releaseIdentity)
                return try Coordinator.DaemonProcessWitness(pid: getpid(), pidVersion: 1)
            },
            excludeDaemons: {
                singletonConsulted = true
                return nil
            }
        )
        guard case .process = witness else {
            Issue.record("an authenticated outgoing daemon must be fenced by its execution")
            return
        }
        #expect(probed == [older])
        #expect(!singletonConsulted)

        let sameReleaseElsewhere = Coordinator.RunningDaemon(bundle: oldBundle, releaseIdentity: incoming)
        guard case .replace(_?) = Coordinator.registrationStep(
            for: .authenticated(sameReleaseElsewhere),
            incoming: incoming,
            bundleURL: incomingURL
        ) else {
            Issue.record("this release running from another app copy must be replaced")
            return
        }
        guard case .keep = Coordinator.registrationStep(
            for: .authenticated(sameReleaseElsewhere),
            incoming: incoming,
            bundleURL: oldBundle.bundleURL
        ) else {
            Issue.record("the exact release from this bundle must be kept")
            return
        }
    }
}

/// A missing endpoint is replaced only while this app holds the state
/// singleton, so no daemon can run; the guard then adopts no daemon identity.
@Test func liveOwnerDecisionReplacesAMissingEndpointOnlyWhileHoldingTheSingleton() throws {
    try withOwnerFixtureDirectory { root in
        let owner = try Coordinator.inspectLiveServiceOwner(
            controlSocket: root.appendingPathComponent("control.sock"),
            configuration: try ownerTestConfiguration()
        )
        guard case .unpublished = owner else {
            Issue.record("a missing endpoint must classify as unpublished")
            return
        }
        guard case .replace(nil) = Coordinator.registrationStep(
            for: owner,
            incoming: ownerTestRelease(version: "0.4.2", digit: "b"),
            bundleURL: root.appendingPathComponent("New.app", isDirectory: true)
        ) else {
            Issue.record("an unpublished owner must be replaced without an outgoing identity")
            return
        }
        #expect(Coordinator.inventoryGuardArguments(outgoing: nil) == [
            "lifecycle", "hold-install-exclusive", "--json",
        ])

        let stateDirectory = root.appendingPathComponent("state", isDirectory: true)
        try FileManager.default.createDirectory(
            at: stateDirectory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let witness = try Coordinator.replacementWitness(
            outgoing: nil,
            probe: { _ in
                Issue.record("an unpublished owner has no execution to probe")
                throw POSIXError(.EINVAL)
            },
            excludeDaemons: {
                try Coordinator.acquireStateSingletonExclusion(at: stateDirectory)
            }
        )
        guard case .excluded = witness else {
            Issue.record("a free singleton must be held across unregistration")
            return
        }
        #expect(try witness.hasDeparted())
        #expect(try !Coordinator.stateSingletonIsUnlocked(at: stateDirectory))
        witness.releaseExclusion()
        #expect(try Coordinator.stateSingletonIsUnlocked(at: stateDirectory))
    }
}

/// No endpoint, but a held state singleton: a daemon is starting or stopping
/// and nothing can authenticate it, so replacement is refused.
@Test func liveOwnerDecisionRefusesAnOccupiedStateSingleton() throws {
    try withOwnerFixtureDirectory { root in
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        let lock = root.appendingPathComponent(".portablefsd-state.lock")
        #expect(FileManager.default.createFile(
            atPath: lock.path,
            contents: Data(),
            attributes: [.posixPermissions: 0o600]
        ))
        let descriptor = Darwin.open(lock.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        try #require(descriptor >= 0)
        defer { Darwin.close(descriptor) }
        try #require(serviceCoordinatorTestFlock(descriptor, LOCK_EX | LOCK_NB) == 0)
        defer { _ = serviceCoordinatorTestFlock(descriptor, LOCK_UN) }

        let refusal = ownerRefusal {
            _ = try Coordinator.replacementWitness(
                outgoing: nil,
                probe: { _ in
                    Issue.record("an unpublished owner has no execution to probe")
                    throw POSIXError(.EINVAL)
                },
                excludeDaemons: {
                    try Coordinator.acquireStateSingletonExclusion(at: root)
                }
            )
        }
        #expect(refusal == .occupiedStateSingleton)
    }
}

private func ownerMessage(_ owner: Coordinator.UnauthenticatedServiceOwner?) -> String {
    guard let owner else { return "" }
    return Coordinator.RegistrationError.unauthenticatedServiceOwner(owner).localizedDescription
}

/// Only an observed absence is reported as a missing owner app. A bundle
/// that exists but does not authenticate is reported as exactly that
/// failure, with the underlying error, not as a guessed replacement.
@Test func liveOwnerDecisionRefusesAMissingOrUnauthenticatableOwnerApp() throws {
    try withOwnerFixtureDirectory { root in
        let configuration = try ownerTestConfiguration()
        let socket = root.appendingPathComponent("control.sock").path

        let deleted = root.appendingPathComponent("Deleted.app", isDirectory: true)
        let missing = ownerRefusal {
            _ = try Coordinator.ownerApp(at: deleted, expected: configuration, controlSocket: socket)
        }
        #expect(missing == .ownerAppMissing(app: deleted.path))
        #expect(ownerMessage(missing).contains("no longer exists at that path"))
        #expect(ownerMessage(missing).contains("log out"))

        // Present, plausible, but unsigned: the signature check's own error
        // is the reported failure.
        let unsigned = root.appendingPathComponent("Unsigned.app", isDirectory: true)
        _ = try makeOwnerBundle(at: unsigned, identifier: "dev.portablefs.oss.KitDev")
        let unauthenticated = ownerRefusal {
            _ = try Coordinator.ownerApp(at: unsigned, expected: configuration, controlSocket: socket)
        }
        guard case let .unauthenticated(reportedSocket, step, failure)? = unauthenticated else {
            Issue.record("an unsigned owner app must be reported as a failed authentication")
            return
        }
        #expect(reportedSocket == socket)
        #expect(step == .ownerAppSignature(app: unsigned.path))
        #expect(failure.contains("signature"))
        #expect(!ownerMessage(unauthenticated).contains("was replaced while"))

        let file = root.appendingPathComponent("File.app", isDirectory: false)
        #expect(FileManager.default.createFile(atPath: file.path, contents: Data("x".utf8)))
        #expect(ownerRefusal {
            _ = try Coordinator.ownerApp(at: file, expected: configuration, controlSocket: socket)
        } == .unauthenticated(
            socket: socket,
            step: .ownerAppSignature(app: file.path),
            failure: "the path is not an app bundle"
        ))
    }
}

/// "Replaced" is reserved for an established identity mismatch: the daemon
/// reports a different release or executable than the signed app at its
/// path. Any other identity mismatch is only a failed proof.
@Test func ownerReplacementRequiresAnEstablishedIdentityMismatch() {
    let installed = ownerTestRelease(version: "0.4.2", digit: "b")
    let app = "/Applications/PortableFS.app"
    let socket = "/tmp/control.sock"
    let olderDaemon = PortableFSDLiveIdentity(
        schemaVersion: 1, controlProtocol: 2, daemonVersion: "0.4.1",
        executableSha256: String(repeating: "c", count: 64), pfslocalMajor: 2, pfslocalMinor: 0
    )
    let replaced = Coordinator.identityRefusal(
        reported: olderDaemon, sealed: installed, app: app, socket: socket
    )
    #expect(replaced == .ownerAppReplaced(
        app: app,
        running: "0.4.1 (executable cccccccccccc)",
        installed: "0.4.2 (executable bbbbbbbbbbbb)"
    ))
    #expect(ownerMessage(replaced).contains("was replaced while its daemon ran"))

    // Same release and executable, but protocol numbers the seal does not
    // declare: a spoofed claim, refused as a failed identity proof.
    let spoofedProtocol = PortableFSDLiveIdentity(
        schemaVersion: 1, controlProtocol: 3, daemonVersion: installed.daemonVersion,
        executableSha256: installed.executableSHA256, pfslocalMajor: 2, pfslocalMinor: 0
    )
    #expect(!spoofedProtocol.matches(installed))
    #expect(Coordinator.identityRefusal(
        reported: spoofedProtocol, sealed: installed, app: app, socket: socket
    ) == .unauthenticated(
        socket: socket,
        step: .daemonIdentity,
        failure: "its reported protocol numbers differ from the release sealed into that app"
    ))
}

/// Whatever serves the endpoint without being the daemon nested in a
/// PortableFS app is a foreign owner. Here the test process itself listens
/// on the endpoint, so its real kernel-reported executable is classified.
@Test func liveOwnerDecisionRefusesAForeignSocketOwner() throws {
    try withOwnerFixtureDirectory { root in
        let configuration = try ownerTestConfiguration()
        let socket = root.appendingPathComponent("control.sock")
        let listener = try PfsUnixSocket.bindAndListen(path: socket.path)
        defer { PfsUnixSocket.close(listener) }

        let refusal = ownerRefusal {
            _ = try Coordinator.inspectLiveServiceOwner(
                controlSocket: socket,
                configuration: configuration
            )
        }
        let executable = try ownProcessExecutablePath()
        #expect(refusal == .foreignProcess(socket: socket.path, executable: executable))
        #expect(ownerMessage(refusal).contains(executable))
        #expect(ownerMessage(refusal).contains("Quit that program"))
    }
}

/// connect(2) failures are classified by their real errno. Only
/// ECONNREFUSED, a socket with no accepting daemon, gets the no-listener
/// explanation. A file that is not a socket, or a path through a file,
/// reports the OS error and invents no owner history or recovery.
@Test func liveOwnerDecisionClassifiesConnectFailuresByTheirErrno() throws {
    try withOwnerFixtureDirectory { root in
        let configuration = try ownerTestConfiguration()
        func classify(_ socket: URL) -> Coordinator.UnauthenticatedServiceOwner? {
            ownerRefusal {
                _ = try Coordinator.inspectLiveServiceOwner(
                    controlSocket: socket,
                    configuration: configuration
                )
            }
        }

        let stale = root.appendingPathComponent("stale.sock")
        PfsUnixSocket.close(try PfsUnixSocket.bindAndListen(path: stale.path))
        let refused = classify(stale)
        #expect(refused == .unreachableEndpoint(socket: stale.path, errno: ECONNREFUSED))
        #expect(ownerMessage(refused).contains("no daemon accepted a connection"))

        let regular = root.appendingPathComponent("regular.sock")
        #expect(FileManager.default.createFile(atPath: regular.path, contents: Data()))
        let notSocket = classify(regular)
        #expect(notSocket == .unreachableEndpoint(socket: regular.path, errno: ENOTSOCK))
        #expect(ownerMessage(notSocket).contains("could not connect"))
        #expect(ownerMessage(notSocket).contains(String(cString: strerror(ENOTSOCK))))
        #expect(!ownerMessage(notSocket).contains("restarting"))
        #expect(!ownerMessage(notSocket).contains("log out"))

        let throughFile = regular.appendingPathComponent("control.sock")
        let notDirectory = classify(throughFile)
        #expect(notDirectory == .unreachableEndpoint(socket: throughFile.path, errno: ENOTDIR))
        #expect(ownerMessage(notDirectory).contains(String(cString: strerror(ENOTDIR))))
    }
}

/// Every refusal says that authentication identifies whose inventory may be
/// trusted, and none of them asks the app to stop the owner it could not
/// authenticate. Recovery is prescribed only where the cause is observed.
@Test func unauthenticatedOwnerDiagnosesNameOnlyWhatWasObserved() {
    let socket = "/Users/example/.local/state/portablefs/portablefsd/control.sock"
    let app = "/Applications/PortableFS.app"
    let cases: [(Coordinator.UnauthenticatedServiceOwner, [String])] = [
        (.occupiedStateSingleton,
         ["state lock", "starting or stopping", "another copy of PortableFS", "log out"]),
        (.foreignService(app: "/Applications/PortableFSKitDev.app"),
         ["/Applications/PortableFSKitDev.app", "different signed PortableFS product", "Quit that app", "Login Items"]),
        (.ownerAppMissing(app: app),
         [app, "no longer exists", "Unmount", "log out", "installer", "quiesces"]),
        (.ownerAppReplaced(app: app, running: "0.4.1 (executable c)", installed: "0.4.2 (executable b)"),
         [app, "0.4.1 (executable c)", "0.4.2 (executable b)", "Unmount", "log out", "installer"]),
        (.unauthenticated(socket: socket, step: .peerBinding, failure: "Operation not permitted"),
         [socket, "could not bind the process serving it", "Operation not permitted.", "Quit any other copy", "installer"]),
        (.unauthenticated(socket: socket, step: .executableResolution, failure: "No such file or directory"),
         ["could not resolve the executable", "No such file or directory."]),
        (.unauthenticated(socket: socket, step: .daemonIdentity, failure: "invalid control reply"),
         ["could not read its running daemon's release identity", "invalid control reply."]),
        (.exitedDuringProof,
         ["exited", "Reopen PortableFS"]),
    ]
    for (owner, facts) in cases {
        let message = ownerMessage(owner)
        for fact in facts {
            #expect(message.contains(fact), "\(owner) diagnosis omits \"\(fact)\": \(message)")
        }
        if owner != .exitedDuringProof {
            #expect(message.contains("authentication identifies the daemon whose mount inventory"))
        }
    }
}

// MARK: - State singleton exclusion

/// What a starting portablefsd does first: open the canonical lock and try a
/// nonblocking exclusive flock (`vcs/internal/portablefsd/run.go`
/// tryAcquireLock). Returns whether this simulated daemon got the lock.
private func simulatedDaemonAcquiresStateSingleton(in directory: URL) throws -> Bool {
    let descriptor = Darwin.open(
        directory.appendingPathComponent(".portablefsd-state.lock").path,
        O_RDWR | O_NOFOLLOW | O_CLOEXEC
    )
    try #require(descriptor >= 0)
    defer { Darwin.close(descriptor) }
    if serviceCoordinatorTestFlock(descriptor, LOCK_EX | LOCK_NB) == 0 {
        _ = serviceCoordinatorTestFlock(descriptor, LOCK_UN)
        return true
    }
    #expect(errno == EWOULDBLOCK)
    return false
}

/// The exclusion is the flock on the one canonical inode. It never writes,
/// truncates, renames or replaces the lock, so whatever bytes a previous
/// process left there stay exactly as they were.
private func expectLockUntouched(in directory: URL, bytes: Data, inode: ino_t) throws {
    let lock = directory.appendingPathComponent(".portablefsd-state.lock")
    #expect(try Data(contentsOf: lock) == bytes)
    var status = stat()
    #expect(Darwin.lstat(lock.path, &status) == 0)
    #expect(status.st_ino == inode)
    #expect(status.st_nlink == 1)
}

private func lockInode(in directory: URL) -> ino_t {
    var status = stat()
    _ = Darwin.lstat(directory.appendingPathComponent(".portablefsd-state.lock").path, &status)
    return status.st_ino
}

/// The absence proof is held, not sampled. Between classification and the
/// unregistration it authorizes, a daemon that KeepAlive starts cannot take
/// the state singleton, so it cannot become an unauthenticated owner that the
/// replacement then stops. Releasing the exclusion lets the incoming daemon
/// start.
@Test func stateSingletonExclusionBlocksADaemonStartUntilReleased() throws {
    try withOwnerFixtureDirectory { root in
        let stateDirectory = root.appendingPathComponent("state", isDirectory: true)
        try FileManager.default.createDirectory(
            at: stateDirectory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        // Bytes a previous process left behind, including an old-format
        // record naming a long-gone pid, are irrelevant: only the flock on
        // this inode excludes, and no content can grant a takeover.
        let lock = stateDirectory.appendingPathComponent(".portablefsd-state.lock")
        for stale in [
            Data(#"{"schemaVersion":1,"pid":2147483646,"startIdentity":"1:1","version":"","owner":"old"}"#.utf8),
            Data(),
            Data([0xff, 0x00, 0x0a]),
        ] {
            try? FileManager.default.removeItem(at: lock)
            #expect(FileManager.default.createFile(
                atPath: lock.path,
                contents: stale,
                attributes: [.posixPermissions: 0o600]
            ))
            let inode = lockInode(in: stateDirectory)

            let exclusion = try #require(
                try Coordinator.acquireStateSingletonExclusion(at: stateDirectory)
            )
            #expect(try !simulatedDaemonAcquiresStateSingleton(in: stateDirectory))
            #expect(try !Coordinator.stateSingletonIsUnlocked(at: stateDirectory))
            // A second replacement cannot take it either.
            #expect(try Coordinator.acquireStateSingletonExclusion(at: stateDirectory) == nil)
            try expectLockUntouched(in: stateDirectory, bytes: stale, inode: inode)

            exclusion.release()
            #expect(try simulatedDaemonAcquiresStateSingleton(in: stateDirectory))
            try expectLockUntouched(in: stateDirectory, bytes: stale, inode: inode)
        }
    }
}

/// A missing directory or lock goes through the same boundary: the
/// exclusion creates them exactly as portablefsd would (0700 directory,
/// single-link 0600 lock) and holds the lock, so a daemon starting later
/// contends on it instead of creating its own.
@Test func stateSingletonExclusionCreatesAMissingDirectoryAndLock() throws {
    try withOwnerFixtureDirectory { root in
        let stateDirectory = root
            .appendingPathComponent("state", isDirectory: true)
            .appendingPathComponent("portablefsd", isDirectory: true)
        #expect(try Coordinator.stateSingletonIsUnlocked(at: stateDirectory))
        #expect(!FileManager.default.fileExists(atPath: stateDirectory.path))

        let exclusion = try #require(
            try Coordinator.acquireStateSingletonExclusion(at: stateDirectory)
        )
        var directory = stat()
        #expect(Darwin.lstat(stateDirectory.path, &directory) == 0)
        #expect(directory.st_mode & 0o777 == 0o700)
        var lock = stat()
        #expect(Darwin.lstat(
            stateDirectory.appendingPathComponent(".portablefsd-state.lock").path,
            &lock
        ) == 0)
        #expect(lock.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG))
        #expect(lock.st_mode & 0o777 == 0o600)
        #expect(lock.st_nlink == 1)
        #expect(try !simulatedDaemonAcquiresStateSingleton(in: stateDirectory))
        try expectLockUntouched(in: stateDirectory, bytes: Data(), inode: lock.st_ino)

        exclusion.release()
        #expect(try simulatedDaemonAcquiresStateSingleton(in: stateDirectory))
    }
}

/// A held exclusion stops proving absence if its lock is replaced by name.
@Test func stateSingletonExclusionDetectsAReplacedLock() throws {
    try withOwnerFixtureDirectory { root in
        let stateDirectory = root.appendingPathComponent("state", isDirectory: true)
        let exclusion = try #require(
            try Coordinator.acquireStateSingletonExclusion(at: stateDirectory)
        )
        defer { exclusion.release() }
        try exclusion.confirmHeld()
        let lock = stateDirectory.appendingPathComponent(".portablefsd-state.lock")
        try FileManager.default.removeItem(at: lock)
        #expect(FileManager.default.createFile(
            atPath: lock.path,
            contents: Data(),
            attributes: [.posixPermissions: 0o600]
        ))
        #expect(throws: (any Error).self) {
            try exclusion.confirmHeld()
        }
        #expect(throws: (any Error).self) {
            _ = try Coordinator.DaemonFenceWitness.excluded(exclusion).hasDeparted()
        }
    }
}
