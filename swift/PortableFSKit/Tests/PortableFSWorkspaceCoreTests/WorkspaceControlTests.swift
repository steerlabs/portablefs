import Foundation
import Testing
@testable import PortableFSWorkspaceCore

func workspaceGolden(_ name: String) throws -> Data {
    let path = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Goldens").appendingPathComponent(name + ".hex")
    let text = try String(contentsOf: path, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
    var bytes = Data()
    var index = text.startIndex
    while index < text.endIndex {
        let end = text.index(index, offsetBy: 2)
        bytes.append(try #require(UInt8(text[index..<end], radix: 16)))
        index = end
    }
    return bytes
}
@Test func workspaceGoldensCoverEveryMessageAndRejectMalformedFrames() throws {
    let names = ["hello", "hello_ack", "suspend", "suspend_ack", "resume", "resume_ack", "status", "status_reply", "provision", "mount", "umount", "result"]
    for name in names {
        let raw = try workspaceGolden(name)
        let envelope = try WorkspaceControl.decode(raw)
        #expect(envelope.version == 8)
        #expect(try WorkspaceControl.encode(envelope) == raw)
    }
    let invalid = ["unequal_version", "unknown_body", "duplicate_version", "multiple_body", "nonminimal_varint", "explicit_default", "unknown_nested", "oversized_length", "truncated", "trailing"]
    for name in invalid {
        let raw = try workspaceGolden(name + ".invalid")
        #expect(throws: (any Error).self) { try WorkspaceControl.decode(raw) }
    }
}
@Test func workspacePairingRejectsEveryReleaseAndBootMismatch() throws {
    let host = try WorkspaceControl.decode(workspaceGolden("hello")).hello
    let guest = try WorkspaceControl.decode(workspaceGolden("hello_ack")).helloAck
    try WorkspaceControl.pair(host: host, guest: guest)
    for field in ["version", "commit", "image", "authority", "boot", "host", "guest"] {
        var bad = guest
        switch field {
        case "version": bad.release.appVersion = "other"
        case "commit": bad.release.commit = String(repeating: "b", count: 40)
        case "image": bad.release.imageDigest = Data(repeating: 12, count: 32)
        case "authority": bad.release.authorityMajor = 7
        case "boot": bad.bootID = Data(repeating: 12, count: 16)
        case "host": bad.hostServiceID = Data(repeating: 12, count: 16)
        default: bad.guestServiceID = Data()
        }
        #expect(throws: (any Error).self) { try WorkspaceControl.pair(host: host, guest: bad) }
    }
}
@Test func workspaceSemanticBoundsAndPrivateKeyImportRefusal() throws {
    var envelope = try WorkspaceControl.decode(workspaceGolden("provision"))
    var provision = envelope.provision
    provision.publicKey = Data("-----BEGIN PRIVATE KEY-----".utf8)
    envelope.body = .provision(provision)
    #expect(throws: (any Error).self) { try WorkspaceControl.encode(envelope) }
    var s = try WorkspaceControl.decode(workspaceGolden("suspend")).suspend
    s.roster.append(s.roster[0])
    #expect(!WorkspaceControl.validSuspension(s))
    s.roster = Array(repeating: s.roster[0], count: 65)
    #expect(!WorkspaceControl.validSuspension(s))
}
