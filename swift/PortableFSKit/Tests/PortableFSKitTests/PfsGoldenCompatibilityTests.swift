import Foundation
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon

private func goldenFrame(_ name: String, sourceLocation: SourceLocation = #_sourceLocation) throws -> Data {
    let testFile = URL(fileURLWithPath: #filePath)
    let url = testFile
        .deletingLastPathComponent()
        .appendingPathComponent("Goldens")
        .appendingPathComponent(name)
    let text = try String(contentsOf: url, encoding: .utf8)
    let hex = text.filter { !$0.isWhitespace }
    var output = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
        guard next <= hex.endIndex, hex.distance(from: index, to: next) == 2 else {
            Issue.record("odd-length hex fixture \(name)", sourceLocation: sourceLocation)
            break
        }
        let byteString = String(hex[index..<next])
        guard let byte = UInt8(byteString, radix: 16) else {
            Issue.record("invalid hex byte \(byteString) in \(name)", sourceLocation: sourceLocation)
            break
        }
        output.append(byte)
        index = next
    }
    return output
}

private func decodeSingleGoldenEnvelope(_ frame: Data) throws -> PfsEnvelope {
    var decoder = PfsFrameDecoder()
    let decoded = try decoder.append(frame)
    #expect(decoded.count == 1)
    #expect(decoder.bufferedByteCount == 0)
    return try #require(decoded.first)
}

private func assertFrameRoundTrip(_ envelope: PfsEnvelope, golden: Data) throws {
    let encoded = try PfsFrameCodec().encode(envelope)
    #expect(encoded == golden)
}

@Test func publicationAckSemanticCommitUsesItsExactFields() throws {
    var ack = PfsPublicationAck()
    ack.operationID = 41
    ack.semanticCommit = .published
    var envelope = PfsEnvelope()
    envelope.body = .publicationAck(ack)

    // Four-byte little-endian frame length, Envelope.body field 36, then
    // PublicationAck.operation_id=2 and semantic_commit=3.
    let expected = Data([0x07, 0x00, 0x00, 0x00, 0xA2, 0x02, 0x04, 0x10, 0x29, 0x18, 0x01])
    try assertFrameRoundTrip(envelope, golden: expected)
    let decoded = try decodeSingleGoldenEnvelope(expected)
    guard case let .publicationAck(roundTrip)? = decoded.body else {
        Issue.record("expected publicationAck body")
        return
    }
    #expect(roundTrip.operationID == 41)
    #expect(roundTrip.semanticCommit == .published)
}

@Test func goHelloRequestGoldenDecodesAndReencodesByteIdentically() throws {
    let frame = try goldenFrame("hello_request.hex")
    let envelope = try decodeSingleGoldenEnvelope(frame)

    #expect(envelope.requestID == 1)
    guard case let .hello(hello)? = envelope.body else {
        Issue.record("expected hello body, got \(String(describing: envelope.body))")
        return
    }
    #expect(hello.protocolMajor == PfsLocalClient.protocolMajor)
    #expect(hello.protocolMinor == PfsLocalClient.protocolMinor)
    #expect(hello.clientName == "swift")
    #expect(hello.clientVersion == "1.0")

    var expectedHello = PfsHello()
    expectedHello.protocolMajor = 2
    expectedHello.protocolMinor = 0
    expectedHello.clientName = "swift"
    expectedHello.clientVersion = "1.0"
    var expectedEnvelope = PfsEnvelope()
    expectedEnvelope.requestID = 1
    expectedEnvelope.body = .hello(expectedHello)
    try assertFrameRoundTrip(expectedEnvelope, golden: frame)
}

@Test func goHelloReplyGoldenCarriesExactPairingAndItsDeadline() throws {
    let frame = try goldenFrame("hello_reply.hex")
    let envelope = try decodeSingleGoldenEnvelope(frame)

    #expect(envelope.requestID == 1)
    guard case let .helloReply(reply)? = envelope.body else {
        Issue.record("expected helloReply body, got \(String(describing: envelope.body))")
        return
    }
    #expect(reply.protocolMajor == PfsLocalClient.protocolMajor)
    #expect(reply.protocolMinor == PfsLocalClient.protocolMinor)
    #expect(reply.daemonVersion == "portablefsd-test")
    #expect(reply.requestDeadlineMs == 60_000)

    var expectedReply = PfsHelloReply()
    expectedReply.protocolMajor = 2
    expectedReply.protocolMinor = 0
    expectedReply.daemonVersion = "portablefsd-test"
    expectedReply.requestDeadlineMs = 60_000
    var expectedEnvelope = PfsEnvelope()
    expectedEnvelope.requestID = 1
    expectedEnvelope.body = .helloReply(expectedReply)
    try assertFrameRoundTrip(expectedEnvelope, golden: frame)
}

private func goldenStableIdentity(_ first: UInt8) -> Data {
    Data([first]) + Data(repeating: 0, count: 15)
}

/// The reduced Resolve: root, root attributes, volume identity and name, and
/// the three numeric limits. It carries no coherence object, policy, epoch or
/// boolean capability, and the shipping resolve installs it as the root.
@Test func goResolveContractGoldenIsTheReducedResolve() throws {
    let frame = try goldenFrame("resolve_contract.hex")
    let envelope = try decodeSingleGoldenEnvelope(frame)
    #expect(envelope.requestID == 2)
    guard case let .resolveReply(reply)? = envelope.body else {
        Issue.record("expected ResolveReply, got \(String(describing: envelope.body))")
        return
    }

    var root = PfsItem()
    root.itemID = 1
    root.itemGeneration = 9
    root.stableIdentity = goldenStableIdentity(0x20)
    var rootAttr = PfsAttr()
    rootAttr.item = root
    rootAttr.kind = .directory
    rootAttr.fileID = 1
    var capabilities = PfsCapabilities()
    capabilities.maxNameBytes = 255
    capabilities.preferredIoBytes = 1_048_576
    var expectedReply = PfsResolveReply()
    expectedReply.root = root
    expectedReply.rootAttr = rootAttr
    expectedReply.volumeID = "volume"
    expectedReply.volumeName = "Shared"
    expectedReply.capabilities = capabilities
    var expectedEnvelope = PfsEnvelope()
    expectedEnvelope.requestID = 2
    expectedEnvelope.body = .resolveReply(expectedReply)
    #expect(envelope == expectedEnvelope)
    try assertFrameRoundTrip(expectedEnvelope, golden: frame)
}

extension PfsLocalMockDaemonTests {
@Test func goResolveContractGoldenIsAcceptedByTheShippingResolve() async throws {
    let frame = try goldenFrame("resolve_contract.hex")
    let golden = try decodeSingleGoldenEnvelope(frame)
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    await daemon.transformNextReply { envelope in
        guard case .resolveReply? = envelope.body else { return nil }
        var replaced = golden
        replaced.requestID = envelope.requestID
        return replaced
    }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let resolved = try #require(await core.resolvedVolume)
    #expect(resolved.root.identity == PfsItemIdentity(golden.resolveReply.root))
    #expect(resolved.root.fileID == 1)
    #expect(resolved.volumeID == "volume")
    #expect(resolved.volumeName == "Shared")
    #expect(resolved.capabilities.maxNameBytes == 255)
    #expect(resolved.capabilities.preferredIoBytes == 1_048_576)
    await core.shutdown()
}
}

@Test func goAttrParentAndFlagsGoldenDecodesAndReencodesByteIdentically() throws {
    let frame = try goldenFrame("attr_parent_flags.hex")
    let envelope = try decodeSingleGoldenEnvelope(frame)

    #expect(envelope.requestID == 53)
    guard case let .getAttrReply(reply)? = envelope.body else {
        Issue.record("expected getAttrReply body, got \(String(describing: envelope.body))")
        return
    }
    #expect(reply.attr.item.itemID == 23)
    #expect(reply.attr.item.itemGeneration == 29)
    #expect(reply.attr.hasParent)
    #expect(reply.attr.parent.itemID == 17)
    #expect(reply.attr.parent.itemGeneration == 19)
    #expect(reply.attr.flags == 0x00008000)
    #expect(reply.attr.allocSize == 8192)

    var item = PfsItem()
    item.itemID = 23
    item.itemGeneration = 29
    item.stableIdentity = goldenStableIdentity(0x01)
    var parent = PfsItem()
    parent.itemID = 17
    parent.itemGeneration = 19
    parent.stableIdentity = goldenStableIdentity(0x01)
    var attr = PfsAttr()
    attr.item = item
    attr.kind = .file
    attr.mode = 0o640
    attr.nlink = 2
    attr.uid = 501
    attr.gid = 20
    attr.size = 4097
    attr.mtimeMs = 31
    attr.ctimeMs = 37
    attr.atimeMs = 41
    attr.birthtimeMs = 43
    attr.contentVersion = 47
    attr.parent = parent
    attr.flags = 0x00008000
    attr.allocSize = 8192
    var expectedReply = PfsGetAttrReply()
    expectedReply.attr = attr
    var expectedEnvelope = PfsEnvelope()
    expectedEnvelope.requestID = 53
    expectedEnvelope.body = .getAttrReply(expectedReply)
    try assertFrameRoundTrip(expectedEnvelope, golden: frame)
}

private func goldenRootItem() -> PfsItem {
    var root = PfsItem()
    root.itemID = 1
    root.itemGeneration = 9
    root.stableIdentity = Data(repeating: 0x20, count: 16)
    return root
}

@Test func goAttrFileIDsGoldenDecodesAndReencodesByteIdentically() throws {
    let frame = try goldenFrame("attr_file_ids.hex")
    let envelope = try decodeSingleGoldenEnvelope(frame)
    guard case let .lookupReply(reply)? = envelope.body else {
        Issue.record("expected lookupReply body, got \(String(describing: envelope.body))")
        return
    }
    #expect(reply.attr.fileID == (1 << 62) + 5)
    #expect(reply.attr.parentFileID == 1)
    #expect(reply.attr.item.itemID == 23)

    var item = PfsItem()
    item.itemID = 23
    item.itemGeneration = 9
    item.stableIdentity = Data(repeating: 0x44, count: 16)
    var attr = PfsAttr()
    attr.item = item
    attr.kind = .file
    attr.mode = 0o644
    attr.nlink = 2
    attr.uid = 501
    attr.gid = 20
    attr.size = 4097
    attr.mtimeMs = 31
    attr.ctimeMs = 37
    attr.atimeMs = 41
    attr.birthtimeMs = 43
    attr.parent = goldenRootItem()
    attr.allocSize = 8192
    attr.fileID = (1 << 62) + 5
    attr.parentFileID = 1
    var expectedReply = PfsLookupReply()
    expectedReply.attr = attr
    var expectedEnvelope = PfsEnvelope()
    expectedEnvelope.requestID = 59
    expectedEnvelope.publicationAckRequired = true
    expectedEnvelope.operationID = 4
    expectedEnvelope.body = .lookupReply(expectedReply)
    try assertFrameRoundTrip(expectedEnvelope, golden: frame)
}

@Test func goEnumerateEntriesRequestGoldenDecodesAndReencodesByteIdentically() throws {
    let frame = try goldenFrame("enumerate_entries_request.hex")
    var request = PfsEnumerateEntriesRequest()
    request.dir = goldenRootItem()
    request.cookie = (1 << 63) + 3
    request.maxEntries = 64
    request.wantAttrs = true
    request.handle = 7
    var expectedEnvelope = PfsEnvelope()
    expectedEnvelope.requestID = 61
    expectedEnvelope.operationID = 5
    expectedEnvelope.body = .enumerateEntries(request)
    #expect(try decodeSingleGoldenEnvelope(frame) == expectedEnvelope)
    try assertFrameRoundTrip(expectedEnvelope, golden: frame)
}

@Test func goEnumerateEntriesReplyGoldenCarriesNonOwningSnapshots() throws {
    let frame = try goldenFrame("enumerate_entries_reply.hex")
    let envelope = try decodeSingleGoldenEnvelope(frame)
    guard case let .enumerateEntriesReply(reply)? = envelope.body else {
        Issue.record("expected enumerateEntriesReply body, got \(String(describing: envelope.body))")
        return
    }
    // The Go codec always emits Attr.item; a snapshot's is the empty message.
    #expect(reply.entries.allSatisfy { $0.attr.item == PfsItem() && !$0.attr.hasParent })

    var file = PfsAttr()
    file.item = PfsItem()
    file.kind = .file
    file.mode = 0o644
    file.nlink = 2
    file.uid = 501
    file.gid = 20
    file.size = 3
    file.mtimeMs = 31
    file.ctimeMs = 37
    file.atimeMs = 41
    file.birthtimeMs = 43
    file.allocSize = 4096
    file.fileID = 1234
    file.parentFileID = 1
    var first = PfsDirEntry()
    first.name = Data("a".utf8)
    first.attr = file
    first.cookie = (1 << 63) + 4
    var directory = PfsAttr()
    directory.item = PfsItem()
    directory.kind = .directory
    directory.fileID = 5678
    directory.parentFileID = 1
    var second = PfsDirEntry()
    second.name = Data([0xFF, 0x62])
    second.attr = directory
    var expectedReply = PfsEnumerateEntriesReply()
    expectedReply.entries = [first, second]
    expectedReply.dirVersion = 77
    var expectedEnvelope = PfsEnvelope()
    expectedEnvelope.requestID = 61
    expectedEnvelope.publicationAckRequired = true
    expectedEnvelope.operationID = 5
    expectedEnvelope.body = .enumerateEntriesReply(expectedReply)
    try assertFrameRoundTrip(expectedEnvelope, golden: frame)
}

@Test func cacheProofSharesTheDaemonContinuousClockAndAuthorizationFixture() throws {
    let frame = try goldenFrame("cache_proof.hex")
    let envelope = try decodeSingleGoldenEnvelope(frame)
    guard case let .event(event)? = envelope.body,
          case let .cacheProof(proof)? = event.kind else {
        Issue.record("expected cache proof event")
        return
    }
    #expect(envelope.requestID == 0)
    #expect(proof.horizonNanos == 123456789)
    #expect(proof.authorizationDeadlineUnixNanos == 1900000000000000000)
    try assertFrameRoundTrip(envelope, golden: frame)
}
