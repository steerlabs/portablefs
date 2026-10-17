import Foundation
import Testing
@testable import PortableFSKit

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

@Test func publicationAckSemanticCommitUsesTheFrozenMinor15Fields() throws {
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
    #expect(hello.protocolMajor == 1)
    #expect(hello.protocolMinor == 0)
    #expect(hello.clientName == "swift")
    #expect(hello.clientVersion == "1.0")

    var expectedHello = PfsHello()
    expectedHello.protocolMajor = 1
    expectedHello.clientName = "swift"
    expectedHello.clientVersion = "1.0"
    var expectedEnvelope = PfsEnvelope()
    expectedEnvelope.requestID = 1
    expectedEnvelope.body = .hello(expectedHello)
    try assertFrameRoundTrip(expectedEnvelope, golden: frame)
}

@Test func goHelloReplyGoldenDecodesAndReencodesByteIdentically() throws {
    let frame = try goldenFrame("hello_reply.hex")
    let envelope = try decodeSingleGoldenEnvelope(frame)

    #expect(envelope.requestID == 1)
    guard case let .helloReply(reply)? = envelope.body else {
        Issue.record("expected helloReply body, got \(String(describing: envelope.body))")
        return
    }
    #expect(reply.protocolMajor == 1)
    #expect(reply.protocolMinor == 0)
    #expect(reply.daemonVersion == "portablefsd-test")

    var expectedReply = PfsHelloReply()
    expectedReply.protocolMajor = 1
    expectedReply.daemonVersion = "portablefsd-test"
    var expectedEnvelope = PfsEnvelope()
    expectedEnvelope.requestID = 1
    expectedEnvelope.body = .helloReply(expectedReply)
    try assertFrameRoundTrip(expectedEnvelope, golden: frame)
}

@Test func goV7ResolveContractGoldenIsAcceptedByTheShippingParser() throws {
    let frame = try goldenFrame("v7_resolve_contract.hex")
    let envelope = try decodeSingleGoldenEnvelope(frame)
    #expect(envelope.requestID == 7)
    guard case let .resolveReply(reply)? = envelope.body else {
        Issue.record("expected ResolveReply carrying the daemon coherence contract")
        return
    }
    #expect(reply.hasV3Coherence)
    let parsed = try PfsLocalMacOSV3CoherenceTransport.parseContract(reply.v3Coherence)
    #expect(parsed.authorityProtocolMajor == 7)
    #expect(parsed.epoch == Data(repeating: 0x11, count: 16))
    #expect(parsed.sessionID == Data(repeating: 0x22, count: 16))
    #expect(parsed.cachePolicy.rawValue == "fskit-native-revocation-v1")
    #expect(parsed.repairBudgetMillis == 60_000)
    #expect(parsed.initialAcknowledgedCursor == .init(sequence: 10, phase: .complete))
    try assertFrameRoundTrip(envelope, golden: frame)
}

/// Protocol minor 6's retraction bit is an ENVELOPE field, so unlike every
/// other cross-language fixture its whole job is to pin the four scalars that
/// precede the body: request_id, publication_ack_required, operation_id,
/// and publication_retracted, in that order, ahead of the oneof. A frontend
/// that silently dropped field 4 would still round-trip every other golden.
@Test func goPublicationRetractedGoldenDecodesAndReencodesByteIdentically() throws {
    let frame = try goldenFrame("publication_retracted.hex")
    let envelope = try decodeSingleGoldenEnvelope(frame)

    #expect(envelope.requestID == 7)
    #expect(envelope.publicationAckRequired)
    #expect(envelope.operationID == 3)
    #expect(envelope.publicationRetracted)
    guard case let .getAttrReply(reply)? = envelope.body else {
        Issue.record("expected getAttrReply body, got \(String(describing: envelope.body))")
        return
    }
    #expect(reply.attr.item.itemID == 23)
    #expect(reply.attr.item.itemGeneration == 29)
    #expect(reply.attr.kind == .file)

    var item = PfsItem()
    item.itemID = 23
    item.itemGeneration = 29
    var attr = PfsAttr()
    attr.item = item
    attr.kind = .file
    var expectedReply = PfsGetAttrReply()
    expectedReply.attr = attr
    var expectedEnvelope = PfsEnvelope()
    expectedEnvelope.requestID = 7
    expectedEnvelope.publicationAckRequired = true
    expectedEnvelope.operationID = 3
    expectedEnvelope.publicationRetracted = true
    expectedEnvelope.body = .getAttrReply(expectedReply)
    try assertFrameRoundTrip(expectedEnvelope, golden: frame)
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
    var parent = PfsItem()
    parent.itemID = 17
    parent.itemGeneration = 19
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
