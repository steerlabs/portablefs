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
