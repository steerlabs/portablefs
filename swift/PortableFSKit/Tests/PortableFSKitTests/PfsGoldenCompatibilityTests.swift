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
