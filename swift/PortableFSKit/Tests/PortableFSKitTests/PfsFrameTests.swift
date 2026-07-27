import Foundation
import Testing
@testable import PortableFSKit

@Test func frameDecoderHandlesPartialFrames() throws {
    var hello = PfsHello()
    hello.protocolMajor = 1
    hello.protocolMinor = 0
    hello.clientName = "test"

    var envelope = PfsEnvelope()
    envelope.requestID = 42
    envelope.body = .hello(hello)

    let encoded = try PfsFrameCodec().encode(envelope)
    var decoder = PfsFrameDecoder()

    #expect(try decoder.append(encoded.prefix(2)).isEmpty)
    #expect(try decoder.append(encoded.dropFirst(2).prefix(3)).isEmpty)
    let decoded = try decoder.append(encoded.dropFirst(5))
    #expect(decoded.count == 1)
    #expect(decoded.first?.requestID == 42)
    #expect(decoded.first?.hello.clientName == "test")
}

@Test func frameDecoderRejectsOversizedFrameBeforePayload() throws {
    var header = Data()
    var length = UInt32(2).littleEndian
    withUnsafeBytes(of: &length) { header.append(contentsOf: $0) }

    var decoder = PfsFrameDecoder(maxFrameLength: 1)
    do {
        _ = try decoder.append(header)
        Issue.record("expected oversized frame error")
    } catch let error as PfsLocalClientError {
        #expect(error == .frameTooLarge(length: 2, max: 1))
    }
}
