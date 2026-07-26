import Foundation
import SwiftProtobuf

/// Length-prefixed pfslocal protobuf framing.
public struct PfsFrameCodec: Sendable {
    public static let defaultMaxFrameLength = 16 * 1024 * 1024

    public let maxFrameLength: Int

    public init(maxFrameLength: Int = PfsFrameCodec.defaultMaxFrameLength) {
        self.maxFrameLength = maxFrameLength
    }

    public func encode(_ envelope: PfsEnvelope) throws -> Data {
        let payload = try envelope.serializedData()
        guard payload.count <= maxFrameLength else {
            throw PfsLocalClientError.frameTooLarge(length: UInt32(clamping: payload.count), max: maxFrameLength)
        }

        var output = Data(capacity: 4 + payload.count)
        var length = UInt32(payload.count).littleEndian
        withUnsafeBytes(of: &length) { output.append(contentsOf: $0) }
        output.append(payload)
        return output
    }
}

/// Streaming decoder that tolerates arbitrary frame-boundary splits.
public struct PfsFrameDecoder: Sendable {
    private var buffer = Data()
    private let maxFrameLength: Int

    public init(maxFrameLength: Int = PfsFrameCodec.defaultMaxFrameLength) {
        self.maxFrameLength = maxFrameLength
    }

    public var bufferedByteCount: Int {
        buffer.count
    }

    public mutating func append(_ bytes: Data) throws -> [PfsEnvelope] {
        buffer.append(bytes)
        var decoded: [PfsEnvelope] = []

        while buffer.count >= 4 {
            let length = UInt32(buffer[buffer.startIndex])
                | (UInt32(buffer[buffer.index(buffer.startIndex, offsetBy: 1)]) << 8)
                | (UInt32(buffer[buffer.index(buffer.startIndex, offsetBy: 2)]) << 16)
                | (UInt32(buffer[buffer.index(buffer.startIndex, offsetBy: 3)]) << 24)

            guard length <= UInt32(maxFrameLength) else {
                throw PfsLocalClientError.frameTooLarge(length: length, max: maxFrameLength)
            }

            let frameLength = Int(length)
            guard buffer.count >= 4 + frameLength else {
                break
            }

            let payloadStart = buffer.index(buffer.startIndex, offsetBy: 4)
            let payloadEnd = buffer.index(payloadStart, offsetBy: frameLength)
            let payload = buffer[payloadStart..<payloadEnd]
            decoded.append(try PfsEnvelope(serializedBytes: payload))
            buffer.removeSubrange(buffer.startIndex..<payloadEnd)
        }

        return decoded
    }
}
