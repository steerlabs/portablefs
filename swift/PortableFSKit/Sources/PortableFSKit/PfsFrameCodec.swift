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
///
/// pfslocal 2.0 is an exact paired grammar: a field this build does not know
/// is not an additive extension but a frame from a different contract. Swift
/// protobuf would otherwise retain such bytes silently (a deleted field such as
/// the old publication-retraction bit would decode as an innocuous unknown
/// field), so every decoded envelope is refused if any message inside it
/// carries unknown fields.
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
            let envelope = try PfsEnvelope(serializedBytes: payload)
            try PfsUnknownFieldGuard.requireKnownFields(envelope)
            decoded.append(envelope)
            buffer.removeSubrange(buffer.startIndex..<payloadEnd)
        }

        return decoded
    }
}

/// Refuses a decoded pfslocal message that carries unknown fields at any depth.
enum PfsUnknownFieldGuard {
    static func requireKnownFields<M: Message>(_ message: M) throws {
        var visitor = PfsUnknownFieldVisitor()
        try message.traverse(visitor: &visitor)
        guard !visitor.foundUnknownFields else {
            throw PfsLocalClientError.invalidFrame("envelope carries a field outside pfslocal 2.0")
        }
    }
}

/// Walks every nested message. pfslocal has no maps, groups or extensions;
/// meeting one is itself a grammar violation.
private struct PfsUnknownFieldVisitor: Visitor {
    private(set) var foundUnknownFields = false

    mutating func visitUnknown(bytes: Data) throws {
        if !bytes.isEmpty { foundUnknownFields = true }
    }

    mutating func visitSingularDoubleField(value: Double, fieldNumber: Int) throws {}
    mutating func visitSingularInt64Field(value: Int64, fieldNumber: Int) throws {}
    mutating func visitSingularUInt64Field(value: UInt64, fieldNumber: Int) throws {}
    mutating func visitSingularBoolField(value: Bool, fieldNumber: Int) throws {}
    mutating func visitSingularStringField(value: String, fieldNumber: Int) throws {}
    mutating func visitSingularBytesField(value: Data, fieldNumber: Int) throws {}
    mutating func visitSingularEnumField<E: Enum>(value: E, fieldNumber: Int) throws {}

    mutating func visitSingularMessageField<M: Message>(value: M, fieldNumber: Int) throws {
        try value.traverse(visitor: &self)
    }

    mutating func visitMapField<KeyType, ValueType: MapValueType>(
        fieldType: _ProtobufMap<KeyType, ValueType>.Type,
        value: _ProtobufMap<KeyType, ValueType>.BaseType,
        fieldNumber: Int
    ) throws {
        foundUnknownFields = true
    }

    mutating func visitMapField<KeyType, ValueType>(
        fieldType: _ProtobufEnumMap<KeyType, ValueType>.Type,
        value: _ProtobufEnumMap<KeyType, ValueType>.BaseType,
        fieldNumber: Int
    ) throws where ValueType.RawValue == Int {
        foundUnknownFields = true
    }

    mutating func visitMapField<KeyType, ValueType>(
        fieldType: _ProtobufMessageMap<KeyType, ValueType>.Type,
        value: _ProtobufMessageMap<KeyType, ValueType>.BaseType,
        fieldNumber: Int
    ) throws {
        foundUnknownFields = true
    }
}
