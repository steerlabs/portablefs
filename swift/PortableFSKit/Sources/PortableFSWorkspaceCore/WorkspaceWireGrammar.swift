import Foundation

struct WorkspaceWireField { let kind: String; let repeated: Bool; let oneof: Bool }

enum WorkspaceWireGrammar {
    static func check(_ data: Data) throws { try check(Array(data), message: "Envelope", depth: 0) }
    private static func check(_ bytes: [UInt8], message: String, depth: Int) throws {
        guard depth <= 16, let fields = WorkspaceWireSchema.messages[message] else { throw WorkspaceControlError.grammar }
        var index = 0
        var prior: UInt64 = 0
        var counts: [UInt64: Int] = [:]
        var oneof = false
        while index < bytes.count {
            let tag = try varint(bytes, index: &index)
            let number = tag >> 3
            let wire = tag & 7
            guard number > 0, number >= prior, let field = fields[number] else { throw WorkspaceControlError.grammar }
            prior = number
            counts[number, default: 0] += 1
            guard let count = counts[number], count <= 128, field.repeated || count == 1 else { throw WorkspaceControlError.grammar }
            if field.oneof {
                guard !oneof else { throw WorkspaceControlError.grammar }
                oneof = true
            }
            if field.kind.isEmpty {
                guard wire == 0 else { throw WorkspaceControlError.grammar }
                _ = try varint(bytes, index: &index)
            } else {
                guard wire == 2 else { throw WorkspaceControlError.grammar }
                let size = try varint(bytes, index: &index)
                guard size <= UInt64(bytes.count - index) else { throw WorkspaceControlError.grammar }
                let end = index + Int(size)
                if field.kind == "$" {
                    guard size <= 65536 else { throw WorkspaceControlError.grammar }
                } else {
                    try check(Array(bytes[index..<end]), message: field.kind, depth: depth + 1)
                }
                index = end
            }
        }
    }
    private static func varint(_ bytes: [UInt8], index: inout Int) throws -> UInt64 {
        var result: UInt64 = 0
        for shift in stride(from: 0, through: 63, by: 7) {
            guard index < bytes.count else { throw WorkspaceControlError.grammar }
            let byte = bytes[index]
            index += 1
            guard shift != 63 || byte <= 1 else { throw WorkspaceControlError.grammar }
            result |= UInt64(byte & 127) << shift
            if byte < 128 { return result }
        }
        throw WorkspaceControlError.grammar
    }
}
