import Foundation

enum PortableFSDStrictJSONError: Error, Equatable {
    case invalid
    case duplicateKey
    case excessiveDepth
}

/// Validates one complete JSON value and rejects duplicate object keys,
/// including keys whose escaped spellings decode to the same string.
/// Foundation's decoders intentionally accept the last duplicate key, which
/// is not suitable for the security-sensitive host update protocol.
enum PortableFSDStrictJSON {
    static func validate(_ data: Data, maximumDepth: Int = 32) throws {
        var scanner = Scanner(bytes: Array(data), maximumDepth: maximumDepth)
        try scanner.parseDocument()
    }

    private struct Scanner {
        let bytes: [UInt8]
        let maximumDepth: Int
        var index = 0

        mutating func parseDocument() throws {
            skipWhitespace()
            try parseValue(depth: 0)
            skipWhitespace()
            guard index == bytes.count else { throw PortableFSDStrictJSONError.invalid }
        }

        private mutating func parseValue(depth: Int) throws {
            guard depth <= maximumDepth, index < bytes.count else {
                throw depth > maximumDepth
                    ? PortableFSDStrictJSONError.excessiveDepth
                    : PortableFSDStrictJSONError.invalid
            }
            switch bytes[index] {
            case 0x7b: try parseObject(depth: depth + 1) // {
            case 0x5b: try parseArray(depth: depth + 1) // [
            case 0x22: _ = try parseString()
            case 0x74: try consumeLiteral("true")
            case 0x66: try consumeLiteral("false")
            case 0x6e: try consumeLiteral("null")
            case 0x2d, 0x30...0x39: try parseNumber()
            default: throw PortableFSDStrictJSONError.invalid
            }
        }

        private mutating func parseObject(depth: Int) throws {
            guard depth <= maximumDepth else {
                throw PortableFSDStrictJSONError.excessiveDepth
            }
            index += 1
            skipWhitespace()
            if consume(0x7d) { return }
            var keys = Set<String>()
            while true {
                guard index < bytes.count, bytes[index] == 0x22 else {
                    throw PortableFSDStrictJSONError.invalid
                }
                let key = try parseString()
                guard keys.insert(key).inserted else {
                    throw PortableFSDStrictJSONError.duplicateKey
                }
                skipWhitespace()
                guard consume(0x3a) else { throw PortableFSDStrictJSONError.invalid }
                skipWhitespace()
                try parseValue(depth: depth)
                skipWhitespace()
                if consume(0x7d) { return }
                guard consume(0x2c) else { throw PortableFSDStrictJSONError.invalid }
                skipWhitespace()
            }
        }

        private mutating func parseArray(depth: Int) throws {
            guard depth <= maximumDepth else {
                throw PortableFSDStrictJSONError.excessiveDepth
            }
            index += 1
            skipWhitespace()
            if consume(0x5d) { return }
            while true {
                try parseValue(depth: depth)
                skipWhitespace()
                if consume(0x5d) { return }
                guard consume(0x2c) else { throw PortableFSDStrictJSONError.invalid }
                skipWhitespace()
            }
        }

        private mutating func parseString() throws -> String {
            let start = index
            index += 1
            while index < bytes.count {
                let byte = bytes[index]
                if byte == 0x22 {
                    index += 1
                    let token = Data(bytes[start..<index])
                    do {
                        return try JSONDecoder().decode(String.self, from: token)
                    } catch {
                        throw PortableFSDStrictJSONError.invalid
                    }
                }
                if byte < 0x20 { throw PortableFSDStrictJSONError.invalid }
                if byte == 0x5c {
                    index += 1
                    guard index < bytes.count else {
                        throw PortableFSDStrictJSONError.invalid
                    }
                    if bytes[index] == 0x75 {
                        guard index + 4 < bytes.count,
                              bytes[(index + 1)...(index + 4)].allSatisfy(Self.isHex) else {
                            throw PortableFSDStrictJSONError.invalid
                        }
                        index += 5
                        continue
                    }
                    guard [0x22, 0x5c, 0x2f, 0x62, 0x66, 0x6e, 0x72, 0x74]
                        .contains(bytes[index]) else {
                        throw PortableFSDStrictJSONError.invalid
                    }
                }
                index += 1
            }
            throw PortableFSDStrictJSONError.invalid
        }

        private mutating func parseNumber() throws {
            if consume(0x2d), index == bytes.count {
                throw PortableFSDStrictJSONError.invalid
            }
            if consume(0x30) {
                if index < bytes.count, (0x30...0x39).contains(bytes[index]) {
                    throw PortableFSDStrictJSONError.invalid
                }
            } else {
                guard index < bytes.count, (0x31...0x39).contains(bytes[index]) else {
                    throw PortableFSDStrictJSONError.invalid
                }
                repeat { index += 1 }
                while index < bytes.count && (0x30...0x39).contains(bytes[index])
            }
            if consume(0x2e) {
                guard index < bytes.count, (0x30...0x39).contains(bytes[index]) else {
                    throw PortableFSDStrictJSONError.invalid
                }
                repeat { index += 1 }
                while index < bytes.count && (0x30...0x39).contains(bytes[index])
            }
            if index < bytes.count, bytes[index] == 0x65 || bytes[index] == 0x45 {
                index += 1
                if index < bytes.count, bytes[index] == 0x2b || bytes[index] == 0x2d {
                    index += 1
                }
                guard index < bytes.count, (0x30...0x39).contains(bytes[index]) else {
                    throw PortableFSDStrictJSONError.invalid
                }
                repeat { index += 1 }
                while index < bytes.count && (0x30...0x39).contains(bytes[index])
            }
        }

        private mutating func consumeLiteral(_ value: StaticString) throws {
            let literal = Array(String(describing: value).utf8)
            guard index + literal.count <= bytes.count,
                  Array(bytes[index..<(index + literal.count)]) == literal else {
                throw PortableFSDStrictJSONError.invalid
            }
            index += literal.count
        }

        private mutating func consume(_ byte: UInt8) -> Bool {
            guard index < bytes.count, bytes[index] == byte else { return false }
            index += 1
            return true
        }

        private mutating func skipWhitespace() {
            while index < bytes.count,
                  bytes[index] == 0x20 || bytes[index] == 0x09 ||
                    bytes[index] == 0x0a || bytes[index] == 0x0d {
                index += 1
            }
        }

        private static func isHex(_ byte: UInt8) -> Bool {
            (0x30...0x39).contains(byte) ||
                (0x41...0x46).contains(byte) ||
                (0x61...0x66).contains(byte)
        }
    }
}
