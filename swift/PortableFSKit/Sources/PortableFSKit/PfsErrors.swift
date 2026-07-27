import Foundation
import Darwin

/// Errors produced by the pfslocal transport and protocol layer.
public enum PfsLocalClientError: Error, Equatable, Sendable, CustomStringConvertible {
    case connectionClosed
    case shutdown
    case timeout
    case cancelled
    case frameTooLarge(length: UInt32, max: Int)
    case invalidFrame(String)
    case protocolMismatch(major: UInt32, minor: UInt32)
    case missingBody
    case unexpectedReply(String)
    case daemon(errno: Int32, message: String)
    case socketPath(String)
    case system(errno: Int32, operation: String)

    public var description: String {
        switch self {
        case .connectionClosed:
            return "pfslocal connection closed"
        case .shutdown:
            return "pfslocal client shut down"
        case .timeout:
            return "pfslocal request timed out"
        case .cancelled:
            return "pfslocal request cancelled"
        case let .frameTooLarge(length, max):
            return "pfslocal frame length \(length) exceeds maximum \(max)"
        case let .invalidFrame(message):
            return "invalid pfslocal frame: \(message)"
        case let .protocolMismatch(major, minor):
            return "unsupported pfslocal protocol \(major).\(minor)"
        case .missingBody:
            return "pfslocal envelope is missing a body"
        case let .unexpectedReply(message):
            return "unexpected pfslocal reply: \(message)"
        case let .daemon(errnoValue, message):
            return "daemon error errno=\(errnoValue): \(message)"
        case let .socketPath(message):
            return "invalid socket path: \(message)"
        case let .system(errnoValue, operation):
            return "\(operation) failed with errno \(errnoValue)"
        }
    }

    public var posixErrno: Int32 {
        switch self {
        case let .daemon(errnoValue, _):
            return errnoValue
        case .timeout:
            return ETIMEDOUT
        case .cancelled:
            return EINTR
        case .socketPath, .protocolMismatch, .missingBody, .unexpectedReply, .invalidFrame:
            return EINVAL
        case .frameTooLarge:
            return EMSGSIZE
        case .connectionClosed, .shutdown, .system:
            return EIO
        }
    }
}

@inline(__always)
func pfsErrno() -> Int32 {
    Darwin.errno
}
