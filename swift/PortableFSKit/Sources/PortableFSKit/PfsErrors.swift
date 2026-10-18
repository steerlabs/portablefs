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
    /// The daemon resolved a strict-v3 authority attach whose declared cache
    /// policy this build does not implement — an unknown policy string, or the
    /// native macOS 27 policy that stays gated on the final SDK. Mounting
    /// while ignoring the declared contract would serve stale kernel state,
    /// so resolution closes the client and terminates with ENOTSUP.
    case v3CoherenceIntegrationUnavailable
    case socketPath(String)
    case system(errno: Int32, operation: String)
    /// PREPARE was already closed before this FSKit callback could issue any
    /// daemon request, so no attempt exists to acknowledge or replay.
    /// macOS 26 transparently re-enters some EINTR callbacks: live
    /// testing observed hidden replay after EINTR, EBUSY, and EAGAIN. Policy
    /// v2 therefore uses the non-restartable ECANCELED verdict for this
    /// definite-preapply boundary. It also releases FSKit's namespace lane so
    /// the repair can run instead of deadlocking behind this callback.
    case publicationAdmissionClosed
    /// Ordinary local contention, and the frozen v1 admission verdict. Unlike
    /// v2's non-restartable ECANCELED, legacy v1 exposed EBUSY at every local
    /// definite-preapply boundary. Namespace-index reservation collisions are
    /// also local contention rather than a coherence-policy refusal and use
    /// this errno under every policy.
    case publicationAdmissionBusy

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
        case .v3CoherenceIntegrationUnavailable:
            return "strict v3 coherence is not integrated into the live FSKit mount"
        case let .socketPath(message):
            return "invalid socket path: \(message)"
        case let .system(errnoValue, operation):
            return "\(operation) failed with errno \(errnoValue)"
        case .publicationAdmissionClosed:
            return "pfslocal publication admission is temporarily closed"
        case .publicationAdmissionBusy:
            return "pfslocal publication admission is busy"
        }
    }

    /// A violation of the pfslocal framing or protocol contract. One such
    /// frame means the peer speaks a contract this client does not, so it is
    /// terminal for the client and never a reason to connect again.
    public var isProtocolDefect: Bool {
        switch self {
        case .frameTooLarge, .invalidFrame, .protocolMismatch, .missingBody, .unexpectedReply:
            return true
        default:
            return false
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
        case .publicationAdmissionClosed:
            return ECANCELED
        case .publicationAdmissionBusy:
            return EBUSY
        case .v3CoherenceIntegrationUnavailable:
            return ENOTSUP
        case .socketPath, .protocolMismatch, .missingBody, .unexpectedReply, .invalidFrame:
            return EINVAL
        case .frameTooLarge:
            return EMSGSIZE
        case .connectionClosed, .shutdown, .system:
            return EIO
        }
    }
}

/// Without this, every surfaced `localizedDescription` is the bridged NSError
/// fallback — "The operation couldn't be completed. (PortableFSKit
/// .PfsLocalClientError error N.)", where N is the case's declaration index and
/// the payload naming the actual failure is dropped. Anything that reports a
/// transport failure to a person (the host app's status line, the registration
/// fence's composed messages) has to be able to say what went wrong.
extension PfsLocalClientError: LocalizedError {
    public var errorDescription: String? { description }
}

@inline(__always)
func pfsErrno() -> Int32 {
    Darwin.errno
}
