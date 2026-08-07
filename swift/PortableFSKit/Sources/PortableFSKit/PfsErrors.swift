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
    /// The daemon retracted this logical operation's publications before the
    /// frontend could install them: a delegation handoff crossed the
    /// operation, so the values it is holding predate a peer's acquisition
    /// and may already be stale.
    ///
    /// It is a distinct case rather than `.cancelled` because the two demand
    /// opposite handling. `.cancelled` retires the connection — the daemon
    /// may still publish a late reply for a request nobody will acknowledge.
    /// A retraction is the daemon speaking on its own initiative: the
    /// connection is healthy, the operation's acknowledgement is still owed
    /// and still sent, and only the framework-visible result is withdrawn.
    ///
    /// Discarding the callback's result is only safe because the daemon
    /// refuses the operation's undispatched requests rather than running
    /// them: once an operation is retracted, every request of it that had not
    /// already been answered is failed EINTR before execution. So a retracted
    /// callback never leaves behind work whose reply it did not see — there
    /// is no unlink that landed while its caller was told the syscall was
    /// interrupted. The frontend may therefore treat a retraction as "none of
    /// what I did not already observe happened" and let the syscall retry.
    case publicationRetracted
    /// PREPARE was already closed before this FSKit callback could issue any
    /// daemon request. Unlike a retraction, no attempt exists to acknowledge
    /// or replay. macOS 26 transparently re-enters some EINTR callbacks: live
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
        case .publicationRetracted:
            return "pfslocal publications retracted by the daemon"
        case .publicationAdmissionClosed:
            return "pfslocal publication admission is temporarily closed"
        case .publicationAdmissionBusy:
            return "pfslocal publication admission is busy"
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
        case .publicationRetracted:
            // EINTR, so the kernel restarts the syscall against a frontend
            // that now holds nothing. Any errno a caller could cache or
            // report (EIO, ESTALE, EAGAIN) would turn a coherence event into
            // an application-visible failure, and EINTR is honest here in the
            // strict POSIX sense: the daemon guarantees the unanswered part
            // of the operation did not run, so the work really was
            // interrupted rather than half-done. The retry is also
            // guaranteed to make progress — the daemon can only refuse after
            // the handoff it was waiting on has completed, so the second
            // attempt has no delegation left to release and cannot be
            // retracted for the same reason.
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

@inline(__always)
func pfsErrno() -> Int32 {
    Darwin.errno
}
