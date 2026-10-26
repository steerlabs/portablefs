import Darwin
import Foundation

/// The durable lease closes the gap between outgoing-host quiescence and the
/// installer's acquisition of the same product-wide mount-lifecycle exclusion.
public enum PortableFSProductUpdate {
    public static func requireNormalAdmission(accountDirectory: URL) throws {
        let host = accountDirectory.appendingPathComponent("host", isDirectory: true)
        var status = stat()
        if lstat(host.path, &status) != 0 {
            guard errno == ENOENT else { throw PortableFSSignedServiceError.invalidIdentity }
            return
        }
        let store = try PortableFSDUpdateLeaseStore(directoryURL: host)
        if let lease = try store.load(), !lease.phase.permitsNormalAdmission {
            throw PortableFSSignedServiceError.codeValidation("PortableFS update is pending")
        }
    }
}
