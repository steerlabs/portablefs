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
        if let lease = try store.load() {
            let now = Int64(Date().timeIntervalSince1970 * 1_000)
            guard lease.createdAtUnixMs <= now + 60_000, lease.phase.permitsNormalAdmission else {
                throw PortableFSSignedServiceError.codeValidation("PortableFS update is pending")
            }
        }
    }
}
