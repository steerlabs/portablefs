import Foundation
import CryptoKit
import CWorkspacePower
import PortableFSWorkspaceCore

public struct WorkspaceVMError: Error, CustomStringConvertible, Sendable {
    public let description: String
    public init(_ description: String) { self.description = description }
}

public struct WorkspaceArtifact: Sendable {
    public static var hostBuildCommit: String { String(cString: PFSWorkspaceCommit()) }
    struct FileRecord: Decodable { let sha256: String; let size: UInt64 }
    struct Release: Decodable {
        let app_version: String; let commit: String; let image_digest: String; let authority_major: UInt32
    }
    struct Manifest: Decodable { let format: Int; let release: Release; let files: [String: FileRecord] }
    public let directory: URL
    public let release: WorkspaceRelease

    public init(directory: URL) throws {
        let manifest = try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: directory.appendingPathComponent("manifest.json")))
        let required: Set<String> = ["kernel", "initramfs", "system.ext4", "kernel.config", "packages.json", "packages.tsv", "source-manifest.json", "licenses.tar.gz", "initramfs.inventory", "image-inputs.json", "release.json", "bin/portablefs", "bin/portablefsd", "bin/portablefs-workspaced"]
        guard manifest.format == 8, Set(manifest.files.keys) == required else { throw WorkspaceVMError("invalid exact image manifest") }
        for (name, record) in manifest.files {
            let path = directory.appendingPathComponent(name)
            let values = try path.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
            guard values.isRegularFile == true, values.isSymbolicLink == false, let size = values.fileSize, size >= 0, UInt64(size) == record.size else { throw WorkspaceVMError("invalid artifact: \(name)") }
            let handle = try FileHandle(forReadingFrom: path)
            defer { try? handle.close() }
            var hash = SHA256()
            while try autoreleasepool(invoking: { () throws -> Bool in
                guard let data = try handle.read(upToCount: 4 << 20), !data.isEmpty else { return false }
                hash.update(data: data)
                return true
            }) {}
            guard hex(Data(hash.finalize())) == record.sha256 else { throw WorkspaceVMError("artifact hash mismatch: \(name)") }
        }
        let identity = try Data(contentsOf: directory.appendingPathComponent("image-inputs.json"))
        let embedded = try JSONDecoder().decode(Release.self, from: Data(contentsOf: directory.appendingPathComponent("release.json")))
        guard hex(Data(SHA256.hash(data: identity))) == manifest.release.image_digest,
              embedded.app_version == manifest.release.app_version, embedded.commit == manifest.release.commit,
              embedded.image_digest == manifest.release.image_digest, embedded.authority_major == manifest.release.authority_major else { throw WorkspaceVMError("image identity mismatch") }
        var r = WorkspaceRelease()
        r.appVersion = manifest.release.app_version; r.commit = manifest.release.commit
        r.imageDigest = try unhex(manifest.release.image_digest); r.authorityMajor = manifest.release.authority_major
        guard WorkspaceControl.validRelease(r) else { throw WorkspaceVMError("invalid image release") }
        self.directory = directory; self.release = r
    }
}

public func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
public func unhex(_ value: String) throws -> Data {
    let bytes = Array(value.utf8)
    guard bytes.count % 2 == 0 else { throw WorkspaceVMError("invalid hex") }
    var result = Data()
    for offset in stride(from: 0, to: bytes.count, by: 2) {
        guard let byte = UInt8(String(decoding: bytes[offset..<offset+2], as: UTF8.self), radix: 16) else { throw WorkspaceVMError("invalid hex") }
        result.append(byte)
    }
    return result
}

// A blocking operation owns its inputs and completion until it returns. No VZ
// API runs here; framework calls and result delivery stay on the main VM queue.
final class WorkspaceIO<Value>: @unchecked Sendable {
    let work: @Sendable () throws -> Value
    let completion: @MainActor (Result<Value, Error>) -> Void
    var result: Result<Value, Error>?
    init(_ work: @escaping @Sendable () throws -> Value, completion: @escaping @MainActor (Result<Value, Error>) -> Void) { self.work = work; self.completion = completion }
    func start() {
        DispatchQueue.global().async { [self] in
            result = Result { try work() }
            DispatchQueue.main.async { [self] in
                if let result { completion(result) }
            }
        }
    }
}
