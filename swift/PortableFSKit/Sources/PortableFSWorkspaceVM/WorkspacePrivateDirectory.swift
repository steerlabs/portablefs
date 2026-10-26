import Darwin
import Foundation
import PortableFSAppCore

@_silgen_name("flock") private func workspaceFlock(_ fd: Int32, _ operation: Int32) -> Int32

/// Descriptor-relative private publications. A replaced directory or lock inode
/// refuses; it never creates an independent coordination namespace.
public final class WorkspacePrivateDirectory {
    public let url: URL
    private let fd: Int32
    private let device: dev_t
    private let inode: ino_t
    public init(_ url: URL) throws {
        self.url = url
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        guard url.isFileURL, url.path.hasPrefix("/"), url.standardizedFileURL == url.resolvingSymlinksInPath().standardizedFileURL else { throw WorkspaceVMError("unsafe workspace state path") }
        let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw WorkspaceVMError("open workspace directory: \(errno)") }
        var st = stat()
        guard fstat(descriptor, &st) == 0, st.st_uid == geteuid(), st.st_mode & 0o777 == 0o700 else { Darwin.close(descriptor); throw WorkspaceVMError("workspace state must be owned and mode 0700") }
        fd = descriptor; device = st.st_dev; inode = st.st_ino
    }
    deinit { Darwin.close(fd) }
    public func validate() throws {
        var st = stat()
        guard lstat(url.path, &st) == 0, st.st_mode & S_IFMT == S_IFDIR, st.st_uid == geteuid(), st.st_mode & 0o777 == 0o700,
              st.st_dev == device, st.st_ino == inode, url.standardizedFileURL == url.resolvingSymlinksInPath().standardizedFileURL else { throw WorkspaceVMError("workspace directory replaced") }
    }
    private func validName(_ name: String) throws {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.contains("\0") else { throw WorkspaceVMError("invalid state filename") }
    }
    private func validateFile(_ file: Int32, name: String) throws {
        var opened = stat(), named = stat()
        guard fstat(file, &opened) == 0, opened.st_mode & S_IFMT == S_IFREG, opened.st_mode & 0o777 == 0o600,
              opened.st_uid == geteuid(), opened.st_nlink == 1,
              fstatat(fd, name, &named, AT_SYMLINK_NOFOLLOW) == 0, opened.st_dev == named.st_dev, opened.st_ino == named.st_ino else { throw WorkspaceVMError("unsafe workspace state file") }
    }
    public func read(_ name: String, limit: Int = 2 << 20) throws -> Data? {
        try validName(name); try validate()
        let file = openat(fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if file < 0, errno == ENOENT { return nil }
        guard file >= 0 else { throw WorkspaceVMError("open workspace state: \(errno)") }; defer { Darwin.close(file) }
        try validateFile(file, name: name)
        var st = stat(); guard fstat(file, &st) == 0, st.st_size >= 0, st.st_size <= limit else { throw WorkspaceVMError("workspace state exceeds bound") }
        let handle = FileHandle(fileDescriptor: file, closeOnDealloc: false)
        let data = try handle.readToEnd() ?? Data()
        guard data.count <= limit else { throw WorkspaceVMError("workspace state exceeds bound") }
        try validateFile(file, name: name); try validate(); return data
    }
    public func write(_ name: String, data: Data) throws {
        try validName(name); try validate()
        _ = try read(name)
        let temporary = "." + name + "." + UUID().uuidString
        let file = openat(fd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard file >= 0 else { throw WorkspaceVMError("create workspace state: \(errno)") }
        defer { Darwin.close(file); unlinkat(fd, temporary, 0) }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { bytes -> Int in
                guard let base = bytes.baseAddress else { return 0 }
                return Darwin.write(file, base.advanced(by: offset), data.count - offset)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw WorkspaceVMError("write workspace state: \(errno)") }; offset += count
        }
        try validate()
        guard fsync(file) == 0, renameat(fd, temporary, fd, name) == 0, fsync(fd) == 0 else { throw WorkspaceVMError("commit workspace state: \(errno)") }
        try validate()
    }
    public func remove(_ name: String) throws {
        try validName(name); try validate()
        if try read(name) != nil { guard unlinkat(fd, name, 0) == 0 else { throw WorkspaceVMError("remove workspace state: \(errno)") } }
        guard fsync(fd) == 0 else { throw WorkspaceVMError("sync workspace state: \(errno)") }; try validate()
    }
    public func lock(_ name: String) throws -> WorkspaceFileLock {
        try validName(name); try validate()
        let file = openat(fd, name, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard file >= 0 else { throw WorkspaceVMError("open workspace lock: \(errno)") }
        do {
            try validateFile(file, name: name)
            guard workspaceFlock(file, LOCK_EX | LOCK_NB) == 0 else { throw WorkspaceVMError("PortableFS mount lifecycle is busy") }
            try validateFile(file, name: name); try validate()
            return WorkspaceFileLock(file)
        } catch { Darwin.close(file); throw error }
    }
}
public final class WorkspaceFileLock {
    private let fd: Int32
    init(_ fd: Int32) { self.fd = fd }
    deinit { workspaceFlock(fd, LOCK_UN); Darwin.close(fd) }
}
