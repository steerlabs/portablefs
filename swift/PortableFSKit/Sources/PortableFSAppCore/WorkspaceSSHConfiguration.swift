import CryptoKit
import Darwin
import Foundation

public struct PortableFSWorkspaceError: Error, LocalizedError, CustomStringConvertible, Equatable {
    public let description: String
    public init(_ description: String) { self.description = description }
    public var errorDescription: String? { description }
}

/// The service calls this with its canonical account home, never process HOME.
/// Tests supply an isolated directory. A first-position include wins OpenSSH's
/// first-value rule; Host * inside the include restores the original scope.
public enum PortableFSWorkspaceSSH {
    public static let alias = "portablefs-workspace"
    public static let command = "ssh portablefs-workspace"
    private static let prefix = Data("# PortableFS Linux Workspace\nInclude ~/.ssh/portablefs-workspace.conf\n# End PortableFS Linux Workspace\n".utf8)
    private static let receiptName = ".portablefs-workspace.json"
    private struct Receipt: Codable {
        var version = 1
        var includeDigest: String
        var configCreated: Bool
        var originalConfigDigest: String
        var installing = true
        var removing = false
    }

    public static func install(home: URL, stanza: Data) throws {
        let directory = home.appendingPathComponent(".ssh", isDirectory: true)
        guard mkdir(directory.path, 0o700) == 0 || errno == EEXIST else { throw PortableFSWorkspaceError("Cannot create SSH directory") }
        let lock = try Lock(directory)
        defer { withExtendedLifetime(lock) {} }
        let config = try File(directory.appendingPathComponent("config"), followSymlink: true)
        let include = try File(directory.appendingPathComponent("portablefs-workspace.conf"))
        let receipt = try File(directory.appendingPathComponent(receiptName))
        let saved: Receipt?
        if let raw = receipt.data {
            saved = try JSONDecoder().decode(Receipt.self, from: raw)
            guard let saved, saved.version == 1, !saved.removing,
                  config.data?.starts(with: prefix) == true || (saved.installing && digest(config.data ?? Data()) == saved.originalConfigDigest),
                  include.data.map(digest) == saved.includeDigest || (saved.installing && include.data == nil),
                  digest(stanza) == saved.includeDigest else { throw PortableFSWorkspaceError("Managed SSH configuration changed. Restore it before starting Linux Workspace.") }
        } else {
            saved = nil
            guard include.data == nil, config.data?.starts(with: prefix) != true else { throw PortableFSWorkspaceError("SSH name already in use") }
            try refuseAlias(in: config.url, home: home, visited: [], depth: 0)
        }
        guard stanza.starts(with: Data("Host portablefs-workspace\n".utf8)),
              stanza.suffix(7) == Data("Host *\n".utf8) else { throw PortableFSWorkspaceError("Invalid managed SSH stanza") }
        try config.requireWritable(); try include.requireWritable(); try receipt.requireWritable()
        if saved == nil || saved?.installing == true {
            var ownership = saved ?? Receipt(includeDigest: digest(stanza), configCreated: config.data == nil, originalConfigDigest: digest(config.data ?? Data()))
            if saved == nil { try receipt.replace(try JSONEncoder().encode(ownership)) }
            if include.data == nil { try include.replace(stanza) }
            if config.data?.starts(with: prefix) != true { try config.replace(prefix + (config.data ?? Data())) }
            ownership.installing = false
            try File(directory.appendingPathComponent(receiptName)).replace(try JSONEncoder().encode(ownership))
        }
    }

    /// Called only after the service's uninstall boundary proves quiescence.
    /// User edits outside our prefix survive byte for byte, including CRLF and
    /// missing final newline. A modified managed file is never deleted.
    public static func remove(home: URL) throws {
        let directory = home.appendingPathComponent(".ssh", isDirectory: true)
        guard FileManager.default.fileExists(atPath: directory.path) else { return }
        let lock = try Lock(directory)
        defer { withExtendedLifetime(lock) {} }
        let receipt = try File(directory.appendingPathComponent(receiptName))
        guard let raw = receipt.data else { return }
        var saved = try JSONDecoder().decode(Receipt.self, from: raw)
        let config = try File(directory.appendingPathComponent("config"), followSymlink: true)
        let include = try File(directory.appendingPathComponent("portablefs-workspace.conf"))
        guard saved.version == 1, (saved.removing || config.data?.starts(with: prefix) == true || (saved.installing && digest(config.data ?? Data()) == saved.originalConfigDigest)),
              include.data.map(digest) == saved.includeDigest || ((saved.removing || saved.installing) && include.data == nil) else { throw PortableFSWorkspaceError("Managed SSH configuration changed. Copy Details before removing Linux Workspace.") }
        try config.requireWritable(); try include.requireWritable(); try receipt.requireWritable()
        if !saved.removing {
            saved.removing = true
            try receipt.replace(try JSONEncoder().encode(saved))
        }
        if let current = config.data, current.starts(with: prefix) {
            let remaining = Data(current.dropFirst(prefix.count))
            if remaining.isEmpty && saved.configCreated && !config.isSymlink { try config.remove() }
            else { try config.replace(remaining) }
        }
        if include.data != nil { try include.remove() }
        try File(directory.appendingPathComponent(receiptName)).remove()
    }

    private static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

    private final class Lock {
        let fd: Int32
        init(_ directory: URL) throws {
            var info = stat()
            guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
                  info.st_uid == geteuid(), info.st_mode & 0o022 == 0 else { throw PortableFSWorkspaceError("Unsafe SSH directory") }
            fd = open(directory.appendingPathComponent(".portablefs-workspace.lock").path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0o600)
            guard fd >= 0 else { throw PortableFSWorkspaceError("Cannot lock SSH configuration") }
            guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(), info.st_nlink == 1,
                  pfsWorkspaceSSHFlock(fd, LOCK_EX | LOCK_NB) == 0 else { Darwin.close(fd); throw PortableFSWorkspaceError("SSH configuration is in use") }
        }
        deinit { _ = pfsWorkspaceSSHFlock(fd, LOCK_UN); Darwin.close(fd) }
    }

    private struct File {
        let named: URL
        let url: URL
        let isSymlink: Bool
        let data: Data?
        let metadata: stat?
        init(_ named: URL, followSymlink: Bool = false) throws {
            self.named = named
            var link = stat()
            let found = lstat(named.path, &link) == 0
            guard found || errno == ENOENT else { throw PortableFSWorkspaceError("Cannot read SSH configuration") }
            isSymlink = found && link.st_mode & S_IFMT == S_IFLNK
            guard !isSymlink || followSymlink else { throw PortableFSWorkspaceError("Unsafe managed SSH file") }
            url = isSymlink ? named.resolvingSymlinksInPath() : named
            var info = stat()
            guard lstat(url.path, &info) == 0 else {
                guard !found && errno == ENOENT else { throw PortableFSWorkspaceError("Cannot resolve SSH configuration") }
                data = nil; metadata = nil; return
            }
            guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(), info.st_nlink == 1,
                  info.st_mode & 0o022 == 0, info.st_size <= 1 << 20 else { throw PortableFSWorkspaceError("Unsafe SSH configuration") }
            let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw PortableFSWorkspaceError("Cannot read SSH configuration") }
            defer { Darwin.close(fd) }
            var opened = stat()
            guard fstat(fd, &opened) == 0, info.st_ino == opened.st_ino, info.st_dev == opened.st_dev else { throw PortableFSWorkspaceError("SSH configuration changed") }
            data = try FileHandle(fileDescriptor: fd, closeOnDealloc: false).readToEnd() ?? Data()
            metadata = info
        }
        func requireWritable() throws {
            guard metadata.map({ $0.st_mode & 0o200 != 0 }) ?? true,
                  access(url.deletingLastPathComponent().path, W_OK) == 0 else { throw PortableFSWorkspaceError("SSH configuration is read-only") }
        }
        func recheck() throws {
            let current = try File(named, followSymlink: isSymlink)
            guard current.url == url, current.data == data, current.metadata?.st_ino == metadata?.st_ino,
                  current.metadata?.st_dev == metadata?.st_dev else { throw PortableFSWorkspaceError("SSH configuration changed") }
        }
        func replace(_ replacement: Data) throws {
            if data == replacement { return }
            try requireWritable(); try recheck()
            let temporary = url.deletingLastPathComponent().appendingPathComponent(".portablefs-ssh-" + UUID().uuidString)
            let fd = open(temporary.path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, metadata.map { $0.st_mode & 0o777 } ?? 0o600)
            guard fd >= 0 else { throw PortableFSWorkspaceError("Cannot create SSH configuration") }
            defer { Darwin.close(fd); unlink(temporary.path) }
            try FileHandle(fileDescriptor: fd, closeOnDealloc: false).write(contentsOf: replacement)
            guard fsync(fd) == 0 else { throw PortableFSWorkspaceError("Cannot sync SSH configuration") }
            try recheck()
            guard rename(temporary.path, url.path) == 0 else { throw PortableFSWorkspaceError("Cannot replace SSH configuration") }
            try syncParent()
        }
        func remove() throws {
            try recheck()
            guard unlink(url.path) == 0 else { throw PortableFSWorkspaceError("Cannot remove managed SSH file") }
            try syncParent()
        }
        func syncParent() throws {
            let fd = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
            guard fd >= 0 else { throw PortableFSWorkspaceError("Cannot open SSH directory") }
            defer { Darwin.close(fd) }
            guard fsync(fd) == 0 else { throw PortableFSWorkspaceError("Cannot sync SSH directory") }
        }
    }

    // Read only configuration files named by Include, never identity files.
    // No Match exec is executed while inspecting another user's configuration.
    private static func refuseAlias(in file: URL, home: URL, visited: Set<String>, depth: Int) throws {
        guard depth <= 16, !visited.contains(file.path) else { throw PortableFSWorkspaceError("SSH Include recursion is too deep") }
        guard FileManager.default.fileExists(atPath: file.path) else { return }
        guard !file.pathComponents.contains(where: { $0.hasPrefix("credentials-") || $0.hasPrefix("creds") }),
              !file.lastPathComponent.hasPrefix("id_"), !file.lastPathComponent.contains("token"), !file.lastPathComponent.hasSuffix(".key") else { throw PortableFSWorkspaceError("SSH Include does not name a configuration file") }
        let raw = try Data(contentsOf: file)
        guard raw.count <= 1 << 20, let text = String(data: raw, encoding: .utf8) else { throw PortableFSWorkspaceError("Cannot read SSH configuration") }
        let next = visited.union([file.path])
        for line in text.components(separatedBy: .newlines) {
            let tokens = try words(line)
            guard let first = tokens.first?.lowercased() else { continue }
            if first == "host" || first == "match" {
                let patterns = tokens.dropFirst().flatMap { $0.lowercased().split(separator: ",").map(String.init) }
                let excluded = patterns.contains { $0.hasPrefix("!") && fnmatch(String($0.dropFirst()), alias, 0) == 0 }
                if !excluded && patterns.contains(where: { !$0.hasPrefix("!") && $0 != "*" && fnmatch($0, alias, 0) == 0 }) { throw PortableFSWorkspaceError("SSH name already in use") }
            }
            if first == "include" {
                for pattern in tokens.dropFirst() {
                    let path: String
                    if pattern.hasPrefix("~/") { path = home.path + pattern.dropFirst() }
                    else if pattern.hasPrefix("/") { path = pattern }
                    else { path = home.appendingPathComponent(".ssh/" + pattern).path }
                    guard !path.contains("credentials-"), !path.contains("creds") else { throw PortableFSWorkspaceError("SSH Include does not name a configuration file") }
                    var matches = glob_t()
                    let result = glob(path, GLOB_NOSORT, nil, &matches)
                    defer { globfree(&matches) }
                    guard result == 0 || result == GLOB_NOMATCH else { throw PortableFSWorkspaceError("Cannot expand SSH Include") }
                    if let paths = matches.gl_pathv {
                        for index in 0..<matches.gl_pathc {
                            if let entry = paths[index] { try refuseAlias(in: URL(fileURLWithPath: String(cString: entry)), home: home, visited: next, depth: depth + 1) }
                        }
                    }
                }
            }
        }
    }
    private static func words(_ line: String) throws -> [String] {
        var result: [String] = [], word = "", quote: Character?, escaped = false
        for character in line {
            if escaped { word.append(character); escaped = false; continue }
            if character == "\\" { escaped = true; continue }
            if let current = quote {
                if character == current { quote = nil } else { word.append(character) }
            } else if character == "\"" || character == "'" { quote = character }
            else if character == "#" { break }
            else if character.isWhitespace || (character == "=" && result.isEmpty) {
                if !word.isEmpty { result.append(word); word = "" }
            } else { word.append(character) }
        }
        guard quote == nil, !escaped else { throw PortableFSWorkspaceError("Cannot parse SSH configuration") }
        if !word.isEmpty { result.append(word) }; return result
    }
}

@_silgen_name("flock") private func pfsWorkspaceSSHFlock(_ fd: Int32, _ operation: Int32) -> Int32
