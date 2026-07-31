import Foundation

/// The immutable identity of one FSKit extension target.
///
/// PortableFS is also embedded by other products. FSKit selects a generic URL
/// provider by `FSSupportedSchemes`, while the kernel publishes
/// `FSShortName` through statfs(2), so the adapter must carry both values from
/// the running extension rather than assuming the OSS product's identity.
public struct PortableFSModuleIdentity: Equatable, Sendable {
    public enum ValidationError: Error, Equatable, LocalizedError {
        case missingExtensionAttributes
        case invalidFileSystemTypeName
        case invalidResourceSchemes

        public var errorDescription: String? {
            switch self {
            case .missingExtensionAttributes:
                "missing EXAppExtensionAttributes"
            case .invalidFileSystemTypeName:
                "FSShortName must be a nonempty canonical string"
            case .invalidResourceSchemes:
                "FSSupportedSchemes must contain exactly one valid canonical URL scheme"
            }
        }
    }

    public let fileSystemTypeName: String
    public let resourceScheme: String

    public var resourcePrefix: String {
        resourceScheme + "://"
    }

    public init(fileSystemTypeName: String, resourceScheme: String) throws {
        guard !fileSystemTypeName.isEmpty,
              fileSystemTypeName == fileSystemTypeName.trimmingCharacters(in: .whitespacesAndNewlines) else {
            throw ValidationError.invalidFileSystemTypeName
        }
        guard Self.isCanonicalURLScheme(resourceScheme) else {
            throw ValidationError.invalidResourceSchemes
        }
        self.fileSystemTypeName = fileSystemTypeName
        self.resourceScheme = resourceScheme
    }

    public init(infoDictionary: [String: Any]) throws {
        guard let attributes = infoDictionary["EXAppExtensionAttributes"] as? [String: Any] else {
            throw ValidationError.missingExtensionAttributes
        }
        guard let fileSystemTypeName = attributes["FSShortName"] as? String else {
            throw ValidationError.invalidFileSystemTypeName
        }
        guard let schemes = attributes["FSSupportedSchemes"] as? [String],
              schemes.count == 1,
              let resourceScheme = schemes.first else {
            throw ValidationError.invalidResourceSchemes
        }
        try self.init(
            fileSystemTypeName: fileSystemTypeName,
            resourceScheme: resourceScheme
        )
    }

    public init(bundle: Bundle) throws {
        guard let infoDictionary = bundle.infoDictionary else {
            throw ValidationError.missingExtensionAttributes
        }
        try self.init(infoDictionary: infoDictionary)
    }

    private static func isCanonicalURLScheme(_ value: String) -> Bool {
        guard value == value.lowercased(),
              let first = value.utf8.first,
              first >= 97, first <= 122 else {
            return false
        }
        return value.utf8.allSatisfy { byte in
            (byte >= 97 && byte <= 122) ||
            (byte >= 48 && byte <= 57) ||
            byte == 43 ||
            byte == 45 ||
            byte == 46
        }
    }
}

/// The signed identity of the OSS PortableFS app and CLI release.
///
/// The shared adapter never reads these constants directly; each extension
/// target is driven by its own validated bundle metadata.
public enum PortableFSIdentity {
    public static let fileSystemTypeName = "pfs"
    public static let resourceScheme = "dev.portablefs.oss"
    public static let resourcePrefix = resourceScheme + "://"
    public static let moduleIdentity = try! PortableFSModuleIdentity(
        fileSystemTypeName: fileSystemTypeName,
        resourceScheme: resourceScheme
    )
}
