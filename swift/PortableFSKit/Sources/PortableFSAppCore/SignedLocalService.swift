import Darwin
import Foundation
import Security
import ServiceManagement

public enum PortableFSSignedServiceError: Error { case invalidIdentity, invalidBundle, invalidFrame, unexpectedStatus(Int), codeValidation(String) }

/// A running-image pin always comes from the same statically verified enclosing
/// release. The shared coordinator owns audit-token, pidversion, CS_VALID and
/// CS_RUNTIME validation; neither socket permissions nor a claimed release ID
/// can substitute for that proof.
public struct PortableFSSignedRelease: Sendable {
    public let bundleURL: URL
    public let bundleIdentifier: String
    private let clients: [String: String]

    public init(bundle: Bundle) throws {
        let root = try Self.canonicalURL(bundle.bundleURL)
        guard let identifier = bundle.bundleIdentifier, let executableURL = bundle.executableURL else {
            throw PortableFSSignedServiceError.invalidBundle
        }
        _ = try Self.codeHash(root)
        try Self.validateWorkspaceService(root: root, identifier: identifier, bundle: bundle)
        bundleURL = root; bundleIdentifier = identifier
        let cli = root.appendingPathComponent("Contents/Helpers/portablefs")
        let executable = try Self.canonicalURL(executableURL)
        clients = [executable.path: try Self.codeHash(executable), cli.path: try Self.codeHash(cli)]
        let team = try Self.team(root), cliTeam = try Self.team(cli)
        #if WORKSPACE_SERVICE_TESTING
        guard team == cliTeam else { throw PortableFSSignedServiceError.invalidIdentity }
        #else
        guard let team, !team.isEmpty, team == cliTeam else { throw PortableFSSignedServiceError.invalidIdentity }
        #endif
        guard let ownURL = Bundle.main.executableURL else { throw PortableFSSignedServiceError.invalidIdentity }
        let own = try Self.canonicalURL(ownURL)
        let service = root.appendingPathComponent("Contents/Library/LaunchAgents/PortableFSWorkspaceService.app/Contents/MacOS/portablefs-workspace-service")
        guard own == executable || own == cli || own.path == service.path,
              try Self.team(own) == cliTeam else { throw PortableFSSignedServiceError.invalidIdentity }
        try PortableFSDServiceCoordinator.requireCurrentRunningImage(expectedPath:own.path,expectedCDHash:Self.codeHash(own))
    }
    private static func validateWorkspaceService(root: URL, identifier: String, bundle: Bundle) throws {
        let service = root.appendingPathComponent("Contents/Library/LaunchAgents/PortableFSWorkspaceService.app")
        guard let nested = Bundle(url: service), nested.bundleIdentifier == identifier + ".WorkspaceService",
              nested.object(forInfoDictionaryKey: "CFBundleExecutable") as? String == "portablefs-workspace-service",
              nested.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String == bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String else {
            throw PortableFSSignedServiceError.invalidBundle
        }
        _ = try codeHash(service)
        guard try team(service) == team(root) else { throw PortableFSSignedServiceError.invalidIdentity }
        var code: SecStaticCode?, raw: CFDictionary?
        guard SecStaticCodeCreateWithPath(service as CFURL, [], &code) == errSecSuccess, let code,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &raw) == errSecSuccess,
              let info = raw as? [CFString: Any],
              info[kSecCodeInfoIdentifier] as? String == identifier + ".WorkspaceService",
              let entitlements = info[kSecCodeInfoEntitlementsDict] as? [String: Any], entitlements.count == 1,
              entitlements["com.apple.security.virtualization"] as? Bool == true else { throw PortableFSSignedServiceError.invalidIdentity }
    }
    public static func canonicalURL(_ url: URL) throws -> URL {
        guard let path = realpath(url.path, nil) else { throw PortableFSSignedServiceError.invalidIdentity }
        defer { free(path) }
        return URL(fileURLWithPath: String(cString: path), isDirectory: url.hasDirectoryPath)
    }
    public static func codeHash(_ named: URL) throws -> String {
        let url = try canonicalURL(named)
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), nil) == errSecSuccess else {
            throw PortableFSSignedServiceError.codeValidation("static signature: " + url.path)
        }
        var raw: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &raw) == errSecSuccess,
              let info = raw as? [CFString: Any], let hash = info[kSecCodeInfoUnique] as? Data,
              hash.count == 20, let flags = info[kSecCodeInfoFlags] as? NSNumber,
              flags.uint32Value & 0x0001_0000 != 0 else { throw PortableFSSignedServiceError.codeValidation("hardened code/hash: " + url.path) }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    private static func team(_ named: URL) throws -> String? {
        var code: SecStaticCode?, raw: CFDictionary?
        let url=try canonicalURL(named)
        guard SecStaticCodeCreateWithPath(url as CFURL,[],&code)==errSecSuccess,let code,
              SecCodeCopySigningInformation(code,SecCSFlags(rawValue:kSecCSSigningInformation),&raw)==errSecSuccess,
              let info=raw as? [CFString:Any] else { throw PortableFSSignedServiceError.invalidIdentity }
        return info[kSecCodeInfoTeamIdentifier] as? String
    }
    func authenticate(_ descriptor: Int32) throws {
        let peer = try PortableFSDServiceCoordinator.captureDaemonPeer(descriptor)
        defer { peer.processWitness.close() }
        guard let hash = clients[peer.executableURL.path] else { throw PortableFSSignedServiceError.invalidIdentity }
        try PortableFSDServiceCoordinator.requireRunningImage(peer, expectedPath: peer.executableURL.path, expectedCDHash: hash)
    }
}

public final class PortableFSSignedLocalConnection: @unchecked Sendable {
    private let connection: PortableFSDUpdateConnection
    init(_ connection: PortableFSDUpdateConnection) { self.connection = connection }
    public func readFrame() throws -> Data { try connection.readFrame().dropLast() }
    public func writeFrame(_ data: Data) throws { var frame = data; frame.append(10); try connection.writeFrame(frame) }
    public func close() { connection.close() }
}

public final class PortableFSSignedLocalListener: @unchecked Sendable {
    private let listener: PortableFSDUpdateListener
    private let release: PortableFSSignedRelease
    private let frameLimit: Int
    /// The caller holds its singleton before reclaiming this owned endpoint.
    public init(directory: URL, socketName: String, release: PortableFSSignedRelease, frameLimit: Int) throws {
        guard !socketName.isEmpty, !socketName.contains("/"), frameLimit > 0, frameLimit <= 4 << 20 else { throw PortableFSSignedServiceError.invalidFrame }
        listener = try PortableFSDUpdateListener(store: PortableFSDUpdateLeaseStore(directoryURL: directory), socketName: socketName)
        self.release = release; self.frameLimit = frameLimit
    }
    public func accept() throws -> PortableFSSignedLocalConnection {
        let accepted: PortableFSDUpdateConnection
        do { accepted = try listener.accept() }
        catch PortableFSDUpdateSocketError.peerIdentity { throw PortableFSSignedServiceError.invalidIdentity }
        do {
            try release.authenticate(accepted.descriptor)
            // The accepted connection already owns its descriptor. Configure
            // the paired bound without handing it to a second closing owner.
            try accepted.prepareBoundedIO()
            accepted.setFrameLimit(frameLimit)
            return PortableFSSignedLocalConnection(accepted)
        } catch { accepted.close(); throw PortableFSSignedServiceError.invalidIdentity }
    }
    public func close() { listener.stop() }
}

public enum PortableFSWorkspaceServiceRegistration {
    public static let serviceName = "PortableFSWorkspaceService.app"
    public static func register(bundle: Bundle = .main) throws -> Bool {
        _ = try PortableFSSignedRelease(bundle: bundle)
        var home = URL(fileURLWithPath: try PortableFSAccountHome.resolve(), isDirectory: true)
        #if WORKSPACE_SERVICE_TESTING
        guard bundle.bundleIdentifier?.hasPrefix("dev.portablefs.workspace-tests.") == true,
              let testHome = bundle.object(forInfoDictionaryKey: "PFSWorkspaceTestHome") as? String else { throw PortableFSSignedServiceError.invalidBundle }
        home = URL(fileURLWithPath: testHome, isDirectory: true)
        #endif
        guard let id = bundle.bundleIdentifier else { throw PortableFSSignedServiceError.invalidBundle }
        try PortableFSProductUpdate.requireNormalAdmission(accountDirectory: home.appendingPathComponent(".local/state/portablefs", isDirectory: true))
        try WorkspaceRemoval.prepareToStart(home: home)
        let service = SMAppService.agent(plistName: id + ".workspace.plist")
        if service.status == .notRegistered || service.status == .notFound { try service.register() }
        switch service.status {
        case .enabled: return true
        case .requiresApproval: return false
        default: throw PortableFSSignedServiceError.unexpectedStatus(service.status.rawValue)
        }
    }
}
