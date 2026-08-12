import Foundation
import Testing
@testable import PortableFSAppCore

@Test func appGroupBootstrapCreatesAnExactPrivateDirectory() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString,
        isDirectory: true
    )
    try FileManager.default.createDirectory(
        at: root,
        withIntermediateDirectories: false
    )
    defer { try? FileManager.default.removeItem(at: root) }

    let directory = try PortableFSAppGroupBootstrap.prepare(
        infoDictionary: ["PFSAppGroupIdentifier": "TEAM.portablefs"],
        containerResolver: { _ in root }
    )
    let attributes = try FileManager.default.attributesOfItem(
        atPath: directory.path
    )
    #expect(attributes[.type] as? FileAttributeType == .typeDirectory)
    #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o700)
}

@Test func appGroupBootstrapRepairsAnExistingDirectoryByDescriptor() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString,
        isDirectory: true
    )
    let directory = root.appendingPathComponent("portablefsd", isDirectory: true)
    try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o755]
    )
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o755],
        ofItemAtPath: directory.path
    )
    defer { try? FileManager.default.removeItem(at: root) }

    _ = try PortableFSAppGroupBootstrap.prepare(
        infoDictionary: ["PFSAppGroupIdentifier": "TEAM.portablefs"],
        containerResolver: { _ in root }
    )
    let attributes = try FileManager.default.attributesOfItem(
        atPath: directory.path
    )
    #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o700)
}

@Test func appGroupBootstrapRefusesASymlinkSocketDirectory() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString,
        isDirectory: true
    )
    let target = root.appendingPathComponent("target", isDirectory: true)
    let directory = root.appendingPathComponent("portablefsd", isDirectory: true)
    try FileManager.default.createDirectory(
        at: target,
        withIntermediateDirectories: true
    )
    try FileManager.default.createSymbolicLink(
        at: directory,
        withDestinationURL: target
    )
    defer { try? FileManager.default.removeItem(at: root) }

    #expect(throws: PortableFSAppGroupBootstrapError.self) {
        _ = try PortableFSAppGroupBootstrap.prepare(
            infoDictionary: ["PFSAppGroupIdentifier": "TEAM.portablefs"],
            containerResolver: { _ in root }
        )
    }
}

@Test func appGroupBootstrapRequiresSignedIdentityAndContainer() {
    #expect(throws: PortableFSAppGroupBootstrapError.self) {
        _ = try PortableFSAppGroupBootstrap.prepare(
            infoDictionary: [:],
            containerResolver: { _ in nil }
        )
    }
    #expect(throws: PortableFSAppGroupBootstrapError.self) {
        _ = try PortableFSAppGroupBootstrap.prepare(
            infoDictionary: ["PFSAppGroupIdentifier": "TEAM.portablefs"],
            containerResolver: { _ in nil }
        )
    }
}
