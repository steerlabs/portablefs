import FSKit
import Foundation
import Testing
@testable import PortableFSKit
@preconcurrency import Darwin

@Test func itemIdentifiersRespectFSKitReservedValues() throws {
    #expect(
        try PfsFSKitMapping.itemIdentifier(from: 1) == .rootDirectory
    )
    #expect(
        try PfsFSKitMapping.itemIdentifier(from: 2).rawValue == 3
    )

    do {
        _ = try PfsFSKitMapping.itemIdentifier(from: 0)
        Issue.record("expected the invalid pfslocal item identifier to fail")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EOVERFLOW)
    }

    var rootItem = PfsItem()
    rootItem.itemID = 1
    rootItem.itemGeneration = 1
    var root = PfsAttr()
    root.item = rootItem
    root.kind = .directory
    root.mode = 0o755
    let attributes = try PfsFSKitMapping.attributes(from: root)
    #expect(attributes.isValid(.fileID))
    #expect(attributes.fileID == .rootDirectory)
    #expect(attributes.type == .directory)

    root.nlink = 0
    let detachedAttributes = try PfsFSKitMapping.attributes(from: root)
    #expect(detachedAttributes.linkCount == 0)

    do {
        _ = try PfsFSKitMapping.itemIdentifier(from: UInt64.max)
        Issue.record("expected an unrepresentable item identifier to fail")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EOVERFLOW)
    }
}

@Test func directoryVerifierNeverLeaksFSKitInitialSentinel() throws {
    #expect(try PfsFSKitMapping.directoryVerifier(from: 0).rawValue == 1)
    #expect(try PfsFSKitMapping.directoryVerifier(from: 41).rawValue == 42)
    do {
        _ = try PfsFSKitMapping.directoryVerifier(from: UInt64.max)
        Issue.record("expected an unrepresentable verifier to fail")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EOVERFLOW)
    }
}

@Test func statfsMappingUsesDaemonValuesAndPreferredIOSize() {
    var reply = PfsStatfsReply()
    reply.blockSize = 8192
    reply.totalBlocks = 10_000
    reply.freeBlocks = 4_000
    reply.totalFiles = 20_000
    reply.freeFiles = 3_000

    var capabilities = PfsCapabilities()
    capabilities.preferredIoBytes = 65_536

    let result = PfsFSKitMapping.statfs(
        from: reply,
        capabilities: capabilities,
        fileSystemTypeName: "portablefs"
    )
    #expect(result.fileSystemTypeName == "portablefs")
    #expect(result.blockSize == 8192)
    #expect(result.ioSize == 65_536)
    #expect(result.totalBlocks == 10_000)
    #expect(result.freeBlocks == 4_000)
    #expect(result.availableBlocks == 4_000)
    #expect(result.totalFiles == 20_000)
    #expect(result.freeFiles == 3_000)

    let defaultIdentityResult = PfsFSKitMapping.statfs(
        from: reply,
        capabilities: capabilities
    )
    #expect(defaultIdentityResult.fileSystemTypeName == PortableFSIdentity.fileSystemTypeName)
}

@Test func moduleIdentitySeparatesTypeAndResourceScheme() throws {
    let identity = try PortableFSModuleIdentity(infoDictionary: [
        "EXAppExtensionAttributes": [
            "FSShortName": "portablefs",
            "FSSupportedSchemes": ["pfs"],
        ],
    ])
    #expect(identity.fileSystemTypeName == "portablefs")
    #expect(identity.resourceScheme == "pfs")
    #expect(identity.resourcePrefix == "pfs://")

    let oss = try PortableFSModuleIdentity(
        fileSystemTypeName: PortableFSIdentity.fileSystemTypeName,
        resourceScheme: PortableFSIdentity.resourceScheme
    )
    #expect(oss.resourcePrefix == "dev.portablefs.oss://")
}

@Test func moduleIdentityRejectsMissingOrAmbiguousSchemes() {
    for schemes in [[], ["pfs", "dev.portablefs.oss"], ["NOT CANONICAL"]] {
        #expect(throws: PortableFSModuleIdentity.ValidationError.self) {
            try PortableFSModuleIdentity(infoDictionary: [
                "EXAppExtensionAttributes": [
                    "FSShortName": "pfs",
                    "FSSupportedSchemes": schemes,
                ],
            ])
        }
    }
}

@Test func supportedCapabilitiesReflectDaemonCapabilities() {
    var capabilities = PfsCapabilities()
    capabilities.symlinks = true
    capabilities.hardLinks = true
    capabilities.caseSensitive = true

    let supported = PfsFSKitMapping.supportedCapabilities(from: capabilities)
    #expect(supported.supportsSymbolicLinks)
    #expect(supported.supportsHardLinks)
    #expect(supported.supports64BitObjectIDs)
    #expect(supported.supportsPersistentObjectIDs)
    #expect(supported.caseFormat == .sensitive)
}
