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

@Test func requestedAttributesAreExactAndCarryAuthoritativeParentAndFlags() throws {
    var item = PfsItem()
    item.itemID = 9
    item.itemGeneration = 3
    var parent = PfsItem()
    parent.itemID = 4
    parent.itemGeneration = 3
    var attr = PfsAttr()
    attr.item = item
    attr.parent = parent
    attr.kind = .file
    attr.mode = 0o640
    attr.nlink = 2
    attr.uid = 501
    attr.gid = 20
    attr.size = 4097
    attr.allocSize = 8192
    attr.flags = 0
    attr.mtimeMs = 10
    attr.ctimeMs = 20
    attr.atimeMs = 30
    attr.birthtimeMs = 40

    let requested: FSItem.Attribute = [
        .type, .mode, .linkCount, .flags, .size, .allocSize,
        .fileID, .parentID, .accessTime, .modifyTime, .changeTime, .birthTime,
    ]
    let attributes = try PfsFSKitMapping.attributes(from: attr, requested: requested)

    for field in [
        FSItem.Attribute.type, .mode, .linkCount, .flags, .size, .allocSize,
        .fileID, .parentID, .accessTime, .modifyTime, .changeTime, .birthTime,
    ] {
        #expect(attributes.isValid(field))
    }
    for field in [
        FSItem.Attribute.uid, .gid, .supportsLimitedXAttrs, .inhibitKernelOffloadedIO,
        .addedTime, .backupTime,
    ] {
        #expect(!attributes.isValid(field))
    }
    #expect(attributes.flags == 0)
    #expect(attributes.allocSize == 8192)
    let expectedParentID = try PfsFSKitMapping.itemIdentifier(from: parent.itemID)
    #expect(attributes.parentID == expectedParentID)
}

@Test func parentMappingDistinguishesRootDetachedAndMalformedParents() throws {
    var rootItem = PfsItem()
    rootItem.itemID = 1
    rootItem.itemGeneration = 5
    var root = PfsAttr()
    root.item = rootItem
    root.kind = .directory
    let rootAttributes = try PfsFSKitMapping.attributes(from: root, requested: [.parentID])
    #expect(rootAttributes.isValid(.parentID))
    #expect(rootAttributes.parentID == .parentOfRoot)

    var detachedItem = PfsItem()
    detachedItem.itemID = 7
    detachedItem.itemGeneration = 5
    var detached = PfsAttr()
    detached.item = detachedItem
    let detachedAttributes = try PfsFSKitMapping.attributes(
        from: detached,
        requested: [.parentID]
    )
    #expect(detachedAttributes.isValid(.parentID))
    #expect(detachedAttributes.parentID == .invalid)

    var invalidParent = PfsItem()
    invalidParent.itemID = 0
    invalidParent.itemGeneration = 5
    detached.parent = invalidParent
    #expect(throws: PfsLocalClientError.self) {
        try PfsFSKitMapping.attributes(from: detached, requested: [.parentID])
    }
}

@Test func unsupportedRequestedTimesAreLeftInvalidWithoutFailing() throws {
    var item = PfsItem()
    item.itemID = 2
    item.itemGeneration = 1
    var parent = PfsItem()
    parent.itemID = 5
    parent.itemGeneration = 1
    var attr = PfsAttr()
    attr.item = item
    attr.parent = parent
    attr.kind = .file
    attr.mode = 0o644
    attr.size = 17
    attr.mtimeMs = 1_700_000_000_000

    for field in [FSItem.Attribute.addedTime, .backupTime] {
        let onlyUnsupported = try PfsFSKitMapping.attributes(from: attr, requested: [field])
        #expect(!onlyUnsupported.isValid(field))

        // FSKit's contract is that every requested SUPPORTED field is valid.
        // An unsupported bit in the mask must not suppress the rest.
        let mixed = try PfsFSKitMapping.attributes(
            from: attr,
            requested: [field, .type, .mode, .size, .fileID, .parentID, .modifyTime]
        )
        #expect(!mixed.isValid(field))
        for supported: FSItem.Attribute in
            [.type, .mode, .size, .fileID, .parentID, .modifyTime] {
            #expect(mixed.isValid(supported))
        }
        #expect(mixed.size == 17)
        #expect(mixed.fileID == (try PfsFSKitMapping.itemIdentifier(from: 2)))
        #expect(mixed.parentID == (try PfsFSKitMapping.itemIdentifier(from: 5)))
    }
}

/// A flags change is FORWARDED to the daemon, never judged in the extension
/// and never silently dropped. Whether it can be honored is per-attach
/// knowledge (the authority's FeatureFlagPersistence bit), so the mapping layer
/// consumes `.flags` and lets the daemon answer — see
/// `flagChangesAreRefusedByTheDaemonWhenTheAuthorityCannotPersistThem` for the
/// refusal half of the contract.
@Test func flagChangesAreForwardedInsteadOfSilentlyDropped() throws {
    let request = FSItem.SetAttributesRequest()
    request.mode = 0o600
    let modeOnly = try PfsFSKitMapping.setAttributes(from: request)
    #expect(modeOnly.mode == 0o600)
    #expect(modeOnly.flags == nil)

    request.flags = UInt32(UF_IMMUTABLE)
    let withFlags = try PfsFSKitMapping.setAttributes(from: request)
    #expect(withFlags.flags == UInt32(UF_IMMUTABLE))
    #expect(withFlags.mode == 0o600)
    // FSKit's contract: an attribute the filesystem acts on must be reported
    // consumed, or the kernel keeps believing the change never happened.
    #expect(request.consumedAttributes.contains(.flags))

    // Zero is a REQUEST (clear every flag), not "no change".
    let clearing = FSItem.SetAttributesRequest()
    clearing.flags = 0
    #expect(try PfsFSKitMapping.setAttributes(from: clearing).flags == 0)
    #expect(clearing.consumedAttributes.contains(.flags))
}

/// The volume capability is answered from the attach's own resolve reply, not
/// hardcoded: a mount claims immutable-file support exactly where a chflags(2)
/// will actually persist.
@Test func immutableFileCapabilityFollowsTheAttachedAuthority() {
    var withoutFlags = PfsCapabilities()
    withoutFlags.caseSensitive = true
    #expect(PfsFSKitMapping.supportedCapabilities(from: withoutFlags).doesNotSupportImmutableFiles)

    var withFlags = withoutFlags
    withFlags.flagsSupported = true
    #expect(!PfsFSKitMapping.supportedCapabilities(from: withFlags).doesNotSupportImmutableFiles)
}

@Test func timespecConversionNormalizesPreEpochNanoseconds() {
    let negative = PfsFSKitMapping.timespec(milliseconds: -1_500)
    #expect(negative.tv_sec == -2)
    #expect(negative.tv_nsec == 500_000_000)
    #expect(PfsFSKitMapping.milliseconds(from: negative) == -1_500)

    let wholeSecond = PfsFSKitMapping.timespec(milliseconds: -2_000)
    #expect(wholeSecond.tv_sec == -2)
    #expect(wholeSecond.tv_nsec == 0)
    #expect(PfsFSKitMapping.milliseconds(from: wholeSecond) == -2_000)

    let positive = PfsFSKitMapping.timespec(milliseconds: 1_500)
    #expect(positive.tv_sec == 1)
    #expect(positive.tv_nsec == 500_000_000)

    for milliseconds in stride(from: Int64(-5_000), through: 5_000, by: 250) {
        let value = PfsFSKitMapping.timespec(milliseconds: milliseconds)
        #expect(value.tv_nsec >= 0 && value.tv_nsec < 1_000_000_000)
        #expect(PfsFSKitMapping.milliseconds(from: value) == milliseconds)
    }
}

@Test func parentDirectoryIdentifierNamesTheTrueParentAndSelfWhenUnknown() throws {
    var rootItem = PfsItem()
    rootItem.itemID = 1
    rootItem.itemGeneration = 2
    var root = PfsAttr()
    root.item = rootItem
    root.kind = .directory
    // POSIX makes the root its own parent; .parentOfRoot is a getattr-only
    // answer and would name no packable directory entry.
    #expect(try PfsFSKitMapping.parentDirectoryIdentifier(from: root) == .rootDirectory)

    var childItem = PfsItem()
    childItem.itemID = 12
    childItem.itemGeneration = 1
    var child = PfsAttr()
    child.item = childItem
    child.kind = .directory
    #expect(
        try PfsFSKitMapping.parentDirectoryIdentifier(from: child)
            == (try PfsFSKitMapping.itemIdentifier(from: 12))
    )

    child.parent = rootItem
    #expect(try PfsFSKitMapping.parentDirectoryIdentifier(from: child) == .rootDirectory)
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
