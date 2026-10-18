import FSKit
import Foundation
import Testing
@testable import PortableFSKit
@preconcurrency import Darwin

@Test func unsupportedXattrOperationsStopAtTheMacOSVFSBoundary() {
    let unsupported = PfsLocalClientError.daemon(
        errno: ENOTSUP,
        message: "user xattrs are read-only"
    )
    #expect(PfsErrorMapper.fsKitError(for: unsupported).code == Int(ENOTSUP))
    #expect(PfsErrorMapper.fsKitXattrError(for: unsupported).code == Int(EOPNOTSUPP))

    let operationUnsupported = PfsLocalClientError.daemon(
        errno: EOPNOTSUPP,
        message: "user xattrs are unsupported"
    )
    #expect(PfsErrorMapper.fsKitXattrError(for: operationUnsupported).code == Int(EOPNOTSUPP))

    let invalid = PfsLocalClientError.daemon(errno: EINVAL, message: "invalid xattr")
    #expect(PfsErrorMapper.fsKitXattrError(for: invalid).code == Int(EINVAL))
}

/// FSKit reserves 0, 1 and 2; the checked successor maps pfslocal's root 1
/// to FSKit's root 2 and every ordinary file ID in [2, UInt64.max) above the
/// reserved values. Both sides of the deleted high-half partition are ordinary
/// daemon file IDs now. Zero and UInt64.max are refused, for an item's own ID
/// and for its parent's.
@Test func itemIdentifiersUseTheCheckedSuccessorAcrossTheWholeRange() throws {
    let formerPartition = UInt64(1) << 63
    #expect(try PfsFSKitMapping.itemIdentifier(from: 1) == .rootDirectory)
    #expect(try PfsFSKitMapping.itemIdentifier(from: 2).rawValue == 3)
    for fileID in [formerPartition - 1, formerPartition, formerPartition + 1, UInt64.max - 1] {
        #expect(try PfsFSKitMapping.itemIdentifier(from: fileID).rawValue == fileID + 1)
    }
    for unrepresentable in [UInt64(0), UInt64.max] {
        do {
            _ = try PfsFSKitMapping.itemIdentifier(from: unrepresentable)
            Issue.record("file ID \(unrepresentable) mapped to an FSKit identifier")
        } catch let error as PfsLocalClientError {
            #expect(error.posixErrno == EOVERFLOW)
        }
    }
    // Directory cookies keep their own, unrelated high-bit marker.
    #expect(PfsEnumerationCookies.daemonCookieMarker == formerPartition)

    var rootItem = PfsItem()
    rootItem.itemID = 1
    rootItem.itemGeneration = 1
    var root = PfsAttr()
    root.item = rootItem
    root.fileID = 1
    root.kind = .directory
    root.mode = 0o755
    let attributes = try PfsFSKitMapping.attributes(from: root)
    #expect(attributes.isValid(.fileID))
    #expect(attributes.fileID == .rootDirectory)
    #expect(attributes.type == .directory)
    root.nlink = 0
    #expect(try PfsFSKitMapping.attributes(from: root).linkCount == 0)

    var high = PfsAttr()
    high.kind = .file
    high.fileID = formerPartition + 7
    high.parentFileID = UInt64.max - 1
    let highAttributes = try PfsFSKitMapping.attributes(from: high, requested: [.fileID, .parentID])
    #expect(highAttributes.fileID.rawValue == formerPartition + 8)
    #expect(highAttributes.parentID.rawValue == UInt64.max)
    #expect(try PfsFSKitMapping.parentDirectoryIdentifier(from: high).rawValue == UInt64.max)

    high.fileID = UInt64.max
    #expect(throws: PfsLocalClientError.self) {
        try PfsFSKitMapping.attributes(from: high, requested: [.fileID])
    }
    high.fileID = formerPartition
    high.parentFileID = UInt64.max
    #expect(throws: PfsLocalClientError.self) {
        try PfsFSKitMapping.attributes(from: high, requested: [.parentID])
    }
    #expect(throws: PfsLocalClientError.self) {
        try PfsFSKitMapping.parentDirectoryIdentifier(from: high)
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
    attr.fileID = item.itemID
    attr.parent = parent
    attr.parentFileID = parent.itemID
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
    root.fileID = rootItem.itemID
    root.kind = .directory
    let rootAttributes = try PfsFSKitMapping.attributes(from: root, requested: [.parentID])
    #expect(rootAttributes.isValid(.parentID))
    #expect(rootAttributes.parentID == .parentOfRoot)

    var detachedItem = PfsItem()
    detachedItem.itemID = 7
    detachedItem.itemGeneration = 5
    var detached = PfsAttr()
    detached.item = detachedItem
    detached.fileID = detachedItem.itemID
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
    detached.parentFileID = UInt64.max
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
    attr.fileID = item.itemID
    attr.parent = parent
    attr.parentFileID = parent.itemID
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

/// A flags change is always forwarded: the daemon decides per object and
/// refuses the whole SetAttr before applying any of it. The mapping consumes
/// `.flags` because the change is actually asked of someone who answers.
@Test func flagChangesAreAlwaysForwarded() {
    let request = FSItem.SetAttributesRequest()
    request.mode = 0o600
    let modeOnly = PfsFSKitMapping.setAttributes(from: request)
    #expect(modeOnly.mode == 0o600)
    #expect(modeOnly.flags == nil)

    request.flags = UInt32(UF_IMMUTABLE)
    let withFlags = PfsFSKitMapping.setAttributes(from: request)
    #expect(withFlags.flags == UInt32(UF_IMMUTABLE))
    #expect(withFlags.mode == 0o600)
    // FSKit's contract: an attribute the filesystem acts on must be reported
    // consumed, or the kernel keeps believing the change never happened.
    #expect(request.consumedAttributes.contains(.flags))

    // Zero is a REQUEST (clear every flag), not "no change".
    let clearing = FSItem.SetAttributesRequest()
    clearing.flags = 0
    #expect(PfsFSKitMapping.setAttributes(from: clearing).flags == 0)
    #expect(clearing.consumedAttributes.contains(.flags))
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
    root.fileID = rootItem.itemID
    root.kind = .directory
    // POSIX makes the root its own parent; .parentOfRoot is a getattr-only
    // answer and would name no packable directory entry.
    #expect(try PfsFSKitMapping.parentDirectoryIdentifier(from: root) == .rootDirectory)

    var childItem = PfsItem()
    childItem.itemID = 12
    childItem.itemGeneration = 1
    var child = PfsAttr()
    child.item = childItem
    child.fileID = childItem.itemID
    child.kind = .directory
    #expect(
        try PfsFSKitMapping.parentDirectoryIdentifier(from: child)
            == (try PfsFSKitMapping.itemIdentifier(from: 12))
    )

    child.parent = rootItem
    child.parentFileID = rootItem.itemID
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

/// Symlinks, hard links and case-sensitive names are baseline semantics, not
/// capabilities a daemon advertises. Immutable-file support stays declared so
/// a flag change reaches the daemon's explicit per-object refusal.
@Test func supportedCapabilitiesAreTheFixedBaseline() {
    let supported = PfsFSKitMapping.supportedCapabilities()
    #expect(supported.supportsSymbolicLinks)
    #expect(supported.supportsHardLinks)
    #expect(supported.supports64BitObjectIDs)
    #expect(!supported.supportsPersistentObjectIDs)
    #expect(supported.caseFormat == .sensitive)
    #expect(!supported.doesNotSupportImmutableFiles)
}
