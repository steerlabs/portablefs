import FSKit
import Testing
@testable import PortableFSKit

@Test func statfsMappingUsesDaemonValuesAndPreferredIOSize() {
    var reply = PfsStatfsReply()
    reply.blockSize = 8192
    reply.totalBlocks = 10_000
    reply.freeBlocks = 4_000
    reply.totalFiles = 20_000
    reply.freeFiles = 3_000

    var capabilities = PfsCapabilities()
    capabilities.preferredIoBytes = 65_536

    let result = PfsFSKitMapping.statfs(from: reply, capabilities: capabilities)
    #expect(result.blockSize == 8192)
    #expect(result.ioSize == 65_536)
    #expect(result.totalBlocks == 10_000)
    #expect(result.freeBlocks == 4_000)
    #expect(result.availableBlocks == 4_000)
    #expect(result.totalFiles == 20_000)
    #expect(result.freeFiles == 3_000)
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
