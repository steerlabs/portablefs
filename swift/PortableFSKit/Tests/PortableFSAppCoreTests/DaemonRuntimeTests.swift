import Testing
@testable import PortableFSAppCore
import PortableFSKit

@Test func mountTableParsesAttachRefs() {
    #expect(MountTable.portableFSFileSystemTypeName == "pfs")
    #expect(PortableFSIdentity.resourceScheme == "dev.portablefs.oss")
    #expect(MountTable.attachRef(fromMountedFrom: "dev.portablefs.oss://att_abc123") == "att_abc123")
    #expect(MountTable.attachRef(fromMountedFrom: "dev.portablefs.oss://att_abc123/") == "att_abc123")
    #expect(MountTable.attachRef(fromMountedFrom: "dev.portablefs.oss://") == nil)
    #expect(MountTable.attachRef(fromMountedFrom: "pfs://att_abc123") == nil)
    #expect(MountTable.attachRef(fromMountedFrom: "/dev/disk3s1") == nil)
    #expect(MountedFilesystem(
        fsTypeName: "pfs",
        mountPoint: "/m",
        mountedFrom: "dev.portablefs.oss://att_x"
    ).attachRef == "att_x")
}

@Test func mountTableSnapshotIncludesRootFilesystem() {
    let mounts = MountTable.current()
    #expect(mounts.contains { $0.mountPoint == "/" })
    #expect(MountTable.portableFSMounts().allSatisfy { $0.fsTypeName == "pfs" })
}

@Test func mountTableIgnoresOtherFSKitProducts() {
    let openSteer = MountedFilesystem(
        fsTypeName: "portablefs",
        mountPoint: "/Users/u/.opensteer/work",
        mountedFrom: "pfs://att_AAAAAAAAAAAAAAAAAAAAAA"
    )
    let portableFS = MountedFilesystem(
        fsTypeName: "pfs",
        mountPoint: "/Users/u/PortableFS/work",
        mountedFrom: "dev.portablefs.oss://att_BBBBBBBBBBBBBBBBBBBBBB"
    )
    #expect(MountTable.portableFSMounts(in: [openSteer, portableFS]) == [portableFS])
}
