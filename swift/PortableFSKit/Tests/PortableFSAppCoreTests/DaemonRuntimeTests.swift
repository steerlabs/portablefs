import Testing
@testable import PortableFSAppCore

@Test func mountTableParsesAttachRefs() {
    #expect(MountTable.portableFSFileSystemTypeName == "pfs")
    #expect(MountTable.attachRef(fromMountedFrom: "pfs://att_abc123") == "att_abc123")
    #expect(MountTable.attachRef(fromMountedFrom: "pfs://att_abc123/") == "att_abc123")
    #expect(MountTable.attachRef(fromMountedFrom: "pfs://") == nil)
    #expect(MountTable.attachRef(fromMountedFrom: "/dev/disk3s1") == nil)
    #expect(MountedFilesystem(fsTypeName: "pfs", mountPoint: "/m", mountedFrom: "pfs://att_x").attachRef == "att_x")
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
        mountedFrom: "pfs://att_BBBBBBBBBBBBBBBBBBBBBB"
    )
    #expect(MountTable.portableFSMounts(in: [openSteer, portableFS]) == [portableFS])
}

@Test func mountPointBuilderSanitizesVolumeIDs() {
    #expect(PortableFSAppPaths.mountPoint(baseDirectory: "/Users/u/PortableFS", volumeID: "vol-a") == "/Users/u/PortableFS/vol-a")
    #expect(PortableFSAppPaths.mountPoint(baseDirectory: "/base", volumeID: "../evil") == "/base/___evil")
    #expect(PortableFSAppPaths.mountPoint(baseDirectory: "/base", volumeID: "a/b c") == "/base/a_b_c")
}
