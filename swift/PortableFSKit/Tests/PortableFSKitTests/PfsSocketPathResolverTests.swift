import Foundation
import Testing
@testable import PortableFSKit

@Test func explicitSocketPathWinsOverAppGroup() throws {
    let resolver = PfsSocketPathResolver(
        infoDictionary: [
            "PFSDaemonSocketPath": "/tmp/explicit.sock",
            "PFSAppGroupIdentifier": "group.example"
        ],
        appGroupContainerResolver: { _ in
            URL(fileURLWithPath: "/tmp/group")
        }
    )

    #expect(try resolver.resolve() == "/tmp/explicit.sock")
}

@Test func appGroupSocketPathFallback() throws {
    let resolver = PfsSocketPathResolver(
        infoDictionary: [
            "PFSAppGroupIdentifier": "group.example"
        ],
        appGroupContainerResolver: { identifier in
            #expect(identifier == "group.example")
            return URL(fileURLWithPath: "/tmp/group")
        }
    )

    #expect(try resolver.resolve() == "/tmp/group/portablefsd/pfs.sock")
}

@Test func relativeExplicitSocketPathIsRejected() throws {
    let resolver = PfsSocketPathResolver(infoDictionary: ["PFSDaemonSocketPath": "relative.sock"])
    do {
        _ = try resolver.resolve()
        Issue.record("expected resolver to reject relative socket path")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EINVAL)
    }
}

@Test func missingSocketPathKeysAreRejected() throws {
    let resolver = PfsSocketPathResolver(infoDictionary: [:])
    do {
        _ = try resolver.resolve()
        Issue.record("expected resolver to reject missing configuration")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EINVAL)
    }
}

@Test func nilAppGroupContainerIsRejected() throws {
    let resolver = PfsSocketPathResolver(
        infoDictionary: ["PFSAppGroupIdentifier": "group.missing"],
        appGroupContainerResolver: { _ in nil }
    )
    do {
        _ = try resolver.resolve()
        Issue.record("expected resolver to reject missing app group container")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EINVAL)
    }
}
