import Foundation
import Testing
@testable import PortableFSKit
@preconcurrency import Darwin

@Test func daemonErrnoMapsToPOSIXNSError() {
    let error = PfsErrorMapper.fsKitError(for: PfsLocalClientError.daemon(errno: ENOENT, message: "missing"))
    #expect(error.domain == NSPOSIXErrorDomain)
    #expect(error.code == Int(ENOENT))
}

@Test func connectionClosedMapsToEIO() {
    let error = PfsErrorMapper.fsKitError(for: PfsLocalClientError.connectionClosed)
    #expect(error.domain == NSPOSIXErrorDomain)
    #expect(error.code == Int(EIO))
}
