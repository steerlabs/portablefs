import FSKit
import Foundation
import PortableFSKit

@main
struct PortableFSDevExtension: UnaryFileSystemExtension {
    var fileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
        // The macOS 26 adapter remains a development qualification lane only.
        // Shipping composition uses PortableFSFileSystem() and is refused before
        // socket resolution because FSKit cannot satisfy protocol-5 coherence.
        PortableFSFileSystem(volumeFactory: { socketPath, attachRef, moduleIdentity in
            let core = try await VolumeCore.connect(
                socketPath: socketPath,
                attachRef: attachRef
            )
            return try await PortableFSVolume.make(
                core: core,
                attachRef: attachRef,
                moduleIdentity: moduleIdentity
            )
        })
    }
}
