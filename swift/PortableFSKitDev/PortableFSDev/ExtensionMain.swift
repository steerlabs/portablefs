import FSKit
import Foundation
import PortableFSKit

@main
struct PortableFSDevExtension: UnaryFileSystemExtension {
    var fileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
        PortableFSFileSystem.macOS26BestEffort()
    }
}
