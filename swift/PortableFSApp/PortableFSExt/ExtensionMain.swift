import FSKit
import Foundation
import PortableFSKit

@main
struct PortableFSExtension: UnaryFileSystemExtension {
    var fileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
        PortableFSFileSystem()
    }
}
