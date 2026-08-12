import FSKit
import Foundation
import PortableFSKitMacOS27

@main
struct PortableFSMacOS27DevExtension: UnaryFileSystemExtension {
    var fileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
        PortableFSKitMacOS27Adapter.makeFileSystem()
    }
}
