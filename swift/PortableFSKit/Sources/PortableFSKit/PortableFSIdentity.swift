public enum PortableFSIdentity {
    /// Must match EXAppExtensionAttributes.FSShortName in both extension
    /// targets. FSKit publishes this value through statfs(2), making it the
    /// kernel-visible boundary between PortableFS and other FSKit products.
    public static let fileSystemTypeName = "pfs"
}
