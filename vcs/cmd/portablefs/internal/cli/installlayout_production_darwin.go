//go:build darwin && !portablefs_devhost

package cli

const (
	macOSAppName             = "PortableFS.app"
	macOSStagedAppName       = "PortableFS.next"
	macOSAppExecutable       = "PortableFS"
	macOSExtensionExecutable = "PortableFSExt"
)

// Each CLI contains one product contract. Bundle contents never select it.
var compiledMacOSInstallLayout = macOSInstallLayout{
	appName:             macOSAppName,
	stagedAppName:       macOSStagedAppName,
	appExecutable:       macOSAppExecutable,
	extensionExecutable: macOSExtensionExecutable,
	serviceMinimumOS:    "26.0",
	requiredAppID:       "",
	codeIdentity:        macOSInstallDeveloperIDRelease,
}
