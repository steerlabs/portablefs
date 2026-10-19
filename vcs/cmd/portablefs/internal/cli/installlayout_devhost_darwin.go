//go:build darwin && portablefs_devhost

package cli

const (
	macOSAppName             = "PortableFSKitDev.app"
	macOSStagedAppName       = "PortableFSKitDev.next"
	macOSAppExecutable       = "PortableFSKitDev"
	macOSExtensionExecutable = "PortableFSDev"
)

// Each CLI contains one product contract. Bundle contents never select it.
var compiledMacOSInstallLayout = macOSInstallLayout{
	appName:             macOSAppName,
	stagedAppName:       macOSStagedAppName,
	appExecutable:       macOSAppExecutable,
	extensionExecutable: macOSExtensionExecutable,
	serviceMinimumOS:    "26.0",
	requiredAppID:       "dev.portablefs.oss.KitDev",
	codeIdentity:        macOSInstallDevelopmentHost,
}
