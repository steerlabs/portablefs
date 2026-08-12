//go:build darwin && portablefs_macos27_qualification

package cli

var macOS27QualificationInstallLayout = macOSInstallLayout{
	appName:               "PortableFSKitDev.app",
	stagedAppName:         "PortableFSKitDev.next",
	appExecutable:         "PortableFSKitDev",
	extensionExecutable:   "PortableFSDev",
	serviceMinimumOS:      "27.0",
	requiredAppID:         "dev.portablefs.oss.KitDev",
	codeIdentity:          macOSInstallAppleDevelopmentQualification,
	installedCodeIdentity: macOSInstallAppleDevelopmentQualification,
	installedRecovery: macOSInstalledRecoveryIdentity{
		hostCodeDirectoryHash:      "f09258ec96fa0e468b91c51005e6f76bee16a660",
		extensionCodeDirectoryHash: "311e2cc459ec796bc88de293957dc3079a579d45",
		cliCodeDirectoryHash:       "027789129c4e749ef4b89887abca1be097d49a56",
		serviceCodeDirectoryHash:   "076636f6ffb95880c83d72fefe08e1a50b126f7d",
		daemonExecutableSHA256:     "eb2d4f8225f11076ddc76bd6208503d5068dc8d7105ddb47b74e4d9748b63a84",
	},
}

func qualificationCommands() []command {
	return []command{{
		name:    "install-macos27-qualification-app",
		summary: "install the signed macOS 27 qualification app bundle",
		run:     cmdInstallMacOS27QualificationApp,
	}}
}

func qualificationCommandHelp(name string) (string, bool) {
	if name != "install-macos27-qualification-app" {
		return "", false
	}
	return `USAGE
  portablefs install-macos27-qualification-app \
    --source-app /absolute/path/to/PortableFSKitDev.app \
    [--link-dir /absolute/path] [--json]

Internal macOS 27 native qualification installer. This command exists only in
the explicitly stamped development CLI and runs the same guarded transaction
as the production macOS application installer with one compiled development
bundle and signing policy. The running CLI must be the exact helper nested in
--source-app.
`, true
}
