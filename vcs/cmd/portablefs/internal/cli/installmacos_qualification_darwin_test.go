//go:build darwin && portablefs_macos27_qualification

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestMacOS27QualificationCommandCarriesOneExactLayout(t *testing.T) {
	want := macOSInstallLayout{
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
	if macOS27QualificationInstallLayout != want {
		t.Fatalf("qualification layout = %+v, want %+v", macOS27QualificationInstallLayout, want)
	}
	command, ok := findCommand("install-macos27-qualification-app")
	if !ok || command.run == nil {
		t.Fatal("tagged qualification command is absent")
	}
	if help, ok := commandHelp(command.name); !ok || help == "" {
		t.Fatal("tagged qualification command has no exact usage text")
	}
	if command.name == "install-macos-app" {
		t.Fatal("qualification command replaced the production installer")
	}
}

func TestMacOS27QualificationCommandRefusesAnUnstampedTaggedBuild(t *testing.T) {
	for _, stamp := range []string{"", "sdk27", sdk27QualificationStamp + "-other"} {
		if macOS27QualificationInstallerAdmitted(stamp) {
			t.Fatalf("qualification installer admitted stamp %q", stamp)
		}
	}
}

func TestMacOS27QualificationCommandAdmitsOnlyTheExactStampBeforeParsing(t *testing.T) {
	if !macOS27QualificationInstallerAdmitted(sdk27QualificationStamp) {
		t.Fatal("qualification installer rejected its exact stamp")
	}
	if nativeFSKitPolicyQualification == sdk27QualificationStamp {
		t.Skip("test binary was linker-stamped; artifact execution covers its parse boundary")
	}
	var stderr bytes.Buffer
	status := cmdInstallMacOS27QualificationApp(
		&cmdEnv{stderr: &stderr},
		nil,
	)
	if status != 1 || !strings.Contains(stderr.String(), "does not carry the exact macOS 27 qualification stamp") {
		t.Fatalf("unstamped command = status %d, stderr %q", status, stderr.String())
	}
}
