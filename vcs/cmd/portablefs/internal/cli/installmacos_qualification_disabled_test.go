//go:build !darwin || !portablefs_macos27_qualification

package cli

import "testing"

func TestProductionCommandSetOmitsMacOS27QualificationInstaller(t *testing.T) {
	if _, ok := findCommand("install-macos27-qualification-app"); ok {
		t.Fatal("production command set exposes the macOS 27 qualification installer")
	}
	if _, ok := commandHelp("install-macos27-qualification-app"); ok {
		t.Fatal("production detailed help exposes the macOS 27 qualification installer")
	}
	if rootHelpContainsQualificationCommand() {
		t.Fatal("production help exposes the macOS 27 qualification installer")
	}
}

func rootHelpContainsQualificationCommand() bool {
	const command = "install-macos27-qualification-app"
	for i := 0; i+len(command) <= len(rootHelp()); i++ {
		if rootHelp()[i:i+len(command)] == command {
			return true
		}
	}
	return false
}
