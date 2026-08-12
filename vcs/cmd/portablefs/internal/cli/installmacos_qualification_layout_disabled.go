//go:build !darwin || !portablefs_macos27_qualification

package cli

func qualificationCommands() []command { return nil }

func qualificationCommandHelp(string) (string, bool) { return "", false }
