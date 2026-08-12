//go:build darwin && portablefs_macos27_qualification

package cli

import "fmt"

func cmdInstallMacOS27QualificationApp(e *cmdEnv, args []string) int {
	if !macOS27QualificationInstallerAdmitted(nativeFSKitPolicyQualification) {
		return e.fail(
			"install-macos27-qualification-app",
			fmt.Errorf("this CLI does not carry the exact macOS 27 qualification stamp"),
		)
	}
	fs := newFlagSet("install-macos27-qualification-app")
	sourceApp := fs.String("source-app", "", "absolute path to the staged PortableFSKitDev.app")
	linkDir := fs.String("link-dir", "", "CLI link directory inside the canonical account home")
	jsonOut := fs.Bool("json", false, "print the versioned installation result")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("install-macos27-qualification-app", err)
	}
	if len(positionals) != 0 {
		return e.usageError("install-macos27-qualification-app", fmt.Errorf("unexpected positional arguments"))
	}
	if *sourceApp == "" {
		return e.usageError("install-macos27-qualification-app", fmt.Errorf("--source-app is required"))
	}
	result, err := runInstallMacOSAppWithLayout(
		e,
		*sourceApp,
		*linkDir,
		macOS27QualificationInstallLayout,
	)
	if err != nil {
		return e.fail("install-macos27-qualification-app", err)
	}
	if *jsonOut {
		return e.printJSON(result)
	}
	fmt.Fprintf(
		e.stdout,
		"installed PortableFSKitDev.app at %s; linked portablefs at %s\n",
		result.AppPath,
		result.CLILink,
	)
	return 0
}

func macOS27QualificationInstallerAdmitted(stamp string) bool {
	return stamp == sdk27QualificationStamp
}
