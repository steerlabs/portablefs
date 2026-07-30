package cli

import "fmt"

type macOSInstallResult struct {
	SchemaVersion int    `json:"schemaVersion"`
	AppPath       string `json:"appPath"`
	CLILink       string `json:"cliLink"`
	Version       string `json:"version"`
}

// cmdInstallMacOSApp is intentionally absent from root help. The verified
// macOS installer invokes it from the CLI nested in the staged app so one
// signed process owns account-path resolution, lifecycle exclusion, legacy
// state refusal, and publication.
func cmdInstallMacOSApp(e *cmdEnv, args []string) int {
	fs := newFlagSet("install-macos-app")
	sourceApp := fs.String("source-app", "", "absolute path to the staged PortableFS.app")
	linkDir := fs.String("link-dir", "", "CLI link directory inside the canonical account home")
	jsonOut := fs.Bool("json", false, "print the versioned installation result")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("install-macos-app", err)
	}
	if len(positionals) != 0 {
		return e.usageError("install-macos-app", fmt.Errorf("unexpected positional arguments"))
	}
	if *sourceApp == "" {
		return e.usageError("install-macos-app", fmt.Errorf("--source-app is required"))
	}
	result, err := runInstallMacOSApp(e, *sourceApp, *linkDir)
	if err != nil {
		return e.fail("install-macos-app", err)
	}
	if *jsonOut {
		return e.printJSON(result)
	}
	fmt.Fprintf(e.stdout, "installed PortableFS.app at %s; linked portablefs at %s\n", result.AppPath, result.CLILink)
	return 0
}
