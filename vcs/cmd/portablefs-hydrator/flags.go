package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/steerlabs/portablefs/vcs/internal/hydrator"
)

// parseFlags turns the command line into run options. The mode is deliberately
// not a flag: it comes from the helper-written launch configuration, so the
// unit cannot be started in the wrong mode by an argument.
func parseFlags(arguments []string) (hydrator.Options, error) {
	flags := flag.NewFlagSet("portablefs-hydrator", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	launchConfig := flags.String("launch-config", hydrator.DefaultLaunchConfigPath,
		"pinned per-volume hydrator launch configuration")
	archiveConfig := flags.String("archive-config", defaultArchiveConfigPath(),
		"root-provisioned archive-store credential file")
	volumeRoot := flags.String("volume-root", hydrator.DefaultVolumeRoot,
		"volume data directory, bound read-write for restore-namespace mode only")
	stateDir := flags.String("state-dir", hydrator.DefaultStateDir,
		"volume state directory holding the bindings, the ready marker, and the socket")
	socket := flags.String("socket", "",
		"serve-mode socket path; empty means the pinned name inside the state directory")
	if err := flags.Parse(arguments); err != nil {
		return hydrator.Options{}, err
	}
	if flags.NArg() != 0 {
		return hydrator.Options{}, errors.New("no positional arguments are accepted")
	}
	paths := []string{*launchConfig, *archiveConfig, *volumeRoot, *stateDir}
	if *socket != "" {
		paths = append(paths, *socket)
	}
	if err := absolutePaths(paths...); err != nil {
		return hydrator.Options{}, err
	}
	return hydrator.Options{
		LaunchConfigPath:  *launchConfig,
		ArchiveConfigPath: *archiveConfig,
		VolumeRoot:        *volumeRoot,
		StateDir:          *stateDir,
		SocketPath:        *socket,
	}, nil
}

func defaultArchiveConfigPath() string {
	if value := os.Getenv(hydrator.ArchiveConfigEnv); value != "" {
		return value
	}
	return hydrator.DefaultArchiveConfigPath
}

func absolutePaths(paths ...string) error {
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("path must be clean and absolute: %q", path)
		}
	}
	return nil
}
