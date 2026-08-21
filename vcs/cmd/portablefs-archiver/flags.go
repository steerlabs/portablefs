package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/steerlabs/portablefs/vcs/internal/archiver"
)

// parseFlags turns the command line into run options. Every path is a pinned
// bind of the unit, so each flag exists to be overridden in a test or by an
// operator debugging a cell, never to be selected by anything the process
// reads.
func parseFlags(arguments []string) (archiver.Options, error) {
	flags := flag.NewFlagSet("portablefs-archiver", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	launchConfig := flags.String("launch-config", archiver.DefaultLaunchConfigPath,
		"pinned per-volume archiver launch configuration")
	archiveConfig := flags.String("archive-config", defaultArchiveConfigPath(),
		"root-provisioned archive-store credential file")
	volumeRoot := flags.String("volume-root", archiver.DefaultVolumeRoot,
		"read-only bind of the quiesced volume tree")
	resultDir := flags.String("result-dir", archiver.DefaultResultDir,
		"result bind the helper reads the seal from")
	partSize := flags.Uint64("part-size-bytes", archiver.DefaultPartSizeBytes,
		"multipart part size, 8..64 MiB")
	verifyStreams := flags.Int("verify-streams", 4,
		"parallel read-back streams, roughly one per 85-90 MB/s of bandwidth")
	if err := flags.Parse(arguments); err != nil {
		return archiver.Options{}, err
	}
	if flags.NArg() != 0 {
		return archiver.Options{}, errors.New("no positional arguments are accepted")
	}
	if err := absolutePaths(*launchConfig, *archiveConfig, *volumeRoot, *resultDir); err != nil {
		return archiver.Options{}, err
	}
	if *verifyStreams <= 0 || *verifyStreams > 64 {
		return archiver.Options{}, errors.New("verify streams must be within 1..64")
	}
	return archiver.Options{
		LaunchConfigPath:  *launchConfig,
		ArchiveConfigPath: *archiveConfig,
		VolumeRoot:        *volumeRoot,
		ResultDir:         *resultDir,
		PartSizeBytes:     *partSize,
		VerifyStreams:     *verifyStreams,
	}, nil
}

// defaultArchiveConfigPath honours the unit's environment override and
// otherwise names the pinned credential file.
func defaultArchiveConfigPath() string {
	if value := os.Getenv(archiver.ArchiveConfigEnv); value != "" {
		return value
	}
	return archiver.DefaultArchiveConfigPath
}

func absolutePaths(paths ...string) error {
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("path must be clean and absolute: %q", path)
		}
	}
	return nil
}
