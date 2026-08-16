//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/cellhost"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "portablefs-authority-launcher:", err)
		os.Exit(1)
	}
}

func run() error {
	showVersion := flag.Bool("version", false, "print exact release identity and exit")
	configPath := flag.String("config", "/run/portablefs-volume/authority.json", "fixed root-owned authority config")
	authorityBinary := flag.String("authority-binary", "/opt/portablefs/current/bin/portablefs-authority", "fixed installed authority binary")
	flag.Parse()
	if *showVersion {
		_, _ = fmt.Fprintln(os.Stdout, version)
		return nil
	}
	if flag.NArg() != 0 || !filepath.IsAbs(*authorityBinary) || filepath.Clean(*authorityBinary) != *authorityBinary {
		return errors.New("authority binary must be a clean absolute path")
	}
	if os.Geteuid() == 0 {
		return errors.New("launcher refuses to run as root")
	}
	info, err := os.Stat(*authorityBinary)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || stat.Uid != 0 {
		return errors.New("authority binary must be a root-owned regular file not writable by group or other users")
	}
	config, err := cellhost.LoadAuthorityConfig(*configPath)
	if err != nil {
		return err
	}
	arguments := append([]string{*authorityBinary}, cellhost.AuthorityArguments(config)...)
	environment := []string{
		"LISTEN_PID=" + os.Getenv("LISTEN_PID"),
		"LISTEN_FDS=" + os.Getenv("LISTEN_FDS"),
		"LISTEN_FDNAMES=" + os.Getenv("LISTEN_FDNAMES"),
		"LANG=C.UTF-8",
	}
	return syscall.Exec(*authorityBinary, arguments, environment)
}
