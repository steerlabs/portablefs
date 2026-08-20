//go:build linux

// Command portablefs-archiver is the per-volume ARCHIVE-phase process. The
// helper starts it once per phase, as the volume's service identity, while the
// authority is quiesced and absent; it archives the read-only bind of the
// volume tree, verifies every uploaded byte by read-back, and writes the sealed
// result the helper observes. Restart=no: a failure is a failed phase, not
// something to retry in place.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/archiver"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "portablefs-archiver:", err)
		os.Exit(1)
	}
}

func run() error {
	options, err := parseFlags(os.Args[1:])
	if err != nil {
		return err
	}
	// The archiver reads one volume tree as that volume's service identity.
	// Running as root would read it with every DAC override the identity model
	// exists to withhold, so it is refused rather than tolerated.
	if os.Geteuid() == 0 {
		return errors.New("must run as the volume service identity, not root")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	options.Logf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(os.Stderr, "portablefs-archiver: "+format+"\n", args...)
	}
	return archiver.Run(ctx, options)
}
