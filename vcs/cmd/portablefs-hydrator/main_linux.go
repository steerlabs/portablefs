//go:build linux

// Command portablefs-hydrator is the per-volume RESTORE-phase process. In
// restore-namespace mode it materializes the sealed namespace into the volume
// tree and reports it ready; in serve mode it answers the authority's chunk
// fetches over one AF_UNIX socket in the volume's state directory and never
// touches the filesystem the authority owns. The helper chooses the mode
// through the pinned launch configuration and sequences the two.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/hydrator"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "portablefs-hydrator:", err)
		os.Exit(1)
	}
}

func run() error {
	options, err := parseFlags(os.Args[1:])
	if err != nil {
		return err
	}
	// The restore writes one volume tree as that volume's service identity, and
	// serve mode owns a socket the authority connects to under the same
	// identity. Running as root would produce a tree and a socket the model
	// forbids, so it is refused.
	if os.Geteuid() == 0 {
		return errors.New("must run as the volume service identity, not root")
	}
	// SIGTERM is the helper's stop: serve mode returns from its accept loop,
	// closes every connection, and removes its socket.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	options.Logf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(os.Stderr, "portablefs-hydrator: "+format+"\n", args...)
	}
	return hydrator.Run(ctx, options)
}
