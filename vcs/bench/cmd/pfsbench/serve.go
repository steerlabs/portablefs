package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/delegation"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// nopBlobs backs a scratch volume with no committed manifest: every file is born
// in the live tree, so there are no backend blobs to read.
type nopBlobs struct{}

func (nopBlobs) Blob(context.Context, string) ([]byte, error) {
	return nil, errors.New("pfsbench: scratch volume has no backed blobs")
}

// startAuthority opens (or replays) the WAL at walPath, builds the workfs and
// serves fsproto on addr. Returns the bound address and a stop func.
func startAuthority(ctx context.Context, addr, walPath string) (string, func(), error) {
	w, err := wal.Open(walPath)
	if err != nil {
		return "", nil, err
	}
	fs, err := workfs.New(nil, nopBlobs{}, w)
	if err != nil {
		return "", nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, err
	}
	sctx, cancel := context.WithCancel(ctx)
	srv := fsproto.NewServer(fs, fs, delegation.New())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(sctx, ln)
	}()
	stop := func() {
		cancel()
		<-done
	}
	return ln.Addr().String(), stop, nil
}

// cmdServe runs a standalone disk-backed authority until SIGINT/SIGTERM (or
// SIGKILL, which is the torture test's whole point). The WAL on disk is the
// durability story: an acked write is fsync'd there before the response, and a
// restart on the same -wal path replays it.
func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:0", "fsproto listen address")
	walPath := fs.String("wal", "", "durable WAL path (required)")
	addrFile := fs.String("addrfile", "", "write the bound address to this file (for orchestration)")
	_ = fs.Parse(args)
	if *walPath == "" {
		log.Fatal("pfsbench serve: -wal is required")
	}
	ctx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSig()
	bound, stop, err := startAuthority(ctx, *addr, *walPath)
	if err != nil {
		log.Fatalf("pfsbench serve: %v", err)
	}
	defer stop()
	if *addrFile != "" {
		tmp := *addrFile + ".tmp"
		if err := os.WriteFile(tmp, []byte(bound), 0o644); err != nil {
			log.Fatalf("pfsbench serve: write addrfile: %v", err)
		}
		if err := os.Rename(tmp, *addrFile); err != nil {
			log.Fatalf("pfsbench serve: rename addrfile: %v", err)
		}
	}
	log.Printf("pfsbench authority serving on %s (wal=%s)", bound, *walPath)
	<-ctx.Done()
}
