package main

// The client-kill torture roles. `wbstorm` is the mount-client child: it
// drives the deterministic storm through the adaptive write-back engine and
// prints one ACK line per acknowledged step, so the SIGKILLing parent knows
// exactly what the mount promised. `wbrecover` is the restarted mount: it
// opens the same write-back store, lets recovery drain every parked stream,
// and exits 0 only when no job and no pending record remains.

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/steerlabs/portablefs/vcs/bench/internal/tortureplan"
	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

func dialTorture(addr, walDir string) (*clientcore.Volume, error) {
	return clientcore.Dial(context.Background(), clientcore.Options{
		Addr: addr, Pool: 4, Owner: "wbtorture",
		VolumeID: "vol-torture", Branch: "main",
		WALDir: walDir,
	})
}

// cmdWBStorm runs the storm and blocks after DONE until killed: every line
// is printed strictly AFTER the volume acknowledged the step.
func cmdWBStorm(args []string) {
	fs := flag.NewFlagSet("wbstorm", flag.ExitOnError)
	addr := fs.String("addr", "", "authority address (required)")
	walDir := fs.String("wal", "", "write-back store directory (required)")
	seed := fs.Int64("seed", 1, "plan seed")
	_ = fs.Parse(args)
	if *addr == "" || *walDir == "" {
		log.Fatal("pfsbench wbstorm: -addr and -wal are required")
	}
	vol, err := dialTorture(*addr, *walDir)
	if err != nil {
		log.Fatalf("pfsbench wbstorm: dial: %v", err)
	}
	ctx := context.Background()
	plan := tortureplan.New(*seed)

	must := func(what string, st int32) {
		if st != fsproto.OK {
			log.Fatalf("pfsbench wbstorm: %s: status %d", what, st)
		}
	}
	if _, st := vol.Mkdir(ctx, "torture", 0o755); st != fsproto.OK {
		log.Fatalf("pfsbench wbstorm: mkdir torture: status %d", st)
	}
	for _, d := range plan.Dirs {
		_, st := vol.Mkdir(ctx, d, 0o755)
		must("mkdir "+d, st)
		fmt.Printf("ACK dir %s\n", d)
	}
	if _, st := vol.Create(ctx, plan.AppendPath, 0o644); st != fsproto.OK {
		log.Fatalf("pfsbench wbstorm: create %s: status %d", plan.AppendPath, st)
	}
	fmt.Printf("ACK logcreate\n")
	appends := 0
	for i, f := range plan.Files {
		_, st := vol.Create(ctx, f.Path, 0o644)
		must("create "+f.Path, st)
		fmt.Printf("ACK create %d\n", i)
		n := clientcore.NewNodeState(clientcore.InoOf(f.Path), false)
		_, st = vol.Write(ctx, f.Path, n, 0, f.Content)
		must("write "+f.Path, st)
		fmt.Printf("ACK write %d\n", i)
		if i%plan.AppendEvery == plan.AppendEvery-1 {
			// A REAL O_APPEND write: under a delegation the engine resolves
			// EOF locally (the acknowledged offset rides the WAL record), so
			// recovery replay must reproduce the exact byte positions.
			ln := clientcore.NewNodeState(clientcore.InoOf(plan.AppendPath), false)
			_, st = vol.WriteAppend(ctx, plan.AppendPath, ln, 0, plan.AppendChunk)
			must("append", st)
			appends++
			fmt.Printf("ACK append %d\n", appends)
		}
	}
	fmt.Printf("DONE\n")
	select {} // hold acknowledged state until the parent kills us
}

// cmdWBRecover opens the same store, waits for recovery to drain every
// parked stream, and closes cleanly.
func cmdWBRecover(args []string) {
	fs := flag.NewFlagSet("wbrecover", flag.ExitOnError)
	addr := fs.String("addr", "", "authority address (required)")
	walDir := fs.String("wal", "", "write-back store directory (required)")
	timeout := fs.Duration("timeout", 90*time.Second, "recovery deadline")
	_ = fs.Parse(args)
	if *addr == "" || *walDir == "" {
		log.Fatal("pfsbench wbrecover: -addr and -wal are required")
	}
	vol, err := dialTorture(*addr, *walDir)
	if err != nil {
		log.Fatalf("pfsbench wbrecover: dial: %v", err)
	}
	deadline := time.Now().Add(*timeout)
	for {
		st := vol.WritebackStatus()
		if len(st.Jobs) == 0 && st.PendingRecords == 0 {
			break
		}
		if time.Now().After(deadline) {
			log.Fatalf("pfsbench wbrecover: recovery did not drain: %+v", st.Jobs)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := vol.Close(); err != nil {
		log.Fatalf("pfsbench wbrecover: close: %v", err)
	}
	fmt.Printf("RECOVERED\n")
}
