package checkpoint

import (
	"context"
	"strings"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
	"github.com/trendup-ai/portablefs/vcs/internal/pfj3"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

// managedLogFake satisfies pfj3.EntryLog through embedding; only the methods
// workfs.NewManagedWithCache touches during a replay-free cold start are
// implemented. Anything else panics — which is the point: a checkpoint pass
// against a managed store must be refused before it can touch the log.
type managedLogFake struct {
	pfj3.EntryLog
}

func (managedLogFake) RecordCodec() string                                   { return pfj3.RecordCodec }
func (managedLogFake) ControlCodec() string                                  { return pfj3.ControlCodec }
func (managedLogFake) Bounds() wal.LogBounds                                 { return wal.ProductionLogBounds() }
func (managedLogFake) ReplayEntriesInto(func(pfj3.JournalEntry) error) error { return nil }
func (managedLogFake) Watermark() uint64                                     { return 0 }
func (managedLogFake) CompactedThrough() uint64                              { return 0 }
func (managedLogFake) Epoch() uint64                                         { return 1 }

type noBlobs struct{}

func (noBlobs) Blob(context.Context, string) ([]byte, error) {
	return nil, context.Canceled
}

type refusingCommitter struct{ t *testing.T }

func (c refusingCommitter) PutBlob(context.Context, string, []byte) error {
	c.t.Fatal("checkpoint against a managed store uploaded a blob")
	return nil
}
func (c refusingCommitter) Version() string { return "portablefs-v1" }
func (c refusingCommitter) Commit(context.Context, string, []backend.ManifestEntry, int64, int64) (string, error) {
	c.t.Fatal("checkpoint against a managed store committed history")
	return "", nil
}

// TestRunRefusesManagedStore: managed serving never checkpoints. The managed
// path never starts the checkpoint loop (structural); this guard keeps the
// invariant even for a miswired caller, refusing before any snapshot, upload,
// or commit work happens.
func TestRunRefusesManagedStore(t *testing.T) {
	fs, err := workfs.NewManaged(nil, noBlobs{}, managedLogFake{})
	if err != nil {
		t.Fatalf("build managed fs: %v", err)
	}
	head, err := Run(context.Background(), fs, refusingCommitter{t: t})
	if err == nil || !strings.Contains(err.Error(), "managed journal store never checkpoints") {
		t.Fatalf("managed checkpoint must be refused by name, got head=%q err=%v", head, err)
	}
}
