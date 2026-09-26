//go:build linux

package fusev3

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

type pausedDataWithdrawalNotifier struct {
	kernelNotifier
	path        string
	once        sync.Once
	invalidated chan struct{}
	release     chan struct{}
}

func (n *pausedDataWithdrawalNotifier) InodeNotify(inode uint64, off, length int64) fuse.Status {
	status := n.kernelNotifier.InodeNotify(inode, off, length)
	if status.Ok() && off >= 0 {
		// Reservation can withdraw pages before storage apply. Pin the later
		// post-truncate withdrawal that precedes publication of the OPEN grant.
		if info, err := os.Stat(n.path); err == nil && info.Size() == 0 {
			n.once.Do(func() { close(n.invalidated); <-n.release })
		}
	}
	return status
}

func TestConcurrentTruncatingOpensDoNotBlockReservedGrantWithdrawal(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	mustWrite(t, f.join(0, "truncate"), []byte("cached peer data"), 0600)
	f.waitForDelegationReleases(t)
	reader := mustOpenFile(t, f.join(1, "truncate"), os.O_RDONLY, 0)
	defer reader.Close()
	readExactlyAt(t, reader, 0, 16, "prime peer pages")
	incarnations := make([]uint64, 2)
	losses := make([]uint64, 2)
	for i, mount := range f.mounts {
		incarnations[i], _, _, _ = mount.subscription.currentIncarnation()
		losses[i] = mount.delegations.LossSequence()
	}
	original := f.mounts[1].notifier()
	notify := &pausedDataWithdrawalNotifier{kernelNotifier: original, path: filepath.Join(f.volumeRoot, "truncate"), invalidated: make(chan struct{}), release: make(chan struct{})}
	f.mounts[1].setNotifier(notify)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(notify.release) }) }
	defer func() { release(); f.mounts[1].setNotifier(original) }()
	type opened struct {
		file *os.File
		err  error
	}
	results := make(chan opened, 2)
	start := func() {
		go func() {
			file, err := os.OpenFile(f.join(0, "truncate"), os.O_RDWR|os.O_TRUNC, 0600)
			results <- opened{file, err}
		}()
	}
	pending := 1
	defer func() {
		release()
		for pending > 0 {
			select {
			case result := <-results:
				pending--
				if result.file != nil {
					result.file.Close()
				}
			case <-time.After(2 * time.Second):
				t.Error("truncating OPEN remained blocked after withdrawal release")
				return
			}
		}
	}()
	start()
	select {
	case <-notify.invalidated:
	case <-time.After(2 * time.Second):
		t.Fatal("first OPEN did not withdraw peer pages")
	}
	start()
	pending++
	readDone := make(chan error, 1)
	go func() { var b [1]byte; _, err := reader.ReadAt(b[:], 0); readDone <- err }()
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("read during reserved grant = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer read waited for an unreported delegation while OPEN waited for withdrawal")
	}
	select {
	case result := <-results:
		pending--
		if result.file != nil {
			result.file.Close()
		}
		t.Fatalf("OPEN completed before peer withdrawal returned: %v", result.err)
	default:
	}
	release()
	for pending > 0 {
		select {
		case result := <-results:
			pending--
			if result.err != nil {
				t.Fatal(result.err)
			}
			if err := result.file.Close(); err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent truncating OPEN did not finish after withdrawal")
		}
	}
	for i, mount := range f.mounts {
		incarnation, _, _, active := mount.subscription.currentIncarnation()
		if mount.delegations.LossSequence() != losses[i] {
			t.Fatalf("mount %d lost buffered state during truncating opens", i)
		}
		if !active || incarnation != incarnations[i] {
			t.Fatalf("mount %d escaped the cycle by expiring its subscription", i)
		}
	}
	requireSize(t, f.join(1, "truncate"), 0, "both truncating opens finished")
}
