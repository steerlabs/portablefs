//go:build linux

package fusev3

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// preNotifyGate stops an unlicensed READ after its reply has reached the
// kernel but before the follow-up inode notification. That is the interval in
// which a foreground writer must not report visibility completion.
type preNotifyGate struct {
	kernelNotifier
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (n *preNotifyGate) InodeNotify(inode uint64, off, length int64) fuse.Status {
	if off >= 0 {
		n.once.Do(func() {
			close(n.entered)
			<-n.release
		})
	}
	return n.kernelNotifier.InodeNotify(inode, off, length)
}

func TestForegroundWritethroughWaitsForPeerVisibility(t *testing.T) {
	tests := []struct {
		name       string
		writerFlag int
		before     []byte
		after      []byte
		mutate     func(*os.File) error
	}{
		{
			name:       "ordinary-write",
			writerFlag: os.O_WRONLY,
			before:     []byte("first-generation"),
			after:      []byte("secondgeneration"),
			mutate: func(file *os.File) error {
				_, err := file.WriteAt([]byte("secondgeneration"), 0)
				return err
			},
		},
		{
			name:       "synchronous-write",
			writerFlag: os.O_WRONLY | syscall.O_SYNC,
			before:     []byte("first-generation"),
			after:      []byte("secondgeneration"),
			mutate: func(file *os.File) error {
				_, err := file.WriteAt([]byte("secondgeneration"), 0)
				return err
			},
		},
		{
			name:       "delegated-metadata",
			writerFlag: os.O_WRONLY,
			before:     []byte("secondgeneration"),
			after:      []byte("second"),
			mutate: func(file *os.File) error {
				return file.Truncate(int64(len("second")))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
			nameA, nameB := f.join(0, "visibility"), f.join(1, "visibility")
			mustWrite(t, nameA, test.before, 0o600)
			f.waitForDelegationReleases(t)

			// The reader exists before the grant, so OPEN makes it a cache-capable
			// holder. The later writer therefore receives WRITETHROUGH.
			reader := mustOpenFile(t, nameB, os.O_RDONLY, 0)
			defer reader.Close()
			writer := mustOpenFile(t, nameA, test.writerFlag, 0)
			defer writer.Close()

			original := f.mounts[1].notifier()
			gate := &preNotifyGate{kernelNotifier: original, entered: make(chan struct{}), release: make(chan struct{})}
			f.mounts[1].setNotifier(gate)
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(gate.release) }) }
			defer func() {
				release()
				f.mounts[1].setNotifier(original)
			}()

			type readResult struct {
				data []byte
				err  error
			}
			firstRead := make(chan readResult, 1)
			go func() {
				data := make([]byte, len(test.before))
				n, err := reader.ReadAt(data, 0)
				firstRead <- readResult{data: data[:n], err: err}
			}()
			select {
			case <-gate.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("reader reply did not reach the pre-notification gate")
			}
			select {
			case got := <-firstRead:
				if got.err != nil || !bytes.Equal(got.data, test.before) {
					t.Fatalf("first reader access = %q, %v", got.data, got.err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("physical READ publication did not reach the reader")
			}

			written := make(chan error, 1)
			go func() { written <- test.mutate(writer) }()
			select {
			case err := <-written:
				t.Fatalf("foreground mutation completed before peer notification: %v", err)
			case <-time.After(100 * time.Millisecond):
			}

			release()
			select {
			case err := <-written:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("foreground mutation did not complete after peer notification")
			}

			got := make([]byte, len(test.after))
			n, err := reader.ReadAt(got, 0)
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			if n != len(test.after) || !bytes.Equal(got[:n], test.after) {
				t.Fatalf("second reader access = %q, want %q", got[:n], test.after)
			}
		})
	}
}
