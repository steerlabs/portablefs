//go:build linux

package fusev3

import (
	"bytes"
	"errors"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

type failingOwnCacheNotifier struct {
	kernelNotifier
	persistent bool
	attempts   atomic.Uint32
}

func (n *failingOwnCacheNotifier) InodeNotify(inode uint64, off, length int64) fuse.Status {
	if off >= 0 {
		attempt := n.attempts.Add(1)
		if n.persistent || attempt == 1 {
			return fuse.EIO
		}
	}
	return n.kernelNotifier.InodeNotify(inode, off, length)
}

func TestSameMountWritesInvalidateLiveAndReopenedCachedReaders(t *testing.T) {
	for _, closed := range []bool{false, true} {
		name := "live"
		if closed {
			name = "closed-before-write"
		}
		t.Run(name, func(t *testing.T) {
			f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
			old, next := bytes.Repeat([]byte("a"), 4096), bytes.Repeat([]byte("b"), 4096)
			mustWrite(t, f.join(0, "cached"), old, 0600)
			f.waitForDelegationReleases(t)
			reader := mustOpenFile(t, f.join(0, "cached"), os.O_RDONLY, 0)
			defer reader.Close()
			if got := readExactlyAt(t, reader, 0, len(old), "prime cached pages"); !bytes.Equal(got, old) {
				t.Fatal("initial data")
			}
			if closed {
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
			}
			writer := mustOpenFile(t, f.join(0, "cached"), os.O_WRONLY, 0)
			if _, err := writer.WriteAt(next, 0); err != nil {
				t.Fatal(err)
			}
			if closed {
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				// Release is an implicit local stream advance. Reopening cannot rely on
				// receiving a CONTROL invalidation for the writer's own release.
				f.waitForDelegationReleases(t)
				reader = mustOpenFile(t, f.join(0, "cached"), os.O_RDONLY, 0)
				defer reader.Close()
			}
			if got := readExactlyAt(t, reader, 0, len(next), "read after successful local write"); !bytes.Equal(got, next) {
				t.Fatal("stale cached folio after write")
			}
			if !closed {
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if f.mounts[0].delegations.LossSequence() != 0 {
				t.Fatal("write escaped invalidation by losing delegation")
			}
		})
	}
}

func TestReopenNotificationFailureIsInodeLocal(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "transient"
		if persistent {
			name = "persistent"
		}
		t.Run("open/"+name, func(t *testing.T) {
			f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
			path := f.join(0, "cached")
			old, next := bytes.Repeat([]byte("a"), 4096), bytes.Repeat([]byte("b"), 4096)
			mustWrite(t, path, old, 0o600)
			f.waitForDelegationReleases(t)
			reader := mustOpenFile(t, path, os.O_RDONLY, 0)
			if got := readExactlyAt(t, reader, 0, len(old), "prime cached pages"); !bytes.Equal(got, old) {
				t.Fatal("initial data")
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			writer := mustOpenFile(t, path, os.O_WRONLY, 0)
			if _, err := writer.WriteAt(next, 0); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			f.waitForDelegationReleases(t)

			mount := f.mounts[0]
			loss := mount.delegations.LossSequence()
			mount.subscription.config.repairLead = 100 * time.Millisecond
			mount.subscription.config.retryDelay = 5 * time.Millisecond
			original := mount.notifier()
			failing := &failingOwnCacheNotifier{kernelNotifier: original, persistent: persistent}
			mount.setNotifier(failing)
			defer mount.setNotifier(original)

			reopened, openErr := os.Open(path)
			if persistent {
				if !errors.Is(openErr, syscall.EIO) || reopened != nil || failing.attempts.Load() < 2 {
					t.Fatalf("persistent reopen = file %v err %v attempts %d", reopened, openErr, failing.attempts.Load())
				}
			} else {
				if openErr != nil || reopened == nil || failing.attempts.Load() != 2 {
					t.Fatalf("transient reopen = file %v err %v attempts %d", reopened, openErr, failing.attempts.Load())
				}
				defer reopened.Close()
				if got := readExactlyAt(t, reopened, 0, len(next), "reopen after retry"); !bytes.Equal(got, next) {
					t.Fatal("retry left stale cached data")
				}
			}
			if mount.isRevoked() {
				t.Fatalf("reopen failure revoked mount: %v", mount.fatalError())
			}
			if got := mount.delegations.LossSequence(); got != loss {
				t.Fatalf("reopen discarded no writeback but advanced loss %d -> %d", loss, got)
			}
			mustWrite(t, f.join(0, "unrelated"), []byte("still-live"), 0o600)
			requireContent(t, f.join(0, "unrelated"), []byte("still-live"), "unrelated file after reopen failure")
		})
	}

	t.Run("tmpfile-direct-io", func(t *testing.T) {
		f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
		mount := f.mounts[0]
		original := mount.notifier()
		failing := &failingOwnCacheNotifier{kernelNotifier: original, persistent: true}
		mount.setNotifier(failing)
		defer mount.setNotifier(original)
		fd, err := unix.Open(f.mountPath(0), unix.O_TMPFILE|unix.O_RDWR|unix.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Close(fd); err != nil {
			t.Fatal(err)
		}
		if failing.attempts.Load() != 0 || mount.isRevoked() {
			t.Fatalf("TMPFILE own-cache attempts=%d revoked=%t", failing.attempts.Load(), mount.isRevoked())
		}
	})
}
