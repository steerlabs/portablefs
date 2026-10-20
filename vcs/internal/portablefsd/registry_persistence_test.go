package portablefsd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
)

// Model removal errors before and after unlink. An absent name after an error
// must still leave the in-memory registration retryable.
func injectRegistryRemovalFailure(t *testing.T, r *registry, afterUnlink bool) error {
	t.Helper()
	failure := syscall.EACCES
	if afterUnlink {
		failure = syscall.EIO
	}
	r.writeAttaches = func(dir string, entries []persistedAttachEntry) error {
		if len(entries) != 0 {
			return errors.New("removal fault reached a nonempty registry write")
		}
		if afterUnlink {
			if err := writePersistedAttaches(dir, entries); err != nil {
				return err
			}
		}
		return fmt.Errorf("injected durable removal failure: %w", failure)
	}
	return failure
}

func TestP4FirstAttachWaitsForPersistence(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "durable", true: "write-failure"}[fail], func(t *testing.T) {
			pki := newV3TestPKI(t)
			h := newV3TestAuthority()
			address := startV3TestAuthority(t, h, pki.serverTLS)
			dir := privateTestDir(t)
			r := newRegistry(dir)
			req := v3TestEnsureRequest(address, pki, "/Volumes/FirstPersist")
			req.AttachRef = testFSKitAttachRef
			entered, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			r.writeAttaches = func(dir string, entries []persistedAttachEntry) error {
				close(entered)
				<-release
				if fail {
					return syscall.EIO
				}
				return writePersistedAttaches(dir, entries)
			}
			type result struct {
				a       *attach
				created bool
				err     error
			}
			done := make(chan result, 1)
			go func() {
				a, created, err := r.ensure(context.Background(), req)
				done <- result{a, created, err}
			}()
			<-entered
			if _, err := os.Lstat(attachRegistryPath(dir)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("first attach already persisted before writer: %v", err)
			}
			select {
			case got := <-done:
				t.Fatalf("attach returned before persistence verdict: %+v", got)
			default:
			}
			unblock()
			got := <-done
			if fail {
				if !errors.Is(got.err, syscall.EIO) || got.created || got.a != nil || r.get(req.AttachRef) != nil {
					t.Fatalf("failed persistence exposed attach: %+v", got)
				}
				if _, err := os.Lstat(attachRegistryPath(dir)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed first write left a registry: %v", err)
				}
				return
			}
			if got.err != nil || !got.created || got.a == nil {
				t.Fatalf("durable first attach: %+v", got)
			}
			t.Cleanup(func() { got.a.fenceV3(errors.New("test cleanup")) })
			entries, err := loadPersistedAttaches(dir)
			if err != nil || len(entries) != 1 || entries[0].Ref != req.AttachRef {
				t.Fatalf("first attach success without strict nonempty registry: %+v err=%v", entries, err)
			}
		})
	}
}

func TestP4StopIfIdleRequiresDurableEmptyRegistry(t *testing.T) {
	for _, phase := range []string{"unlink", "directory-sync", "unsafe-entry", "success"} {
		t.Run(phase, func(t *testing.T) {
			dir := privateTestDir(t)
			r := newRegistry(dir)
			path := attachRegistryPath(dir)
			if phase == "unsafe-entry" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				writeFSKitDetachFixture(t, dir)
			}
			if phase == "unlink" || phase == "directory-sync" {
				injectRegistryRemovalFailure(t, r, phase == "directory-sync")
			}
			s := NewServer(Config{})
			s.registry = r
			stop := func() *httptest.ResponseRecorder {
				reply := httptest.NewRecorder()
				s.handleStopIfIdle(reply, httptest.NewRequest(http.MethodPost, daemonctl.LifecycleStopIfIdlePath, nil))
				return reply
			}
			if phase != "success" {
				reply := stop()
				if reply.Code != http.StatusInternalServerError || r.quiescing {
					t.Fatalf("persistence failure allowed quiescence: status=%d quiescing=%t body=%s", reply.Code, r.quiescing, reply.Body.String())
				}
				select {
				case <-s.stopCh:
					t.Fatal("persistence failure stopped the daemon")
				default:
				}
				if phase == "directory-sync" {
					if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("directory-sync failure must exercise already-absent retry: %v", err)
					}
				}
				if phase == "unsafe-entry" {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				r.writeAttaches = writePersistedAttaches
			}
			reply := stop()
			if err := daemonctl.ValidateStopIfIdleResponse(reply.Code, reply.Body.Bytes()); err != nil || !r.quiescing {
				t.Fatalf("durable idle stop: %v quiescing=%t", err, r.quiescing)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("successful idle stop left a registry entry: %v", err)
			}
		})
	}
}
