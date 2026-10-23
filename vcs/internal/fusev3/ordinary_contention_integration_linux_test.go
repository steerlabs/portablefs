//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

func TestOrdinaryAtomicSaveWithLocalReader(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{})
	name := f.join(0, "document")
	mustWrite(t, name, bytes.Repeat([]byte("0"), 4096), 0600)
	stop := make(chan struct{})
	readers := make(chan error, 2)
	for mount := range 2 {
		go func() {
			for {
				select {
				case <-stop:
					readers <- nil
					return
				default:
				}
				data, err := os.ReadFile(f.join(mount, "document"))
				if err != nil {
					readers <- err
					return
				}
				if len(data) != 4096 || !bytes.Equal(data, bytes.Repeat(data[:1], 4096)) {
					readers <- fmt.Errorf("torn atomic save: %d bytes", len(data))
					return
				}
			}
		}()
	}
	defer func() {
		close(stop)
		for range 2 {
			select {
			case err := <-readers:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(10 * time.Second):
				t.Error("atomic-save reader did not stop")
			}
		}
	}()
	for round := range 500 {
		file, err := os.OpenFile(f.join(0, "temporary"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = file.Write(bytes.Repeat([]byte{byte(round%10 + '0')}, 4096))
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("save %d: %v, close %v", round, err, closeErr)
		}
		if err := os.Rename(f.join(0, "temporary"), name); err != nil {
			t.Fatalf("save %d: %v", round, err)
		}
	}
	for mount := range 2 {
		if _, err := os.ReadDir(f.mountPath(mount)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOrdinaryDelayedLookupCannotRestorePreRenameBinding(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{})
	mustWrite(t, f.join(0, "document"), []byte("original"), 0600)
	raw := f.mounts[0].raw
	raw.mu.Lock()
	raw.dropCachedNameLocked(nameKey{parent: raw.nodesByID[1].key.inode, name: "document"})
	raw.mu.Unlock()
	var armed atomic.Bool
	armed.Store(true)
	sampled, release := make(chan struct{}), make(chan struct{})
	f.transports[0].setAfterMutation(func(request *authoritypb.Request, response *authoritypb.Response, err error) {
		if request.GetLookup() != nil && string(request.GetLookup().GetName()) == "document" && response.GetLookup().GetItem() != nil && armed.CompareAndSwap(true, false) {
			close(sampled)
			<-release
		}
	})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	done := make(chan error, 1)
	go func() { _, err := os.Stat(f.join(0, "document")); done <- err }()
	select {
	case <-sampled:
	case <-time.After(3 * time.Second):
		t.Fatal("LOOKUP did not sample pre-rename binding")
	}
	mustWrite(t, f.join(0, "temporary"), []byte("replacement"), 0600)
	if err := os.Rename(f.join(0, "temporary"), f.join(0, "document")); err != nil {
		t.Fatal(err)
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for mount := range 2 {
		if got, err := os.ReadFile(f.join(mount, "document")); err != nil || string(got) != "replacement" {
			t.Fatalf("mount %d retained old binding: %q, %v", mount, got, err)
		}
	}
	mustWrite(t, f.join(0, "temporary"), []byte("third"), 0600)
	if err := os.Rename(f.join(0, "temporary"), f.join(0, "document")); err != nil {
		t.Fatalf("next save: %v", err)
	}
}

func TestOrdinaryThreeInPlaceWriters(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{beforeServe: func(f *integrationFixture) {
		f.counter.inner = &ordinaryResultHandler{Handler: f.counter.inner, observe: func(request *authoritypb.Request, response *authoritypb.Response) {
			if response.GetErrno() == int32(syscall.EIO) || response.GetUncertain() {
				t.Logf("authority %s errno=%d uncertain=%t failure=%s health=%v", requestKind(request), response.GetErrno(), response.GetUncertain(), response.GetFailure(), f.store.Health())
			}
		}}
	}})
	mustWrite(t, f.join(0, "overwrite"), []byte("initial"), 0600)
	start := make(chan struct{})
	done := make(chan error, 3)
	for writer := range 3 {
		go func() {
			<-start
			for round := range 200 {
				file, err := os.OpenFile(f.join(writer/2, "overwrite"), os.O_WRONLY|os.O_TRUNC, 0)
				if err != nil {
					done <- fmt.Errorf("writer %d open %d: %w", writer, round, err)
					return
				}
				_, err = file.Write(bytes.Repeat([]byte{byte('a' + writer)}, 4096))
				if err == nil {
					err = file.Sync()
				}
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					done <- fmt.Errorf("writer %d round %d: %v, close %v", writer, round, err, closeErr)
					return
				}
			}
			done <- nil
		}()
	}
	close(start)
	for range 3 {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%v; mount errors: %v / %v", err, f.mounts[0].fatalError(), f.mounts[1].fatalError())
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("in-place writers stalled: %s", f.sessionDiagnostics())
		}
	}
	for mount := range 2 {
		if _, err := os.ReadDir(f.mountPath(mount)); err != nil {
			t.Fatal(err)
		}
	}
}

type ordinaryResultHandler struct {
	authorityrpc.Handler
	observe func(*authoritypb.Request, *authoritypb.Response)
}

func TestOrdinaryPeerReplacementBeforeSourceDispatch(t *testing.T) {
	for _, operation := range []string{"rename", "unlink"} {
		t.Run(operation, func(t *testing.T) {
			f := newIntegrationFixture(t, integrationConfig{})
			mustWrite(t, f.join(0, "document"), []byte("old"), 0600)
			mustWrite(t, f.join(0, "local"), []byte("local"), 0600)
			mustWrite(t, f.join(1, "peer"), []byte("peer"), 0600)
			if _, err := os.Stat(f.join(0, "document")); err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var armed atomic.Bool
			armed.Store(true)
			f.transports[0].setBeforeMutation(func(r *authoritypb.Request) {
				if (r.GetRename() != nil || r.GetUnlink() != nil) && armed.CompareAndSwap(true, false) {
					close(entered)
					<-release
				}
			})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			done := make(chan error, 1)
			go func() {
				if operation == "rename" {
					done <- os.Rename(f.join(0, "local"), f.join(0, "document"))
				} else {
					done <- os.Remove(f.join(0, "document"))
				}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("source did not acquire its pre-binding")
			}
			if err := os.Rename(f.join(1, "peer"), f.join(1, "document")); err != nil {
				t.Fatal(err)
			}
			unblock()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("source %s after legitimate peer replacement: %v", operation, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("source did not finish")
			}
			for mount := range 2 {
				data, err := os.ReadFile(f.join(mount, "document"))
				if operation == "unlink" {
					if !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("mount %d removed binding: %q %v", mount, data, err)
					}
				} else if err != nil || string(data) != "local" {
					t.Fatalf("mount %d renamed binding: %q %v", mount, data, err)
				}
			}
		})
	}
}

func (h *ordinaryResultHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	response := h.Handler.Handle(ctx, request)
	h.observe(request, response)
	return response
}

func TestOrdinaryRecoverableUncertainRename(t *testing.T) {
	var inject atomic.Bool
	f := newIntegrationFixture(t, integrationConfig{beforeServe: func(f *integrationFixture) {
		f.counter.inner = &ordinaryResultHandler{Handler: f.counter.inner, observe: func(request *authoritypb.Request, response *authoritypb.Response) {
			if request.GetRename() != nil && response.GetErrno() == 0 && inject.CompareAndSwap(true, false) {
				// The source proof can expire after XFS application. The retained
				// replay result then reports uncertainty without ending the session.
				response.Body, response.PostState = nil, nil
				response.Errno, response.Uncertain = int32(syscall.EIO), true
				response.Failure = authoritypb.FailureClass_FAILURE_CLASS_COHERENCE
			}
		}}
	}})
	mustWrite(t, f.join(0, "old"), []byte("original"), 0600)
	mustWrite(t, f.join(0, "new"), []byte("replacement"), 0600)
	inject.Store(true)
	if err := os.Rename(f.join(0, "new"), f.join(0, "old")); !errors.Is(err, syscall.EREMOTEIO) {
		t.Fatalf("uncertain rename = %v, want EREMOTEIO", err)
	}
	if got, err := os.ReadFile(f.join(1, "old")); err != nil || string(got) != "replacement" {
		t.Fatalf("applied uncertain rename = %q, %v", got, err)
	}
	waitUntil(t, 5*time.Second, "cold subscription after uncertain result", func() bool { return f.mounts[0].subscription.stamp() != (subscriptionStamp{}) })
	if f.mounts[0].isRevoked() || f.clients[0].SessionEndCause() != nil {
		t.Fatalf("uncertainty killed mount/session: %v / %v", f.mounts[0].fatalError(), f.clients[0].SessionEndCause())
	}
	if got, err := os.ReadFile(f.join(0, "old")); err != nil || string(got) != "replacement" {
		t.Fatalf("inspect after uncertainty = %q, %v", got, err)
	}
	mustWrite(t, f.join(0, "after-uncertainty"), []byte("healthy"), 0600)
}

func TestOrdinaryItemPressurePreservesExistingAccess(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{MaxItemsPerSession: 64, MaxItems: 96, NameCacheCapacity: 64})
	for i := range 80 {
		file, err := os.OpenFile(f.join(0, fmt.Sprintf("item-%03d", i)), os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			if !errors.Is(err, syscall.ENFILE) {
				t.Fatal(err)
			}
			break
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		_, _ = os.Stat(f.join(1, fmt.Sprintf("item-%03d", i)))
	}
	for mount := range 2 {
		if _, err := os.ReadDir(f.mountPath(mount)); err != nil {
			t.Fatalf("mount %d lost existing directory access at item saturation: %v", mount, err)
		}
	}
}

func TestOrdinaryQuotaExhaustionIsLocal(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{})
	// An occupied block keeps exhaustion off the flush wave's MiB boundary.
	mustWrite(t, f.join(1, "occupied"), bytes.Repeat([]byte{0x33}, 4096), 0600)
	file := mustOpenFile(t, f.join(0, "fill"), os.O_CREATE|os.O_WRONLY, 0600)
	defer file.Close()
	block := bytes.Repeat([]byte{0x5a}, 1<<20)
	var fillErr error
	for range 2048 {
		if _, fillErr = file.Write(block); fillErr != nil {
			break
		}
	}
	if fillErr == nil {
		fillErr = file.Sync()
	}
	if !errors.Is(fillErr, syscall.EDQUOT) && !errors.Is(fillErr, syscall.ENOSPC) {
		t.Fatalf("quota writer error = %v, want EDQUOT or ENOSPC", fillErr)
	}
	if err := f.store.Health(); err != nil {
		t.Fatalf("quota fenced authority: %v", err)
	}
	if err := file.Truncate(0); err != nil {
		t.Fatalf("free quota through existing descriptor: %v", err)
	}
	if err := file.Sync(); err != nil {
		t.Fatalf("sync after freeing quota: %v", err)
	}
	for mount := range 2 {
		if _, err := os.ReadDir(f.mountPath(mount)); err != nil {
			t.Fatalf("quota killed mount %d: %v", mount, err)
		}
	}
	if err := file.Close(); err != nil && !errors.Is(err, syscall.EDQUOT) && !errors.Is(err, syscall.ENOSPC) {
		t.Fatal(err)
	}
	if err := os.Remove(f.join(1, "fill")); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, f.join(1, "after-quota"), []byte("recovered"), 0600)
}
