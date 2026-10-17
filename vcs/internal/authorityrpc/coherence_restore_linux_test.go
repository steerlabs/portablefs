//go:build linux

package authorityrpc

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/restoremode"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

func TestCoherenceActiveRestoreRefusesKernelDataCache(t *testing.T) {
	// Active() needs no hydrated entry: the health contract covers the volume,
	// including newly created and already hydrated files.
	h := &VolumeHandler{Restore: &restoremode.Mode{}}
	for _, writeIntent := range []bool{false, true} {
		admitted, err := h.coherenceAdmitOpen(volumeserver.SessionID{}, xfsstore.Capability{}, [16]byte{1}, true, writeIntent)
		if err != nil || admitted {
			t.Fatalf("restore cache admission(write=%v) = %v, %v", writeIntent, admitted, err)
		}
	}
}

// A zero truncate needs no archived bytes, so these failures occur strictly
// after apply rather than in the restore recall/preparation path.
type restoreTruncateSyncFailure struct {
	restoremode.Store
	calls   int
	syncErr error
}

func (s *restoreTruncateSyncFailure) Fdatasync(uint32) error { s.calls++; return s.syncErr }

type restoreTruncateTestStore struct {
	*partialSetAttrStore
	closes int
}

func (s *restoreTruncateTestStore) Fence(err error) {
	if !s.fenced.Load() {
		s.fskitDurabilityTestStore.Fence(err)
	}
}

func (s *restoreTruncateTestStore) OpenFile(xfsstore.Capability, xfsstore.OpenFlags) (xfsstore.Capability, error) {
	s.applies++
	return xfsstore.Capability{0x42}, nil
}
func (s *restoreTruncateTestStore) CloseOpen(xfsstore.Capability) error { s.closes++; return nil }
func (s *restoreTruncateTestStore) Getattr(item xfsstore.Capability) (xfsstore.Attr, error) {
	if s.fenced.Load() {
		return xfsstore.Attr{}, xfsstore.ErrFenced
	}
	if item[0] == 0x71 {
		return xfsstore.Attr{Kind: xfsstore.KindDirectory, Ino: 0x71, Mode: 0700, Nlink: 2, DeviceMinor: 1}, nil
	}
	attr := s.post
	if s.applies == 0 {
		attr.Size = 8
	}
	return attr, nil
}

func (s *restoreTruncateTestStore) Lookup(xfsstore.Capability, string) (xfsstore.Capability, xfsstore.Attr, error) {
	item := xfsstore.Capability{0x70}
	attr, err := s.Getattr(item)
	return item, attr, err
}

func (s *restoreTruncateTestStore) Create(parent xfsstore.Capability, name string, _ fs.FileMode, _ bool) (xfsstore.Capability, xfsstore.Attr, error) {
	return s.Lookup(parent, name)
}

func TestRestoreTruncatePostApplyFailureFencesStorage(t *testing.T) {
	for _, operation := range []string{"SETATTR", "OPEN", "CREATE existing"} {
		for _, failure := range []struct {
			name         string
			err          error
			laterSyncErr error
		}{
			{"ENOSPC", syscall.ENOSPC, nil}, {"EDQUOT", syscall.EDQUOT, nil}, {"map", nil, nil},
			{"ENOSPC then failed barrier", syscall.ENOSPC, syscall.EDQUOT},
		} {
			t.Run(operation+"/"+failure.name, func(t *testing.T) {
				h, cred, store, _ := newDirectFskitHarness(t)
				store.syncErr = failure.laterSyncErr
				backend := &restoreTruncateTestStore{partialSetAttrStore: &partialSetAttrStore{fskitDurabilityTestStore: store, post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x70, Mode: 0600, DeviceMinor: 1}}}
				h.Store = backend
				h.OnStorageFailure = func(error) {}
				restoreStore := &restoreTruncateSyncFailure{syncErr: failure.err}
				h.Restore = newRestoreTruncateMode(t, restoreStore, failure.name == "map", failure.name == "map")
				item := xfsstore.Capability{0x70}
				req := &authoritypb.Request{RequestId: 1, Epoch: cred.Epoch[:], Session: &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]}}
				switch operation {
				case "SETATTR":
					req.Body = &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: item[:], Size: proto.Int64(0)}}
				case "OPEN":
					req.Body = &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: item[:], Flags: &authoritypb.OpenFlags{Write: true, Truncate: true}}}
				case "CREATE existing":
					parent := xfsstore.Capability{0x71}
					if err := h.trackItem(cred.ID, parent, false); err != nil {
						t.Fatal(err)
					}
					req.Body = &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: parent[:], Name: []byte("existing"), Mode: 0600, Flags: &authoritypb.OpenFlags{Write: true, Truncate: true}}}
				}
				stampMutation(t, req, 0, 1)
				stampResolvedFskitPublication(t, h, cred.ID, req)
				ctx := context.WithValue(t.Context(), peerIdentityKey{}, [32]byte{1})
				reply := h.Handle(ctx, req)
				if reply.GetErrno() != int32(syscall.EIO) || !reply.GetUncertain() || reply.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_STORAGE || reply.GetMutation() == nil || backend.applies != 1 || restoreStore.calls != 1 {
					t.Fatalf("restore truncate = %v; apply/restore-sync = %d/%d", reply, backend.applies, restoreStore.calls)
				}
				objects := reply.GetPostState().GetObjects()
				wantObjects := 1
				if operation == "CREATE existing" {
					wantObjects = 2
				}
				if len(objects) != wantObjects || !proto.Equal(objects[0].GetAttr(), attrProto(backend.post)) || !validMutationPostStateRoles(req, reply.GetPostState()) {
					t.Fatalf("lost exact truncate post-state: %v", reply)
				}
				cause := store.fenceCause.Load()
				if !store.fenced.Load() || cause == nil || !errors.Is(cause, xfsstore.ErrOutcomeUncertain) {
					t.Fatalf("missing typed storage fence: %v", cause)
				}
				if failure.err != nil && !errors.Is(cause.Cause, failure.err) || failure.name == "map" && !strings.Contains(cause.Cause.Error(), "hydration map record bound reached") {
					t.Fatalf("lost diagnostic cause: %v", cause)
				}
				// A later FSKit barrier must preserve the first restore failure and
				// exact post-state whether its syscall succeeds or fails again.
				if store.syncs.Load() != 1 || store.fenceCause.Load() != cause {
					t.Fatalf("second sync changed failure: syncs=%d cause=%v", store.syncs.Load(), store.fenceCause.Load())
				}
				if operation != "SETATTR" && (reply.GetOpen() != nil || reply.GetCreate() != nil || backend.closes != 1) {
					t.Fatalf("failed truncate retained an open handle: %v closes=%d", reply, backend.closes)
				}
				req.RequestId++
				stampMutation(t, req, 1, 1)
				next := h.Handle(ctx, req)
				if next.GetErrno() == 0 || next.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_STORAGE || backend.applies != 1 || restoreStore.calls != 1 || store.syncs.Load() != 1 {
					t.Fatalf("mutation after storage fence = %v; applies=%d", next, backend.applies)
				}
			})
		}
	}
}

func newRestoreTruncateMode(t *testing.T, store *restoreTruncateSyncFailure, mapFailure, initialize bool) *restoremode.Mode {
	t.Helper()
	root, err := os.MkdirTemp("", "pfs-restore-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	volume := "12345678-1234-1234-1234-123456789abc"
	attempt := "abcdefab-cdef-cdef-cdef-abcdefabcdef"
	identity := [16]byte{0x70}
	bindings := append([]byte("PFSRBND1"), 1, 0, 0, 0, 1, 0, 0, 0)
	bindings = binary.LittleEndian.AppendUint32(bindings, 0)
	bindings = append(bindings, identity[:]...)
	seal := sha256.Sum256(bindings)
	bindings = append(bindings, seal[:]...)
	if err := os.WriteFile(filepath.Join(root, restoremode.BindingsFilename), bindings, 0600); err != nil {
		t.Fatal(err)
	}
	ready := fmt.Sprintf(`{"version":1,"volume_id":%q,"sealed_epoch":7,"attempt":%q,"entries":1,"written_unix":1}`, volume, attempt)
	if err := os.WriteFile(filepath.Join(root, restoremode.ReadyFilename), []byte(ready), 0600); err != nil {
		t.Fatal(err)
	}
	if mapFailure {
		// Fill the two-record bound with replayable duplicate chunk records, leaving
		// the user-modified transition unrecorded. Truncate's real post-apply map
		// update must fail even though Fdatasync succeeds. No production hook is used.
		raw := []byte("PFS-RESTORE-MAP\x00")
		raw = binary.LittleEndian.AppendUint32(raw, 1)
		raw = binary.LittleEndian.AppendUint32(raw, 4096)
		raw = append(raw, seal[:]...)
		record := make([]byte, 16)
		record[0] = 1
		binary.LittleEndian.PutUint32(record[12:], crc32.ChecksumIEEE(record[:12]))
		raw = append(raw, record...)
		raw = append(raw, record...)
		if err := os.WriteFile(filepath.Join(root, restoremode.MapFilename), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if initialize {
		// Keep this empty-drain fixture RESTORING: convergence cannot replace a
		// directory with its marker file, and the failed marker does not affect map IO.
		if err := os.Mkdir(filepath.Join(root, restoremode.ConvergedFilename), 0700); err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("unix", filepath.Join(root, restoremode.HydratorSocket))
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			var request [5]byte
			if _, err = io.ReadFull(conn, request[:]); err != nil {
				done <- err
				return
			}
			if binary.LittleEndian.Uint32(request[:4]) != 1 || request[4] != restoremode.FrameInfo {
				done <- fmt.Errorf("unexpected hydrator request: %x", request)
				return
			}
			payload, err := restoremode.MarshalInfoPage(restoremode.InfoPage{FormatVersion: 1, VolumeID: volume, SealedEpoch: 7, Attempt: attempt, ChunkSize: 4096, EntryCount: 1, PageSize: 8192})
			if err != nil {
				done <- err
				return
			}
			frame := binary.LittleEndian.AppendUint32(nil, uint32(len(payload)+1))
			frame = append(frame, restoremode.FrameInfoOK)
			frame = append(frame, payload...)
			_, err = conn.Write(frame)
			done <- err
		}()
		t.Cleanup(func() { _ = listener.Close() })
		defer func() {
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}()
	}
	mode, err := restoremode.Open(t.Context(), restoremode.Config{StateRoot: root, VolumeID: volume, Store: store, MaxStoredChunks: 1, ProgressInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mode.Close() })
	return mode
}
