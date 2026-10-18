//go:build linux

package xfsstore

import (
	"errors"
	"io/fs"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSetAttrPrevalidatesCompoundRequests(t *testing.T) {
	for _, test := range []struct {
		name     string
		change   func(*SetAttrSpec, *Volume)
		readOnly bool
		want     error
	}{
		{"uid", func(s *SetAttrSpec, v *Volume) { id := v.ownerUID + 1; s.UID = &id }, false, syscall.EPERM},
		{"gid", func(s *SetAttrSpec, v *Volume) { id := v.ownerGID + 1; s.GID = &id }, false, syscall.EPERM},
		{"negative size", func(s *SetAttrSpec, _ *Volume) { n := int64(-1); s.Size = &n }, false, fs.ErrInvalid},
		{"read-only handle", func(s *SetAttrSpec, _ *Volume) { n := int64(0); s.Size = &n }, true, fs.ErrInvalid},
		{"atime conflict", func(s *SetAttrSpec, _ *Volume) { n := int64(1); s.ATimeNS = &n; s.ATimeNow = true }, false, fs.ErrInvalid},
		{"mtime conflict", func(s *SetAttrSpec, _ *Volume) { n := int64(1); s.MTimeNS = &n; s.MTimeNow = true }, false, fs.ErrInvalid},
		{"invalid mode", func(s *SetAttrSpec, _ *Volume) { mode := fs.ModeSetuid | 0600; s.Mode = &mode }, false, syscall.EPERM},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := openTestVolume(t)
			root, _ := v.Root()
			item, _, err := v.Create(root, "prevalidate", 0600, true)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: !test.readOnly})
			if err != nil {
				t.Fatal(err)
			}
			mode := fs.FileMode(0644)
			spec := SetAttrSpec{Mode: &mode}
			test.change(&spec, v)
			if _, err := v.SetAttr(item, handle, spec); !errors.Is(err, test.want) || errors.Is(err, ErrOutcomeUncertain) {
				t.Fatalf("SetAttr = %v, want definite %v", err, test.want)
			}
			post, err := v.Getattr(item)
			if err != nil || post.Mode.Perm() != 0600 {
				t.Fatalf("partially applied validation refusal: %+v, %v", post, err)
			}
		})
	}
}

func TestSetAttrSymlinkConstraintsPrecedeOwnershipChange(t *testing.T) {
	for _, field := range []string{"mode", "size"} {
		t.Run(field, func(t *testing.T) {
			v := openTestVolume(t)
			root, _ := v.Root()
			item, _, err := v.Symlink(root, "link", "missing")
			if err != nil {
				t.Fatal(err)
			}
			uid := v.ownerUID
			spec := SetAttrSpec{UID: &uid}
			if field == "mode" {
				mode := fs.FileMode(0600)
				spec.Mode = &mode
			} else {
				size := int64(0)
				spec.Size = &size
			}
			if _, err := v.SetAttr(item, Capability{}, spec); !errors.Is(err, map[string]error{"mode": syscall.EOPNOTSUPP, "size": syscall.EINVAL}[field]) || errors.Is(err, ErrOutcomeUncertain) {
				t.Fatalf("SetAttr = %v", err)
			}
		})
	}
}

func TestSetAttrPostStatFailureRemainsUncertain(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "partial", 0600, true)
	if err != nil {
		t.Fatal(err)
	}
	v.postStat = func(int) (Attr, error) { return Attr{}, syscall.EIO }
	mode := fs.FileMode(0644)
	if _, err := v.SetAttr(item, Capability{}, SetAttrSpec{Mode: &mode}); !errors.Is(err, ErrOutcomeUncertain) {
		t.Fatalf("post-apply stat failure = %v", err)
	}
	post, err := v.Getattr(item)
	if err != nil || post.Mode.Perm() != 0644 {
		t.Fatalf("applied mode = %+v, %v", post, err)
	}
}

func TestSetAttrDirectoryTruncateIsDefiniteRefusal(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Mkdir(root, "directory", 0700)
	if err != nil {
		t.Fatal(err)
	}
	mode := fs.FileMode(0755)
	size := int64(0)
	if _, err := v.SetAttr(item, Capability{}, SetAttrSpec{Mode: &mode, Size: &size}); !errors.Is(err, syscall.EISDIR) || errors.Is(err, ErrOutcomeUncertain) {
		t.Fatalf("directory SetAttr = %v", err)
	}
	post, err := v.Getattr(item)
	if err != nil || post.Mode.Perm() != 0700 {
		t.Fatalf("refusal changed mode: %+v, %v", post, err)
	}
}

func TestDurabilityTargetPinsAndFences(t *testing.T) {
	for _, kind := range []string{"handle", "object", "syncfs"} {
		for _, failure := range []syscall.Errno{0, syscall.EIO, syscall.ENOSPC, syscall.EDQUOT} {
			t.Run(kind+"/"+failure.Error(), func(t *testing.T) {
				v := openTestVolume(t)
				root, _ := v.Root()
				item, _, err := v.Create(root, "durable", 0600, true)
				if err != nil {
					t.Fatal(err)
				}
				handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				syscallSync := func(fd int) error {
					calls++
					if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
						t.Error(err)
					}
					if failure != 0 {
						return failure
					}
					return nil
				}
				v.fsync = syscallSync
				v.syncfs = syscallSync
				v.fdatasync = func(int) error { t.Error("fdatasync used"); return nil }
				var sync func() error
				if kind == "syncfs" {
					sync = v.SyncFS
				} else {
					var target SyncTarget
					if kind == "handle" {
						target, err = v.PinSyncHandle(handle)
					} else {
						target, err = v.PinSyncObject(item)
					}
					if err != nil {
						t.Fatal(err)
					}
					defer target.Close()
					sync = target.Sync
					if err := v.CloseOpen(handle); err != nil {
						t.Fatal(err)
					}
					if err := v.Forget(item); err != nil {
						t.Fatal(err)
					}
				}
				err = sync()
				if failure == 0 {
					if err != nil {
						t.Fatal(err)
					}
				} else {
					var fatal *DurabilityError
					if !errors.As(err, &fatal) || !errors.Is(err, ErrOutcomeUncertain) || errors.Is(err, failure) || v.Health() == nil {
						t.Fatalf("sync = %v; health = %v", err, v.Health())
					}
					if _, err := v.Root(); !errors.Is(err, ErrFenced) {
						t.Fatalf("post-fence root = %v", err)
					}
				}
				if calls != 1 {
					t.Fatalf("sync calls = %d", calls)
				}
			})
		}
	}
}

func TestDurabilityFailureCannotReleaseLaterCoalescerSuccess(t *testing.T) {
	v, handle, state := fsyncTestHandle(t)
	first, err := v.PinSyncHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := v.PinSyncHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	calls := 0
	v.fsync = func(int) error {
		calls++
		if calls == 1 {
			close(entered)
			<-release
			return syscall.ENOSPC
		}
		return nil
	}
	a := make(chan error, 1)
	b := make(chan error, 1)
	go func() { a <- first.Sync() }()
	<-entered
	go func() { b <- second.Sync() }()
	waitFsyncPending(t, state, 1)
	close(release)
	for _, ch := range []chan error{a, b} {
		if err := <-ch; !errors.Is(err, ErrOutcomeUncertain) {
			t.Fatalf("released successful waiter after failure: %v", err)
		}
	}
}

func TestPersistenceFailuresFenceEveryLaterBarrier(t *testing.T) {
	for _, kind := range []string{"fsync", "fdatasync", "syncfs", "handle", "object", "write sync", "write datasync", "restore"} {
		for _, failure := range []error{syscall.ENOSPC, syscall.EDQUOT, syscall.EIO} {
			t.Run(kind+"/"+failure.Error(), func(t *testing.T) {
				v, handle, _ := fsyncTestHandle(t)
				root, _ := v.Root()
				item, _, err := v.Lookup(root, "fsync-group")
				if err != nil {
					t.Fatal(err)
				}
				pin, err := v.PinSyncHandle(handle)
				if err != nil {
					t.Fatal(err)
				}
				defer pin.Close()
				write, err := v.PinWriteTarget(handle)
				if err != nil {
					t.Fatal(err)
				}
				defer write.Close()
				calls := 0
				call := func(int) error {
					calls++
					if calls == 1 {
						return failure
					}
					return nil
				}
				v.fsync, v.fdatasync, v.syncfs = call, call, call
				var first error
				switch kind {
				case "fsync":
					first = v.Fsync(handle, false)
				case "fdatasync":
					first = v.Fsync(handle, true)
				case "syncfs":
					first = v.SyncFS()
				case "handle":
					first = pin.Sync()
				case "object":
					first = v.SyncObject(item)
				case "write sync", "write datasync":
					_, _, _, first = write.CommitWriteData([]byte("x"), WriteCommit{
						RequestedSize: 1, RLimitSize: ^uint64(0), FileMaxSize: 1<<63 - 1,
						Mode: WritePositioned, Sync: kind == "write sync", DataSync: kind == "write datasync"})
				case "restore":
					opened, err := v.holdOpen(handle)
					if err != nil {
						t.Fatal(err)
					}
					defer opened.release()
					restore := &RestoreFiles{volume: v, files: map[uint32]restoreFile{1: {res: opened.res, identity: opened.coordinate.Stable}}}
					first = restore.Fdatasync(1)
				}
				var fatal *DurabilityError
				if !errors.As(first, &fatal) || fatal.Cause != failure || !errors.Is(v.Health(), ErrFenced) {
					t.Fatalf("first error=%v; health=%v", first, v.Health())
				}
				health := v.Health()
				for _, barrier := range []func() error{v.SyncFS, pin.Sync, write.Sync, func() error { return v.Fsync(handle, false) }, func() error { return v.Fsync(handle, true) }} {
					err := barrier()
					if !errors.As(err, &fatal) || fatal.Cause != failure {
						t.Fatalf("lost first failure: %v", err)
					}
				}
				v.Fence(syscall.EDQUOT)
				if v.Health() != health || calls != 1 {
					t.Fatalf("first failure changed or retry ran: health=%v calls=%d", v.Health(), calls)
				}
			})
		}
	}
}

func TestInvalidSyncHandlesDoNotFence(t *testing.T) {
	v := openTestVolume(t)
	if err := v.Fsync(Capability{99}, false); !errors.Is(err, ErrStaleOpen) || v.Health() != nil {
		t.Fatalf("invalid sync=%v health=%v", err, v.Health())
	}
	if err := v.SyncFS(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenTruncatePostApplyFailuresRemainUncertain(t *testing.T) {
	for _, granted := range []bool{false, true} {
		t.Run(map[bool]string{false: "reopen verification", true: "handle installation"}[granted], func(t *testing.T) {
			v := openTestVolume(t)
			root, _ := v.Root()
			item, _, err := v.Create(root, "truncate", 0600, true)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.WriteAt(handle, []byte("data"), 0); err != nil {
				t.Fatal(err)
			}
			if granted {
				opened, holdErr := v.holdOpen(handle)
				if holdErr != nil {
					t.Fatal(holdErr)
				}
				defer opened.release()
				if err := v.Forget(item); err != nil {
					t.Fatal(err)
				}
				// Truncate succeeds, then installation discovers that the client
				// concurrently reclaimed the item. Installation owns this ref.
				opened.res.acquire()
				_, err = v.adoptGrantedDescription(nil, opened.res, item, KindRegular, OpenFlags{Read: true, Write: true, Truncate: true})
				if !errors.Is(err, ErrOutcomeUncertain) {
					t.Fatalf("post-truncate installation = %v", err)
				}
			} else {
				v.projectID = 123 // Reopen succeeds before project validation fails.
				_, err = v.OpenFile(item, OpenFlags{Read: true, Write: true, Truncate: true})
				v.projectID = 0
				if !errors.Is(err, ErrOutcomeUncertain) {
					t.Fatalf("post-open failure = %v", err)
				}
			}
			if post, err := v.GetattrOpen(handle); err != nil || post.Size != 0 {
				t.Fatalf("truncate did not apply: %+v, %v", post, err)
			}

		})
	}
}

func TestFencedSyncFSDoesNotWaitForAnActiveStorageSync(t *testing.T) {
	v := openTestVolume(t)
	entered, release := make(chan struct{}), make(chan struct{})
	v.syncfs = func(int) error { close(entered); <-release; return nil }
	first := make(chan error, 1)
	go func() { first <- v.SyncFS() }()
	<-entered
	t.Cleanup(func() {
		close(release)
		if err := <-first; !errors.Is(err, ErrFenced) {
			t.Errorf("in-flight fenced syncfs = %v", err)
		}
	})
	v.Fence(syscall.EIO)
	second := make(chan error, 1)
	go func() { second <- v.SyncFS() }()
	select {
	case err := <-second:
		if !errors.Is(err, ErrFenced) {
			t.Fatalf("fenced syncfs = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fenced syncfs waited for an active storage sync")
	}
}

func TestSyncFSCoalescesArrivalsIntoNextBatch(t *testing.T) {
	v := openTestVolume(t)
	entered := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	release := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	var calls atomic.Int32
	v.syncfs = func(fd int) error {
		if fd != v.rootFD {
			t.Errorf("syncfs description=%d want root=%d", fd, v.rootFD)
		}
		n := int(calls.Add(1)) - 1
		if n >= 2 {
			return syscall.EIO
		}
		close(entered[n])
		<-release[n]
		return nil
	}
	first, next := make(chan error, 1), make(chan error, 5)
	go func() { first <- v.SyncFS() }()
	<-entered[0]
	for range 5 {
		go func() { next <- v.SyncFS() }()
	}
	waitSyncPending(t, &v.volumeSync, 5)
	close(release[0])
	<-entered[1]
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-next:
		t.Fatalf("next waiter escaped its syscall: %v", err)
	default:
	}
	close(release[1])
	for range 5 {
		if err := <-next; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("syncfs calls=%d want 2", calls.Load())
	}
}

func waitSyncPending(t *testing.T, state *syncGroup, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		state.mu.Lock()
		pending := len(state.pending)
		state.mu.Unlock()
		if pending == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending=%d want %d", pending, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPersistenceFailureFencesBeforeReleasingPendingWaiters(t *testing.T) {
	for _, kind := range []string{"fsync", "fdatasync", "syncfs"} {
		for _, cause := range []error{syscall.ENOSPC, syscall.EDQUOT, syscall.EIO} {
			t.Run(kind+"/"+cause.Error(), func(t *testing.T) {
				v, handle, state := fsyncTestHandle(t)
				entered, release := make(chan struct{}), make(chan struct{})
				var calls atomic.Int32
				fail := func(int) error {
					if calls.Add(1) == 1 {
						close(entered)
						<-release
						return cause
					}
					return nil
				}
				v.fsync, v.fdatasync, v.syncfs = fail, fail, fail
				barrier := func() error { return v.Fsync(handle, kind == "fdatasync") }
				group := &state.syncGroup
				if kind == "syncfs" {
					barrier = v.SyncFS
					group = &v.volumeSync
				}
				first, next := make(chan error, 1), make(chan error, 4)
				go func() { first <- barrier() }()
				<-entered
				for range 4 {
					go func() { next <- barrier() }()
				}
				waitSyncPending(t, group, 4)
				close(release)
				for _, ch := range []chan error{first, next, next, next, next} {
					err := <-ch
					var fatal *DurabilityError
					if !errors.As(err, &fatal) || fatal.Cause != cause || !errors.Is(v.Health(), ErrFenced) {
						t.Fatalf("waiter=%v health=%v", err, v.Health())
					}
				}
				if calls.Load() != 1 {
					t.Fatalf("syscalls=%d", calls.Load())
				}
			})
		}
	}
}

func TestConcurrentPersistenceFailurePreservesFirstCause(t *testing.T) {
	for _, laterError := range []error{nil, syscall.EDQUOT} {
		name := "successful in-flight syscall"
		if laterError != nil {
			name = laterError.Error()
		}
		t.Run(name, func(t *testing.T) {
			v, handle, _ := fsyncTestHandle(t)
			entered, release := make(chan struct{}), make(chan struct{})
			v.syncfs = func(int) error { close(entered); <-release; return laterError }
			later := make(chan error, 1)
			go func() { later <- v.SyncFS() }()
			<-entered
			v.fsync = func(int) error { return syscall.ENOSPC }
			first := v.Fsync(handle, false)
			close(release)
			second := <-later
			if first != second {
				t.Fatalf("first failure replaced: %v / %v", first, second)
			}
			var fatal *DurabilityError
			if !errors.As(second, &fatal) || fatal.Cause != syscall.ENOSPC {
				t.Fatalf("cause=%v", second)
			}
		})
	}
}

// Both paths used to call persistence outside the shared inode group. Model a
// consumed error by pausing the first syscall after it has chosen its result;
// a concurrent call must queue until that error has fenced the volume.
func TestSameDescriptionPersistenceCannotConsumeErrorThenSucceed(t *testing.T) {
	for _, kind := range []string{"logical sync", "logical datasync", "restore hydration chunks"} {
		for _, cause := range []error{syscall.ENOSPC, syscall.EDQUOT, syscall.EIO} {
			t.Run(kind+"/"+cause.Error(), func(t *testing.T) {
				v, handle, state := fsyncTestHandle(t)
				opened, err := v.holdOpen(handle)
				if err != nil {
					t.Fatal(err)
				}
				defer opened.release()
				restore := &RestoreFiles{volume: v, files: map[uint32]restoreFile{1: {res: opened.res, identity: opened.coordinate.Stable}}}
				entered, release := make(chan struct{}), make(chan struct{})
				var calls atomic.Int32
				call := func(fd int) error {
					if fd != opened.fd() {
						t.Errorf("description changed: %d / %d", fd, opened.fd())
					}
					if calls.Add(1) == 1 {
						close(entered)
						<-release
						return cause
					}
					return nil
				}
				v.fsync, v.fdatasync = call, call
				barrier := func() error {
					return v.syncDescriptor(state, opened.fd(), kind == "logical sync", kind == "logical datasync")
				}
				if kind == "restore hydration chunks" {
					barrier = func() error { return restore.Fdatasync(1) }
				}
				first, second := make(chan error, 1), make(chan error, 1)
				go func() { first <- barrier() }()
				<-entered
				go func() { second <- barrier() }()
				waitFsyncPending(t, state, 1)
				if calls.Load() != 1 {
					t.Fatalf("overlapping persistence syscalls: %d", calls.Load())
				}
				close(release)
				a, b := <-first, <-second
				var failure *DurabilityError
				if a != b || !errors.As(a, &failure) || failure.Cause != cause || calls.Load() != 1 || !errors.Is(v.Health(), ErrFenced) {
					t.Fatalf("first=%v second=%v calls=%d health=%v", a, b, calls.Load(), v.Health())
				}
				if err := restore.PWrite(1, 0, []byte("forbidden")); !errors.Is(err, ErrFenced) {
					t.Fatalf("restore wrote after fence: %v", err)
				}
			})
		}
	}
}

func TestFenceDoesNotExposeCauseClassification(t *testing.T) {
	v := openTestVolume(t)
	cause := &DurabilityError{Cause: ErrStaleObject}
	v.Fence(cause)
	if !errors.Is(v.Health(), ErrFenced) || errors.Is(v.Health(), ErrOutcomeUncertain) || errors.Is(v.Health(), ErrStaleObject) {
		t.Fatalf("fence leaked cause classification: %v", v.Health())
	}
	if err := v.SyncFS(); err != cause {
		t.Fatalf("barrier lost durability cause: %v", err)
	}
}

func TestLogicalSyncThenFullBarrierUsesTwoSyscalls(t *testing.T) {
	for _, dataOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "sync", true: "datasync"}[dataOnly], func(t *testing.T) {
			v, handle, _ := fsyncTestHandle(t)
			target, err := v.PinWriteTarget(handle)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			full, data := 0, 0
			v.fsync = func(int) error { full++; return nil }
			v.fdatasync = func(int) error { data++; return nil }
			_, _, _, err = target.CommitWriteData([]byte("x"), WriteCommit{
				RequestedSize: 1, RLimitSize: ^uint64(0), FileMaxSize: 1<<63 - 1,
				Mode: WritePositioned, Sync: !dataOnly, DataSync: dataOnly,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := target.Sync(); err != nil {
				t.Fatal(err)
			}
			wantFull, wantData := 2, 0
			if dataOnly {
				wantFull, wantData = 1, 1
			}
			if full != wantFull || data != wantData {
				t.Fatalf("sequential barriers: fsync=%d fdatasync=%d; want %d/%d", full, data, wantFull, wantData)
			}
		})
	}
}
