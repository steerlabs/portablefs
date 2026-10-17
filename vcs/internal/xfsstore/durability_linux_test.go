//go:build linux

package xfsstore

import (
	"errors"
	"io/fs"
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
					sync = v.SyncMutationFS
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

func TestOrdinarySyncErrorRemainsStickyForRequiredBarrier(t *testing.T) {
	for _, failure := range []error{syscall.ENOSPC, syscall.EDQUOT} {
		t.Run(failure.Error(), func(t *testing.T) {
			v := openTestVolume(t)
			root, _ := v.Root()
			item, _, err := v.Create(root, "consumed-error", 0600, true)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			v.fsync = func(int) error {
				calls++
				if calls == 1 {
					return failure
				}
				return nil // errseq was consumed by the ordinary caller.
			}
			if err := v.Fsync(handle, false); !errors.Is(err, failure) {
				t.Fatalf("ordinary fsync = %v", err)
			}
			if err := v.Fsync(handle, false); err != nil {
				t.Fatalf("ordinary retry = %v", err)
			}
			other, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := v.CloseOpen(handle); err != nil {
				t.Fatal(err)
			}
			if err := v.CloseOpen(other); err != nil {
				t.Fatal(err)
			}
			// Even closing every description must not erase a consumed error.
			other, err = v.OpenFile(item, OpenFlags{Read: true, Write: true})
			if err != nil {
				t.Fatal(err)
			}
			pinned, err := v.PinSyncHandle(other)
			if err != nil {
				t.Fatal(err)
			}
			defer pinned.Close()
			var fatal *DurabilityError
			if err := pinned.Sync(); !errors.As(err, &fatal) || !errors.Is(fatal.Cause, failure) {
				t.Fatalf("required barrier = %v", err)
			}
			if calls != 2 || v.Health() == nil {
				t.Fatalf("sync calls/health = %d/%v", calls, v.Health())
			}
		})
	}
}

func TestSyncFSDescriptionsAndFencedFastFailure(t *testing.T) {
	v := openTestVolume(t)
	var descriptors []int
	v.syncfs = func(fd int) error {
		descriptors = append(descriptors, fd)
		if fd == v.rootFD {
			return syscall.ENOSPC
		}
		return nil
	}
	if err := v.SyncFS(); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("ordinary syncfs = %v", err)
	}
	if err := v.SyncMutationFS(); err != nil {
		t.Fatal(err)
	}
	if len(descriptors) != 2 || descriptors[0] == descriptors[1] {
		t.Fatalf("syncfs descriptions = %v", descriptors)
	}
	// A separate open, rather than dup, also has independent file status flags.
	if _, err := unix.FcntlInt(uintptr(v.rootFD), unix.F_SETFL, unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	if flags, err := unix.FcntlInt(uintptr(descriptors[1]), unix.F_GETFL, 0); err != nil || flags&unix.O_NONBLOCK != 0 {
		t.Fatalf("required root shares open description: flags=%#x err=%v", flags, err)
	}
	v.Fence(syscall.EIO)
	if err := v.SyncMutationFS(); !errors.Is(err, ErrOutcomeUncertain) {
		t.Fatalf("fenced syncfs = %v", err)
	}
	if len(descriptors) != 2 {
		t.Fatal("fenced barrier ran syncfs")
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
	go func() { first <- v.SyncMutationFS() }()
	<-entered
	t.Cleanup(func() {
		close(release)
		if err := <-first; !errors.Is(err, ErrOutcomeUncertain) {
			t.Errorf("in-flight fenced syncfs = %v", err)
		}
	})
	v.Fence(syscall.EIO)
	second := make(chan error, 1)
	go func() { second <- v.SyncMutationFS() }()
	select {
	case err := <-second:
		if !errors.Is(err, ErrOutcomeUncertain) {
			t.Fatalf("fenced syncfs = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fenced syncfs waited for an active storage sync")
	}
}
