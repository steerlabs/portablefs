//go:build linux

package xfsstore

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func openTestVolume(t *testing.T) *Volume {
	t.Helper()
	v, err := open(filepath.Clean(t.TempDir()), false, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := v.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return v
}

type fsyncTestResult struct {
	batch int
	err   error
}

func fsyncTestHandle(t *testing.T) (*Volume, Capability, *inodeFsyncState) {
	t.Helper()
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "fsync-group", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := v.CloseOpen(handle); err != nil && !errors.Is(err, ErrClosed) {
			t.Errorf("CloseOpen: %v", err)
		}
	})
	opened, err := v.holdOpen(handle)
	if err != nil {
		t.Fatal(err)
	}
	state := opened.fsyncState
	opened.release()
	return v, handle, state
}

func waitFsyncPending(t *testing.T, state *inodeFsyncState, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		state.mu.Lock()
		got := len(state.pending)
		state.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("fsync pending batch did not reach %d waiters", want)
}

func requireFsyncBlocked(t *testing.T, result <-chan fsyncTestResult, what string) {
	t.Helper()
	select {
	case got := <-result:
		t.Fatalf("%s returned before its covering sync completed: %+v", what, got)
	case <-time.After(25 * time.Millisecond):
	}
}

func TestFsyncCoalescesArrivalsIntoTheNextCompletedBatch(t *testing.T) {
	v, handle, state := fsyncTestHandle(t)
	started := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	release := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	var calls atomic.Int32
	v.fdatasync = func(int) error {
		call := int(calls.Add(1)) - 1
		if call >= len(started) {
			return syscall.EIO
		}
		close(started[call])
		<-release[call]
		return nil
	}

	first := make(chan fsyncTestResult, 1)
	go func() {
		batch, err := v.FsyncCoalesced(handle, true)
		first <- fsyncTestResult{batch: batch, err: err}
	}()
	<-started[0]

	const followers = 4
	results := make(chan fsyncTestResult, followers)
	for range followers {
		go func() {
			batch, err := v.FsyncCoalesced(handle, true)
			results <- fsyncTestResult{batch: batch, err: err}
		}()
	}
	waitFsyncPending(t, state, followers)
	requireFsyncBlocked(t, results, "follower")
	close(release[0])
	<-started[1]
	if got := <-first; got.err != nil || got.batch != 1 {
		t.Fatalf("first fsync = %+v, want one-handle batch", got)
	}
	requireFsyncBlocked(t, results, "next-batch follower")
	close(release[1])

	batchLeaders := 0
	for range followers {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.batch != 0 {
			batchLeaders++
			if got.batch != followers {
				t.Fatalf("coalesced batch size = %d, want %d", got.batch, followers)
			}
		}
	}
	if batchLeaders != 1 || calls.Load() != 2 {
		t.Fatalf("batch leaders=%d storage syncs=%d, want 1 and 2", batchLeaders, calls.Load())
	}
}

func TestFsyncFullClassIsNeverCoveredByFdatasync(t *testing.T) {
	v, handle, state := fsyncTestHandle(t)
	dataStarted, dataRelease := make(chan struct{}), make(chan struct{})
	fullStarted, fullRelease := make(chan struct{}), make(chan struct{})
	var dataCalls, fullCalls atomic.Int32
	v.fdatasync = func(int) error {
		dataCalls.Add(1)
		close(dataStarted)
		<-dataRelease
		return nil
	}
	v.fsync = func(int) error {
		fullCalls.Add(1)
		close(fullStarted)
		<-fullRelease
		return nil
	}

	first := make(chan fsyncTestResult, 1)
	go func() {
		batch, err := v.FsyncCoalesced(handle, true)
		first <- fsyncTestResult{batch: batch, err: err}
	}()
	<-dataStarted
	pending := make(chan fsyncTestResult, 2)
	go func() {
		batch, err := v.FsyncCoalesced(handle, false)
		pending <- fsyncTestResult{batch: batch, err: err}
	}()
	go func() {
		batch, err := v.FsyncCoalesced(handle, true)
		pending <- fsyncTestResult{batch: batch, err: err}
	}()
	waitFsyncPending(t, state, 2)
	close(dataRelease)
	<-fullStarted
	if got := <-first; got.err != nil {
		t.Fatal(got.err)
	}
	requireFsyncBlocked(t, pending, "full-class batch")
	if dataCalls.Load() != 1 || fullCalls.Load() != 1 {
		t.Fatalf("sync classes = fdatasync:%d fsync:%d, want 1/1", dataCalls.Load(), fullCalls.Load())
	}
	close(fullRelease)
	for range 2 {
		if got := <-pending; got.err != nil {
			t.Fatal(got.err)
		}
	}
}

func TestFsyncGenerationAppliedDuringFlightRequiresNextSync(t *testing.T) {
	v, handle, state := fsyncTestHandle(t)
	target, err := v.PinWriteTarget(handle)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	started := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	release := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	var calls atomic.Int32
	v.fdatasync = func(int) error {
		call := int(calls.Add(1)) - 1
		close(started[call])
		<-release[call]
		return nil
	}

	first := make(chan fsyncTestResult, 1)
	go func() {
		batch, err := v.FsyncCoalesced(handle, true)
		first <- fsyncTestResult{batch: batch, err: err}
	}()
	<-started[0]
	if committed, _, _, err := target.CommitWriteData([]byte{'x'}, WriteCommit{
		RequestedSize: 1, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64, Mode: WritePositioned,
	}); err != nil || committed != 1 {
		t.Fatalf("CommitWriteData = (%d, %v)", committed, err)
	}

	second := make(chan fsyncTestResult, 1)
	go func() {
		batch, err := v.FsyncCoalesced(handle, true)
		second <- fsyncTestResult{batch: batch, err: err}
	}()
	waitFsyncPending(t, state, 1)
	state.mu.Lock()
	applied := state.appliedGeneration
	required := state.pending[0].requiredGeneration
	state.mu.Unlock()
	if applied != 1 || required != applied {
		t.Fatalf("generation applied=%d required=%d, want 1/1", applied, required)
	}
	close(release[0])
	<-started[1]
	if got := <-first; got.err != nil {
		t.Fatal(got.err)
	}
	requireFsyncBlocked(t, second, "post-write barrier")
	close(release[1])
	if got := <-second; got.err != nil || got.batch != 1 {
		t.Fatalf("post-write fsync = %+v", got)
	}
}

func writeCommitStage(t testing.TB, data []byte) *os.File {
	t.Helper()
	fd, err := unix.MemfdCreate("portablefs-commit-test", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "portablefs-commit-test")
	if file == nil {
		_ = unix.Close(fd)
		t.Fatal("os.NewFile returned nil")
	}
	t.Cleanup(func() { _ = file.Close() })
	if err := unix.Ftruncate(fd, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if n, err := file.WriteAt(data, 0); err != nil || n != len(data) {
		t.Fatalf("stage WriteAt = (%d, %v)", n, err)
	}
	return file
}

func TestOpenAfterUnlinkUsesRetainedFD(t *testing.T) {
	v := openTestVolume(t)
	root, err := v.Root()
	if err != nil {
		t.Fatal(err)
	}
	item, _, err := v.Create(root, "file", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	h, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := v.WriteAt(h, []byte("hello"), 0); n != 5 || err != nil {
		t.Fatalf("WriteAt = %d, %v", n, err)
	}
	if err := v.Unlink(root, "file", false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Lookup(root, "file"); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("Lookup after unlink = %v, want ENOENT", err)
	}
	buf := make([]byte, 5)
	if n, err := v.ReadAt(h, buf, 0); n != 5 || err != nil {
		t.Fatalf("ReadAt after unlink = %d, %v", n, err)
	}
	if string(buf) != "hello" {
		t.Fatalf("ReadAt = %q", buf)
	}
	if err := v.Fsync(h, false); err != nil {
		t.Fatal(err)
	}
	if err := v.CloseOpen(h); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedAppendIsPerCallAndSurvivesHandleClose(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "append", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Write: true, Append: true})
	if err != nil {
		t.Fatal(err)
	}
	// OPEN-time append intent never makes the authority descriptor sticky.
	if n, err := v.WriteAt(handle, []byte("p"), 0); n != 1 || err != nil {
		t.Fatalf("positional write on append-intent handle = (%d, %v)", n, err)
	}
	target, err := v.PinWriteTarget(handle)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.CloseOpen(handle); err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	data := []byte("ayload")
	var appendCalls, sendfileCalls int
	pwritev2 := v.pwritev2
	v.pwritev2 = func(fd int, buffers [][]byte, offset int64, flags int) (int, error) {
		appendCalls++
		return pwritev2(fd, buffers, offset, flags)
	}
	sendfile := v.sendfile
	v.sendfile = func(outFD, inFD int, offset *int64, count int) (int, error) {
		sendfileCalls++
		return sendfile(outFD, inFD, offset, count)
	}
	committed, assigned, post, err := target.CommitWrite(bytes.NewReader(data), WriteCommit{RequestedSize: uint64(len(data)), RLimitSize: 1 << 20, FileMaxSize: 1 << 20, Mode: WriteAppend}, make([]byte, 3))
	if err != nil || committed != uint64(len(data)) || assigned != 1 || post.Size != int64(1+len(data)) {
		t.Fatalf("CommitWrite = (%d,%d,%+v,%v)", committed, assigned, post, err)
	}
	if appendCalls != 2 || sendfileCalls != 0 {
		t.Fatalf("append data path = pwritev2:%d sendfile:%d, want 2/0", appendCalls, sendfileCalls)
	}
	reader, err := v.OpenFile(item, OpenFlags{Read: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(reader)
	got := make([]byte, post.Size)
	if n, err := v.ReadAt(reader, got, 0); err != nil || int64(n) != post.Size || string(got) != "payload" {
		t.Fatalf("post append = %q n=%d err=%v", got, n, err)
	}
}

func TestCoordinateItemMatchesInstalledIdentityAndAttributes(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, attr, err := v.Create(root, "retained-coordinate", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := v.Identity(item)
	if err != nil {
		t.Fatal(err)
	}
	coordinate, err := v.CoordinateItem(item)
	if err != nil {
		t.Fatal(err)
	}
	want := ObjectCoordinate{
		Stable: identity, Ino: attr.Ino,
		DeviceMajor: attr.DeviceMajor, DeviceMinor: attr.DeviceMinor,
	}
	if coordinate != want {
		t.Fatalf("CoordinateItem = %+v, want %+v", coordinate, want)
	}
	if err := v.Chmod(item, 0o640); err != nil {
		t.Fatal(err)
	}
	after, err := v.CoordinateItem(item)
	if err != nil {
		t.Fatal(err)
	}
	if after != want {
		t.Fatalf("CoordinateItem after mutable attr change = %+v, want %+v", after, want)
	}
}

func TestOpenSyncIntentIsLogicalNotSticky(t *testing.T) {
	for _, test := range []struct {
		name     string
		flags    OpenFlags
		wantSync bool
		wantData bool
	}{
		{name: "sync", flags: OpenFlags{Write: true, Sync: true}, wantSync: true},
		{name: "datasync", flags: OpenFlags{Write: true, DataSync: true}, wantData: true},
		{name: "sync-wins", flags: OpenFlags{Write: true, Sync: true, DataSync: true}, wantSync: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := openTestVolume(t)
			root, _ := v.Root()
			item, _, err := v.Create(root, "logical-sync", 0o600, true)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := v.OpenFile(item, test.flags)
			if err != nil {
				t.Fatal(err)
			}
			defer v.CloseOpen(handle)
			file, err := v.holdOpen(handle)
			if err != nil {
				t.Fatal(err)
			}
			defer file.release()
			gotFlags, err := unix.FcntlInt(uintptr(file.fd()), unix.F_GETFL, 0)
			if err != nil {
				t.Fatal(err)
			}
			if gotFlags&(unix.O_SYNC|unix.O_DSYNC) != 0 {
				t.Fatalf("retained fd flags = %#x, want no sticky sync bits", gotFlags)
			}
			if file.sync != test.wantSync || file.dataSync != test.wantData {
				t.Fatalf("logical sync = (%v,%v), want (%v,%v)", file.sync, file.dataSync, test.wantSync, test.wantData)
			}
		})
	}
}

func TestCommitWriteSyncsOnceAfterAllFragments(t *testing.T) {
	for _, test := range []struct {
		name     string
		commit   WriteCommit
		wantFull int
		wantData int
	}{
		{name: "sync", commit: WriteCommit{Sync: true}, wantFull: 1},
		{name: "datasync", commit: WriteCommit{DataSync: true}, wantData: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := openTestVolume(t)
			root, _ := v.Root()
			item, _, err := v.Create(root, "aggregate-sync", 0o600, true)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := v.OpenFile(item, OpenFlags{Write: true})
			if err != nil {
				t.Fatal(err)
			}
			target, err := v.PinWriteTarget(handle)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			var copies, fullSyncs, dataSyncs int
			sendfile := v.sendfile
			v.sendfile = func(outFD, inFD int, offset *int64, count int) (int, error) {
				copies++
				return sendfile(outFD, inFD, offset, count)
			}
			v.fsync = func(int) error { fullSyncs++; return nil }
			v.fdatasync = func(int) error { dataSyncs++; return nil }
			data := []byte("eightbyt")
			test.commit.RequestedSize = uint64(len(data))
			test.commit.RLimitSize = math.MaxUint64
			test.commit.FileMaxSize = math.MaxInt64
			test.commit.Mode = WritePositioned
			committed, _, _, err := target.CommitWrite(writeCommitStage(t, data), test.commit, nil)
			if err != nil || committed != uint64(len(data)) {
				t.Fatalf("CommitWrite = (%d,%v)", committed, err)
			}
			if copies != 1 || fullSyncs != test.wantFull || dataSyncs != test.wantData {
				t.Fatalf("calls = sendfile:%d fsync:%d fdatasync:%d, want 1/%d/%d", copies, fullSyncs, dataSyncs, test.wantFull, test.wantData)
			}
		})
	}
}

func TestCommitWritePositionedSendfileCopiesMemfdAtExactOffset(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "positioned-sendfile", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)
	if n, err := v.WriteAt(handle, []byte("abcdefghij"), 0); err != nil || n != 10 {
		t.Fatalf("seed WriteAt = (%d, %v)", n, err)
	}
	target, err := v.PinWriteTarget(handle)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	payload := []byte("WXYZ")
	committed, assigned, post, err := target.CommitWrite(writeCommitStage(t, payload), WriteCommit{
		RequestedSize: uint64(len(payload)), Position: 3,
		RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64, Mode: WritePositioned,
	}, nil)
	if err != nil || committed != 4 || assigned != 3 || post.Size != 10 {
		t.Fatalf("CommitWrite = (%d, %d, size %d, %v)", committed, assigned, post.Size, err)
	}
	got := make([]byte, 10)
	if n, err := v.ReadAt(handle, got, 0); err != nil || n != len(got) || string(got) != "abcWXYZhij" {
		t.Fatalf("positioned result = %q n=%d err=%v", got, n, err)
	}
}

func TestCommitWriteDataPositionedUsesExactlyOnePwriteWithoutStaging(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "one-shot-positioned", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)
	if n, err := v.WriteAt(handle, []byte("abcdefghij"), 0); err != nil || n != 10 {
		t.Fatalf("seed WriteAt = (%d, %v)", n, err)
	}
	target, err := v.PinWriteTarget(handle)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	realPwrite := v.pwrite
	var pwriteCalls, pwritev2Calls, sendfileCalls int
	v.pwrite = func(fd int, data []byte, offset int64) (int, error) {
		pwriteCalls++
		if string(data) != "WXYZ" || offset != 3 {
			t.Fatalf("pwrite input = %q at %d, want WXYZ at 3", data, offset)
		}
		return realPwrite(fd, data, offset)
	}
	v.pwritev2 = func(int, [][]byte, int64, int) (int, error) {
		pwritev2Calls++
		return 0, syscall.EIO
	}
	v.sendfile = func(int, int, *int64, int) (int, error) {
		sendfileCalls++
		return 0, syscall.EIO
	}
	payload := []byte("WXYZ")
	committed, assigned, post, err := target.CommitWriteData(payload, WriteCommit{
		RequestedSize: uint64(len(payload)), Position: 3,
		RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64, Mode: WritePositioned,
	})
	if err != nil || committed != 4 || assigned != 3 || post.Size != 10 {
		t.Fatalf("CommitWriteData = (%d, %d, size %d, %v)", committed, assigned, post.Size, err)
	}
	if pwriteCalls != 1 || pwritev2Calls != 0 || sendfileCalls != 0 {
		t.Fatalf("one-shot positioned path = pwrite:%d pwritev2:%d sendfile:%d, want 1/0/0", pwriteCalls, pwritev2Calls, sendfileCalls)
	}
	got := make([]byte, 10)
	if n, err := v.ReadAt(handle, got, 0); err != nil || n != len(got) || string(got) != "abcWXYZhij" {
		t.Fatalf("one-shot positioned result = %q n=%d err=%v", got, n, err)
	}
}

func TestCommitWriteDataAppendUsesOneRWFAppendCall(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "one-shot-append", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)
	if n, err := v.WriteAt(handle, []byte("prefix"), 0); err != nil || n != 6 {
		t.Fatalf("seed WriteAt = (%d, %v)", n, err)
	}
	target, err := v.PinWriteTarget(handle)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	realPwritev2 := v.pwritev2
	var pwriteCalls, appendCalls, sendfileCalls int
	v.pwrite = func(int, []byte, int64) (int, error) {
		pwriteCalls++
		return 0, syscall.EIO
	}
	v.pwritev2 = func(fd int, buffers [][]byte, offset int64, flags int) (int, error) {
		appendCalls++
		if len(buffers) != 1 || string(buffers[0]) != "-tail" || offset != 0 || flags != unix.RWF_APPEND {
			t.Fatalf("pwritev2 input = %q offset %d flags %#x", buffers, offset, flags)
		}
		return realPwritev2(fd, buffers, offset, flags)
	}
	v.sendfile = func(int, int, *int64, int) (int, error) {
		sendfileCalls++
		return 0, syscall.EIO
	}
	payload := []byte("-tail")
	committed, assigned, post, err := target.CommitWriteData(payload, WriteCommit{
		RequestedSize: uint64(len(payload)), RLimitSize: math.MaxUint64,
		FileMaxSize: math.MaxInt64, Mode: WriteAppend,
	})
	if err != nil || committed != 5 || assigned != 6 || post.Size != 11 {
		t.Fatalf("append CommitWriteData = (%d, %d, size %d, %v)", committed, assigned, post.Size, err)
	}
	if pwriteCalls != 0 || appendCalls != 1 || sendfileCalls != 0 {
		t.Fatalf("one-shot append path = pwrite:%d pwritev2:%d sendfile:%d, want 0/1/0", pwriteCalls, appendCalls, sendfileCalls)
	}
	got := make([]byte, 11)
	if n, err := v.ReadAt(handle, got, 0); err != nil || n != len(got) || string(got) != "prefix-tail" {
		t.Fatalf("one-shot append result = %q n=%d err=%v", got, n, err)
	}
}

func TestCommitWritePositionedSendfileReturnsExactShortPrefix(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "positioned-sendfile-short", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)
	target, err := v.PinWriteTarget(handle)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	stage := writeCommitStage(t, []byte("abcd"))
	var calls int
	v.sendfile = func(outFD, inFD int, offset *int64, count int) (int, error) {
		calls++
		if count != 4 || *offset != 0 {
			t.Fatalf("sendfile input = count %d offset %d, want 4/0", count, *offset)
		}
		buf := make([]byte, 2)
		if n, err := unix.Pread(inFD, buf, *offset); err != nil || n != len(buf) {
			t.Fatalf("seam Pread = (%d, %v)", n, err)
		}
		if n, err := unix.Write(outFD, buf); err != nil || n != len(buf) {
			t.Fatalf("seam Write = (%d, %v)", n, err)
		}
		*offset += int64(len(buf))
		return len(buf), nil
	}
	committed, assigned, post, err := target.CommitWrite(stage, WriteCommit{
		RequestedSize: 4, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64, Mode: WritePositioned,
	}, nil)
	if committed != 2 || assigned != 0 || post.Size != 2 || calls != 1 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short CommitWrite = (%d, %d, size %d, %v), calls=%d", committed, assigned, post.Size, err, calls)
	}
}

func TestCommitWritePrivilegeFailureStillAttemptsAndJoinsLogicalSync(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "aggregate-sync-after-killpriv", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	target, err := v.PinWriteTarget(handle)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	defer v.CloseOpen(handle)

	var privilegeCalls, syncCalls int
	v.removePinnedWritePrivileges = func(int, uint32, bool, *bool) error {
		privilegeCalls++
		return errors.Join(ErrWritePrivilege, syscall.EPERM)
	}
	v.fsync = func(int) error {
		syncCalls++
		return syscall.EIO
	}
	committed, assigned, post, err := target.CommitWrite(writeCommitStage(t, []byte("x")), WriteCommit{
		RequestedSize: 1, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
		Mode: WritePositioned, Sync: true, KillPrivileges: true,
	}, nil)
	if committed != 1 || assigned != 0 || post.Size != 1 || privilegeCalls != 1 || syncCalls != 1 ||
		!errors.Is(err, ErrWritePostApply) || !errors.Is(err, ErrWritePrivilege) ||
		!errors.Is(err, syscall.EPERM) || !errors.Is(err, syscall.EIO) {
		t.Fatalf("CommitWrite = (%d,%d,%+v,%v), privilege=%d sync=%d", committed, assigned, post, err, privilegeCalls, syncCalls)
	}
}

func TestAbsentFileCapabilityNeedsNoPrivilegedRemoval(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "no-file-capability-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := removeWritePrivileges(int(file.Fd()), 0o600, false); err != nil {
		t.Fatalf("ordinary unprivileged file was treated as a failed capability removal: %v", err)
	}
}

func TestPinnedWriteTargetCachesSecurityCapabilityUntilLastOpenCloses(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "capability-cache", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	var probes int
	v.inspectSecurityCapability = func(int) (bool, error) {
		probes++
		return false, nil
	}
	commit := WriteCommit{
		RequestedSize: 1, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
		Mode: WritePositioned,
	}
	target, err := v.PinWriteTarget(handle)
	if err != nil {
		t.Fatal(err)
	}
	for offset := uint64(0); offset < 2; offset++ {
		commit.Position = offset
		if committed, _, _, err := target.CommitWriteData([]byte{'x'}, commit); err != nil || committed != 1 {
			t.Fatalf("CommitWriteData(%d) = (%d, %v)", offset, committed, err)
		}
	}
	if probes != 1 {
		t.Fatalf("security.capability probes during one pin = %d, want 1", probes)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := v.PinWriteTarget(handle)
	if err != nil {
		t.Fatal(err)
	}
	if probes != 1 {
		t.Fatalf("security.capability probes after repin = %d, want cached 1", probes)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := v.CloseOpen(handle); err != nil {
		t.Fatal(err)
	}

	newHandle, err := v.OpenFile(item, OpenFlags{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(newHandle)
	third, err := v.PinWriteTarget(newHandle)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if probes != 2 {
		t.Fatalf("security.capability probes after cache lifetime ended = %d, want 2", probes)
	}
}

func TestRangeMutationsHonorLogicalSyncOnce(t *testing.T) {
	t.Run("fallocate-post-sync-error", func(t *testing.T) {
		v := openTestVolume(t)
		root, _ := v.Root()
		item, _, err := v.Create(root, "sync-fallocate", 0o600, true)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := v.OpenFile(item, OpenFlags{Write: true, Sync: true})
		if err != nil {
			t.Fatal(err)
		}
		defer v.CloseOpen(handle)
		v.fallocate = func(int, uint32, int64, int64) error { return nil }
		var syncs int
		v.fsync = func(int) error { syncs++; return syscall.EIO }
		post, err := v.Fallocate(handle, FallocateSpec{
			Offset: 0, Length: 4096, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
			Mode: uint32(unix.FALLOC_FL_KEEP_SIZE),
		})
		if syncs != 1 || post.Size != 0 || !errors.Is(err, ErrWritePostApply) || !errors.Is(err, syscall.EIO) {
			t.Fatalf("Fallocate = (post=%+v, err=%v), syncs=%d", post, err, syncs)
		}
	})

	t.Run("fallocate-killpriv-failure-still-syncs-and-backend-error-does-not", func(t *testing.T) {
		v := openTestVolume(t)
		root, _ := v.Root()
		item, _, err := v.Create(root, "sync-fallocate-killpriv", 0o600, true)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := v.OpenFile(item, OpenFlags{Write: true, Sync: true})
		if err != nil {
			t.Fatal(err)
		}
		defer v.CloseOpen(handle)
		v.fallocate = func(int, uint32, int64, int64) error { return nil }
		v.removeWritePrivileges = func(int, uint32, bool) error {
			return errors.Join(ErrWritePrivilege, syscall.EPERM)
		}
		var syncs int
		v.fsync = func(int) error { syncs++; return syscall.EIO }
		post, err := v.Fallocate(handle, FallocateSpec{
			Offset: 0, Length: 4096, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
			Mode: uint32(unix.FALLOC_FL_KEEP_SIZE), KillPrivileges: true,
		})
		if syncs != 1 || post.Size != 0 || !errors.Is(err, ErrWritePostApply) ||
			!errors.Is(err, ErrWritePrivilege) || !errors.Is(err, syscall.EPERM) || !errors.Is(err, syscall.EIO) {
			t.Fatalf("clean Fallocate = (post=%+v, err=%v), syncs=%d", post, err, syncs)
		}

		syncs = 0
		v.fallocate = func(int, uint32, int64, int64) error { return syscall.ENOSPC }
		v.removeWritePrivileges = removeWritePrivileges
		post, err = v.Fallocate(handle, FallocateSpec{
			Offset: 0, Length: 4096, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
			Mode: uint32(unix.FALLOC_FL_KEEP_SIZE),
		})
		if syncs != 0 || post.Size != 0 || !errors.Is(err, ErrWritePostApply) || !errors.Is(err, syscall.ENOSPC) {
			t.Fatalf("failed Fallocate = (post=%+v, err=%v), syncs=%d", post, err, syncs)
		}
	})

	t.Run("source-datasync-forces-destination", func(t *testing.T) {
		v := openTestVolume(t)
		root, _ := v.Root()
		sourceItem, _, err := v.Create(root, "sync-copy-source", 0o600, true)
		if err != nil {
			t.Fatal(err)
		}
		source, err := v.OpenFile(sourceItem, OpenFlags{Read: true, Write: true, DataSync: true})
		if err != nil {
			t.Fatal(err)
		}
		defer v.CloseOpen(source)
		if n, err := v.WriteAt(source, []byte("x"), 0); n != 1 || err != nil {
			t.Fatalf("seed source = (%d,%v)", n, err)
		}
		destinationItem, _, err := v.Create(root, "sync-copy-destination", 0o600, true)
		if err != nil {
			t.Fatal(err)
		}
		destination, err := v.OpenFile(destinationItem, OpenFlags{Write: true})
		if err != nil {
			t.Fatal(err)
		}
		defer v.CloseOpen(destination)
		v.copyFileRange = func(input int, inputOffset *int64, output int, outputOffset *int64, length, flags int) (int, error) {
			buf := make([]byte, length)
			n, err := unix.Pread(input, buf, *inputOffset)
			if err != nil {
				return n, err
			}
			n, err = unix.Pwrite(output, buf[:n], *outputOffset)
			*inputOffset += int64(n)
			*outputOffset += int64(n)
			return n, err
		}
		var dataSyncs int
		v.fdatasync = func(int) error { dataSyncs++; return syscall.EIO }
		v.removeWritePrivileges = func(int, uint32, bool) error {
			return errors.Join(ErrWritePrivilege, syscall.EPERM)
		}
		copied, post, err := v.CopyFileRange(source, destination, CopyFileRangeSpec{
			Length: 1, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64, KillPrivileges: true,
		})
		if copied != 1 || post.Size != 1 || dataSyncs != 1 || !errors.Is(err, ErrWritePostApply) ||
			!errors.Is(err, ErrWritePrivilege) || !errors.Is(err, syscall.EPERM) || !errors.Is(err, syscall.EIO) {
			t.Fatalf("CopyFileRange = (%d,%+v,%v), fdatasyncs=%d", copied, post, err, dataSyncs)
		}

		dataSyncs = 0
		v.removeWritePrivileges = removeWritePrivileges
		v.copyFileRange = func(int, *int64, int, *int64, int, int) (int, error) {
			return -1, syscall.ENOSPC
		}
		copied, post, err = v.CopyFileRange(source, destination, CopyFileRangeSpec{
			Length: 1, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
		})
		if copied != 0 || post.Size != 1 || dataSyncs != 0 || !errors.Is(err, ErrWritePostApply) || !errors.Is(err, syscall.ENOSPC) {
			t.Fatalf("failed CopyFileRange = (%d,%+v,%v), fdatasyncs=%d", copied, post, err, dataSyncs)
		}
	})
}

func TestCommitWriteZeroByteBackendErrorPublishesExactMetadataState(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "zero-write-postapply", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	target, err := v.PinWriteTarget(handle)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := v.CloseOpen(handle); err != nil {
		t.Fatal(err)
	}
	realSendfile := v.sendfile
	v.sendfile = func(outFD, _ int, _ *int64, _ int) (int, error) {
		if err := unix.Fchmod(outFD, 0o640); err != nil {
			t.Fatal(err)
		}
		return -1, syscall.ENOSPC
	}
	t.Cleanup(func() { v.sendfile = realSendfile })
	committed, assigned, post, err := target.CommitWrite(writeCommitStage(t, []byte("x")), WriteCommit{
		RequestedSize: 1, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64, Mode: WritePositioned,
	}, nil)
	if committed != 0 || assigned != 0 || !errors.Is(err, ErrWritePostApply) || !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("zero-byte CommitWrite = (%d, %d, %+v, %v), want exact postapply ENOSPC", committed, assigned, post, err)
	}
	if post.Kind != KindRegular || post.Size != 0 || post.Mode.Perm() != 0o640 {
		t.Fatalf("zero-byte CommitWrite post attr = %+v", post)
	}
}

func TestCommitWriteZeroByteBackendErrorWithLostPostStatIsUncertain(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "zero-write-unknown", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	target, err := v.PinWriteTarget(handle)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := v.CloseOpen(handle); err != nil {
		t.Fatal(err)
	}
	v.sendfile = func(int, int, *int64, int) (int, error) { return -1, syscall.ENOSPC }
	v.postStat = func(int) (Attr, error) { return Attr{}, syscall.EIO }
	committed, _, post, err := target.CommitWrite(writeCommitStage(t, []byte("x")), WriteCommit{
		RequestedSize: 1, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64, Mode: WritePositioned,
	}, nil)
	if committed != 0 || post != (Attr{}) || !errors.Is(err, ErrOutcomeUncertain) || !errors.Is(err, syscall.EIO) {
		t.Fatalf("zero-byte CommitWrite lost post-stat = (%d, %+v, %v), want uncertain EIO", committed, post, err)
	}
}

func TestFallocateUsesActualEOFAndPreservesKeepSize(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "fallocate", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)
	post, err := v.Fallocate(handle, FallocateSpec{
		Length: 4096, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
	})
	if err != nil || post.Size != 4096 {
		t.Fatalf("allocating fallocate = (size %d, %v), want 4096", post.Size, err)
	}
	post, err = v.Fallocate(handle, FallocateSpec{
		Offset: 8192, Length: 4096, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
		Mode: uint32(unix.FALLOC_FL_KEEP_SIZE),
	})
	if err != nil || post.Size != 4096 {
		t.Fatalf("KEEP_SIZE fallocate = (size %d, %v), want unchanged 4096", post.Size, err)
	}
	post, err = v.Fallocate(handle, FallocateSpec{
		Offset: 4096, Length: 1, RLimitSize: 4096, FileMaxSize: math.MaxInt64,
	})
	var limit *WriteLimitError
	if !errors.As(err, &limit) || !limit.RLimit {
		t.Fatalf("RLIMIT fallocate = %v, want typed RLIMIT refusal", err)
	}
	if fresh, statErr := v.GetattrOpen(handle); statErr != nil || fresh.Size != 4096 || post.Kind != KindRegular || post.Size != fresh.Size {
		t.Fatalf("post-refusal state = (%+v, returned %+v, %v), want exact unchanged pre-size proof", fresh, post, statErr)
	}
}

func TestFallocateFullModeExpectedSizeAndLimitPrecedence(t *testing.T) {
	const unlimited = uint64(math.MaxInt64)
	tests := []struct {
		name string
		spec FallocateSpec
		want uint64
	}{
		{name: "allocate within EOF", spec: FallocateSpec{Offset: 10, Length: 20, RLimitSize: math.MaxUint64, FileMaxSize: unlimited}, want: 100},
		{name: "allocate grows", spec: FallocateSpec{Offset: 90, Length: 20, RLimitSize: math.MaxUint64, FileMaxSize: unlimited}, want: 110},
		{name: "keep", spec: FallocateSpec{Offset: 90, Length: 20, RLimitSize: 1, FileMaxSize: unlimited, Mode: uint32(unix.FALLOC_FL_KEEP_SIZE)}, want: 100},
		{name: "punch", spec: FallocateSpec{Offset: 10, Length: 20, RLimitSize: 1, FileMaxSize: unlimited, Mode: uint32(unix.FALLOC_FL_PUNCH_HOLE | unix.FALLOC_FL_KEEP_SIZE)}, want: 100},
		{name: "zero grows", spec: FallocateSpec{Offset: 90, Length: 20, RLimitSize: math.MaxUint64, FileMaxSize: unlimited, Mode: uint32(unix.FALLOC_FL_ZERO_RANGE)}, want: 110},
		{name: "zero keep", spec: FallocateSpec{Offset: 90, Length: 20, RLimitSize: 1, FileMaxSize: unlimited, Mode: uint32(unix.FALLOC_FL_ZERO_RANGE | unix.FALLOC_FL_KEEP_SIZE)}, want: 100},
		{name: "collapse", spec: FallocateSpec{Offset: 20, Length: 10, RLimitSize: 1, FileMaxSize: unlimited, Mode: uint32(unix.FALLOC_FL_COLLAPSE_RANGE)}, want: 90},
		{name: "insert", spec: FallocateSpec{Offset: 20, Length: 10, RLimitSize: math.MaxUint64, FileMaxSize: unlimited, Mode: uint32(unix.FALLOC_FL_INSERT_RANGE)}, want: 110},
		{name: "unshare grows", spec: FallocateSpec{Offset: 90, Length: 20, RLimitSize: math.MaxUint64, FileMaxSize: unlimited, Mode: uint32(unix.FALLOC_FL_UNSHARE_RANGE)}, want: 110},
		{name: "unshare keep", spec: FallocateSpec{Offset: 90, Length: 20, RLimitSize: 1, FileMaxSize: unlimited, Mode: uint32(unix.FALLOC_FL_UNSHARE_RANGE | unix.FALLOC_FL_KEEP_SIZE)}, want: 100},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fallocateExpectedSize(100, tc.spec)
			if err != nil || got != tc.want {
				t.Fatalf("fallocateExpectedSize = (%d, %v), want (%d, nil)", got, err, tc.want)
			}
		})
	}

	t.Run("collapse may not meet EOF", func(t *testing.T) {
		_, err := fallocateExpectedSize(100, FallocateSpec{Offset: 90, Length: 10, RLimitSize: math.MaxUint64, FileMaxSize: unlimited, Mode: uint32(unix.FALLOC_FL_COLLAPSE_RANGE)})
		if !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("collapse error = %v, want EINVAL", err)
		}
	})
	t.Run("insert file maximum precedes offset", func(t *testing.T) {
		_, err := fallocateExpectedSize(100, FallocateSpec{Offset: 100, Length: 10, RLimitSize: 1, FileMaxSize: 105, Mode: uint32(unix.FALLOC_FL_INSERT_RANGE)})
		var limit *WriteLimitError
		if !errors.As(err, &limit) || limit.RLimit {
			t.Fatalf("insert error = %v, want filesystem limit", err)
		}
	})
	t.Run("insert offset precedes rlimit", func(t *testing.T) {
		_, err := fallocateExpectedSize(100, FallocateSpec{Offset: 100, Length: 10, RLimitSize: 1, FileMaxSize: unlimited, Mode: uint32(unix.FALLOC_FL_INSERT_RANGE)})
		if !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("insert error = %v, want EINVAL", err)
		}
	})
	t.Run("insert authoritative EOF proves rlimit", func(t *testing.T) {
		_, err := fallocateExpectedSize(100, FallocateSpec{Offset: 20, Length: 10, RLimitSize: 109, FileMaxSize: unlimited, Mode: uint32(unix.FALLOC_FL_INSERT_RANGE)})
		var limit *WriteLimitError
		if !errors.As(err, &limit) || !limit.RLimit {
			t.Fatalf("insert error = %v, want RLIMIT", err)
		}
	})
}

func TestXFSFallocateGeometryABI(t *testing.T) {
	if got := unsafe.Sizeof(xfsFSGeometryV1{}); got != 112 {
		t.Fatalf("xfs_fsop_geom_v1 size = %d, want 112", got)
	}
	if !fallocateNeedsAlignment(uint32(unix.FALLOC_FL_COLLAPSE_RANGE)) ||
		!fallocateNeedsAlignment(uint32(unix.FALLOC_FL_INSERT_RANGE)) || fallocateNeedsAlignment(0) {
		t.Fatal("collapse/insert alignment classification is not exact")
	}
}

func TestFallocateGeometryQueryFailureIsDefiniteBeforeDispatch(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "geometry-refusal", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)

	queryErr := errors.New("geometry unavailable")
	v.fallocateAllocationUnit = func(int) (uint64, error) { return 0, queryErr }
	dispatched := 0
	v.fallocate = func(int, uint32, int64, int64) error {
		dispatched++
		return nil
	}
	post, err := v.Fallocate(handle, FallocateSpec{
		Offset: 0, Length: 4096, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
		Mode: uint32(unix.FALLOC_FL_COLLAPSE_RANGE),
	})
	if !errors.Is(err, queryErr) || errors.Is(err, ErrOutcomeUncertain) || errors.Is(err, ErrWritePostApply) {
		t.Fatalf("Fallocate geometry error = %v, want definite query refusal", err)
	}
	if dispatched != 0 || post != (Attr{}) {
		t.Fatalf("Fallocate geometry refusal = (post=%+v, dispatched=%d), want no state and no syscall", post, dispatched)
	}
}

func TestFallocateSyscallErrorPublishesExactPartialMutation(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "partial-fallocate", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)
	if n, err := v.WriteAt(handle, []byte("abcdef"), 0); n != 6 || err != nil {
		t.Fatalf("seed = (%d, %v)", n, err)
	}

	realFallocate := v.fallocate
	v.fallocate = func(fd int, _ uint32, _ int64, _ int64) error {
		if n, err := unix.Pwrite(fd, []byte{'X'}, 1); n != 1 || err != nil {
			t.Fatalf("partial mutation = (%d, %v)", n, err)
		}
		return syscall.ENOSPC
	}
	t.Cleanup(func() { v.fallocate = realFallocate })
	post, err := v.Fallocate(handle, FallocateSpec{
		Length: 4096, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
	})
	if !errors.Is(err, ErrWritePostApply) || !errors.Is(err, syscall.ENOSPC) || errors.Is(err, ErrOutcomeUncertain) {
		t.Fatalf("Fallocate error = %v, want exact post-apply ENOSPC", err)
	}
	if post.Kind != KindRegular || post.Size != 6 {
		t.Fatalf("post attr = %+v, want exact unchanged EOF 6", post)
	}
	got := make([]byte, 6)
	if n, readErr := v.ReadAt(handle, got, 0); n != 6 || readErr != nil || string(got) != "aXcdef" {
		t.Fatalf("partially mutated data = %q (%d, %v)", got, n, readErr)
	}
}

func TestCopyFileRangeUsesAuthoritativeSourceEOFAndExactDestinationSize(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	sourceItem, _, err := v.Create(root, "copy-source", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	source, err := v.OpenFile(sourceItem, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(source)
	if n, err := v.WriteAt(source, []byte("abcdef"), 0); n != 6 || err != nil {
		t.Fatalf("seed source = (%d, %v)", n, err)
	}
	destinationItem, _, err := v.Create(root, "copy-destination", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := v.OpenFile(destinationItem, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(destination)
	copied, post, err := v.CopyFileRange(source, destination, CopyFileRangeSpec{
		Length: 6, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
	})
	if err != nil || copied != 6 || post.Size != 6 {
		t.Fatalf("CopyFileRange = (%d, size %d, %v), want 6", copied, post.Size, err)
	}
	got := make([]byte, 6)
	if n, err := v.ReadAt(destination, got, 0); n != 6 || err != nil || string(got) != "abcdef" {
		t.Fatalf("copied bytes = %q (%d, %v)", got, n, err)
	}
	if copied, post, err := v.CopyFileRange(source, destination, CopyFileRangeSpec{
		InputOffset: 6, OutputOffset: 12, Length: 4, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
	}); copied != 0 || err != nil || post != (Attr{}) {
		t.Fatalf("source EOF copy = (%d, %+v, %v), want exact no-op", copied, post, err)
	}
}

func TestCopyFileRangeZeroByteBackendErrorPublishesExactMetadataState(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	sourceItem, _, err := v.Create(root, "zero-copy-source", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	source, err := v.OpenFile(sourceItem, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(source)
	if n, err := v.WriteAt(source, []byte("x"), 0); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	destinationItem, _, err := v.Create(root, "zero-copy-destination", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := v.OpenFile(destinationItem, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(destination)
	realCopy := v.copyFileRange
	v.copyFileRange = func(_ int, _ *int64, output int, _ *int64, _ int, _ int) (int, error) {
		if err := unix.Fchmod(output, 0o640); err != nil {
			t.Fatal(err)
		}
		return 0, syscall.ENOSPC
	}
	t.Cleanup(func() { v.copyFileRange = realCopy })
	copied, post, err := v.CopyFileRange(source, destination, CopyFileRangeSpec{
		Length: 1, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
	})
	if copied != 0 || !errors.Is(err, ErrWritePostApply) || !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("zero-byte CopyFileRange = (%d, %+v, %v), want exact postapply ENOSPC", copied, post, err)
	}
	if post.Kind != KindRegular || post.Size != 0 || post.Mode.Perm() != 0o640 {
		t.Fatalf("zero-byte CopyFileRange post attr = %+v", post)
	}
}

func TestCopyFileRangeCanonicalizesRawLinuxNegativeOneError(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	sourceItem, _, err := v.Create(root, "negative-copy-source", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	source, err := v.OpenFile(sourceItem, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(source)
	if n, err := v.WriteAt(source, []byte("x"), 0); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	destinationItem, _, err := v.Create(root, "negative-copy-destination", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := v.OpenFile(destinationItem, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(destination)
	v.copyFileRange = func(_ int, _ *int64, output int, _ *int64, _ int, _ int) (int, error) {
		if err := unix.Fchmod(output, 0o640); err != nil {
			t.Fatal(err)
		}
		return -1, syscall.ENOSPC
	}
	copied, post, err := v.CopyFileRange(source, destination, CopyFileRangeSpec{
		Length: 1, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
	})
	if copied != 0 || !errors.Is(err, ErrWritePostApply) || !errors.Is(err, syscall.ENOSPC) || errors.Is(err, ErrOutcomeUncertain) {
		t.Fatalf("raw -1 CopyFileRange = (%d, %+v, %v), want exact zero-byte postapply ENOSPC", copied, post, err)
	}
	if post.Kind != KindRegular || post.Size != 0 || post.Mode.Perm() != 0o640 {
		t.Fatalf("raw -1 CopyFileRange post attr = %+v", post)
	}
}

func TestCopyFileRangeRLimitConstrainsOverwriteBelowExistingEOF(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	sourceItem, _, err := v.Create(root, "limit-source", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	source, err := v.OpenFile(sourceItem, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(source)
	if n, err := v.WriteAt(source, []byte("abcdefghij"), 0); n != 10 || err != nil {
		t.Fatal(n, err)
	}
	destinationItem, _, err := v.Create(root, "limit-destination", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := v.OpenFile(destinationItem, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(destination)
	if n, err := v.WriteAt(destination, bytes.Repeat([]byte{'x'}, 32), 0); n != 32 || err != nil {
		t.Fatal(n, err)
	}
	if copied, _, err := v.CopyFileRange(source, destination, CopyFileRangeSpec{
		OutputOffset: 9, Length: 1, RLimitSize: 8, FileMaxSize: math.MaxInt64,
	}); copied != 0 {
		t.Fatalf("copy above RLIMIT applied %d bytes", copied)
	} else {
		var limit *WriteLimitError
		if !errors.As(err, &limit) || !limit.RLimit {
			t.Fatalf("copy above existing EOF-independent RLIMIT = %v, want typed RLIMIT refusal", err)
		}
	}
	copied, post, err := v.CopyFileRange(source, destination, CopyFileRangeSpec{
		OutputOffset: 6, Length: 4, RLimitSize: 8, FileMaxSize: math.MaxInt64,
	})
	if copied != 2 || err != nil || post.Size != 32 {
		t.Fatalf("copy crossing RLIMIT = (%d, size %d, %v), want short 2 and unchanged EOF", copied, post.Size, err)
	}
}

func TestCopyFileRangeChecksOutputCeilingsBeforeSourceEOFNoop(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	sourceItem, _, err := v.Create(root, "empty-limit-source", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	source, err := v.OpenFile(sourceItem, OpenFlags{Read: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(source)
	destinationItem, _, err := v.Create(root, "empty-limit-destination", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := v.OpenFile(destinationItem, OpenFlags{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(destination)

	for _, test := range []struct {
		name       string
		offset     uint64
		rlimit     uint64
		fileMax    uint64
		wantLimit  bool
		wantRLimit bool
	}{
		{name: "below both", offset: 7, rlimit: 8, fileMax: 9},
		{name: "at rlimit", offset: 8, rlimit: 8, fileMax: 9, wantLimit: true, wantRLimit: true},
		{name: "rlimit precedes file max", offset: 9, rlimit: 8, fileMax: 9, wantLimit: true, wantRLimit: true},
		{name: "at file max", offset: 9, rlimit: math.MaxUint64, fileMax: 9, wantLimit: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			copied, post, err := v.CopyFileRange(source, destination, CopyFileRangeSpec{
				OutputOffset: test.offset,
				Length:       1,
				RLimitSize:   test.rlimit,
				FileMaxSize:  test.fileMax,
			})
			if copied != 0 || post != (Attr{}) {
				t.Fatalf("CopyFileRange = (%d, %+v, %v), want zero result", copied, post, err)
			}
			var limit *WriteLimitError
			if errors.As(err, &limit) != test.wantLimit {
				t.Fatalf("limit error = %v, wantLimit=%t", err, test.wantLimit)
			}
			if test.wantLimit && limit.RLimit != test.wantRLimit {
				t.Fatalf("RLIMIT classification = %t, want %t", limit.RLimit, test.wantRLimit)
			}
			if !test.wantLimit && err != nil {
				t.Fatalf("source-EOF copy below ceilings = %v, want no-op", err)
			}
		})
	}
}

func TestSameInodeCopyOverlapUsesEOFClippedLength(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "same-copy", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)
	if n, err := v.WriteAt(handle, []byte("abcdef"), 0); n != 6 || err != nil {
		t.Fatal(n, err)
	}
	// Requested ranges overlap, but clipping input [4,14) to EOF produces
	// [4,6), which is disjoint from output [8,10). This must not be rejected.
	copied, post, err := v.CopyFileRange(handle, handle, CopyFileRangeSpec{
		InputOffset: 4, OutputOffset: 8, Length: 10, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
	})
	if err != nil || copied != 2 || post.Size != 10 {
		t.Fatalf("EOF-clipped nonoverlap = (%d, size %d, %v), want 2/10", copied, post.Size, err)
	}
	if _, _, err := v.CopyFileRange(handle, handle, CopyFileRangeSpec{
		InputOffset: 0, OutputOffset: 2, Length: 4, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64,
	}); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("true same-inode overlap = %v, want EINVAL", err)
	}
}

func TestCanonicalCopyLocksCannotDeadlockReverseDirections(t *testing.T) {
	v := openTestVolume(t)
	left, right := [16]byte{1}, [16]byte{2}
	done := make(chan struct{}, 2)
	start := make(chan struct{})
	for _, pair := range [][2][16]byte{{left, right}, {right, left}} {
		go func(source, destination [16]byte) {
			<-start
			for range 1000 {
				unlock := v.LockMutation([][16]byte{source, destination})
				unlock()
			}
			done <- struct{}{}
		}(pair[0], pair[1])
	}
	close(start)
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for range 2 {
		select {
		case <-done:
		case <-deadline.C:
			t.Fatal("reverse-direction canonical copy locks deadlocked")
		}
	}
}

func TestWriteTransactionRLimitUsesRawLinuxEncoding(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "rlimit", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.CloseOpen(handle) })

	zero, err := v.PinWriteTarget(handle)
	if err != nil {
		t.Fatal(err)
	}
	committed, _, _, err := zero.CommitWrite(writeCommitStage(t, []byte("x")), WriteCommit{
		RequestedSize: 1, RLimitSize: 0, FileMaxSize: math.MaxInt64, Mode: WritePositioned,
	}, nil)
	_ = zero.Close()
	var limit *WriteLimitError
	if committed != 0 || !errors.As(err, &limit) || !limit.RLimit {
		t.Fatalf("finite zero RLIMIT = committed %d, err %v; want RLIMIT EFBIG", committed, err)
	}

	unlimited, err := v.PinWriteTarget(handle)
	if err != nil {
		t.Fatal(err)
	}
	committed, assigned, post, err := unlimited.CommitWrite(writeCommitStage(t, []byte("x")), WriteCommit{
		RequestedSize: 1, RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64, Mode: WritePositioned,
	}, nil)
	_ = unlimited.Close()
	if err != nil || committed != 1 || assigned != 0 || post.Size != 1 {
		t.Fatalf("RLIM_INFINITY write = (%d, %d, size %d, %v)", committed, assigned, post.Size, err)
	}
}

func TestWriteTransactionReturnsPositivePrefixAtLimits(t *testing.T) {
	for _, test := range []struct {
		name      string
		rlimit    uint64
		fileLimit uint64
	}{
		{name: "rlimit", rlimit: 2, fileLimit: 8},
		{name: "file", rlimit: math.MaxUint64, fileLimit: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := openTestVolume(t)
			root, _ := v.Root()
			item, _, err := v.Create(root, "partial", 0o600, true)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := v.OpenFile(item, OpenFlags{Write: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = v.CloseOpen(handle) })
			target, err := v.PinWriteTarget(handle)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			committed, assigned, post, err := target.CommitWrite(writeCommitStage(t, []byte("abcd")), WriteCommit{
				RequestedSize: 4, RLimitSize: test.rlimit, FileMaxSize: test.fileLimit, Mode: WritePositioned,
			}, nil)
			var limit *WriteLimitError
			if committed != 2 || assigned != 0 || post.Size != 2 || !errors.As(err, &limit) {
				t.Fatalf("limit prefix = (%d, %d, size %d, %v), want positive prefix and typed limit", committed, assigned, post.Size, err)
			}
			if limit.RLimit != (test.name == "rlimit") {
				t.Fatalf("limit kind = RLIMIT %v, want %v", limit.RLimit, test.name == "rlimit")
			}
		})
	}
}

func TestPinnedAppendAcrossAliasesSerializesWholeTransactions(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "source", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Link(item, root, "alias"); err != nil {
		t.Fatal(err)
	}
	alias, _, err := v.Lookup(root, "alias")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Forget(alias)
	first, err := v.OpenFile(item, OpenFlags{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := v.OpenFile(alias, OpenFlags{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(first)
	defer v.CloseOpen(second)
	left, err := v.PinWriteTarget(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := v.PinWriteTarget(second)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	defer right.Close()
	type result struct {
		assigned uint64
		err      error
	}
	results := make(chan result, 2)
	for target, data := range map[WriteTarget]string{left: "aaa", right: "bbb"} {
		go func(target WriteTarget, data string) {
			// CommitWrite is the store half of an authority transaction.  The
			// authority's mutation lease deliberately spans this call, exact
			// post-state sampling, and replay persistence.
			unlock := v.LockMutation([][16]byte{target.Coordinate().Stable})
			defer unlock()
			_, assigned, _, err := target.CommitWrite(bytes.NewReader([]byte(data)), WriteCommit{RequestedSize: uint64(len(data)), RLimitSize: 1 << 20, FileMaxSize: 1 << 20, Mode: WriteAppend}, make([]byte, 2))
			results <- result{assigned: assigned, err: err}
		}(target, data)
	}
	a, b := <-results, <-results
	if a.err != nil || b.err != nil || a.assigned == b.assigned || a.assigned+b.assigned != 3 {
		t.Fatalf("alias append results = %+v %+v", a, b)
	}
}

func BenchmarkStagingToTargetCopyPaths(b *testing.B) {
	const size = 1 << 20
	payload := make([]byte, size)
	stage := writeCommitStage(b, payload)
	target, err := os.CreateTemp(b.TempDir(), "portablefs-copy-benchmark-")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = target.Close() })
	resetTarget := func() {
		if err := target.Truncate(0); err != nil {
			b.Fatal(err)
		}
		if _, err := target.Seek(0, io.SeekStart); err != nil {
			b.Fatal(err)
		}
	}
	b.Run("pread-pwrite-bounce", func(b *testing.B) {
		b.SetBytes(size)
		b.ReportAllocs()
		for range b.N {
			resetTarget()
			scratch := make([]byte, size)
			if n, err := stage.ReadAt(scratch, 0); err != nil || n != len(scratch) {
				b.Fatalf("ReadAt = (%d, %v)", n, err)
			}
			if n, err := target.WriteAt(scratch, 0); err != nil || n != len(scratch) {
				b.Fatalf("WriteAt = (%d, %v)", n, err)
			}
		}
	})
	b.Run("sendfile", func(b *testing.B) {
		b.SetBytes(size)
		b.ReportAllocs()
		for range b.N {
			resetTarget()
			offset := int64(0)
			for offset < size {
				n, err := unix.Sendfile(int(target.Fd()), int(stage.Fd()), &offset, size-int(offset))
				if err != nil || n <= 0 {
					b.Fatalf("Sendfile at %d = (%d, %v)", offset, n, err)
				}
			}
		}
	})
	b.Run("direct-pwrite-retained-frame", func(b *testing.B) {
		b.SetBytes(size)
		b.ReportAllocs()
		for range b.N {
			resetTarget()
			if n, err := unix.Pwrite(int(target.Fd()), payload, 0); err != nil || n != len(payload) {
				b.Fatalf("Pwrite = (%d, %v)", n, err)
			}
		}
	})
}

func TestRenameKeepsObjectIdentity(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, before, err := v.Create(root, "old", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	stableBefore, err := v.Identity(item)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.CloseOpen(handle) })
	coordinateBefore, err := v.CoordinateOpen(handle)
	if err != nil {
		t.Fatal(err)
	}
	if coordinateBefore.Stable != stableBefore || coordinateBefore.Ino != before.Ino ||
		coordinateBefore.DeviceMajor != before.DeviceMajor || coordinateBefore.DeviceMinor != before.DeviceMinor {
		t.Fatalf("retained open coordinate = %+v, want identity %x inode %d device %d:%d",
			coordinateBefore, stableBefore, before.Ino, before.DeviceMajor, before.DeviceMinor)
	}
	if _, err := v.WriteAt(handle, []byte("identity"), 0); err != nil {
		t.Fatal(err)
	}
	if err := v.Chmod(item, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := v.Rename(root, "old", root, "new", 0); err != nil {
		t.Fatal(err)
	}
	after, err := v.Getattr(item)
	if err != nil {
		t.Fatal(err)
	}
	if before.Ino != after.Ino {
		t.Fatalf("inode changed across rename: %d -> %d", before.Ino, after.Ino)
	}
	looked, got, err := v.Lookup(root, "new")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Forget(looked)
	if got.Ino != before.Ino {
		t.Fatalf("lookup inode = %d, want %d", got.Ino, before.Ino)
	}
	stableAfter, err := v.Identity(looked)
	if err != nil {
		t.Fatal(err)
	}
	if stableAfter != stableBefore {
		t.Fatalf("write/chmod/rename changed stable identity: %x -> %x", stableBefore, stableAfter)
	}
	coordinateAfter, err := v.CoordinateOpen(handle)
	if err != nil {
		t.Fatal(err)
	}
	if coordinateAfter != coordinateBefore {
		t.Fatalf("write/chmod/rename changed retained open coordinate: %+v -> %+v", coordinateBefore, coordinateAfter)
	}
	if err := v.CloseOpen(handle); err != nil {
		t.Fatal(err)
	}
}

func TestHardLinkUsesUnprivilegedRetainedFD(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "source", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	if attr, err := v.Link(item, root, "alias"); err != nil || attr.Nlink != 2 {
		t.Fatalf("Link through retained fd: %v", err)
	}
	alias, aliasAttr, err := v.Lookup(root, "alias")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Forget(alias)
	sourceAttr, err := v.Getattr(item)
	if err != nil {
		t.Fatal(err)
	}
	if aliasAttr.Ino != sourceAttr.Ino || sourceAttr.Nlink != 2 {
		t.Fatalf("hard-link attrs source=%+v alias=%+v", sourceAttr, aliasAttr)
	}
	sourceIdentity, err := v.Identity(item)
	if err != nil {
		t.Fatal(err)
	}
	aliasIdentity, err := v.Identity(alias)
	if err != nil {
		t.Fatal(err)
	}
	if sourceIdentity != aliasIdentity {
		t.Fatalf("hard-link aliases have different stable identities: %x != %x", sourceIdentity, aliasIdentity)
	}

	symlink, _, err := v.Symlink(root, "symlink", "source")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Link(symlink, root, "symlink-alias"); err != nil {
		t.Fatalf("hard-link symlink through retained fd: %v", err)
	}
	linkedSymlink, attr, err := v.Lookup(root, "symlink-alias")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Forget(linkedSymlink)
	if attr.Kind != KindSymlink {
		t.Fatalf("hard-linked symlink kind = %v", attr.Kind)
	}
	if target, err := v.Readlink(linkedSymlink); err != nil || target != "source" {
		t.Fatalf("hard-linked symlink target = %q, %v", target, err)
	}
}

func TestExactXFSHandleIdentityIncludesGeneration(t *testing.T) {
	firstRaw := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	first, ok := exactXFSHandleIdentity(129, firstRaw)
	if !ok || first == ([16]byte{}) {
		t.Fatalf("exact XFS handle was refused: %x, %v", first, ok)
	}
	same, ok := exactXFSHandleIdentity(129, append([]byte(nil), firstRaw...))
	if !ok || same != first {
		t.Fatal("the same XFS handle did not preserve hard-link identity")
	}
	reusedRaw := append([]byte(nil), firstRaw...)
	reusedRaw[len(reusedRaw)-1]++ // model the XFS i_generation component
	reused, ok := exactXFSHandleIdentity(129, reusedRaw)
	if !ok || reused == first {
		t.Fatal("a reused inode generation aliased the prior XFS identity")
	}
	if _, ok := exactXFSHandleIdentity(1, firstRaw); ok {
		t.Fatal("a non-XFS export handle was accepted as exact production identity")
	}
	if _, ok := exactXFSHandleIdentity(129, firstRaw[:11]); ok {
		t.Fatal("a truncated XFS export handle was accepted")
	}
}

func TestSetTimesUsesAuthorityClockForNow(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "server-clock", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().Add(-time.Second).UnixNano()
	if err := v.SetTimes(item, nil, nil, false, true); err != nil {
		t.Fatal(err)
	}
	after := time.Now().Add(time.Second).UnixNano()
	attr, err := v.Getattr(item)
	if err != nil {
		t.Fatal(err)
	}
	if attr.MTimeNS < before || attr.MTimeNS > after {
		t.Fatalf("server-clock mtime = %d, want within [%d,%d]", attr.MTimeNS, before, after)
	}
	explicit := int64(1)
	if err := v.SetTimes(item, &explicit, nil, true, false); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("conflicting time intent = %v, want invalid", err)
	}
}

func TestSymlinkTargetIsDataNotHostTraversal(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	link, attr, err := v.Symlink(root, "escape", "../../outside")
	if err != nil {
		t.Fatal(err)
	}
	if attr.Kind != KindSymlink {
		t.Fatalf("kind = %v", attr.Kind)
	}
	target, err := v.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if target != "../../outside" {
		t.Fatalf("target = %q", target)
	}
	if _, err := v.OpenFile(link, OpenFlags{Read: true}); !errors.Is(err, ErrForbiddenType) {
		t.Fatalf("OpenFile(symlink) = %v", err)
	}
}

func TestShortReadPreservesProgress(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "file", fs.FileMode(0o600), true)
	if err != nil {
		t.Fatal(err)
	}
	h, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(h)
	if _, err := v.WriteAt(h, []byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	n, err := v.ReadAt(h, buf, 0)
	if n != 1 || (err != nil && !errors.Is(err, io.EOF)) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
}

func TestUserXattrWritesAreDisabledOnProjectQuotaStorage(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "file", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.SetXattr(item, "security.capability", []byte("x"), XattrUpsert); !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Fatalf("privileged xattr write = %v, want EOPNOTSUPP", err)
	}
	for _, mode := range []XattrMode{XattrUpsert, XattrCreate, XattrReplace} {
		if err := v.SetXattr(item, "user.one", []byte("value"), mode); !errors.Is(err, syscall.EOPNOTSUPP) {
			t.Fatalf("SetXattr mode %d = %v, want EOPNOTSUPP", mode, err)
		}
	}
}

func TestGetXattrHandlesConcurrentReplacement(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "file", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	v.mu.RLock()
	fd, err := v.reopen(v.objects[item].res.fd, unix.O_RDWR, KindRegular)
	v.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Fsetxattr(fd, "user.race", []byte("seed"), 0); errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
		t.Skip("test filesystem has no user xattrs")
	} else if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	setterErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		small, large := []byte("x"), make([]byte, 2<<10)
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			value := small
			if i&1 != 0 {
				value = large
			}
			if err := unix.Fsetxattr(fd, "user.race", value, unix.XATTR_REPLACE); err != nil {
				setterErr <- err
				return
			}
		}
	}()
	for range 2000 {
		// Never EAGAIN: getxattr(2) cannot return it, so a client that gets
		// one has no correct handling for it. The probe/fetch race resolves
		// against the kernel's own value ceiling instead.
		value, err := v.GetXattr(item, "user.race")
		if err != nil {
			close(done)
			wg.Wait()
			t.Fatalf("GetXattr during replacement: %v", err)
		}
		if err == nil && len(value) != len("seed") && len(value) != 1 && len(value) != 2<<10 {
			close(done)
			wg.Wait()
			t.Fatalf("GetXattr returned torn length %d", len(value))
		}
	}
	close(done)
	wg.Wait()
	select {
	case err := <-setterErr:
		t.Fatal(err)
	default:
	}
}

func TestCreateAndMkdirDoNotApplyWorkerUmask(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	previous := unix.Umask(0o077)
	t.Cleanup(func() { unix.Umask(previous) })

	_, attr, err := v.Create(root, "wide-file", 0o777, true)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Mode.Perm() != 0o777 {
		t.Fatalf("created file mode = %o, want 777", attr.Mode.Perm())
	}
	_, attr, err = v.Mkdir(root, "wide-directory", 0o777)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Mode.Perm() != 0o777 {
		t.Fatalf("created directory mode = %o, want 777", attr.Mode.Perm())
	}
	if _, attr, err := v.Create(root, "wide-file", 0o700, false); err != nil {
		t.Fatal(err)
	} else if attr.Mode.Perm() != 0o777 {
		t.Fatalf("opening an existing file changed mode to %o", attr.Mode.Perm())
	}
}

func TestChmodCanRestoreModeZeroObject(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "sealed", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Chmod(item, 0); err != nil {
		t.Fatal(err)
	}
	if err := v.Chmod(item, 0o600); err != nil {
		t.Fatalf("restore chmod after mode 000: %v", err)
	}
	attr, err := v.Getattr(item)
	if err != nil || attr.Mode.Perm() != 0o600 {
		t.Fatalf("restored attr = %+v, %v", attr, err)
	}
}

func TestReadDirCanSeekToIssuedCookie(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	for _, name := range []string{"a", "b", "c", "d"} {
		if _, _, err := v.Create(root, name, 0o600, true); err != nil {
			t.Fatal(err)
		}
	}
	handle, err := v.OpenFile(root, OpenFlags{Read: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)
	first, next, verifier, _, _, err := v.ReadDirOpen(handle, 0, [16]byte{}, 2)
	if err != nil || len(first) != 2 || next != 2 {
		t.Fatalf("first page = %v, %d, %v", first, next, err)
	}
	if _, _, _, _, _, err := v.ReadDirOpen(handle, next, verifier, 2); err != nil {
		t.Fatal(err)
	}
	back, next, _, _, _, err := v.ReadDirOpen(handle, 1, verifier, 1)
	if err != nil || len(back) != 1 || next != 2 || back[0].Name != first[1].Name {
		t.Fatalf("seeked page = %v, %d, %v", back, next, err)
	}
}

func TestReadDirStatDoesNotAllocateCapability(t *testing.T) {
	v := openTestVolume(t)
	root, _ := v.Root()
	if _, _, err := v.Create(root, "entry", 0o600, true); err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(root, OpenFlags{Read: true})
	if err != nil {
		t.Fatal(err)
	}
	defer v.CloseOpen(handle)
	v.mu.RLock()
	before := len(v.objects)
	v.mu.RUnlock()
	if _, err := v.StatOpenDirChild(handle, "entry"); err != nil {
		t.Fatal(err)
	}
	v.mu.RLock()
	after := len(v.objects)
	v.mu.RUnlock()
	if after != before {
		t.Fatalf("object capability count changed: %d -> %d", before, after)
	}
}

func TestForeignOwnerFailsClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires chown privilege")
	}
	v := openTestVolume(t)
	root, _ := v.Root()
	item, _, err := v.Create(root, "foreign", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	v.mu.RLock()
	fd := v.objects[item].res.fd
	v.mu.RUnlock()
	if err := unix.Fchownat(fd, "", 12345, 12345, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if _, err := v.StatOpenDirChild(mustOpenDir(t, v, root), "foreign"); !errors.Is(err, ErrProjectIsolation) {
		t.Fatalf("foreign owner stat = %v", err)
	}
}

func TestFenceRejectsDataOperationsButAllowsCleanup(t *testing.T) {
	v := openTestVolume(t)
	root, err := v.Root()
	if err != nil {
		t.Fatal(err)
	}
	item, _, err := v.Create(root, "fenced", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	v.Fence(syscall.EIO)
	if !errors.Is(v.Health(), ErrFenced) {
		t.Fatalf("Health = %v, want ErrFenced", v.Health())
	}
	if _, err := v.Root(); !errors.Is(err, ErrFenced) {
		t.Fatalf("Root after fence = %v, want ErrFenced", err)
	}
	if _, err := v.ReadAt(handle, make([]byte, 1), 0); !errors.Is(err, ErrFenced) {
		t.Fatalf("ReadAt after fence = %v, want ErrFenced", err)
	}
	if _, err := v.StatFS(); !errors.Is(err, ErrFenced) {
		t.Fatalf("StatFS after fence = %v, want ErrFenced", err)
	}
	if err := v.SyncFS(); !errors.Is(err, ErrFenced) {
		t.Fatalf("SyncFS after fence = %v, want ErrFenced", err)
	}
	if err := v.CloseOpen(handle); err != nil {
		t.Fatalf("CloseOpen cleanup after fence: %v", err)
	}
	if err := v.Forget(item); err != nil {
		t.Fatalf("Forget cleanup after fence: %v", err)
	}
}

func mustOpenDir(t *testing.T, v *Volume, item Capability) Capability {
	t.Helper()
	handle, err := v.OpenFile(item, OpenFlags{Read: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.CloseOpen(handle) })
	return handle
}

// A name that disappears while this authority still holds the object open is
// the ordinary two-mount race: a peer unlinks or renames the name during a
// create or lookup. The identity's subject is the open descriptor, not the
// pathname, so derivation must keep working after the name is gone. Two
// regressions hide here: an earlier revision re-resolved the pathname and
// reported a healthy held-open object as stale, and the revision before that
// touched NameToHandleAt's zero FileHandle before its error and took the
// whole authority process down.
func TestStableIdentityFDSurvivesConcurrentUnlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "victim")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, err := stableIdentityFD(int(f.Fd()), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	after, err := stableIdentityFD(int(f.Fd()), false)
	if err != nil {
		t.Fatalf("identity of a held-open object with no name = %v; an open descriptor is the identity's subject", err)
	}
	if before != after {
		t.Fatalf("identity changed across an unlink of the name: %x != %x", before, after)
	}
}
