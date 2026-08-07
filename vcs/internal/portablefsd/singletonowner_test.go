package portablefsd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

func TestSingletonAcquisitionPublishesItsOwner(t *testing.T) {
	dir := privateTempDir(t)
	lock, err := acquireStateSingleton(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSingleton(lock)

	record, err := readSingletonOwner(lock.file)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatal("the lock must name its holder; an unnamed lock can never be proven stale")
	}
	if record.PID != os.Getpid() {
		t.Fatalf("owner pid = %d, want %d", record.PID, os.Getpid())
	}
	if verdict, why := classifySingletonHolder(record); verdict != holderLive {
		t.Fatalf("this process must classify as live, got %s (%s)", verdict, why)
	}
}

// A ZOMBIE IS PROVABLY GONE. This is the same proof the incident needed: the
// process still exists, is still listed, and still answers kill(pid, 0) — and
// has nonetheless run its last instruction.
func TestProcessInExitClassifiesAsGone(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a helper process: %v", err)
	}
	pid := cmd.Process.Pid
	defer func() { _, _ = cmd.Process.Wait() }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		state, err := inspectProcessState(pid)
		if err == errProcessStateUnsupported {
			t.Skip("this platform cannot classify process exit state")
		}
		if err == nil && state.exiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("an exited-but-unreaped child never classified as exiting (state %+v, err %v)", state, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDepartedHolderClassifiesAsGoneAndLiveHolderDoesNot(t *testing.T) {
	live, err := processStartIdentity(os.Getpid())
	if err == errProcessStateUnsupported {
		t.Skip("this platform cannot classify process state")
	}
	if err != nil {
		t.Fatal(err)
	}
	if verdict, _ := classifySingletonHolder(&singletonOwnerRecord{
		SchemaVersion: singletonOwnerSchemaVersion, PID: os.Getpid(), StartIdentity: live,
	}); verdict != holderLive {
		t.Fatalf("a live holder must never be classified gone, got %s", verdict)
	}
	// Same pid, different start identity: the pid was recycled, so the RECORDED
	// holder is gone even though something is running under that number.
	if verdict, _ := classifySingletonHolder(&singletonOwnerRecord{
		SchemaVersion: singletonOwnerSchemaVersion, PID: os.Getpid(), StartIdentity: live + "x",
	}); verdict != holderGone {
		t.Fatalf("a recycled pid must classify as gone, got %s", verdict)
	}
	// No owner record at all is never proof of death.
	if verdict, _ := classifySingletonHolder(nil); verdict != holderUnprovable {
		t.Fatalf("an unnamed holder must be unprovable, got %s", verdict)
	}
}

// holdSingletonLockAs takes the singleton lock through a SEPARATE open file
// description and stamps it with the given owner record. flock conflicts across
// descriptions even within one process, so this is a faithful stand-in for a
// holder that will never close its descriptors.
func holdSingletonLockAs(t *testing.T, dir string, record singletonOwnerRecord) *os.File {
	t.Helper()
	pinned, err := privatepath.OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	file, err := privatepath.OpenLockFile(pinned, dir, ".portablefsd-state.lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	guard := &singletonLock{dirPath: dir, name: ".portablefsd-state.lock", file: file}
	if err := writeOwnerRecordForTest(guard, record); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	})
	return file
}

func writeOwnerRecordForTest(lock *singletonLock, record singletonOwnerRecord) error {
	body := []byte(`{"schemaVersion":1,"pid":` + itoa(record.PID) +
		`,"startIdentity":"` + record.StartIdentity + `","version":"","owner":""}` + "\n")
	if err := lock.file.Truncate(0); err != nil {
		return err
	}
	_, err := lock.file.WriteAt(body, 0)
	return err
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	return string(digits)
}

// THE INCIDENT, INVERTED. The lock is held by a descriptor whose recorded owner
// is provably gone. On the base revision that state was permanent and no
// portablefsd could ever start again on that machine without a reboot.
func TestSingletonLockIsTakenOverFromAProvablyDepartedHolder(t *testing.T) {
	if _, err := processStartIdentity(os.Getpid()); err == errProcessStateUnsupported {
		t.Skip("this platform cannot classify process state")
	}
	// A REAL departed process: started, exited, and reaped. Its pid names
	// nothing, which is exactly what classifySingletonHolder must prove.
	departed := exec.Command("/bin/sh", "-c", "exit 0")
	if err := departed.Start(); err != nil {
		t.Skipf("cannot start a helper process: %v", err)
	}
	departedPID := departed.Process.Pid
	if err := departed.Wait(); err != nil {
		t.Fatal(err)
	}
	if verdict, why := classifySingletonHolder(&singletonOwnerRecord{
		SchemaVersion: singletonOwnerSchemaVersion, PID: departedPID, StartIdentity: "0:0",
	}); verdict != holderGone {
		t.Skipf("pid %d was recycled before the test could use it (%s)", departedPID, why)
	}

	dir := privateTempDir(t)
	stuck := holdSingletonLockAs(t, dir, singletonOwnerRecord{
		SchemaVersion: singletonOwnerSchemaVersion,
		PID:           departedPID,
		StartIdentity: "0:0",
	})

	lock, err := acquireStateSingleton(dir)
	if err != nil {
		t.Fatalf("a lock whose recorded holder is provably gone must be recoverable without a reboot: %v", err)
	}
	defer releaseSingleton(lock)

	// The departed holder keeps its lock on an inode that is no longer named.
	if err := syscall.Flock(int(stuck.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("the stuck holder must keep its own lock undisturbed: %v", err)
	}
	// And the new owner genuinely owns the canonical lock: a third acquirer fails.
	if extra, err := acquireStateSingleton(dir); err == nil {
		releaseSingleton(extra)
		t.Fatal("takeover must leave exactly one owner of the canonical lock")
	}
	record, err := readSingletonOwner(lock.file)
	if err != nil || record == nil || record.PID != os.Getpid() {
		t.Fatalf("the new owner must publish itself: %+v (%v)", record, err)
	}
}

func TestSingletonLockIsNeverStolenFromALiveHolder(t *testing.T) {
	identity, err := processStartIdentity(os.Getpid())
	if err == errProcessStateUnsupported {
		t.Skip("this platform cannot classify process state")
	}
	if err != nil {
		t.Fatal(err)
	}
	dir := privateTempDir(t)
	holdSingletonLockAs(t, dir, singletonOwnerRecord{
		SchemaVersion: singletonOwnerSchemaVersion,
		PID:           os.Getpid(),
		StartIdentity: identity,
	})
	lock, err := acquireStateSingleton(dir)
	if err == nil {
		releaseSingleton(lock)
		t.Fatal("a live holder's lock must never be taken over")
	}
	if !strings.Contains(err.Error(), "another portablefsd owns") {
		t.Fatalf("the refusal must name the conflict: %v", err)
	}
	if !strings.Contains(err.Error(), "live") {
		t.Fatalf("the refusal must name the holder's state so an operator can act: %v", err)
	}
}

func TestSingletonLockWithNoOwnerRecordIsNeverTakenOver(t *testing.T) {
	dir := privateTempDir(t)
	// An unstamped lock: a holder from an older build, or a file created by
	// something else entirely. Absence of a record is not evidence of death.
	pinned, err := privatepath.OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	file, err := privatepath.OpenLockFile(pinned, dir, ".portablefsd-state.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

	if lock, err := acquireStateSingleton(dir); err == nil {
		releaseSingleton(lock)
		t.Fatal("an unprovable holder must be treated as live")
	}
	if _, err := os.Lstat(filepath.Join(dir, ".portablefsd-state.lock.replacement")); err == nil {
		t.Fatal("a refused takeover must not leave a replacement lock behind")
	}
}

// privateTempDir is a 0700 temp dir: privatepath refuses anything looser, and
// the Go test temp dir is 0755.
func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}
