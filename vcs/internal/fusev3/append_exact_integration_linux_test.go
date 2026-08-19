//go:build linux

package fusev3

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// appendRecord is a distinguishable, fixed-width record. Fixed width makes a
// torn or misplaced record obvious without having to parse the file.
const appendRecordWidth = 64

func appendRecord(writer, index int) []byte {
	record := []byte(fmt.Sprintf("writer=%04d record=%06d ", writer, index))
	return append(record, bytes.Repeat([]byte{byte('a' + writer%26)}, appendRecordWidth-len(record)-1)...)
}

// requireExactAppendMultiset proves every record landed exactly once, whole, and
// record-aligned. The interleaving is deliberately unconstrained: POSIX promises
// atomic placement for O_APPEND, not an order.
func requireExactAppendMultiset(t *testing.T, path string, writers, records int) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	want := writers * records
	if len(content) != want*appendRecordWidth {
		t.Fatalf("%s holds %d bytes, want %d whole records (%d bytes)", path, len(content), want, want*appendRecordWidth)
	}
	got := make([]string, 0, want)
	for offset := 0; offset < len(content); offset += appendRecordWidth {
		line := content[offset : offset+appendRecordWidth]
		if line[len(line)-1] != '\n' {
			t.Fatalf("record at offset %d is torn: %q", offset, string(line))
		}
		got = append(got, string(line))
	}
	expected := make([]string, 0, want)
	for writer := range writers {
		for index := range records {
			expected = append(expected, string(appendRecord(writer, index))+"\n")
		}
	}
	sort.Strings(got)
	sort.Strings(expected)
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("record multiset differs at %d: got %q, want %q", i, got[i], expected[i])
		}
	}
}

func appendAll(t *testing.T, path string, writer, records int, start *sync.WaitGroup, failures chan<- error) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		failures <- fmt.Errorf("open %s for append: %w", path, err)
		start.Done()
		return
	}
	defer func() { _ = file.Close() }()
	start.Done()
	start.Wait()
	for index := range records {
		record := append(appendRecord(writer, index), '\n')
		if n, err := file.Write(record); err != nil || n != len(record) {
			failures <- fmt.Errorf("append writer %d record %d = (%d, %v)", writer, index, n, err)
			return
		}
	}
}

// TestConcurrentAppendersOnOneMountLoseNoRecord proves the exactness the kernel
// already guarantees within one mount: IOCB_APPEND holds the inode lock, so the
// authority sees one append at a time on this mount's inode.
func TestConcurrentAppendersOnOneMountLoseNoRecord(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
	const (
		writers = 6
		records = 40
	)
	path := f.join(0, "single-mount-append")
	mustWrite(t, path, nil, 0o600)

	var start, done sync.WaitGroup
	failures := make(chan error, writers)
	start.Add(writers)
	for writer := range writers {
		done.Add(1)
		go func(writer int) {
			defer done.Done()
			appendAll(t, path, writer, records, &start, failures)
		}(writer)
	}
	done.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	requireExactAppendMultiset(t, path, writers, records)
}

// TestConcurrentAppendersAcrossMountsLoseNoRecord is the headline case. Two
// kernel mounts have two independent i_size values, so nothing in either kernel
// can place these appends; only the authority's EOF under the per-inode writer
// stripe can, and it must place every one of them.
func TestConcurrentAppendersAcrossMountsLoseNoRecord(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	const (
		perMount = 4
		records  = 40
		writers  = 2 * perMount
	)
	mustWrite(t, f.join(0, "cross-mount-append"), nil, 0o600)

	var start, done sync.WaitGroup
	failures := make(chan error, writers)
	start.Add(writers)
	for writer := range writers {
		done.Add(1)
		go func(writer int) {
			defer done.Done()
			appendAll(t, f.join(writer%2, "cross-mount-append"), writer, records, &start, failures)
		}(writer)
	}
	done.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	requireExactAppendMultiset(t, f.join(0, "cross-mount-append"), writers, records)
	requireExactAppendMultiset(t, f.join(1, "cross-mount-append"), writers, records)
}

// TestShellAppendRedirectionAcrossMounts runs the real workload shape: a shell
// >> redirection, which is an O_APPEND open per line, and tee -a.
func TestShellAppendRedirectionAcrossMounts(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2})
	path := f.join(0, "shell-append")
	mustWrite(t, path, nil, 0o600)
	const lines = 32
	var want strings.Builder
	for i := range lines {
		f.runWorkload("sh", "-c", fmt.Sprintf("echo line-%03d >> %s", i, f.join(i%2, "shell-append")))
		fmt.Fprintf(&want, "line-%03d\n", i)
	}
	for i := range lines {
		f.runWorkload("sh", "-c", fmt.Sprintf("echo tee-%03d | tee -a %s >/dev/null", i, f.join(i%2, "shell-append")))
		fmt.Fprintf(&want, "tee-%03d\n", i)
	}
	requireExactFile(t, f.join(1, "shell-append"), []byte(want.String()), "shell append redirection")
}

// TestKernelSizeShadowTracksTheKernelAcrossRandomOperations is the audit the
// placement rule depends on: if the shadow ever disagreed with the kernel's
// i_size, an unforwarded RWF_APPEND would be placed at the wrong offset. fstat
// reports exactly the value being shadowed, so the two must never diverge.
func TestKernelSizeShadowTracksTheKernelAcrossRandomOperations(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1})
	path := f.join(0, "shadow-audit")
	mustWrite(t, path, nil, 0o600)
	file := mustOpenFile(t, path, os.O_RDWR, 0)
	appendFile := mustOpenFile(t, path, os.O_WRONLY|os.O_APPEND, 0)

	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	inode := stat.Ino
	shadow := f.mounts[0].raw.sizes

	requireAgreement := func(step int, operation string) {
		t.Helper()
		var stat unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
			t.Fatalf("step %d (%s): fstat: %v", step, operation, err)
		}
		size, known := shadow.lookup(inode)
		if !known {
			t.Fatalf("step %d (%s): the kernel-size shadow became unknown; every later write would be refused", step, operation)
		}
		if size != uint64(stat.Size) {
			t.Fatalf("step %d (%s): shadow = %d, kernel i_size = %d", step, operation, size, stat.Size)
		}
	}

	random := rand.New(rand.NewSource(20260819))
	payload := deterministicIntegrationData(4096, 11)
	for step := range 200 {
		switch random.Intn(6) {
		case 0:
			size := 1 + random.Intn(len(payload))
			offset := random.Intn(1 << 16)
			if _, err := unix.Pwrite(int(file.Fd()), payload[:size], int64(offset)); err != nil {
				t.Fatalf("step %d: pwrite: %v", step, err)
			}
			requireAgreement(step, "positioned write")
		case 1:
			size := 1 + random.Intn(len(payload))
			if _, err := unix.Write(int(appendFile.Fd()), payload[:size]); err != nil {
				t.Fatalf("step %d: append: %v", step, err)
			}
			requireAgreement(step, "append")
		case 2:
			size := int64(random.Intn(1 << 16))
			if err := unix.Ftruncate(int(file.Fd()), size); err != nil {
				t.Fatalf("step %d: ftruncate: %v", step, err)
			}
			requireAgreement(step, "truncate")
		case 3:
			buffer := make([]byte, 1+random.Intn(len(payload)))
			if _, err := unix.Pread(int(file.Fd()), buffer, int64(random.Intn(1<<16))); err != nil {
				t.Fatalf("step %d: pread: %v", step, err)
			}
			requireAgreement(step, "read")
		case 4:
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("step %d: stat: %v", step, err)
			}
			requireAgreement(step, "path stat")
		case 5:
			size := 1 + random.Intn(len(payload))
			written, err := unix.Pwritev2(int(file.Fd()), [][]byte{payload[:size]}, 0, unix.RWF_APPEND)
			if err != nil && !errorIsUnsupported(err) {
				t.Fatalf("step %d: RWF_APPEND: %v", step, err)
			}
			if err == nil && written != size {
				t.Fatalf("step %d: RWF_APPEND wrote %d bytes, want %d", step, written, size)
			}
			requireAgreement(step, "per-call append")
		}
	}
}

func errorIsUnsupported(err error) bool {
	return err == syscall.EOPNOTSUPP || err == syscall.EINVAL || err == syscall.ENOTSUP
}
