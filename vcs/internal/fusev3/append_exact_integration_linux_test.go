//go:build linux

package fusev3

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
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
