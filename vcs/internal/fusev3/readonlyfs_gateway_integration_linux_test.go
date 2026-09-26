//go:build linux

package fusev3_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/readonlyfs"
)

// The gateway reads buffered bytes through BreakForRead while retaining neither
// cache permission nor Mac compatibility-writer participation.
func TestFilesGatewayAttachesToRealXFSWithoutObstructingAMountingPeer(t *testing.T) {
	// One kernel mount is the mutator. The gateway is the second participant,
	// and it is deliberately not a mount: it projects no namespace at all.
	peer := fusev3.NewGatewayPeerFixture(t, 1)

	const (
		name    = "served"
		listing = "listing"
	)
	initial := bytes.Repeat([]byte{'a'}, 48*1024)
	writer, err := os.OpenFile(peer.Join(0, name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Write(initial); err != nil {
		t.Fatal(err)
	}
	if peer.DelegatedIdentityCount() == 0 {
		t.Fatal("writer has no delegation")
	}
	if err := os.Mkdir(peer.Join(0, listing), 0o700); err != nil {
		t.Fatalf("create a directory through the mount: %v", err)
	}
	mustWriteFile(t, peer.Join(0, listing, "one"), []byte("1"))
	mustWriteFile(t, peer.Join(0, listing, "two"), []byte("2"))

	// Exactly the six fields cmd/portablefs-files/main.go fills from a
	// control-plane grant, and nothing else. RequestTimeout is left zero there,
	// so it is left zero here: production runs on readonlyfs's own default, and
	// a test that set one would be qualifying a configuration nothing deploys.
	dialContext, cancelDial := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelDial()
	gateway, err := readonlyfs.Dial(dialContext, readonlyfs.Config{
		Address:              peer.AuthorityAddress(),
		AuthorityCAPEM:       peer.AuthorityCAPEM(),
		AuthorityServerName:  peer.ServerName(),
		Capability:           peer.Capability(),
		ClientCertificatePEM: peer.ClientCertificatePEM(),
		ClientPrivateKeyPEM:  peer.ClientPrivateKeyPEM(),
		VolumeID:             peer.VolumeID(),
	})
	if err != nil {
		t.Fatalf("dial the files gateway against the real authority: %v (%s)", err, peer.Diagnostics())
	}
	closed := false
	defer func() {
		if !closed {
			_ = gateway.Close()
		}
	}()

	// The profile is read off the wire rather than assumed from the constant in
	// readonlyfs.Dial. What had never been proven is what the authority
	// receives and accepts; the mount's own attach is already behind us, so the
	// most recent one is the gateway's.
	if got := peer.LastAttachProfile(); got != fusev3.CachelessReaderProfile() {
		t.Fatalf("the authority accepted the gateway under frontend profile %v, want %v", got, fusev3.CachelessReaderProfile())
	}
	if count := peer.ActiveParticipants(); count != 2 {
		t.Fatalf("the volume has %d visibility participants, want the mount and the gateway", count)
	}

	if peer.DelegatedIdentityCount() == 0 {
		t.Fatal("gateway activation recalled the writer")
	}
	ctx := context.Background()
	servedKey := mustEncodePath(t, name)
	// The root is the empty key.
	rootPathKey := mustEncodePath(t)

	page, err := gateway.List(ctx, rootPathKey, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range page.Entries {
		if string(entry.Name) == name {
			found = true
			if entry.Attr.Size != uint64(len(initial)) {
				t.Fatalf("gateway listing size=%d", entry.Attr.Size)
			}
		}
	}
	if !found {
		t.Fatal("gateway listing omitted delegated file")
	}
	if peer.DelegatedIdentityCount() == 0 {
		t.Fatal("gateway listing retired the writer")
	}
	// Reads: the gateway resolves an opaque path, opens, and reads bytes that
	// came out of real XFS through the real handler.
	requireGatewayContent(t, ctx, gateway, servedKey, initial, "the gateway's first read")

	// Attribute versions and the directory cut use the same storage domain.
	requireGatewayListing(t, ctx, gateway, mustEncodePath(t, listing), []string{"one", "two"}, "the gateway's listing of a peer-written directory")

	// No gateway acknowledgment is needed for this write to complete.
	mutated := bytes.Repeat([]byte{'b'}, 72*1024)
	writeStart := time.Now()
	if err := os.WriteFile(peer.Join(0, name), mutated, 0o600); err != nil {
		t.Fatalf("peer mount rewrite while the gateway is attached: %v (%s)", err, peer.Diagnostics())
	}
	writeElapsed := time.Since(writeStart)
	// Keep a bound well below recall expiry so waiting for a nonexistent
	// gateway repair worker cannot satisfy the test.
	if writeElapsed > peer.RepairBudget()/4 {
		t.Fatalf("a rewrite beside the attached gateway took %s, more than a quarter of the %s recall budget: the gateway obstructed the writer (%s)",
			writeElapsed, peer.RepairBudget(), peer.Diagnostics())
	}
	requireGatewayContent(t, ctx, gateway, servedKey, mutated, "the gateway's read after the peer mutation")

	// Exercise breaks while the peer repeatedly truncates and rewrites.
	const rounds = 24
	payloads := [2][]byte{mutated, initial}
	readContext, stopReads := context.WithCancel(ctx)
	var reads atomic.Int64
	var readFailure atomic.Pointer[error]
	var reading sync.WaitGroup
	reading.Add(1)
	go func() {
		defer reading.Done()
		for readContext.Err() == nil {
			file, openErr := gateway.OpenFile(readContext, servedKey)
			if openErr != nil {
				if readContext.Err() != nil {
					return
				}
				recorded := fmt.Errorf("gateway open during a peer mutation loop: %w", openErr)
				readFailure.CompareAndSwap(nil, &recorded)
				return
			}
			buffer := make([]byte, file.Attr().Size)
			// Content is deliberately not asserted here. A read concurrent with
			// a multi-chunk rewrite may legitimately observe an intermediate
			// size; what this loop is about is that the reads complete and cost
			// the writer nothing.
			// io.EOF is the ordinary answer to a short read, and the size this
			// buffer was cut to came from an attribute the concurrent rewrite may
			// already have replaced. It is not a failure to read.
			_, readErr := file.ReadAt(readContext, buffer, 0)
			closeErr := file.Close(readContext)
			if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, context.Canceled) {
				recorded := fmt.Errorf("gateway read during a peer mutation loop: %w", readErr)
				readFailure.CompareAndSwap(nil, &recorded)
				return
			}
			if closeErr != nil && readContext.Err() == nil {
				recorded := fmt.Errorf("gateway handle release during a peer mutation loop: %w", closeErr)
				readFailure.CompareAndSwap(nil, &recorded)
				return
			}
			reads.Add(1)
		}
	}()

	loopStart := time.Now()
	for round := range rounds {
		before := reads.Load()
		// Every few rounds, enumerate the directory the rewrite is happening in.
		// A page whose own entry is being rewritten underneath it is the case
		// stabilization exists for, and the assertion is that it terminates with
		// the right names rather than exhausting its attempts into EAGAIN.
		if round%8 == 0 {
			requireGatewayListing(t, ctx, gateway, rootPathKey, []string{name, listing}, fmt.Sprintf("round %d: the gateway's listing during a concurrent rewrite", round))
		}
		if err := os.WriteFile(peer.Join(0, name), payloads[round%2], 0o600); err != nil {
			stopReads()
			reading.Wait()
			t.Fatalf("round %d: peer mount write while the gateway reads: %v (%s)", round, err, peer.Diagnostics())
		}
		deadline := time.Now().Add(2 * time.Second)
		for reads.Load() <= before && readFailure.Load() == nil && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if recorded := readFailure.Load(); recorded != nil {
			stopReads()
			reading.Wait()
			t.Fatalf("round %d: %v (%s)", round, *recorded, peer.Diagnostics())
		}
	}
	loopElapsed := time.Since(loopStart)
	stopReads()
	reading.Wait()

	// Vacuity guard. A loop whose reader never got a request in would prove
	// nothing about a reader obstructing a writer.
	if completed := reads.Load(); completed < rounds {
		t.Fatalf("only %d gateway reads overlapped %d peer rewrites; the window this test exists for was not entered", completed, rounds)
	}
	// Expiry must not be the mechanism that lets the writer proceed.
	if perRound := loopElapsed / rounds; perRound > peer.RepairBudget()/4 {
		t.Fatalf("%d rewrites beside a continuously reading gateway averaged %s each, more than a quarter of the %s recall budget (%s)",
			rounds, perRound, peer.RepairBudget(), peer.Diagnostics())
	}
	if fenced := peer.FencedSessions(); fenced != 0 {
		t.Fatalf("%d session(s) were fenced while the gateway read beside a mutating mount; a recall budget was exhausted (%s)", fenced, peer.Diagnostics())
	}
	if err := gateway.Err(); err != nil {
		t.Fatalf("the gateway session ended during the mutation loop: %v", err)
	}
	if cause := peer.MountFatal(0); cause != nil {
		t.Fatalf("the mutating mount was revoked beside the gateway: %v", cause)
	}

	// Quiescent, the ordering is exact: a read issued after the last write
	// returned observes what that write left.
	requireGatewayContent(t, ctx, gateway, servedKey, payloads[(rounds-1)%2], "the gateway's read after the mutation loop")

	// A clean authenticated detach leaves no terminal error.
	if err := gateway.Close(); err != nil {
		t.Fatalf("close the gateway session: %v", err)
	}
	closed = true
	if err := gateway.Err(); err != nil {
		t.Fatalf("the gateway reported a terminal cause across a clean close: %v", err)
	}

	// Departure must leave no outstanding reader obligation.
	afterDetach := time.Now()
	if err := os.WriteFile(peer.Join(0, name), initial, 0o600); err != nil {
		t.Fatalf("peer mount write after the gateway detached: %v (%s)", err, peer.Diagnostics())
	}
	if elapsed := time.Since(afterDetach); elapsed > peer.RepairBudget()/4 {
		t.Fatalf("the first write after the gateway detached took %s; the gateway left an undischarged obligation (%s)", elapsed, peer.Diagnostics())
	}
	got, err := os.ReadFile(peer.Join(0, name))
	if err != nil {
		t.Fatalf("read the mount after the gateway detached: %v", err)
	}
	if !bytes.Equal(got, initial) {
		t.Fatalf("the mount holds %d bytes after the gateway detached, want %d", len(got), len(initial))
	}
	// A clean detach fences nobody. Reaching this line with a fence recorded
	// would mean the departure was taken as a failure.
	if fenced := peer.FencedSessions(); fenced != 0 {
		t.Fatalf("%d session(s) were fenced across the gateway's detach", fenced)
	}
	if cause := peer.MountFatal(0); cause != nil {
		t.Fatalf("the mount was revoked across the gateway's detach: %v", cause)
	}
}

func requireGatewayListing(t *testing.T, ctx context.Context, gateway *readonlyfs.Client, pathKey string, want []string, what string) {
	t.Helper()
	got := make([]string, 0, len(want))
	var cursor *readonlyfs.Cursor
	for {
		page, err := gateway.List(ctx, pathKey, 16, cursor)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		for _, entry := range page.Entries {
			got = append(got, string(entry.Name))
		}
		if page.Next == nil {
			break
		}
		cursor = page.Next
	}
	slices.Sort(got)
	sortedWant := slices.Clone(want)
	slices.Sort(sortedWant)
	if !slices.Equal(got, sortedWant) {
		t.Fatalf("%s: listed %q, want exactly %q", what, got, sortedWant)
	}
}

func mustWriteFile(t *testing.T, path string, payload []byte) {
	t.Helper()
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustEncodePath(t *testing.T, components ...string) string {
	t.Helper()
	raw := make([][]byte, 0, len(components))
	for _, component := range components {
		raw = append(raw, []byte(component))
	}
	key, err := readonlyfs.EncodePath(raw)
	if err != nil {
		t.Fatalf("encode gateway path %q: %v", components, err)
	}
	return key
}

func requireGatewayContent(t *testing.T, ctx context.Context, gateway *readonlyfs.Client, pathKey string, want []byte, what string) {
	t.Helper()
	file, err := gateway.OpenFile(ctx, pathKey)
	if err != nil {
		t.Fatalf("%s: open: %v", what, err)
	}
	defer func() {
		if err := file.Close(ctx); err != nil {
			t.Errorf("%s: release the authority handle: %v", what, err)
		}
	}()
	if size := file.Attr().Size; size != uint64(len(want)) {
		t.Fatalf("%s: the gateway reports size %d, want %d", what, size, len(want))
	}
	got := make([]byte, len(want))
	read, err := file.ReadAt(ctx, got, 0)
	if err != nil {
		t.Fatalf("%s: read: %v", what, err)
	}
	if read != len(want) || !bytes.Equal(got[:read], want) {
		t.Fatalf("%s: read %d bytes, and they are not the %d expected", what, read, len(want))
	}
}
