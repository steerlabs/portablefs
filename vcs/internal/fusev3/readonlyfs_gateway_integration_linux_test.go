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

// TestFilesGatewayAttachesToRealXFSWithoutObstructingAMountingPeer is the files
// gateway's first handshake with the real volume handler.
//
// vcs/readonlyfs is dialled only by cmd/portablefs-files, and every test it had
// drove a fake that satisfied the client's own interface. A fake can prove op
// ordering and handle release, and nothing else: not that the authority accepts
// FRONTEND_PROFILE_FSKIT_SYNC_REPAIR from a Linux participant, not that a
// session which discharges every repair phase the instant it arrives is a
// lawful member of a barrier, and not that such a session is harmless to the
// mounts it shares a volume with.
//
// That last claim is the load-bearing one. The gateway declares sync-repair
// because it caches nothing, so it can answer a repair phase immediately. The
// reason that matters is the converse: a frontend that answered slowly would
// hold every barrier open for as long as it took, and one that never answered
// would be fenced only after RecallBudget elapsed -- by which time the mutating
// mount has waited that entire budget. A reader that can stall a writer is not
// a read-only client, whatever profile it declares. The mutation loop below is
// what turns that argument into an observation, and the fence count is what
// distinguishes "discharged" from "escaped through the budget".
//
// It lives in package fusev3_test rather than package fusev3 because readonlyfs
// depends on mountv3 and mountv3 depends on fusev3: importing the gateway from
// inside the package is an import cycle even in a test file. The fixture
// reaches it through fusev3.GatewayPeerFixture.
func TestFilesGatewayAttachesToRealXFSWithoutObstructingAMountingPeer(t *testing.T) {
	// One kernel mount is the mutator. The gateway is the second participant,
	// and it is deliberately not a mount: it projects no namespace at all.
	peer := fusev3.NewGatewayPeerFixture(t, 1)

	const (
		name    = "served"
		listing = "listing"
	)
	initial := bytes.Repeat([]byte{'a'}, 48*1024)
	mustWriteFile(t, peer.Join(0, name), initial)
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
	if got := peer.LastAttachProfile(); got != fusev3.SyncRepairProfile() {
		t.Fatalf("the authority accepted the gateway under frontend profile %v, want %v", got, fusev3.SyncRepairProfile())
	}
	if count := peer.ActiveParticipants(); count != 2 {
		t.Fatalf("the volume has %d visibility participants, want the mount and the gateway", count)
	}

	ctx := context.Background()
	servedKey := mustEncodePath(t, name)
	// The root is the empty key.
	rootPathKey := mustEncodePath(t)

	// Reads: the gateway resolves an opaque path, opens, and reads bytes that
	// came out of real XFS through the real handler.
	requireGatewayContent(t, ctx, gateway, servedKey, initial, "the gateway's first read")

	// Enumeration over the same session, of a directory a Linux-lease mount
	// wrote. This is the assertion the version-domain defect broke: readdir
	// discards any page carrying an entry whose ObjectVersion is ahead of the
	// snapshot it stabilized at, and a sync-repair session used to stabilize
	// against the visibility coordinator's barrier sequence while those versions
	// were stamped from the storage cut. On any volume a lease mount had written
	// to -- which is this one -- every entry looked like it came from the future
	// and the page could never stabilize, so the gateway answered EAGAIN to every
	// List. Both profiles now stabilize against the storage cut.
	requireGatewayListing(t, ctx, gateway, mustEncodePath(t, listing), []string{"one", "two"}, "the gateway's listing of a lease-written directory")

	// A peer mount's mutation, observed through the gateway after apply. The
	// gateway caches nothing, so this is not a cache-invalidation assertion --
	// it is the assertion that the mutation's barrier closed at all, which
	// requires the gateway to have polled its repair phase and acknowledged it.
	// A gateway that never answered would leave the barrier open and this write
	// would not return until the recall budget fenced it.
	mutated := bytes.Repeat([]byte{'b'}, 72*1024)
	writeStart := time.Now()
	if err := os.WriteFile(peer.Join(0, name), mutated, 0o600); err != nil {
		t.Fatalf("peer mount rewrite while the gateway is attached: %v (%s)", err, peer.Diagnostics())
	}
	writeElapsed := time.Since(writeStart)
	// The budget the mount declared is what fences a frontend that will not
	// discharge. A write that consumed a meaningful fraction of it did not fail,
	// but it did not demonstrate immediate discharge either.
	if writeElapsed > peer.RepairBudget()/4 {
		t.Fatalf("a rewrite beside the attached gateway took %s, more than a quarter of the %s repair budget: the gateway is not discharging on arrival (%s)",
			writeElapsed, peer.RepairBudget(), peer.Diagnostics())
	}
	requireGatewayContent(t, ctx, gateway, servedKey, mutated, "the gateway's read after the peer mutation")

	// The gateway cannot block a writer. A continuous read loop runs against the
	// same inode the mutation loop rewrites, so rounds land inside the window
	// each recall covers. What is asserted is not throughput: it is that no
	// round was ever answered by the escape hatch. No session was fenced, and
	// neither participant ended.
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
	// Per-round cost is the point: a writer waiting on this reader waits for one
	// repair phase, and a phase discharged on arrival costs a round trip, not a
	// budget.
	if perRound := loopElapsed / rounds; perRound > peer.RepairBudget()/4 {
		t.Fatalf("%d rewrites beside a continuously reading gateway averaged %s each, more than a quarter of the %s repair budget (%s)",
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

	// Detach. Close joins the keepalive and visibility workers, so a clean
	// return is also the statement that neither of them had already failed.
	if err := gateway.Close(); err != nil {
		t.Fatalf("close the gateway session: %v", err)
	}
	closed = true
	if err := gateway.Err(); err != nil {
		t.Fatalf("the gateway reported a terminal cause across a clean close: %v", err)
	}

	// A departure that left an obligation behind shows up as a barrier the next
	// mutation cannot close. Close sends an authenticated Detach, so the session
	// leaves the audience before its transport drops and this write costs a
	// round trip. Without it the write waits the gateway's whole repair budget
	// for a phase nobody will acknowledge, plus a budget of post-fence grace,
	// and the mount's own watchdog revokes it in the meantime.
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
