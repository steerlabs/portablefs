package portablefsd

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

const (
	appendRecordLen = 48
	appendKeyLen    = 10
)

func appendKey(machine string, seq int) string { return fmt.Sprintf("%s-%06d-", machine, seq) }

func appendRecordBytes(machine string, seq int) []byte {
	body := appendKey(machine, seq)
	return []byte(body + strings.Repeat("x", appendRecordLen-len(body)-1) + "\n")
}

// appendConn is a goroutine-safe minimal pfslocal client: the shared
// pfsTestClient reports failures with t.Fatal, which is invalid from the
// worker goroutines this test needs in order to make two machines append
// concurrently.
type appendConn struct {
	mu   sync.Mutex
	conn net.Conn
	next uint64
}

func (c *appendConn) call(body any) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	body = currentTestProtocol(body)
	c.next++
	id := c.next
	if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
		RequestID: id, OperationID: testOperationID(body, id), Body: body,
	}); err != nil {
		return nil, err
	}
	for {
		env, err := pfslocal.ReadFrame(c.conn)
		if err != nil {
			return nil, err
		}
		if env.RequestID == 0 {
			continue
		}
		if env.RequestID != id {
			return nil, fmt.Errorf("reply id=%d want %d", env.RequestID, id)
		}
		if er, ok := env.Body.(*pfslocal.ErrorReply); ok {
			return nil, fmt.Errorf("error reply: %+v", er)
		}
		if env.PublicationAckRequired {
			if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
				Body: &pfslocal.PublicationAck{OperationID: testOperationID(body, id)},
			}); err != nil {
				return nil, err
			}
		}
		return env.Body, nil
	}
}

// TestCrossMachineAppendHandlesNeverCollide is the daemon-boundary regression
// test for the two-Mac corruption. Two independent daemons (two machines)
// attach to one authority volume and each appends fixed-length records to the
// SAME file through the pfslocal frontend.
//
// The bug this pins was structural: pfslocal had no way to say "append", so
// attach.write always called the positional WriteOpenHandle with the offset
// the frontend supplied. Each machine therefore wrote at an offset derived
// from its own cached size and the two ranges overlapped. With the append
// intent carried on the wire, attach.write routes to WriteAppendOpenHandle
// and the authority assigns every offset in sequencer order, so no two
// records can share a byte.
func TestCrossMachineAppendHandlesNeverCollide(t *testing.T) {
	authority := serveAuthority(t)
	const (
		perMachine = 150
		fileName   = "shared-append.log"
	)

	type machine struct {
		name string
		conn *appendConn
		root pfslocal.Item
	}
	dial := func(name string) *machine {
		cfg, _, ref, _ := startDaemon(t, authority)
		raw, err := net.Dial("unix", cfg.FrontendSocket)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = raw.Close() })
		c := &appendConn{conn: raw}
		if _, err := c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "append-" + name}); err != nil {
			t.Fatal(err)
		}
		res, err := c.call(&pfslocal.ResolveRequest{AttachRef: ref})
		if err != nil {
			t.Fatal(err)
		}
		return &machine{name: name, conn: c, root: res.(*pfslocal.ResolveReply).Root}
	}
	left := dial("AA")
	right := dial("BB")

	// Machine AA creates the shared log; machine BB reaches it by name.
	created, err := left.conn.call(&pfslocal.CreateRequest{
		Dir: left.root, Name: []byte(fileName), Mode: 0o644, Exclusive: true, Append: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	leftHandle := created.(*pfslocal.CreateReply).Handle

	found, err := right.conn.call(&pfslocal.LookupRequest{Dir: right.root, Name: []byte(fileName)})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := right.conn.call(&pfslocal.OpenRequest{
		Item: found.(*pfslocal.LookupReply).Attr.Item,
		Mode: pfslocal.OpenModeWrite,
		// O_APPEND: sticky on this descriptor, so every write below resolves
		// its offset at the authority rather than at a frontend-held size.
		Append: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	rightHandle := opened.(*pfslocal.OpenReply).Handle

	writers := []struct {
		m      *machine
		handle uint64
	}{{left, leftHandle}, {right, rightHandle}}
	var wg sync.WaitGroup
	errCh := make(chan error, len(writers))
	for _, w := range writers {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := 0; seq < perMachine; seq++ {
				rec := appendRecordBytes(w.m.name, seq)
				reply, err := w.m.conn.call(&pfslocal.WriteRequest{
					Handle: w.handle, Data: rec,
					// Offset is deliberately left zero: an append must never
					// carry a frontend-computed absolute offset.
					Append: true,
				})
				if err != nil {
					errCh <- fmt.Errorf("machine %s append %d: %w", w.m.name, seq, err)
					return
				}
				if got := reply.(*pfslocal.WriteReply).Written; got != uint32(len(rec)) {
					errCh <- fmt.Errorf("machine %s append %d: wrote %d of %d", w.m.name, seq, got, len(rec))
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	// Verify against the authority itself, not either mount's cache.
	verifier, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	wantTotal := 2 * perMachine
	data, st := verifier.Read(context.Background(), fileName, nil, 0, wantTotal*appendRecordLen*2)
	if st != fsproto.OK {
		t.Fatalf("verify read: %d", st)
	}
	if len(data) != wantTotal*appendRecordLen {
		t.Fatalf("durable size = %d bytes (%d records), want %d bytes (%d records): "+
			"appends collided and records were lost",
			len(data), len(data)/appendRecordLen, wantTotal*appendRecordLen, wantTotal)
	}
	seen := make(map[string]bool, wantTotal)
	for off := 0; off < len(data); off += appendRecordLen {
		rec := data[off : off+appendRecordLen]
		if rec[appendRecordLen-1] != '\n' || strings.Count(string(rec), "\n") != 1 {
			t.Fatalf("record at offset %d is torn or spliced: %q", off, rec)
		}
		key := string(rec[:appendKeyLen])
		if seen[key] {
			t.Fatalf("record %q appears twice; two appends shared an offset", key)
		}
		seen[key] = true
	}
	for _, name := range []string{"AA", "BB"} {
		for seq := 0; seq < perMachine; seq++ {
			if !seen[appendKey(name, seq)] {
				t.Fatalf("record %q was lost", appendKey(name, seq))
			}
		}
	}
}
