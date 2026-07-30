package portablefsd

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// rawPFSClient is a goroutine-safe pfslocal test client: it returns errors
// instead of calling t.Fatal, so concurrency tests can drive many connections
// from worker goroutines (the shared pfsTestClient may only Fatal from the
// test goroutine).
type rawPFSClient struct {
	conn net.Conn
	next uint64
}

func dialRawPFS(sock string) (*rawPFSClient, error) {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return nil, err
	}
	return &rawPFSClient{conn: c}, nil
}

func (c *rawPFSClient) close() { _ = c.conn.Close() }

// call returns (reply, daemonError, transportError).
func (c *rawPFSClient) call(body any) (any, *pfslocal.ErrorReply, error) {
	c.next++
	id := c.next
	operationID := testOperationID(body, id)
	if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
		RequestID: id, OperationID: operationID, Body: body,
	}); err != nil {
		return nil, nil, err
	}
	for {
		env, err := pfslocal.ReadFrame(c.conn)
		if err != nil {
			return nil, nil, err
		}
		if env.RequestID != id {
			continue // events and other-request replies
		}
		if env.PublicationAckRequired {
			if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
				Body: &pfslocal.PublicationAck{OperationID: operationID},
			}); err != nil {
				return nil, nil, err
			}
		}
		if er, ok := env.Body.(*pfslocal.ErrorReply); ok {
			return nil, er, nil
		}
		return env.Body, nil, nil
	}
}

func (c *rawPFSClient) mustCall(body any) (any, error) {
	rep, er, err := c.call(body)
	if err != nil {
		return nil, err
	}
	if er != nil {
		return nil, fmt.Errorf("%T: errno %d (%s)", body, er.Errno, er.Message)
	}
	return rep, nil
}

func (c *rawPFSClient) start(ref string) (pfslocal.Item, error) {
	if _, err := c.mustCall(&pfslocal.Hello{
		ProtocolMajor: 1,
		ProtocolMinor: pfslocal.ProtocolMinor,
		ClientName:    "stripes-test",
	}); err != nil {
		return pfslocal.Item{}, err
	}
	rep, err := c.mustCall(&pfslocal.ResolveRequest{AttachRef: ref})
	if err != nil {
		return pfslocal.Item{}, err
	}
	return rep.(*pfslocal.ResolveReply).Root, nil
}

func (c *rawPFSClient) createWriteClose(dir pfslocal.Item, name, content string) error {
	rep, err := c.mustCall(&pfslocal.CreateRequest{Dir: dir, Name: []byte(name), Mode: 0o644, Exclusive: true})
	if err != nil {
		return fmt.Errorf("create %q: %w", name, err)
	}
	cr := rep.(*pfslocal.CreateReply)
	if _, err := c.mustCall(&pfslocal.WriteRequest{Handle: cr.Handle, Data: []byte(content)}); err != nil {
		return fmt.Errorf("write %q: %w", name, err)
	}
	_, err = c.mustCall(&pfslocal.CloseRequest{Handle: cr.Handle})
	if err != nil {
		return fmt.Errorf("close %q: %w", name, err)
	}
	return nil
}

// TestDaemonParallelNamespaceMutations exercises the shared-nsMu +
// per-directory-stripe locking under real concurrency: parallel creates,
// removes, and re-creates in disjoint directories AND in one contended
// directory, interleaved with whole-tree renames (which hold nsMu
// exclusively) and an O_EXCL create race that exactly one racer may win.
// The registry must come out consistent: every expected name resolves, every
// removed name is gone, and no daemon error or panic occurred.
func TestDaemonParallelNamespaceMutations(t *testing.T) {
	authority := serveAuthority(t)
	cfg, _, ref, cancel := startDaemon(t, authority)
	defer cancel()

	setup := dialPFS(t, cfg.FrontendSocket)
	defer setup.close()
	root := resolveRoot(t, setup, ref)
	shared := mkdirItem(t, setup, root, "shared")
	var dirs []pfslocal.Attr
	for i := 0; i < 4; i++ {
		dirs = append(dirs, mkdirItem(t, setup, root, fmt.Sprintf("d%d", i)))
	}

	const perWorker = 10
	errCh := make(chan error, 128)
	var wg sync.WaitGroup

	worker := func(dir pfslocal.Item, prefix string) {
		defer wg.Done()
		c, err := dialRawPFS(cfg.FrontendSocket)
		if err != nil {
			errCh <- err
			return
		}
		defer c.close()
		if _, err := c.start(ref); err != nil {
			errCh <- err
			return
		}
		for i := 0; i < perWorker; i++ {
			name := fmt.Sprintf("%s-%d.txt", prefix, i)
			if err := c.createWriteClose(dir, name, "payload-"+name); err != nil {
				errCh <- err
				return
			}
			if i%3 == 0 {
				// Churn: remove and recreate the same name (same stripe).
				if _, err := c.mustCall(&pfslocal.RemoveRequest{Dir: dir, Name: []byte(name)}); err != nil {
					errCh <- err
					return
				}
				if err := c.createWriteClose(dir, name, "payload2-"+name); err != nil {
					errCh <- err
					return
				}
			}
		}
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go worker(dirs[i].Item, fmt.Sprintf("w%d", i))
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go worker(shared.Item, fmt.Sprintf("s%d", i))
	}

	// Renames hold nsMu exclusively and must interleave cleanly with the
	// stripe holders: files created at the root migrate into d0.
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := dialRawPFS(cfg.FrontendSocket)
		if err != nil {
			errCh <- err
			return
		}
		defer c.close()
		if _, err := c.start(ref); err != nil {
			errCh <- err
			return
		}
		for i := 0; i < 8; i++ {
			name := fmt.Sprintf("mv-%d.txt", i)
			if err := c.createWriteClose(root, name, "mv"); err != nil {
				errCh <- err
				return
			}
			if _, err := c.mustCall(&pfslocal.RenameRequest{
				FromDir: root, FromName: []byte(name),
				ToDir: dirs[0].Item, ToName: []byte(name),
			}); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// O_EXCL race on ONE name in the contended directory: exactly one winner.
	var exclWins atomic.Int32
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := dialRawPFS(cfg.FrontendSocket)
			if err != nil {
				errCh <- err
				return
			}
			defer c.close()
			if _, err := c.start(ref); err != nil {
				errCh <- err
				return
			}
			rep, er, err := c.call(&pfslocal.CreateRequest{Dir: shared.Item, Name: []byte("x.lock"), Mode: 0o600, Exclusive: true})
			if err != nil {
				errCh <- err
				return
			}
			if er != nil {
				if er.Errno != darwinEEXIST {
					errCh <- fmt.Errorf("excl loser errno=%d, want EEXIST", er.Errno)
				}
				return
			}
			exclWins.Add(1)
			if _, err := c.mustCall(&pfslocal.CloseRequest{Handle: rep.(*pfslocal.CreateReply).Handle}); err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	if got := exclWins.Load(); got != 1 {
		t.Fatalf("O_EXCL winners = %d, want exactly 1", got)
	}

	// The registry survived the storm: every expected name resolves through a
	// fresh connection and the moved files live at their new home only.
	verify := dialPFS(t, cfg.FrontendSocket)
	defer verify.close()
	vroot := resolveRoot(t, verify, ref)
	vdirs := make([]pfslocal.Attr, 4)
	for i := 0; i < 4; i++ {
		vdirs[i] = lookupItem(t, verify, vroot, fmt.Sprintf("d%d", i))
	}
	vshared := lookupItem(t, verify, vroot, "shared")
	for i := 0; i < 4; i++ {
		for j := 0; j < perWorker; j++ {
			lookupItem(t, verify, vdirs[i].Item, fmt.Sprintf("w%d-%d.txt", i, j))
			lookupItem(t, verify, vshared.Item, fmt.Sprintf("s%d-%d.txt", i, j))
		}
	}
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("mv-%d.txt", i)
		lookupItem(t, verify, vdirs[0].Item, name)
		expectLookupErrno(t, verify, vroot, name, darwinENOENT)
	}
	lookupItem(t, verify, vshared.Item, "x.lock")
}
