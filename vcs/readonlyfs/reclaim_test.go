package readonlyfs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// capabilityLedger is an authority that mints a distinct item capability per
// LOOKUP and audits every RECLAIM against what it minted. It is how the
// gateway's resource discipline is proven without a kernel or an XFS volume:
// every capability is returned exactly once, in a one-entry repeated list, on
// success and on every failure path.
type capabilityLedger struct {
	mu          sync.Mutex
	root        *authoritypb.Item
	minted      uint64
	outstanding map[string]bool
	peak        int
	reclaims    int
	handles     map[string]bool
	violations  []string
	kinds       map[string]authoritypb.Attr_Kind
	missing     string
	openErrno   syscall.Errno
}

func newCapabilityLedger() *capabilityLedger {
	return &capabilityLedger{
		root:        testItem(1, authoritypb.Attr_DIRECTORY, []byte("root"), 0),
		outstanding: make(map[string]bool),
		handles:     make(map[string]bool),
		kinds:       make(map[string]authoritypb.Attr_Kind),
	}
}

func (l *capabilityLedger) CallMutation(_ context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch body := request.GetBody().(type) {
	case *authoritypb.Request_Lookup:
		name := string(body.Lookup.GetName())
		if name == l.missing {
			return &authoritypb.Response{Errno: int32(syscall.ENOENT)}, nil
		}
		parent := string(body.Lookup.GetParent())
		if parent != string(l.root.GetToken()) && !l.outstanding[parent] {
			l.violations = append(l.violations, "lookup through a capability the gateway no longer owns")
		}
		l.minted++
		token := fmt.Sprintf("item-%d", l.minted)
		l.outstanding[token] = true
		l.peak = max(l.peak, len(l.outstanding))
		kind, ok := l.kinds[name]
		if !ok {
			kind = authoritypb.Attr_DIRECTORY
		}
		return &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{
			Item: testItem(100+l.minted, kind, []byte(token), 3),
		}}}, nil
	case *authoritypb.Request_Reclaim:
		l.reclaims++
		items := body.Reclaim.GetItems()
		if len(items) != 1 {
			l.violations = append(l.violations, fmt.Sprintf("reclaim carried %d items, want one", len(items)))
		}
		for _, item := range items {
			if !l.outstanding[string(item)] {
				l.violations = append(l.violations, fmt.Sprintf("reclaim of %q, which is not outstanding", item))
			}
			delete(l.outstanding, string(item))
		}
		return &authoritypb.Response{}, nil
	case *authoritypb.Request_Open:
		if !l.outstanding[string(body.Open.GetItem())] && string(body.Open.GetItem()) != string(l.root.GetToken()) {
			l.violations = append(l.violations, "open through a capability the gateway no longer owns")
		}
		if l.openErrno != 0 {
			return &authoritypb.Response{Errno: int32(l.openErrno)}, nil
		}
		handle := fmt.Sprintf("handle-%s", body.Open.GetItem())
		l.handles[handle] = true
		return &authoritypb.Response{Body: &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: []byte(handle)}}}, nil
	case *authoritypb.Request_Close:
		if !l.handles[string(body.Close.GetHandle())] {
			l.violations = append(l.violations, "close of a handle that is not open")
		}
		delete(l.handles, string(body.Close.GetHandle()))
		return &authoritypb.Response{}, nil
	case *authoritypb.Request_ReadDir:
		return &authoritypb.Response{Body: &authoritypb.Response_ReadDir{ReadDir: &authoritypb.ReadDirReply{Eof: true, Verifier: []byte("v")}}}, nil
	default:
		return nil, fmt.Errorf("unexpected mutation %T", body)
	}
}

func (l *capabilityLedger) CallRead(_ context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetKeepAlive() != nil {
		return &authoritypb.Response{}, nil
	}
	return nil, errors.New("unexpected read")
}
func (l *capabilityLedger) Close() error                             { return nil }
func (l *capabilityLedger) ReleaseBeforeMount(context.Context) error { return nil }
func (l *capabilityLedger) IOLimits() (uint32, uint32)               { return 4096, 4096 }
func (l *capabilityLedger) Root() *authoritypb.Item                  { return l.root }
func (l *capabilityLedger) SessionLease() time.Duration              { return time.Hour }
func (l *capabilityLedger) audit(t *testing.T, wantMinted uint64) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.violations) != 0 {
		t.Fatalf("capability discipline violated: %s", strings.Join(l.violations, "; "))
	}
	if l.minted != wantMinted || len(l.outstanding) != 0 || l.reclaims != int(wantMinted) {
		t.Fatalf("minted %d (want %d), reclaimed %d, still outstanding %v", l.minted, wantMinted, l.reclaims, l.outstanding)
	}
	if l.peak > 2 {
		t.Fatalf("resolution held %d item capabilities at once, want at most the current and the next", l.peak)
	}
}

func pathKey(t *testing.T, components ...string) string {
	t.Helper()
	raw := make([][]byte, len(components))
	for i, component := range components {
		raw[i] = []byte(component)
	}
	key, err := EncodePath(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestGatewayReclaimsEveryResolvedCapabilityExactlyOnce(t *testing.T) {
	deep := []string{"a", "b", "c", "d", "file"}
	for _, tc := range []struct {
		name       string
		prepare    func(*capabilityLedger)
		operate    func(*testing.T, *Client) error
		wantErr    error
		wantMinted uint64
	}{
		{
			name:    "file opened through a deep path",
			prepare: func(l *capabilityLedger) { l.kinds["file"] = authoritypb.Attr_REGULAR },
			operate: func(t *testing.T, c *Client) error {
				file, err := c.OpenFile(t.Context(), pathKey(t, deep...))
				if err != nil {
					return err
				}
				return file.Close(t.Context())
			},
			wantMinted: 5,
		},
		{
			name:    "lookup fails midway",
			prepare: func(l *capabilityLedger) { l.missing = "c" },
			operate: func(t *testing.T, c *Client) error {
				_, err := c.OpenFile(t.Context(), pathKey(t, deep...))
				return err
			},
			wantErr:    syscall.ENOENT,
			wantMinted: 2,
		},
		{
			name: "final component is a directory",
			operate: func(t *testing.T, c *Client) error {
				_, err := c.OpenFile(t.Context(), pathKey(t, deep...))
				return err
			},
			wantErr:    syscall.EISDIR,
			wantMinted: 5,
		},
		{
			name: "open is refused",
			prepare: func(l *capabilityLedger) {
				l.kinds["file"] = authoritypb.Attr_REGULAR
				l.openErrno = syscall.EACCES
			},
			operate: func(t *testing.T, c *Client) error {
				_, err := c.OpenFile(t.Context(), pathKey(t, deep...))
				return err
			},
			wantErr:    syscall.EACCES,
			wantMinted: 5,
		},
		{
			name: "directory listed through a deep path",
			operate: func(t *testing.T, c *Client) error {
				_, err := c.List(t.Context(), pathKey(t, "a", "b", "c"), 10, nil)
				return err
			},
			wantMinted: 3,
		},
		{
			name: "root is never reclaimed",
			operate: func(t *testing.T, c *Client) error {
				_, err := c.List(t.Context(), "", 10, nil)
				return err
			},
			wantMinted: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ledger := newCapabilityLedger()
			if tc.prepare != nil {
				tc.prepare(ledger)
			}
			client := newClient(ledger, time.Second)
			t.Cleanup(func() { _ = client.Close() })
			if err := tc.operate(t, client); !errors.Is(err, tc.wantErr) {
				t.Fatalf("operation error = %v, want %v", err, tc.wantErr)
			}
			ledger.audit(t, tc.wantMinted)
			ledger.mu.Lock()
			open := len(ledger.handles)
			ledger.mu.Unlock()
			if open != 0 {
				t.Fatalf("%d authority handles left open", open)
			}
		})
	}
}
