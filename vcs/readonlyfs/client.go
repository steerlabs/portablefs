// Package readonlyfs is the non-mounting PortableFS data client for bounded
// file inspection. It speaks directly to one authority using a read-only
// capability and never projects the volume into a host namespace.
package readonlyfs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/mountv3"
)

const (
	defaultRequestTimeout = 30 * time.Second
	maximumListEntries    = 500
	authorityListPage     = 256
	// repairBudget is the per-phase deadline this cacheless session commits to.
	// It has nothing to purge, so the budget only bounds transport latency.
	repairBudget = 10 * time.Second
)

type Config struct {
	Address              string
	AuthorityCAPEM       []byte
	AuthorityServerName  string
	Capability           []byte
	ClientCertificatePEM []byte
	ClientPrivateKeyPEM  []byte
	RequestTimeout       time.Duration
	VolumeID             string
}

type Kind string

const (
	KindDirectory Kind = "directory"
	KindFile      Kind = "file"
	KindOpaque    Kind = "opaque"
	KindSymlink   Kind = "symlink"
)

type Attr struct {
	Inode      uint64
	Kind       Kind
	Mode       uint32
	ChangedAt  time.Time
	ModifiedAt time.Time
	Size       uint64
}

type Entry struct {
	Attr Attr
	Name []byte
}

type Page struct {
	Directory Attr
	Entries   []Entry
	Next      *Cursor
}

type authorityClient interface {
	CallMutation(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	CallRead(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	Close() error
	// ReleaseBeforeMount is the authenticated detach for an ACTIVE session that
	// never installed a kernel mount. That is the abort path for a mount
	// supervisor and the permanent condition of this client, so it is the exact
	// contract to leave on: it observes this process's own mount-absence
	// evidence, sends Detach, and closes.
	ReleaseBeforeMount(context.Context) error
	IOLimits() (uint32, uint32)
	InitialVisibilityCursor() *authoritypb.VisibilityCursor
	AckVisibility(context.Context, *authoritypb.VisibilityCursor) error
	NextVisibility(context.Context, *authoritypb.VisibilityCursor) (*authoritypb.VisibilityEvent, error)
	Root() *authoritypb.Item
	SessionLease() time.Duration
}

type Client struct {
	rpc            authorityClient
	requestTimeout time.Duration
	maxRead        uint32
	stop           context.CancelFunc
	done           chan struct{}
	fatalMu        sync.Mutex
	fatal          error
	closeOnce      sync.Once
	workers        sync.WaitGroup
}

func Dial(ctx context.Context, config Config) (*Client, error) {
	if config.Address == "" || config.AuthorityServerName == "" || config.VolumeID == "" || len(config.Capability) == 0 {
		return nil, errors.New("readonlyfs: complete authority configuration is required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(config.AuthorityCAPEM) {
		return nil, errors.New("readonlyfs: authority CA contains no certificate")
	}
	identity, err := tls.X509KeyPair(config.ClientCertificatePEM, config.ClientPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("readonlyfs: client identity: %w", err)
	}
	// The gateway is not a mount: it holds no kernel namespace, no page cache,
	// and no lease state. Protocol-6 offers exactly two frontend contracts, and
	// the synchronous-repair one is the only one that grants no cache leases, so
	// it is the honest declaration here — every repair phase completes
	// immediately for a client that caches nothing. Declaring the Linux lease
	// profile would claim recall participation this client cannot honor and
	// would stall writers behind a reader that never caches.
	rpc, err := authorityrpc.DialClient(ctx, authorityrpc.ClientConfig{
		AccessToken:             append([]byte(nil), config.Capability...),
		Address:                 config.Address,
		CancelDrainTimeout:      mountv3.CancelDrainTimeout,
		DialTimeout:             mountv3.DialTimeout,
		FrontendProfile:         authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR,
		FskitCachedNameCapacity: 1,
		FskitNamespaceRepair:    authoritypb.NamespaceRepair_NAMESPACE_REPAIR_INDEPENDENT,
		FskitRepairBudget:       repairBudget,
		MaxFrame:                mountv3.MaxFrame,
		MaxInFlight:             mountv3.MaxInFlight,
		ObservePreKernelMountAbsence: func(context.Context) (*authoritypb.MountAbsenceProof, error) {
			return &authoritypb.MountAbsenceProof{
				ObservedUnixNanos: time.Now().UnixNano(),
				Observation:       []byte("portablefs-files has no kernel mount, FUSE connection, or namespace cache"),
				Component:         "portablefs-files/no-kernel-mount",
			}, nil
		},
		Purpose:        authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT,
		ReplaySlots:    mountv3.ReplaySlots,
		RoutesRevision: localroutes.RuleSet{}.Revision(),
		TLS: &tls.Config{
			Certificates: []tls.Certificate{identity},
			MinVersion:   tls.VersionTLS13,
			RootCAs:      roots,
			ServerName:   config.AuthorityServerName,
		},
		VolumeID: config.VolumeID,
	})
	if err != nil {
		return nil, err
	}
	return newClient(rpc, config.RequestTimeout), nil
}

func newClient(rpc authorityClient, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	maxRead, _ := rpc.IOLimits()
	keepaliveContext, stop := context.WithCancel(context.Background())
	client := &Client{rpc: rpc, requestTimeout: timeout, maxRead: maxRead, stop: stop, done: make(chan struct{})}
	client.workers.Add(2)
	go func() {
		defer client.workers.Done()
		client.keepalive(keepaliveContext)
	}()
	go func() {
		defer client.workers.Done()
		client.acknowledgeVisibility(keepaliveContext)
	}()
	go func() {
		client.workers.Wait()
		close(client.done)
	}()
	return client
}

func (c *Client) OpenFile(ctx context.Context, pathKey string) (*File, error) {
	item, owned, err := c.resolve(ctx, pathKey)
	if err != nil {
		return nil, err
	}
	attr, err := attrFromProto(item.GetAttr())
	if err != nil {
		if owned {
			_ = c.reclaim(ctx, item.GetToken())
		}
		return nil, err
	}
	if attr.Kind != KindFile {
		if owned {
			_ = c.reclaim(ctx, item.GetToken())
		}
		return nil, syscall.EISDIR
	}
	response, err := c.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{
		Item:  append([]byte(nil), item.GetToken()...),
		Flags: &authoritypb.OpenFlags{Read: true},
	}}})
	if err != nil {
		if owned {
			_ = c.reclaim(ctx, item.GetToken())
		}
		return nil, err
	}
	handle := response.GetOpen().GetHandle()
	if len(handle) == 0 {
		if owned {
			_ = c.reclaim(ctx, item.GetToken())
		}
		return nil, errors.New("readonlyfs: authority returned an empty file handle")
	}
	if owned {
		if err := c.reclaim(ctx, item.GetToken()); err != nil {
			_ = c.closeHandle(ctx, handle)
			return nil, err
		}
	}
	return &File{client: c, attr: attr, handle: append([]byte(nil), handle...)}, nil
}

func (c *Client) List(ctx context.Context, pathKey string, limit int, cursor *Cursor) (Page, error) {
	if limit < 1 || limit > maximumListEntries {
		return Page{}, syscall.EINVAL
	}
	if cursor == nil {
		created, err := c.openDirectory(ctx, pathKey)
		if err != nil {
			return Page{}, err
		}
		cursor = created
	} else if cursor.client != c {
		return Page{}, syscall.EINVAL
	}
	entries, eof, err := cursor.read(ctx, limit)
	if err != nil {
		_ = cursor.Close(context.Background())
		return Page{}, err
	}
	page := Page{Directory: cursor.directory, Entries: entries}
	if eof {
		if err := cursor.Close(ctx); err != nil {
			return Page{}, err
		}
	} else {
		page.Next = cursor
	}
	return page, nil
}

func (c *Client) openDirectory(ctx context.Context, pathKey string) (*Cursor, error) {
	item, owned, err := c.resolve(ctx, pathKey)
	if err != nil {
		return nil, err
	}
	attr, err := attrFromProto(item.GetAttr())
	if err != nil {
		if owned {
			_ = c.reclaim(ctx, item.GetToken())
		}
		return nil, err
	}
	if attr.Kind != KindDirectory {
		if owned {
			_ = c.reclaim(ctx, item.GetToken())
		}
		return nil, syscall.ENOTDIR
	}
	response, err := c.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{
		Item:  append([]byte(nil), item.GetToken()...),
		Flags: &authoritypb.OpenFlags{Read: true},
	}}})
	if err != nil {
		if owned {
			_ = c.reclaim(ctx, item.GetToken())
		}
		return nil, err
	}
	handle := response.GetOpen().GetHandle()
	if len(handle) == 0 {
		if owned {
			_ = c.reclaim(ctx, item.GetToken())
		}
		return nil, errors.New("readonlyfs: authority returned an empty directory handle")
	}
	if owned {
		if err := c.reclaim(ctx, item.GetToken()); err != nil {
			_ = c.closeHandle(ctx, handle)
			return nil, err
		}
	}
	return &Cursor{client: c, directory: attr, handle: append([]byte(nil), handle...)}, nil
}

func (c *Client) resolve(ctx context.Context, pathKey string) (*authoritypb.Item, bool, error) {
	components, err := DecodePath(pathKey)
	if err != nil {
		return nil, false, syscall.EINVAL
	}
	current := c.rpc.Root()
	if current == nil || current.GetAttr() == nil {
		return nil, false, errors.New("readonlyfs: authority session has no root")
	}
	owned := false
	for _, component := range components {
		response, lookupErr := c.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{
			Name:   append([]byte(nil), component...),
			Parent: append([]byte(nil), current.GetToken()...),
		}}})
		if lookupErr != nil {
			if owned {
				_ = c.reclaim(ctx, current.GetToken())
			}
			return nil, false, lookupErr
		}
		next := response.GetLookup().GetItem()
		if next == nil || next.GetAttr() == nil || len(next.GetToken()) == 0 {
			if owned {
				_ = c.reclaim(ctx, current.GetToken())
			}
			return nil, false, errors.New("readonlyfs: authority returned a malformed lookup")
		}
		if owned {
			if err := c.reclaim(ctx, current.GetToken()); err != nil {
				_ = c.reclaim(ctx, next.GetToken())
				return nil, false, err
			}
		}
		current = next
		owned = true
	}
	return current, owned, nil
}

func (c *Client) mutate(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if err := c.sessionError(); err != nil {
		return nil, err
	}
	callContext, cancel := c.operationContext(ctx)
	defer cancel()
	response, err := c.rpc.CallMutation(callContext, request)
	return response, responseError(response, err)
}

func (c *Client) read(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if err := c.sessionError(); err != nil {
		return nil, err
	}
	callContext, cancel := c.operationContext(ctx)
	defer cancel()
	response, err := c.rpc.CallRead(callContext, request)
	return response, responseError(response, err)
}

func (c *Client) reclaim(ctx context.Context, item []byte) error {
	_, err := c.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: append([]byte(nil), item...)}}})
	return err
}

func (c *Client) closeHandle(ctx context.Context, handle []byte) error {
	_, err := c.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: append([]byte(nil), handle...)}}})
	return err
}

func (c *Client) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, c.requestTimeout)
}

func (c *Client) keepalive(ctx context.Context) {
	lease := c.rpc.SessionLease()
	if lease <= 0 {
		c.fail(errors.New("readonlyfs: authority omitted its session lease"))
		return
	}
	interval := lease / 3
	if interval < time.Second {
		interval = time.Second
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			callContext, cancel := context.WithTimeout(ctx, min(interval, c.requestTimeout))
			response, err := c.rpc.CallRead(callContext, &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
			cancel()
			if responseErr := responseError(response, err); responseErr != nil {
				if ctx.Err() == nil {
					c.fail(fmt.Errorf("readonlyfs: authority keepalive: %w", responseErr))
				}
				return
			}
			timer.Reset(interval)
		}
	}
}

// A files reader keeps no kernel or userspace namespace cache. Protocol 5 has
// one coherent session model, so this cacheless participant still joins the
// visibility stream and acknowledges each phase only after it has observed it.
func (c *Client) acknowledgeVisibility(ctx context.Context) {
	cursor := c.rpc.InitialVisibilityCursor()
	if cursor == nil {
		c.fail(errors.New("readonlyfs: authority omitted its initial visibility cursor"))
		return
	}
	// A cacheless session has nothing to purge, so each repair phase is
	// discharged by acknowledging it and polling the next one.
	var event *authoritypb.VisibilityEvent
	event, err := c.rpc.NextVisibility(ctx, cursor)
	for err == nil {
		if err = c.rpc.AckVisibility(ctx, event.GetCursor()); err != nil {
			break
		}
		event, err = c.rpc.NextVisibility(ctx, event.GetCursor())
	}
	if ctx.Err() == nil {
		c.fail(fmt.Errorf("readonlyfs: authority visibility stream: %w", err))
	}
}

func (c *Client) fail(err error) {
	c.fatalMu.Lock()
	if c.fatal == nil {
		c.fatal = err
		c.stop()
		_ = c.rpc.Close()
	}
	c.fatalMu.Unlock()
}

func (c *Client) sessionError() error {
	c.fatalMu.Lock()
	defer c.fatalMu.Unlock()
	return c.fatal
}

// Err reports a terminal authority-session failure. Ordinary path errors such
// as ENOENT do not poison the session and are not returned here.
func (c *Client) Err() error { return c.sessionError() }

// detachBudget bounds the authenticated detach on Close. Leaving without
// detaching is not free: the authority keeps this session in the barrier
// audience, so the next peer mutation waits this session's whole repair budget
// for a phase nobody will acknowledge before the authority expels it. A
// departure that costs a round trip is strictly better than one that costs a
// writer a budget, so Close spends a bounded amount of time on it and gives up
// rather than hanging.
const detachBudget = 10 * time.Second

// Close ends the session, detaching first.
//
// The workers stop before the detach rather than after it. Both of them treat a
// failed call as a terminal session cause, and the detach deliberately ends the
// session underneath them -- a visibility poll outstanding across it would
// report the departure it was asked for as a fatal error.
//
// A session that already has a terminal cause does not detach: there is nothing
// live to detach, and Err has already told the caller so.
func (c *Client) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		c.stop()
		<-c.done
		if c.sessionError() == nil {
			detachContext, cancel := context.WithTimeout(context.Background(), detachBudget)
			closeErr = c.rpc.ReleaseBeforeMount(detachContext)
			cancel()
		}
		closeErr = errors.Join(closeErr, c.rpc.Close())
	})
	return closeErr
}

type File struct {
	client    *Client
	attr      Attr
	handle    []byte
	closeOnce sync.Once
}

func (f *File) Attr() Attr { return f.attr }

func (f *File) ReadAt(ctx context.Context, destination []byte, offset uint64) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	if f.client.maxRead == 0 {
		return 0, errors.New("readonlyfs: authority advertised a zero read limit")
	}
	written := 0
	for written < len(destination) {
		length := min(len(destination)-written, int(f.client.maxRead))
		response, err := f.client.read(ctx, &authoritypb.Request{Body: &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{
			Handle: append([]byte(nil), f.handle...),
			Length: uint32(length),
			Offset: offset + uint64(written),
		}}})
		if err != nil {
			return written, err
		}
		chunk := response.GetRead().GetData()
		if len(chunk) > length {
			return written, errors.New("readonlyfs: authority exceeded the requested read bound")
		}
		copy(destination[written:], chunk)
		written += len(chunk)
		if len(chunk) < length {
			return written, io.EOF
		}
	}
	return written, nil
}

func (f *File) Close(ctx context.Context) error {
	var closeErr error
	f.closeOnce.Do(func() { closeErr = f.client.closeHandle(ctx, f.handle) })
	return closeErr
}

type Cursor struct {
	client    *Client
	directory Attr
	handle    []byte
	cookie    []byte
	verifier  []byte
	closed    bool
	mu        sync.Mutex
}

func (cursor *Cursor) read(ctx context.Context, limit int) ([]Entry, bool, error) {
	cursor.mu.Lock()
	defer cursor.mu.Unlock()
	if cursor.closed {
		return nil, false, syscall.EBADF
	}
	entries := make([]Entry, 0, limit)
	for len(entries) < limit {
		requested := min(limit-len(entries), authorityListPage)
		response, err := cursor.client.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{
			Cookie:     append([]byte(nil), cursor.cookie...),
			Handle:     append([]byte(nil), cursor.handle...),
			MaxEntries: uint32(requested),
			Verifier:   append([]byte(nil), cursor.verifier...),
			WantItems:  false,
		}}})
		if err != nil {
			return nil, false, err
		}
		page := response.GetReadDir()
		if page == nil || len(page.GetVerifier()) == 0 || len(page.GetEntries()) > requested {
			return nil, false, errors.New("readonlyfs: authority returned a malformed directory page")
		}
		cursor.verifier = append(cursor.verifier[:0], page.GetVerifier()...)
		for _, raw := range page.GetEntries() {
			attr, attrErr := attrFromProto(raw.GetAttr())
			if attrErr != nil || len(raw.GetName()) == 0 || len(raw.GetNextCookie()) == 0 {
				return nil, false, errors.New("readonlyfs: authority returned a malformed directory entry")
			}
			entries = append(entries, Entry{Attr: attr, Name: append([]byte(nil), raw.GetName()...)})
			cursor.cookie = append(cursor.cookie[:0], raw.GetNextCookie()...)
		}
		if page.GetEof() {
			return entries, true, nil
		}
		if len(page.GetEntries()) == 0 {
			return nil, false, errors.New("readonlyfs: authority returned an empty non-terminal directory page")
		}
	}
	return entries, false, nil
}

func (cursor *Cursor) Close(ctx context.Context) error {
	cursor.mu.Lock()
	defer cursor.mu.Unlock()
	if cursor.closed {
		return nil
	}
	cursor.closed = true
	return cursor.client.closeHandle(ctx, cursor.handle)
}

func responseError(response *authoritypb.Response, err error) error {
	if err != nil {
		return err
	}
	if response == nil {
		return errors.New("readonlyfs: authority returned no response")
	}
	if response.GetErrno() != 0 {
		return syscall.Errno(response.GetErrno())
	}
	return nil
}

func attrFromProto(raw *authoritypb.Attr) (Attr, error) {
	if raw == nil || raw.GetInode() == 0 || raw.GetSize() < 0 {
		return Attr{}, errors.New("readonlyfs: authority returned malformed attributes")
	}
	var kind Kind
	switch raw.GetKind() {
	case authoritypb.Attr_DIRECTORY:
		kind = KindDirectory
	case authoritypb.Attr_REGULAR:
		kind = KindFile
	case authoritypb.Attr_SYMLINK:
		kind = KindSymlink
	default:
		kind = KindOpaque
	}
	return Attr{
		ChangedAt:  time.Unix(0, raw.GetCtimeNs()).UTC(),
		Inode:      raw.GetInode(),
		Kind:       kind,
		Mode:       raw.GetMode(),
		ModifiedAt: time.Unix(0, raw.GetMtimeNs()).UTC(),
		Size:       uint64(raw.GetSize()),
	}, nil
}
