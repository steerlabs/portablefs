package portablefsd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func (s *Server) ServeFrontend(ctx context.Context) error {
	if s.cfg.FrontendSocket == "" {
		return fmt.Errorf("frontend socket is required")
	}
	ln, err := listenUnixSocket(s.cfg.FrontendSocket)
	if err != nil {
		return err
	}
	s.frontendLnMu.Lock()
	s.frontendLnMu.Unlock()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	log.Printf("portablefsd frontend socket listening at %s", s.cfg.FrontendSocket)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		fc := &frontendConn{srv: s, conn: c}
		go fc.serve(ctx)
	}
}

type frontendConn struct {
	srv    *Server
	conn   net.Conn
	origin uint64

	writeMu sync.Mutex

	attachMu sync.RWMutex
	attach   *attach

	eventsMu sync.Mutex
	events   *eventSubscriber
}

func (c *frontendConn) serve(ctx context.Context) {
	defer c.close()
	for {
		env, err := pfslocal.ReadFrame(c.conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("frontend read: %v", err)
			}
			return
		}
		go c.handle(ctx, env)
	}
}

func (c *frontendConn) close() {
	if a := c.currentAttach(); a != nil {
		a.removeConn(c.conn)
	}
	c.eventsMu.Lock()
	if c.events != nil {
		if a := c.currentAttach(); a != nil {
			a.unsubscribe(c.events)
		}
		c.events = nil
	}
	c.eventsMu.Unlock()
	_ = c.conn.Close()
}

func (c *frontendConn) currentAttach() *attach {
	c.attachMu.RLock()
	defer c.attachMu.RUnlock()
	return c.attach
}

func (c *frontendConn) setAttach(a *attach) {
	c.attachMu.Lock()
	c.attach = a
	if c.origin == 0 {
		c.origin = a.newOrigin()
	}
	c.attachMu.Unlock()
	a.addConn(c.conn)
}

func (c *frontendConn) write(env *pfslocal.Envelope) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return pfslocal.WriteFrame(c.conn, env)
}

func (c *frontendConn) reply(req uint64, body any) {
	if err := c.write(&pfslocal.Envelope{RequestID: req, Body: body}); err != nil {
		log.Printf("frontend write reply: %v", err)
		_ = c.conn.Close()
	}
}

func (c *frontendConn) errorReply(req uint64, eno int32, msg string) {
	c.reply(req, &pfslocal.ErrorReply{Errno: eno, Message: msg})
}

func (c *frontendConn) handle(ctx context.Context, env *pfslocal.Envelope) {
	switch req := env.Body.(type) {
	case *pfslocal.Hello:
		if req.ProtocolMajor != pfslocal.ProtocolMajor {
			c.errorReply(env.RequestID, darwinEINVAL, "unsupported protocol major")
			return
		}
		c.reply(env.RequestID, &pfslocal.HelloReply{ProtocolMajor: pfslocal.ProtocolMajor, ProtocolMinor: pfslocal.ProtocolMinor, DaemonVersion: c.srv.cfg.Version})
	case *pfslocal.ResolveRequest:
		a := c.srv.registry.get(req.AttachRef)
		if a == nil {
			c.errorReply(env.RequestID, darwinENOENT, "unknown attach_ref")
			return
		}
		rep, eno := a.rootReply(ctx)
		if eno != 0 {
			c.errorReply(env.RequestID, eno, errMessage("resolve", eno))
			return
		}
		c.setAttach(a)
		c.reply(env.RequestID, &rep)
	default:
		a := c.currentAttach()
		if a == nil {
			c.errorReply(env.RequestID, darwinEINVAL, "connection is not resolved")
			return
		}
		c.handleAttached(ctx, a, env.RequestID, req)
	}
}

func (c *frontendConn) handleAttached(ctx context.Context, a *attach, requestID uint64, body any) {
	var (
		reply any
		eno   int32
	)
	switch req := body.(type) {
	case *pfslocal.LookupRequest:
		reply, eno = a.lookup(ctx, req)
	case *pfslocal.EnumerateRequest:
		reply, eno = a.enumerate(ctx, req)
	case *pfslocal.GetAttrRequest:
		reply, eno = a.getattr(ctx, req)
	case *pfslocal.SetAttrRequest:
		reply, eno = a.setattr(ctx, req)
	case *pfslocal.OpenRequest:
		reply, eno = a.open(ctx, req)
	case *pfslocal.CloseRequest:
		eno, _ = a.close(req)
		reply = &pfslocal.CloseReply{}
	case *pfslocal.ReadRequest:
		reply, eno = a.read(ctx, req)
	case *pfslocal.WriteRequest:
		reply, eno = a.write(ctx, req)
	case *pfslocal.CreateRequest:
		reply, eno = a.create(ctx, req)
	case *pfslocal.MkdirRequest:
		reply, eno = a.mkdir(ctx, req)
	case *pfslocal.RemoveRequest:
		eno = a.remove(ctx, req)
		reply = &pfslocal.RemoveReply{}
	case *pfslocal.RenameRequest:
		eno = a.rename(ctx, req)
		reply = &pfslocal.RenameReply{}
	case *pfslocal.SymlinkRequest:
		reply, eno = a.symlink(ctx, req)
	case *pfslocal.ReadlinkRequest:
		reply, eno = a.readlink(ctx, req)
	case *pfslocal.HardLinkRequest:
		reply, eno = a.hardLink(ctx, req)
	case *pfslocal.XattrGetRequest:
		reply, eno = a.xattrGet(ctx, req)
	case *pfslocal.XattrSetRequest:
		reply, eno = a.xattrSet(ctx, req)
	case *pfslocal.XattrListRequest:
		reply, eno = a.xattrList(ctx, req)
	case *pfslocal.XattrRemoveRequest:
		reply, eno = a.xattrRemove(ctx, req)
	case *pfslocal.StatfsRequest:
		reply, eno = a.statfs()
	case *pfslocal.SyncVolumeRequest:
		reply, eno = a.syncVolume(ctx)
	case *pfslocal.FsyncRequest:
		eno = a.fsync(ctx, req)
		reply = &pfslocal.FsyncReply{}
	case *pfslocal.ReclaimRequest:
		eno = a.reclaim(req)
		reply = &pfslocal.ReclaimReply{}
	case *pfslocal.SubscribeEventsRequest:
		if err := c.subscribeEvents(a); err != nil {
			c.errorReply(requestID, darwinEIO, err.Error())
			return
		}
		reply = &pfslocal.SubscribeEventsReply{}
	default:
		c.errorReply(requestID, darwinEINVAL, fmt.Sprintf("unsupported request %T", body))
		return
	}
	if pfsdTrace {
		log.Printf("pfsd-trace %s eno=%d", traceOp(a, body), eno)
	}
	if eno != 0 {
		c.errorReply(requestID, eno, errMessage(fmt.Sprintf("%T", body), eno))
		return
	}
	a.synthesizeFrontendMutation(body, c.origin)
	c.reply(requestID, reply)
}

// pfsdTrace (PFSD_TRACE=1) logs every frontend op with its resolved paths and
// errno — the pfslocal boundary is otherwise invisible, and kernel-side
// caching bugs can only be diagnosed by seeing exactly what the extension
// asked and what the daemon answered.
var pfsdTrace = os.Getenv("PFSD_TRACE") == "1"

func traceOp(a *attach, body any) string {
	itemPath := func(item pfslocal.Item) string {
		a.mu.RLock()
		defer a.mu.RUnlock()
		if rec := a.items[item.ItemID]; rec != nil {
			return rec.path
		}
		return fmt.Sprintf("item#%d?", item.ItemID)
	}
	switch req := body.(type) {
	case *pfslocal.LookupRequest:
		return fmt.Sprintf("lookup dir=%q name=%q", itemPath(req.Dir), req.Name)
	case *pfslocal.EnumerateRequest:
		return fmt.Sprintf("enumerate dir=%q", itemPath(req.Dir))
	case *pfslocal.GetAttrRequest:
		return fmt.Sprintf("getattr %q", itemPath(req.Item))
	case *pfslocal.OpenRequest:
		return fmt.Sprintf("open %q", itemPath(req.Item))
	case *pfslocal.CreateRequest:
		return fmt.Sprintf("create dir=%q name=%q", itemPath(req.Dir), req.Name)
	case *pfslocal.RemoveRequest:
		return fmt.Sprintf("remove dir=%q name=%q", itemPath(req.Dir), req.Name)
	case *pfslocal.RenameRequest:
		return fmt.Sprintf("rename %q/%q -> %q/%q", itemPath(req.FromDir), req.FromName, itemPath(req.ToDir), req.ToName)
	default:
		return fmt.Sprintf("%T", body)
	}
}

func (c *frontendConn) subscribeEvents(a *attach) error {
	c.eventsMu.Lock()
	defer c.eventsMu.Unlock()
	if c.events != nil {
		return nil
	}
	if !a.isCredentialPending() {
		readyCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if !a.waitEventsReady(readyCtx) {
			return fmt.Errorf("authority event stream is not ready")
		}
	}
	sub := a.subscribe(c.origin)
	c.events = sub
	go func() {
		for ev := range sub.ch {
			if err := c.write(&pfslocal.Envelope{RequestID: 0, Body: &pfslocal.Event{Kind: ev.Kind}}); err != nil {
				_ = c.conn.Close()
				return
			}
		}
		_ = c.conn.Close()
	}()
	return nil
}

func listenUnixSocket(p string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(p)
	ln, err := net.Listen("unix", p)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(p, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}
