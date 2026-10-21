//go:build linux

package mountcontrol

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type Peer struct {
	UID   uint32
	PID   int32
	Start uint64
}
type PeerClass uint8

const (
	Refused PeerClass = iota
	Ordinary
	WorkspacePeer
)

func ProcessStart(pid int32) (uint64, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return 0, ErrGrammar
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) <= 19 {
		return 0, ErrGrammar
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
func Credentials(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var u *unix.Ucred
	var inner error
	if err = raw.Control(func(fd uintptr) { u, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return Peer{}, err
	}
	if inner != nil {
		return Peer{}, inner
	}
	if u == nil {
		return Peer{}, ErrGrammar
	}
	start, err := ProcessStart(u.Pid)
	return Peer{UID: u.Uid, PID: u.Pid, Start: start}, err
}
func Classify(peer Peer, user uint32, supervisor *Peer) PeerClass {
	if supervisor != nil && supervisor.UID == 0 && supervisor.PID > 0 && supervisor.Start > 0 && peer == *supervisor {
		return WorkspacePeer
	}
	if peer.UID == user {
		return Ordinary
	}
	return Refused
}

// Receive reads through write-half-close. recvmsg atomically marks every right
// close-on-exec, and all error paths dispose of the entire received inventory.
func Receive(c *net.UnixConn, limit int) (body []byte, rights *Rights, err error) {
	rights = &Rights{}
	defer func() {
		if err != nil {
			rights.Close()
		}
	}()
	raw, e := c.SyscallConn()
	if e != nil {
		return nil, rights, e
	}
	data := make([]byte, 8192)
	oob := make([]byte, unix.CmsgSpace(256*4))
	for {
		var n, on, flags int
		var inner error
		e = raw.Read(func(fd uintptr) bool {
			n, on, flags, _, inner = unix.Recvmsg(int(fd), data, oob, unix.MSG_CMSG_CLOEXEC)
			return inner != unix.EAGAIN && inner != unix.EWOULDBLOCK
		})
		if e != nil {
			return nil, rights, e
		}
		if inner != nil {
			return nil, rights, inner
		}
		if err := receiveAncillary(rights, oob[:on], flags); err != nil {
			return nil, rights, err
		}

		if n == 0 {
			return body, rights, nil
		}
		if len(body)+n > limit {
			return nil, rights, ErrGrammar
		}
		body = append(body, data[:n]...)
	}
}

func receiveAncillary(rights *Rights, raw []byte, flags int) error {
	messages, parseErr := unix.ParseSocketControlMessage(raw)
	for _, m := range messages {
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			parseErr = err
			continue
		}
		rights.FDs = append(rights.FDs, fds...)
	}
	if parseErr != nil || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 || len(rights.FDs) > 2 {
		rights.Close()
		return ErrGrammar
	}
	return nil
}

// WatchDisconnect ignores POLLRDHUP (the required framing half-close). It
// cancels only this bounded waiter on full hangup or exact peer-process death.
// The Handler's generation-owned job must outlive the waiter.
func WatchDisconnect(ctx context.Context, c *net.UnixConn, peer Peer, cancel context.CancelFunc) func() {
	stopped := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, err := c.SyscallConn()
		if err != nil {
			cancel()
			return
		}
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopped:
				return
			case <-ticker.C:
			}
			start, err := ProcessStart(peer.PID)
			if err != nil || start != peer.Start {
				cancel()
				return
			}
			var gone bool
			err = raw.Control(func(fd uintptr) {
				p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLHUP | unix.POLLERR}}
				_, e := unix.Poll(p, 0)
				gone = e != nil || p[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0
			})
			if err != nil || gone {
				cancel()
				return
			}
		}
	}()
	return func() { close(stopped); <-done }
}
func WriteResponse(w io.Writer, r Response) error {
	raw, err := EncodeResponse(r)
	if err != nil {
		return err
	}
	for len(raw) > 0 {
		n, err := w.Write(raw)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}
