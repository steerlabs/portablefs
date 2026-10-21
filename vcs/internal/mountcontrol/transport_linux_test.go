//go:build linux

package mountcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"testing"
	"time"
)

func sockets(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var conns []*net.UnixConn
	for _, fd := range fds {
		f := os.NewFile(uintptr(fd), "owned-control")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c.(*net.UnixConn))
	}
	t.Cleanup(func() {
		for _, c := range conns {
			c.Close()
		}
	})
	return conns[0], conns[1]
}
func TestControlHalfCloseFramesRequestAndFullDeathCancelsWaiter(t *testing.T) {
	client, server := sockets(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	peer, err := Credentials(server)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(request("workspace-prepare", 1, 1))
	if _, err := client.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, rights, err := Receive(server, MaxWorkspaceRequest)
	if err != nil || string(got) != string(body) {
		t.Fatal(err)
	}
	defer rights.Close()
	waiter, stopWaiter := context.WithCancel(ctx)
	defer stopWaiter()
	stop := WatchDisconnect(waiter, server, peer, stopWaiter)
	defer stop()
	if err := WriteResponse(server, response(request("workspace-prepare", 1, 1), "accepted")); err != nil {
		t.Fatal(err)
	}
	var r Response
	if err := json.NewDecoder(client).Decode(&r); err != nil {
		t.Fatal(err)
	}
	if waiter.Err() != nil {
		t.Fatal("write-half-close canceled request")
	}
	client.Close()
	select {
	case <-waiter.Done():
	case <-time.After(time.Second):
		t.Fatal("full death did not cancel waiter")
	}
}
func TestReceiveRightsAreCloexecAndEveryRejectionCloses(t *testing.T) {
	for _, count := range []int{0, 1, 2, 3} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			client, server := sockets(t)
			d, original := descriptors(t)
			defer d.Close()
			fds := append([]int{}, original...)
			if count == 3 {
				x, err := unix.Dup(fds[0])
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(x)
				fds = append(fds, x)
			}
			fds = fds[:count]
			body := []byte(`{"ok":true}`)
			var oob []byte
			if len(fds) > 0 {
				oob = unix.UnixRights(fds...)
			}
			if _, _, err := client.WriteMsgUnix(body, oob, nil); err != nil {
				t.Fatal(err)
			}
			client.CloseWrite()
			_, received, err := Receive(server, MaxWorkspaceRequest)
			if count > 2 {
				if err == nil {
					t.Fatal("extra rights accepted")
				}
				if len(received.FDs) != 0 {
					t.Fatal("extra rights not closed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, fd := range received.FDs {
				flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
				if err != nil || flags&unix.FD_CLOEXEC == 0 {
					t.Fatal("inherited right", err)
				}
			}
			saved := append([]int{}, received.FDs...)
			received.Close()
			assertClosed(t, saved)
		})
	}
}
func TestReceiveDisconnectAndOversizeRetainNoRights(t *testing.T) {
	for _, oversize := range []bool{false, true} {
		client, server := sockets(t)
		d, _ := descriptors(t)
		defer d.Close()
		body := []byte("partial")
		if oversize {
			body = make([]byte, 32)
		}
		if _, _, err := client.WriteMsgUnix(body, unix.UnixRights(d.FDs...), nil); err != nil {
			t.Fatal(err)
		}
		client.Close()
		raw, received, err := Receive(server, 16)
		if oversize {
			if err == nil || len(received.FDs) != 0 {
				t.Fatal("oversize leaked")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRequest(raw); err == nil {
				t.Fatal("partial decode")
			}
			received.Close()
		}
	}
}
func TestDisconnectWatcherChecksExactPeerStart(t *testing.T) {
	_, server := sockets(t)
	peer, err := Credentials(server)
	if err != nil {
		t.Fatal(err)
	}
	peer.Start++
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := WatchDisconnect(ctx, server, peer, cancel)
	defer stop()
	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal(ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("obsolete process identity retained")
	}
}

func TestTruncatedAncillaryDisposesOfEveryDecodedRight(t *testing.T) {
	for _, flags := range []int{unix.MSG_CTRUNC, unix.MSG_TRUNC} {
		d, fds := descriptors(t)
		raw := unix.UnixRights(d.FDs...)
		got := &Rights{}
		if receiveAncillary(got, raw, flags) == nil {
			t.Fatal("truncated ancillary accepted")
		}
		assertClosed(t, fds)
	}
}
