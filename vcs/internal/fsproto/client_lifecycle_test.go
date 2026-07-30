package fsproto

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAbortCancelsInflightLegacyTransportDial exercises both transport paths:
// an operation can own a pooled conn, while a subscription owns a dedicated
// conn. In either case Abort must terminate without waiting for a legacy dial
// callback that has not returned a socket. If that callback eventually
// returns, its socket must be closed before authentication or request traffic.
func TestAbortCancelsInflightLegacyTransportDial(t *testing.T) {
	for _, mode := range []string{"pooled", "dedicated"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			var releaseOnce sync.Once
			dialEntered := make(chan struct{})
			releaseDial := make(chan struct{})
			initialDone := make(chan struct{})
			lateTraffic := make(chan bool, 1)
			release := func() {
				releaseOnce.Do(func() { close(releaseDial) })
			}
			t.Cleanup(release)

			dial := func() (net.Conn, error) {
				client, server := net.Pipe()
				if calls.Add(1) == 1 {
					go func() {
						defer close(initialDone)
						defer server.Close()
						if err := acceptTestClientHandshake(server); err != nil {
							return
						}
						_, _ = io.Copy(io.Discard, server)
					}()
					return client, nil
				}
				close(dialEntered)
				go func() {
					defer server.Close()
					var first [1]byte
					n, _ := server.Read(first[:])
					lateTraffic <- n != 0
				}()
				<-releaseDial
				return client, nil
			}

			cli, err := DialWithTransport(1, dial)
			if err != nil {
				t.Fatalf("dial client: %v", err)
			}

			opDone := make(chan error, 1)
			switch mode {
			case "pooled":
				// Make the sole pooled conn require a new dial, then hold that
				// dial before it returns a socket to the conn lifecycle.
				cli.pool[0].reset()
				select {
				case <-initialDone:
				case <-time.After(time.Second):
					t.Fatal("initial transport did not close")
				}
				go func() {
					_, _, err := cli.Getattr("")
					opDone <- err
				}()
			case "dedicated":
				go func() {
					_, _, err := cli.Subscribe()
					opDone <- err
				}()
			default:
				t.Fatalf("unknown transport mode %q", mode)
			}
			select {
			case <-dialEntered:
			case <-time.After(time.Second):
				t.Fatal("operation did not enter the delayed dial")
			}

			abortDone := make(chan error, 1)
			go func() { abortDone <- cli.Abort() }()
			select {
			case <-cli.closed:
				// The terminal gate is closed while the dial still owns no
				// socket and the legacy callback remains blocked.
			case <-time.After(time.Second):
				t.Fatal("abort did not close the client lifecycle gate")
			}
			select {
			case err := <-abortDone:
				if err != nil {
					t.Fatalf("abort: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("abort waited for the blocked legacy dial callback")
			}
			select {
			case err := <-opDone:
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("operation error = %v, want net.ErrClosed", err)
				}
			case <-time.After(time.Second):
				t.Fatal("operation survived abort")
			}
			if cli.pool[0].connected() {
				t.Fatal("pooled transport remained installed after abort")
			}

			release()
			select {
			case sent := <-lateTraffic:
				if sent {
					t.Fatal("late transport sent authentication or request bytes after abort")
				}
			case <-time.After(time.Second):
				t.Fatal("late transport was not closed")
			}
			select {
			case <-initialDone:
			case <-time.After(time.Second):
				t.Fatal("initial transport did not close")
			}
		})
	}
}

func TestFlushContextCancelsDisconnectedRedialBeforeAnySend(t *testing.T) {
	var calls atomic.Int32
	var releaseOnce sync.Once
	dialEntered := make(chan struct{})
	releaseDial := make(chan struct{})
	initialDone := make(chan struct{})
	lateTraffic := make(chan bool, 1)
	release := func() {
		releaseOnce.Do(func() { close(releaseDial) })
	}
	t.Cleanup(release)

	dial := func() (net.Conn, error) {
		client, server := net.Pipe()
		if calls.Add(1) == 1 {
			go func() {
				defer close(initialDone)
				defer server.Close()
				if err := acceptTestClientHandshake(server); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, server)
			}()
			return client, nil
		}
		close(dialEntered)
		go func() {
			defer server.Close()
			var first [1]byte
			n, _ := server.Read(first[:])
			lateTraffic <- n != 0
		}()
		<-releaseDial
		return client, nil
	}

	cli, err := DialWithTransport(1, dial)
	if err != nil {
		t.Fatalf("dial client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Abort() })
	cli.pool[0].reset()
	select {
	case <-initialDone:
	case <-time.After(time.Second):
		t.Fatal("initial transport did not close")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := cli.FlushWritebackContext(ctx, "wb", nil, [32]byte{}, [32]byte{}, nil)
		done <- err
	}()
	select {
	case <-dialEntered:
	case <-time.After(time.Second):
		t.Fatal("flush did not enter disconnected redial")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("flush error = %v, want context deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("flush context cancellation waited for delayed dial")
	}

	release()
	select {
	case sent := <-lateTraffic:
		if sent {
			t.Fatal("canceled flush authenticated or sent on late transport")
		}
	case <-time.After(time.Second):
		t.Fatal("late transport was not retired")
	}
}

func acceptTestClientHandshake(conn net.Conn) error {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	token := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(conn, token); err != nil {
		return err
	}
	_, err := conn.Write([]byte{0})
	return err
}
