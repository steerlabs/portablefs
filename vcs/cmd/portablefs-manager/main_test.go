package main

import (
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNotifySystemdReady(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socketPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", socketPath)

	if err := notifySystemdReady(); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	message := make([]byte, 32)
	count, _, err := listener.ReadFromUnix(message)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(message[:count]); got != "READY=1" {
		t.Fatalf("notification = %q, want READY=1", got)
	}
}

func TestNotifySystemdReadyWithoutSocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := notifySystemdReady(); err != nil {
		t.Fatal(err)
	}
}

func TestSystemdNotifyAddressAbstractSocket(t *testing.T) {
	address := systemdNotifyAddress("@portablefs-manager")
	if address.Net != "unixgram" {
		t.Fatalf("network = %q, want unixgram", address.Net)
	}
	if address.Name != "\x00portablefs-manager" {
		t.Fatalf("name = %q, want leading NUL", address.Name)
	}
}

func TestServeManagerNotifiesAfterBindBeforeAccept(t *testing.T) {
	boundListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer boundListener.Close()
	listener := &orderingListener{Listener: boundListener}
	server := &http.Server{}

	err = serveManager(server, listener, func() error {
		connection, err := net.DialTimeout("tcp", boundListener.Addr().String(), time.Second)
		if err != nil {
			t.Fatalf("listener was not bound at readiness notification: %v", err)
		}
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
		listener.ready = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), errTestAccept.Error()) {
		t.Fatalf("Serve error = %v, want accept error", err)
	}
	if !listener.accepted {
		t.Fatal("Serve did not enter the accept loop")
	}
}

var errTestAccept = errors.New("test accept stopped")

type orderingListener struct {
	net.Listener
	ready    bool
	accepted bool
}

func (listener *orderingListener) Accept() (net.Conn, error) {
	listener.accepted = true
	if !listener.ready {
		return nil, errors.New("accept preceded readiness notification")
	}
	return nil, errTestAccept
}
