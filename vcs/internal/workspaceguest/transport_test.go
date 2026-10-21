package workspaceguest

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

func transportHello() *pb.Hello {
	return &pb.Hello{Release: &pb.Release{AppVersion: "dev", Commit: strings.Repeat("a", 40), ImageDigest: bytes.Repeat([]byte{1}, 32), AuthorityMajor: 8}, BootId: id(1), HostServiceId: id(2), GuestServiceId: id(3)}
}
func transportRig(t *testing.T) (net.Conn, *Supervisor, <-chan error) {
	t.Helper()
	host, guest := net.Pipe()
	if err := host.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	s, err := New(id(1), id(2), id(3), true)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Register(mountID(4), Witness{}, NoMount{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), guest, transportHello(), s, nil); guest.Close() }()
	t.Cleanup(func() { host.Close() })
	return host, s, done
}
func exchange(t *testing.T, c net.Conn, e *pb.Envelope) *pb.Envelope {
	t.Helper()
	if err := control.Write(c, e); err != nil {
		t.Fatal(err)
	}
	r, err := control.Read(c)
	if err != nil {
		t.Fatal(err)
	}
	if r.RequestId != e.RequestId {
		t.Fatal("uncorrelated reply")
	}
	return r
}
func pairTransport(t *testing.T, c net.Conn) {
	host := proto.Clone(transportHello()).(*pb.Hello)
	host.GuestServiceId = nil
	r := exchange(t, c, &pb.Envelope{Version: 8, RequestId: 1, Body: &pb.Envelope_Hello{Hello: host}})
	if err := control.Pair(host, r.GetHelloAck()); err != nil {
		t.Fatal(err)
	}
}
func TestTransportExactReleaseAndBootPairing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*pb.Hello)
	}{
		{"version", func(h *pb.Hello) { h.Release.AppVersion = "other" }},
		{"commit", func(h *pb.Hello) { h.Release.Commit = strings.Repeat("b", 40) }},
		{"digest", func(h *pb.Hello) { h.Release.ImageDigest = bytes.Repeat([]byte{2}, 32) }},
		{"boot", func(h *pb.Hello) { h.BootId = id(9) }},
		{"host", func(h *pb.Hello) { h.HostServiceId = id(9) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s, done := transportRig(t)
			h := transportHello()
			h.GuestServiceId = nil
			tc.change(h)
			if err := control.Write(c, &pb.Envelope{Version: 8, RequestId: 1, Body: &pb.Envelope_Hello{Hello: h}}); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil {
				t.Fatal("mismatch paired")
			}
			if s.Status().State != "discard-only" {
				t.Fatal("mismatch retained eligibility")
			}
		})
	}
}
func TestTransportColdResumeSingleUseAndDisconnect(t *testing.T) {
	c, s, done := transportRig(t)
	pairTransport(t, c)
	x := suspension(s)
	r := exchange(t, c, &pb.Envelope{Version: 8, RequestId: 2, Body: &pb.Envelope_Suspend{Suspend: x}})
	if r.GetSuspendAck() == nil || !r.GetSuspendAck().Mounts[0].ColdComplete {
		t.Fatal("no cold proof")
	}
	token := &pb.ResumeToken{Suspension: x, WakeNonce: id(9)}
	r = exchange(t, c, &pb.Envelope{Version: 8, RequestId: 3, Body: &pb.Envelope_Resume{Resume: token}})
	if r.GetResumeAck() == nil || r.GetResumeAck().Mounts[0].State != "authorization-required" {
		t.Fatal("no-mount opened admission")
	}
	if err := control.Write(c, &pb.Envelope{Version: 8, RequestId: 4, Body: &pb.Envelope_Resume{Resume: token}}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("token replay accepted")
	}
	if s.Status().State != "discard-only" {
		t.Fatal("broken stream retained eligibility")
	}
}
func TestTransportRejectsUnpairedAndRepeatedRequests(t *testing.T) {
	for _, paired := range []bool{false, true} {
		t.Run(map[bool]string{false: "unpaired", true: "request-replay"}[paired], func(t *testing.T) {
			c, s, done := transportRig(t)
			if paired {
				pairTransport(t, c)
			}
			if err := control.Write(c, &pb.Envelope{Version: 8, RequestId: 1, Body: &pb.Envelope_Status{Status: &pb.StatusRequest{}}}); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil {
				t.Fatal("invalid sequence accepted")
			}
			if s.Status().State != "discard-only" {
				t.Fatal("invalid sequence not discarded")
			}
		})
	}
}
func TestTransportMountUnavailableAndStatusCorrelated(t *testing.T) {
	c, s, done := transportRig(t)
	pairTransport(t, c)
	r := exchange(t, c, &pb.Envelope{Version: 8, RequestId: 2, Body: &pb.Envelope_Status{Status: &pb.StatusRequest{}}})
	if !proto.Equal(r.GetStatusReply(), s.Status()) {
		t.Fatal("wrong status")
	}
	r = exchange(t, c, &pb.Envelope{Version: 8, RequestId: 3, Body: &pb.Envelope_Mount{Mount: &pb.MountRequest{Mount: mountID(4)}}})
	if r.GetResult().GetCode() != "unavailable" {
		t.Fatal("created a mount")
	}
	c.Close()
	if err := <-done; err == nil {
		t.Fatal("disconnect succeeded")
	}
	if s.Status().State != "discard-only" {
		t.Fatal("disconnect not discarded")
	}
}
