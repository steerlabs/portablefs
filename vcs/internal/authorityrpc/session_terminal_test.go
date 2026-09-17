package authorityrpc

import (
	"context"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"syscall"
	"testing"
	"time"
)

type terminalReplyHandler struct {
	clientTestHandler
	terminal bool
	errno    int32
}

func (h terminalReplyHandler) Handle(ctx context.Context, r *authoritypb.Request) *authoritypb.Response {
	if r.GetGetAttr() != nil {
		return &authoritypb.Response{RequestId: r.RequestId, Epoch: h.Epoch(), Errno: h.errno, SessionTerminal: h.terminal}
	}
	return h.clientTestHandler.Handle(ctx, r)
}
func TestTerminalSessionReplyEndsClientBeforeSocketClose(t *testing.T) {
	for _, tc := range []struct {
		name     string
		terminal bool
		errno    int32
		want     error
	}{
		{"expired session", true, int32(syscall.ESTALE), ErrSessionEnded},
		{"stale capability", false, int32(syscall.ESTALE), nil},
		{"invalid marker", true, 0, ErrTransportBinding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := terminalReplyHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 5}, terminal: tc.terminal, errno: tc.errno}
			address, tls, stop := startTestServer(t, h, 5, time.Minute)
			defer stop()
			c, err := DialClient(t.Context(), coherentTestClientConfig(address, tls, "volume", 5, 5))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			response, err := c.CallRead(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}})
			if tc.errno != 0 && (err != nil || response.GetErrno() != tc.errno) {
				t.Fatalf("exact refusal lost: %v %v", response, err)
			}
			if tc.errno == 0 && !errors.Is(err, ErrTransportBinding) {
				t.Fatalf("malformed marker accepted: %v", err)
			}
			if !errors.Is(c.SessionEndCause(), tc.want) {
				t.Fatalf("terminal cause=%v want %v", c.SessionEndCause(), tc.want)
			}
			if tc.want == nil {
				if _, err := c.CallRead(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}}); err != nil {
					t.Fatalf("ordinary stale handle ended session: %v", err)
				}
			}
		})
	}
}
