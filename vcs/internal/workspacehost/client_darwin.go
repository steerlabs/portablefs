//go:build darwin

package workspacehost

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/hostctl"
)

func Exchange(ctx context.Context, path, executable, cdhash string, request Request) (Reply, error) {
	if err := request.Validate(); err != nil {
		return Reply{}, err
	}
	conn, err := hostctl.ConnectAuthenticated(ctx, path, executable, cdhash)
	if err != nil {
		return Reply{}, err
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(20 * time.Second)
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return Reply{}, err
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return Reply{}, err
	}
	if len(raw)+1 > MaxFrame {
		return Reply{}, fmt.Errorf("workspace request exceeds bound")
	}
	raw = append(raw, '\n')
	for len(raw) > 0 {
		n, e := conn.Write(raw)
		if e != nil {
			return Reply{}, e
		}
		if n == 0 {
			return Reply{}, io.ErrUnexpectedEOF
		}
		raw = raw[n:]
	}
	reader := bufio.NewReader(io.LimitReader(conn, MaxFrame+1))
	frame, err := reader.ReadBytes('\n')
	if err != nil {
		return Reply{}, fmt.Errorf("read workspace reply: %w", err)
	}
	if len(frame) > MaxFrame {
		return Reply{}, fmt.Errorf("workspace reply exceeds bound")
	}
	return DecodeReply(frame[:len(frame)-1])
}
