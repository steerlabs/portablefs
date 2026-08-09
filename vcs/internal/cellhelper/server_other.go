//go:build !linux

package cellhelper

import (
	"context"
	"errors"
)

type Server struct {
	SocketPath string
	SocketGID  int
	AgentUID   uint32
	Reconciler *Reconciler
}

func (*Server) Serve(context.Context) error {
	return errors.New("cellhelper: privileged helper is supported only on Linux")
}
