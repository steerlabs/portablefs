// Package server serves a billy.Filesystem over NFSv3 and shuts down cleanly on
// context cancellation.
package server

import (
	"context"
	"net"

	"github.com/go-git/go-billy/v5"
	nfs "github.com/willscott/go-nfs"
	nfshelper "github.com/willscott/go-nfs/helpers"
)

type kernelCompatibleAuthHandler struct {
	nfs.Handler
}

func newKernelCompatibleAuthHandler(fs billy.Filesystem) nfs.Handler {
	return &kernelCompatibleAuthHandler{Handler: nfshelper.NewNullAuthHandler(fs)}
}

func (h *kernelCompatibleAuthHandler) Mount(ctx context.Context, conn net.Conn, req nfs.MountRequest) (nfs.MountStatus, billy.Filesystem, []nfs.AuthFlavor) {
	status, handle, _ := h.Handler.Mount(ctx, conn, req)
	return status, handle, []nfs.AuthFlavor{nfs.AuthFlavorUnix, nfs.AuthFlavorNull}
}

// Serve serves fs over NFSv3 on ln until ctx is cancelled or ln is closed.
// On ctx cancellation it returns nil (clean shutdown).
func Serve(ctx context.Context, ln net.Listener, fs billy.Filesystem) error {
	handler := newKernelCompatibleAuthHandler(fs)
	cached := nfshelper.NewCachingHandler(handler, 1024)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	err := nfs.Serve(ln, cached)
	if ctx.Err() != nil {
		return nil
	}
	return err
}
