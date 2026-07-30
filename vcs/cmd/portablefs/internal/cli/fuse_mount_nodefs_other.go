//go:build !linux

package cli

import (
	"fmt"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func mountNodeFS(
	dir string,
	root fs.InodeEmbedder,
	options *fs.Options,
	mechanism, _ string,
	beforeServe func(),
) (*fuse.Server, error) {
	if mechanism != "direct" {
		return nil, fmt.Errorf("FUSE helper mounting is unsupported on this platform")
	}
	rawFS := fs.NewNodeFS(root, options)
	server, err := fuse.NewServer(rawFS, dir, &options.MountOptions)
	if err != nil {
		return nil, err
	}
	if beforeServe != nil {
		beforeServe()
	}
	go server.Serve()
	if err := server.WaitMount(); err != nil {
		return nil, err
	}
	return server, nil
}
