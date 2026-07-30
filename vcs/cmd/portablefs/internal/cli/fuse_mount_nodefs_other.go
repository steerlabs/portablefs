//go:build !linux

package cli

import (
	"fmt"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func mountNodeFS(dir string, root fs.InodeEmbedder, options *fs.Options, mechanism, _ string) (*fuse.Server, error) {
	if mechanism != "direct" {
		return nil, fmt.Errorf("FUSE helper mounting is unsupported on this platform")
	}
	return fs.Mount(dir, root, options)
}
