//go:build !linux

package fusev3

import "errors"

var ErrUnsupportedPlatform = errors.New("fusev3: the exact v3 mount frontend requires Linux FUSE")
