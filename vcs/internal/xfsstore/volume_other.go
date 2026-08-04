//go:build !linux

package xfsstore

// Volume deliberately has no non-Linux implementation. A test or deployment
// can never silently substitute another filesystem for authoritative XFS.
type Volume struct{}

func Open(string, Config) (*Volume, error) { return nil, ErrUnsupportedPlatform }

func (v *Volume) Close() error { return nil }
