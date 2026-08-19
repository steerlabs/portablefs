//go:build !darwin

package portablefsd

import "io"

func prepareRuntimeConfig(*Config) error { return nil }

// openDaemonLog is a no-op off Darwin. The service manager here is systemd,
// whose journal already captures the daemon's stderr, so the process must keep
// writing there: opening a private file instead would move every diagnostic
// out of `journalctl -u portablefs-*`, where the deployment docs and the
// privileged Linux gates both expect to find it.
func openDaemonLog(*Config) (io.Closer, error) { return nil, nil }
