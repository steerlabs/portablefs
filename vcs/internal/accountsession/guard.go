// Package accountsession serializes live mount sessions against credential
// and profile mutation for one OS account.
package accountsession

import (
	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
)

const lockName = "account-session.lock"

type Guard = mountlifecycle.Guard

func Path(stateDir string) string {
	path, err := mountlifecycle.NamedPath(stateDir, lockName)
	if err != nil {
		panic(err)
	}
	return path
}

func AcquireShared(stateDir string) (*Guard, error) {
	return mountlifecycle.AcquireNamedShared(stateDir, lockName)
}

func AcquireExclusive(stateDir string) (*Guard, error) {
	return mountlifecycle.AcquireNamedExclusive(stateDir, lockName)
}
