//go:build !darwin

package portablefsd

import (
	"errors"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

func hostPreKernelFSKitMountAbsenceObserver(_, _ string) (authorityrpc.PreKernelMountAbsenceObserver, error) {
	return nil, errors.New("portablefsd: authority-v3 FSKit attach requires Darwin getfsstat")
}
