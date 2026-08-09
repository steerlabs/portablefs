//go:build !linux

package cli

import (
	"context"
	"fmt"
	"time"
)

// The v3 FUSE engine mounts through vcs/internal/fusev3, which exists only on
// Linux. Strategy resolution already refuses "fuse" off-Linux; these stubs
// keep the shared mount flow compiling everywhere while failing closed if a
// future change ever reaches them.

type fuseV3Config struct {
	addr                   string
	token                  string
	transport              dataPlaneTransport
	identity               *clientTLSIdentity
	coherence              string
	volumeID               string
	mountPath              string
	mountInstanceID        string
	backingRoot            string
	noLocalDirs            bool
	requireMountEnrollment bool
}

type fuseV3Mount struct {
	routes  mountRoutes
	backing string
}

func (m *fuseV3Mount) Unmount() error                          { return fmt.Errorf("the v3 FUSE engine requires Linux") }
func (m *fuseV3Mount) Wait()                                   {}
func (m *fuseV3Mount) Close() error                            { return fmt.Errorf("the v3 FUSE engine requires Linux") }
func (m *fuseV3Mount) AuthorizationSessionID() string          { return "" }
func (m *fuseV3Mount) InitialAuthorizationDeadline() time.Time { return time.Time{} }
func (m *fuseV3Mount) Reauthorize(context.Context, string, uint64, []byte) (time.Time, error) {
	return time.Time{}, fmt.Errorf("the v3 FUSE engine requires Linux")
}

func mountFUSEv3(fuseV3Config) (*fuseV3Mount, error) {
	return nil, fmt.Errorf("the v3 FUSE engine requires Linux")
}
