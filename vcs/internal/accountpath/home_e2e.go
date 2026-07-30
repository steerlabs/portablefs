//go:build portablefs_e2e

package accountpath

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// The end-to-end quickstart binary is compiled with portablefs_e2e so it can
// exercise account-scoped persistence without touching the developer's real
// account. Production binaries do not contain this override.
func init() {
	root := os.Getenv("PORTABLEFS_E2E_ACCOUNT_HOME")
	if root == "" {
		return
	}
	uid := os.Geteuid()
	lookupID = func(rawUID string) (*user.User, error) {
		if rawUID != strconv.Itoa(uid) {
			return nil, fmt.Errorf("portablefs e2e account lookup requested uid %s, want %d", rawUID, uid)
		}
		return &user.User{
			Uid:     rawUID,
			Gid:     strconv.Itoa(os.Getegid()),
			HomeDir: root,
		}, nil
	}
}
