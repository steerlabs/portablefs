//go:build linux

package workspacemount

import (
	"errors"
	"os"
	"path/filepath"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"golang.org/x/sys/unix"
)

func (m *Manager) protectedTarget(id *pb.MountID) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	path := filepath.Join(m.Targets, id.VolumeId)
	if err := os.Mkdir(path, 0); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, st, err
	}
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, st, err
	}
	target := os.NewFile(uintptr(fd), "protected workspace target")
	if err = unix.Fstat(fd, &st); err != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&0777 != 0 {
		target.Close()
		return nil, st, errors.New("workspace target must be root-owned mode 000")
	}
	return target, st, nil
}

// Machine-local routes belong to this machine and authority/volume, across
// terminal replacement and cold boots. Incarnation metadata is separate.
func (m *Manager) backingRoot(id *pb.MountID) (string, error) {
	path := filepath.Join(m.Backing, volumeKey(id.AuthorityId, id.VolumeId))
	if err := os.Mkdir(path, 0700); err == nil {
		if err = os.Chown(path, 1000, 1000); err != nil {
			return "", err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return "", err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return "", err
	}
	if st.Uid != 1000 || st.Gid != 1000 || st.Mode&0777 != 0700 {
		return "", errors.New("workspace local backing ownership changed")
	}
	return path, nil
}

// The host has durably retained these outcomes before ACK. Delete only exact
// cleaned incarnation metadata before releasing the root's retained record;
// machine-local route data deliberately survives.
func (m *Manager) Acknowledge(ids []*pb.MountID) error {
	runs := m.Inventory.Snapshot()
	for _, id := range ids {
		for _, run := range runs {
			if string(run.Mount.AuthorityId) != string(id.AuthorityId) || run.Mount.VolumeId != id.VolumeId || string(run.Mount.Incarnation) != string(id.Incarnation) {
				continue
			}
			if !run.Removed {
				return errors.New("workspace acknowledgement retains live child metadata")
			}
			if err := os.RemoveAll(filepath.Join(m.Clients, run.Witness.Intent)); err != nil {
				return err
			}
		}
	}
	return m.Inventory.Acknowledge(ids)
}
