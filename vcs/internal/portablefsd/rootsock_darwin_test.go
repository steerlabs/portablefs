//go:build darwin

package portablefsd

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMountRootLeaseSurvivesOwnerRetirementWithoutFDReuse(t *testing.T) {
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	owner, err := unix.FcntlInt(root.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	_ = root.Close()
	if err != nil {
		t.Fatal(err)
	}
	a := &attach{mountRootFD: owner, mountRootBound: true}
	lease, err := a.mountRootDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	defer closeMountRootFD(lease)

	a.releaseMountRoot()
	a.releaseMountRoot()
	if _, err := a.mountRootDescriptor(); err == nil {
		t.Fatal("retired mount root issued another lease")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(lease, &stat); err != nil {
		t.Fatalf("owned repair lease died with its owner: %v", err)
	}
	if err := unix.Fstat(owner, &stat); err == nil {
		t.Fatal("mount-root owner remained open after retirement")
	}
}

func TestMountRootBindingCanRepresentDescriptorZero(t *testing.T) {
	a := &attach{mountRootFD: 0, mountRootBound: true}
	lease, err := a.mountRootDescriptor()
	if err != nil {
		t.Fatalf("valid descriptor zero was treated as unbound: %v", err)
	}
	closeMountRootFD(lease)
}
