package mountid

import "testing"

func TestStableIdentityShapes(t *testing.T) {
	mount, err := NewMountInstance()
	if err != nil || !ValidMountInstance(mount) {
		t.Fatalf("mount id = %q, %v", mount, err)
	}
	attach, err := NewAttachRef()
	if err != nil || !ValidAttachRef(attach) {
		t.Fatalf("attach ref = %q, %v", attach, err)
	}
	if mount == attach {
		t.Fatal("identity domains collided")
	}
}
