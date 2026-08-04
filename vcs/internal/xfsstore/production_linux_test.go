//go:build linux

package xfsstore

import (
	"os"
	"strconv"
	"testing"
)

// TestProductionXFSProjectGate runs only in the Linux XFS job. It runs as the
// unprivileged volume identity and exercises the exact startup checks that
// ordinary temp-directory tests skip. Quota setup is attested by the separate
// privileged provisioner; this process deliberately has no quota-admin power.
func TestProductionXFSProjectGate(t *testing.T) {
	root := os.Getenv("PORTABLEFS_XFS_TEST_ROOT")
	projectRaw := os.Getenv("PORTABLEFS_XFS_TEST_PROJECT")
	if root == "" || projectRaw == "" {
		t.Skip("PORTABLEFS_XFS_TEST_ROOT and PORTABLEFS_XFS_TEST_PROJECT are required")
	}
	project, err := strconv.ParseUint(projectRaw, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Open(root, Config{ExpectedProjectID: uint32(project), ExpectedOwnerUID: uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid())})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	stat, err := v.StatFS()
	if err != nil {
		t.Fatal(err)
	}
	if stat.Blocks == 0 || stat.Files == 0 || stat.BlocksAvailable > stat.Blocks || stat.FilesFree > stat.Files {
		t.Fatalf("invalid project statfs: %+v", stat)
	}
	rootCap, _ := v.Root()
	item, _, err := v.Create(rootCap, "production-gate", 0o600, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := v.OpenFile(item, OpenFlags{Read: true, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.WriteAt(handle, []byte("durable"), 0); err != nil {
		t.Fatal(err)
	}
	if err := v.Fsync(handle, false); err != nil {
		t.Fatal(err)
	}
	if err := v.CloseOpen(handle); err != nil {
		t.Fatal(err)
	}
	if err := v.SyncObject(rootCap); err != nil {
		t.Fatal(err)
	}
}
