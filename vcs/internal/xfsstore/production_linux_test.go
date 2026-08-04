//go:build linux

package xfsstore

import (
	"os"
	"strconv"
	"testing"
)

// requireProvisionedXFS resolves the privileged XFS gate.
//
// PORTABLEFS_XFS_TEST_REQUIRED is set by the privileged CI job and converts a
// missing gate, or a root-owned test process, into a hard failure. Without it a
// broken provisioner would present as a green run with a silent skip, which is
// exactly how this test reached production having never executed.
func requireProvisionedXFS(t *testing.T) (string, uint32) {
	t.Helper()
	root := os.Getenv("PORTABLEFS_XFS_TEST_ROOT")
	projectRaw := os.Getenv("PORTABLEFS_XFS_TEST_PROJECT")
	required := os.Getenv("PORTABLEFS_XFS_TEST_REQUIRED") == "1"
	if root == "" || projectRaw == "" {
		if required {
			t.Fatalf("PORTABLEFS_XFS_TEST_REQUIRED=1 but PORTABLEFS_XFS_TEST_ROOT=%q PORTABLEFS_XFS_TEST_PROJECT=%q", root, projectRaw)
		}
		t.Skip("PORTABLEFS_XFS_TEST_ROOT and PORTABLEFS_XFS_TEST_PROJECT are required")
	}
	// The ownership gate below is only a real check for an unprivileged identity.
	if required && os.Geteuid() == 0 {
		t.Fatal("PORTABLEFS_XFS_TEST_REQUIRED=1 requires the unprivileged volume identity, not root")
	}
	project, err := strconv.ParseUint(projectRaw, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	return root, uint32(project)
}

// TestProductionXFSProjectGate runs only in the Linux XFS job. It runs as the
// unprivileged volume identity against the directory the production provisioner
// published, so it validates that provisioner's output as well as the startup
// checks that ordinary temp-directory tests skip. Quota setup is attested by the
// separate privileged provisioner; this process deliberately has no quota-admin
// power.
func TestProductionXFSProjectGate(t *testing.T) {
	root, project := requireProvisionedXFS(t)
	v, err := Open(root, Config{ExpectedProjectID: project, ExpectedOwnerUID: uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid())})
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
	// Leave the cell as it was found: repeated runs must not accumulate names,
	// and the exclusive-create above must be able to succeed again.
	if err := v.Unlink(rootCap, "production-gate", false); err != nil {
		t.Fatal(err)
	}
}

// TestProductionXFSGateRefusesAForeignProjectID proves the gate is load-bearing.
// A directory inside the provisioned cell carries the real project ID, so
// opening it while expecting a different one must fail closed. Without this, the
// gate above would pass identically if project verification were removed.
func TestProductionXFSGateRefusesAForeignProjectID(t *testing.T) {
	root, project := requireProvisionedXFS(t)
	if _, err := Open(root, Config{ExpectedProjectID: project + 1, ExpectedOwnerUID: uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid())}); err == nil {
		t.Fatalf("Open accepted project %d on a cell provisioned for %d", project+1, project)
	}
}
