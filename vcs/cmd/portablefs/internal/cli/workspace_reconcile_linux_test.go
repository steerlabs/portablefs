//go:build linux

package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	"github.com/steerlabs/portablefs/vcs/internal/workspacemount"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func TestWorkspaceReconcileHelper(t *testing.T) {
	mode := os.Getenv("PFS_PR6_RECONCILE_HELPER")
	if mode == "" {
		return
	}
	directory, target := os.Getenv("PFS_PR6_STATE"), os.Getenv("PFS_PR6_TARGET")
	if mode == "seed" {
		start, err := processStartIdentity(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(strconv.Itoa(os.Getpid()) + ":" + start); err != nil {
			t.Fatal(err)
		}
		var b [1]byte
		if _, err = io.ReadFull(os.Stdin, b[:]); err != nil || b[0] != 's' {
			t.Fatal("seed not authorized", err)
		}
		state := mountState{SchemaVersion: mountStateSchemaVersion, MountPath: target, VolumeID: "volume", PID: os.Getpid(), ProcessStartIdentity: start, Strategy: "fuse", Engine: mountEngineFuseV3, MountInstanceID: "mnt_AAAAAAAAAAAAAAAAAAAAAA", KernelMountID: "777", MountTargetDevice: 1, MountTargetInode: 2, MountMechanism: "direct", AuthorityURL: "unused.test:7443", DataPlaneTransport: dataPlaneTransportPlaintext, StartedAtMs: 1, LocalRouteRevision: emptyRoutesRevision()}
		if os.Getenv("PFS_PR6_CLI_FIRST") == "1" {
			state.AuthorizationSessionID = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 16))
		}
		op, err := acquireMountOperation(directory, target, "volume", "fuse")
		if err != nil {
			t.Fatal(err)
		}
		hydrateMountOperationFromState(op, &state)
		if err = op.writeIntent("mounting", os.Getpid(), start); err != nil {
			t.Fatal(err)
		}
		if err = writeMountState(directory, state); err != nil {
			t.Fatal(err)
		}
		if err = op.close(false); err != nil {
			t.Fatal(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode("seeded"); err != nil {
			t.Fatal(err)
		}
		if _, err = io.ReadFull(os.Stdin, b[:]); err != nil || b[0] != 'g' {
			t.Fatal("reconcile not authorized", err)
		}
	}
	e := &cmdEnv{stdout: os.Stdout, stderr: os.Stderr}
	os.Exit(e.runWorkspaceReconcile(3, "volume", target))
}

// Both real CLI stores survive a missing root commit acknowledgement. A fresh
// helper may remove them only after the root durably owns their partial facts.
// The first helper deliberately has the recorded PID/start: the discarded boot
// proof must prevent reconciliation from signalling that reused identity.
func TestWorkspaceReconcileIndependentCommitsAndLostAcknowledgment(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root inventory and UID 1000 CLI inventory owners")
	}
	for _, first := range []string{"workspace", "cli"} {
		for _, lost := range []bool{false, true} {
			t.Run(first+"/lost-ack-"+strconv.FormatBool(lost), func(t *testing.T) {
				directory, err := os.MkdirTemp("/tmp", "pfs-pr6-reconcile-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(directory)
				if err = os.Chmod(directory, 0755); err != nil {
					t.Fatal(err)
				}
				stateDir := filepath.Join(directory, "client")
				if err = os.Mkdir(stateDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err = os.Chown(stateDir, 1000, 1000); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(directory, "protected")
				if err = os.Mkdir(target, 0); err != nil {
					t.Fatal(err)
				}
				binary, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				source, err := os.Open(binary)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				copyPath := filepath.Join(directory, "cli-test")
				out, err := os.OpenFile(copyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.Copy(out, source)
				out.Close()
				if err != nil {
					t.Fatal(err)
				}
				rootDir := filepath.Join(directory, "root-inventory")
				inventory, err := workspacemount.OpenInventory(rootDir)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { inventory.Close() }()
				id := &pb.MountID{AuthorityId: bytes.Repeat([]byte{1}, 32), VolumeId: "volume", Incarnation: bytes.Repeat([]byte{2}, 16)}
				run := &workspacemount.Desired{KernelBoot: "discarded-kernel-boot", Mount: id, Boot: bytes.Repeat([]byte{3}, 16), Witness: workspacemount.Witness{Intent: "mnt_AAAAAAAAAAAAAAAAAAAAAA", Source: "portablefs:mnt_AAAAAAAAAAAAAAAAAAAAAA", Target: target, Kernel: "777@0:42"}, TargetDevice: 1, TargetInode: 2, Outcome: control.UnknownOutcome()}
				if first == "workspace" {
					run.Witness.Session = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 16))
				}
				startHelper := func(mode string) (*exec.Cmd, io.WriteCloser, *json.Decoder, io.WriteCloser) {
					t.Helper()
					read, write, err := os.Pipe()
					if err != nil {
						t.Fatal(err)
					}
					cmd := exec.Command(copyPath, "-test.run=^TestWorkspaceReconcileHelper$")
					cliFirst := "0"
					if first == "cli" {
						cliFirst = "1"
					}
					cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + directory, "PFS_PR6_RECONCILE_HELPER=" + mode, "PFS_PR6_STATE=" + stateDir, "PFS_PR6_TARGET=" + target, "PFS_PR6_CLI_FIRST=" + cliFirst}
					cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
					cmd.ExtraFiles = []*os.File{read}
					cmd.Stderr = os.Stderr
					stdin, err := cmd.StdinPipe()
					if err != nil {
						t.Fatal(err)
					}
					stdout, err := cmd.StdoutPipe()
					if err != nil {
						t.Fatal(err)
					}
					if err = cmd.Start(); err != nil {
						t.Fatal(err)
					}
					read.Close()
					t.Cleanup(func() { _ = cmd.Process.Kill(); stdin.Close(); write.Close() })
					return cmd, stdin, json.NewDecoder(stdout), write
				}
				cmd, ack, decoder, request := startHelper("seed")
				if err = decoder.Decode(&run.Witness.Process); err != nil {
					t.Fatal(err)
				}
				if first == "workspace" {
					if err = inventory.CommitDesired(run); err != nil {
						t.Fatal(err)
					}
				}
				if _, err = ack.Write([]byte{'s'}); err != nil {
					t.Fatal(err)
				}
				var seeded string
				if err = decoder.Decode(&seeded); err != nil || seeded != "seeded" {
					t.Fatal(seeded, err)
				}
				if first == "cli" {
					if err = inventory.CommitDesired(run); err != nil {
						t.Fatal(err)
					}
				}
				_, intentPath := mountOperationPaths(stateDir, target)
				statePath := mountStatePath(stateDir, target)
				retained := func() {
					t.Helper()
					for _, path := range []string{intentPath, statePath} {
						if _, e := os.Stat(path); e != nil {
							t.Fatal("CLI evidence disappeared before root commit acknowledgement", path, e)
						}
					}
				}
				retained()
				if err = json.NewEncoder(request).Encode(workspacemount.Reconciliation{Desired: run, StateDirectory: stateDir}); err != nil {
					t.Fatal(err)
				}
				request.Close()
				if _, err = ack.Write([]byte{'g'}); err != nil {
					t.Fatal(err)
				}
				var witness workspacemount.Witness
				if err = decoder.Decode(&witness); err != nil {
					t.Fatal("helper signalled the reused PID or lost independent evidence", err)
				}
				retained()
				if witness.Session == "" || witness.Process != run.Witness.Process {
					t.Fatal(witness)
				}
				if err = inventory.BindWitness(id, witness); err != nil {
					t.Fatal(err)
				}
				if lost {
					ack.Close()
					if err = cmd.Wait(); err == nil {
						t.Fatal("missing durable acknowledgement finalized CLI evidence")
					}
					retained()
					inventory.Close()
					inventory, err = workspacemount.OpenInventory(rootDir)
					if err != nil {
						t.Fatal(err)
					}
					current := inventory.Snapshot()[0]
					if current.Removed || current.Witness.Session != witness.Session {
						t.Fatal("crash lost partial durable ownership", current)
					}
					cmd, ack, decoder, request = startHelper("reconcile")
					if err = json.NewEncoder(request).Encode(workspacemount.Reconciliation{Desired: current, StateDirectory: stateDir}); err != nil {
						t.Fatal(err)
					}
					request.Close()
					if err = decoder.Decode(&witness); err != nil {
						t.Fatal(err)
					}
					if err = inventory.BindWitness(id, witness); err != nil {
						t.Fatal(err)
					}
				}
				if _, err = ack.Write([]byte{'c'}); err != nil {
					t.Fatal(err)
				}
				ack.Close()
				if err = cmd.Wait(); err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{intentPath, statePath} {
					if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("acknowledged CLI inventory was not removed", path, err)
					}
				}
				if err = inventory.Reconcile(id, func(d *workspacemount.Desired) error {
					_, e := fusev3.ObservePlannedKernelMountAbsent(d.Witness.Source, d.Witness.Target)
					return e
				}); err != nil {
					t.Fatal(err)
				}
				final := inventory.Snapshot()[0]
				if !final.Removed || final.Outcome.Observation != "unobserved" || final.Outcome.Durability != "unresolved" {
					t.Fatal("reconciliation invented a durability observation", final)
				}
			})
		}
	}
}
