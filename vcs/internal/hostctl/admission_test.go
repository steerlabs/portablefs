package hostctl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalAdmissionRefusesEveryNonterminalPhase(t *testing.T) {
	for _, phase := range []string{PhasePreparingOld, PhaseOldAbsent, PhaseTargetReady, PhaseTargetActive, PhaseRollbackAbsent, PhaseRollbackReady, PhaseRollbackActive, PhaseTargetComplete, PhaseRollbackComplete} {
		for _, expired := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/expired=%t", phase, expired), func(t *testing.T) {
				root, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(root, 0o700); err != nil {
					t.Fatal(err)
				}
				host := filepath.Join(root, "host")
				if err := os.Mkdir(host, 0o700); err != nil {
					t.Fatal(err)
				}
				now := time.Now()
				if expired {
					now = now.Add(-2 * LeaseLifetime)
				}
				hash, err := TokenSHA256(strings.Repeat("a", 64))
				if err != nil {
					t.Fatal(err)
				}
				lease := ActivationLease{SchemaVersion: SchemaVersion, Phase: phase, TokenSHA256: hash,
					OldRelease: testReleaseIdentity("b", "1"), TargetRelease: testReleaseIdentity("c", "2"), CreatedAtUnixMS: now.UnixMilli(), DeadlineUnixMS: now.Add(LeaseLifetime).UnixMilli()}
				body, err := json.Marshal(lease)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(host, LeaseName), body, 0o600); err != nil {
					t.Fatal(err)
				}
				err = RequireNormalAdmission(root)
				complete := phase == PhaseTargetComplete || phase == PhaseRollbackComplete
				if (err == nil) != complete {
					t.Fatalf("phase %s expired %v: %v", phase, expired, err)
				}
			})
		}
	}
}

func TestNormalAdmissionRequiresSafeBoundedPublicRecord(t *testing.T) {
	for _, fault := range []string{"absent", "empty", "oversized", "symlink", "public", "invalid"} {
		t.Run(fault, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			host := filepath.Join(root, "host")
			if err := os.Mkdir(host, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(host, LeaseName)
			if fault != "absent" {
				body := []byte{}
				if fault == "oversized" {
					body = make([]byte, MaxFrameBytes+1)
				}
				if fault == "invalid" {
					body = []byte(`{"schemaVersion":1,"phase":"target-complete"}`)
				}
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
				if fault == "public" {
					if err := os.Chmod(path, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				if fault == "symlink" {
					if err := os.Rename(path, path+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(path+".original", path); err != nil {
						t.Fatal(err)
					}
				}
			}
			err = RequireNormalAdmission(root)
			if (err == nil) != (fault == "absent") {
				t.Fatalf("%s: %v", fault, err)
			}
		})
	}
}
