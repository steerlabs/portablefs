package cli

import (
	"context"
	"encoding/json"
	"github.com/steerlabs/portablefs/vcs/internal/workspacehost"
	"strings"
	"testing"
)

func TestWorkspaceExactlyFiveVerbsAndFlags(t *testing.T) {
	for _, args := range [][]string{{"start"}, {"status", "--json"}, {"status", "--dismiss", "1/01010101010101010101010101010101/vol-1", "--json"}, {"umount", "vol-1", "--force", "--json"}, {"stop", "--json"}, {"stop", "--force"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			e, out, errs := testEnv(t)
			called := false
			e.workspaceRequestFn = func(_ context.Context, r workspacehost.Request) (workspacehost.Reply, error) {
				called = true
				if err := r.Validate(); err != nil {
					t.Fatal(err)
				}
				return workspacehost.Reply{Version: 1, State: "pending", Message: "pending", Volumes: []workspacehost.Volume{}}, nil
			}
			if code := cmdWorkspace(e, args); code != 0 || !called {
				t.Fatalf("code=%d out=%s err=%s", code, out, errs)
			}
		})
	}
	for _, args := range [][]string{{}, {"shell"}, {"pause"}, {"identity"}, {"exec", "true"}, {"vm-list"}, {"ssh-config"}, {"start", "--json"}, {"start", "--force"}, {"status", "--force"}, {"status", "--dismiss", ""}, {"status", "--dismiss", "all"}, {"dismiss", "1/01010101010101010101010101010101/vol-1"}, {"stop", "--dismiss", "1/01010101010101010101010101010101/vol-1"}, {"umount", "../bad"}, {"umount"}, {"stop", "extra"}, {"mount"}, {"mount", "key.pem"}} {
		t.Run("refuse "+strings.Join(args, " "), func(t *testing.T) {
			e, _, _ := testEnv(t)
			e.workspaceRequestFn = func(context.Context, workspacehost.Request) (workspacehost.Reply, error) {
				t.Fatal("invalid CLI reached service")
				return workspacehost.Reply{}, nil
			}
			if cmdWorkspace(e, args) != 2 {
				t.Fatal("invalid args not usage error")
			}
		})
	}
	if help, ok := commandHelp("workspace"); !ok || !strings.Contains(help, ".pfsworkspace") {
		t.Fatal("workspace help missing")
	}
}
func TestWorkspaceReportsPendingAuthorizationAndBusyWithoutMountCompletion(t *testing.T) {
	e, out, _ := testEnv(t)
	e.workspaceRequestFn = func(context.Context, workspacehost.Request) (workspacehost.Reply, error) {
		return workspacehost.Reply{Version: 1, State: "running", Message: workspacehost.Running, DesiredRunning: true, Volumes: []workspacehost.Volume{{VolumeID: "vol-1", Path: "/workspaces/vol-1", State: "authorization-required", Message: workspacehost.AuthorizationRequired, AuthorizationRequest: "/generated/authorization.pfsworkspace"}}}, nil
	}
	if cmdWorkspace(e, []string{"status", "--json"}) != 0 {
		t.Fatal("status failed")
	}
	if !strings.Contains(out.String(), `"state": "authorization-required"`) || strings.Contains(out.String(), `"state": "ready"`) {
		t.Fatal(out.String())
	}
}

func TestWorkspaceCleanupRequiredStatusKeepsMachineReadableEvidence(t *testing.T) {
	e, out, errs := testEnv(t)
	e.workspaceRequestFn = func(context.Context, workspacehost.Request) (workspacehost.Reply, error) {
		return workspacehost.Reply{Version: 1, State: "cleanup-required", Message: "Cleanup required", DesiredRunning: true, PreviousWriteOutcomeUnknown: true, Volumes: []workspacehost.Volume{}}, nil
	}
	if code := cmdWorkspace(e, []string{"status", "--json"}); code != 1 {
		t.Fatalf("cleanup status exit=%d, want 1", code)
	}
	var reply workspacehost.Reply
	if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
		t.Fatal("nonzero status lost JSON evidence", err)
	}
	if reply.State != "cleanup-required" || !reply.PreviousWriteOutcomeUnknown || !reply.DesiredRunning || errs.Len() != 0 {
		t.Fatalf("cleanup status changed: %+v, stderr=%s", reply, errs)
	}
}

func TestWorkspaceStatusNamesExactOutcomeAndDismissUsesOnlyStatusVerb(t *testing.T) {
	const id = "8/08080808080808080808080808080808/vol-1"
	e, out, errs := testEnv(t)
	var requests []workspacehost.Request
	e.workspaceRequestFn = func(_ context.Context, request workspacehost.Request) (workspacehost.Reply, error) {
		requests = append(requests, request)
		return workspacehost.Reply{Version: 1, State: "stopped", Message: "Linux Workspace: Stopped", Volumes: []workspacehost.Volume{}, Outcomes: []workspacehost.Outcome{{ID: id, SomeChangesWereNotSaved: true}}}, nil
	}
	if cmdWorkspace(e, []string{"status"}) != 0 || !strings.Contains(out.String(), "Some changes were not saved") || !strings.Contains(out.String(), "portablefs workspace status --dismiss "+id) {
		t.Fatal(out, errs)
	}
	if cmdWorkspace(e, []string{"status", "--dismiss", id}) != 0 {
		t.Fatal(errs)
	}
	if len(requests) != 2 || requests[0].Operation != "status" || requests[0].OutcomeID != "" || requests[1].Operation != "dismiss" || requests[1].OutcomeID != id {
		t.Fatal(requests)
	}
}
