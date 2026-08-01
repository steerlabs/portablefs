package cli

import (
	"encoding/json"
	"testing"
)

// TestMountsJSONCarriesTheDaemonsFailureVerdicts pins the fidelity of the
// `portablefs mounts --json` write-back view against the daemon's own status.
//
// The CLI decodes the daemon's attach status into its own presentation types,
// and those types silently DROPPED every field that says something went wrong:
// writeBack.degraded, writeBack.lastFailure and delegations[].drainError. An
// agent or operator reading --json therefore saw a mount with a small stable
// backlog and no visible problem while the daemon held a latched stall verdict
// and a recorded release failure naming the exact scope. The printed line
// showed some of it; the machine-readable view did not.
//
// The decode below is the daemon's real JSON shape (portablefsd's
// writeBackStatus / delegationView / attachStatus tags).
func TestMountsJSONCarriesTheDaemonsFailureVerdicts(t *testing.T) {
	const daemonStatus = `{
	  "attachRef": "att_x",
	  "mountPath": "/Volumes/X",
	  "volumeId": "vol",
	  "branch": "main",
	  "state": "degraded",
	  "lastError": "access credential rejected by a REACHABLE authority",
	  "writeBack": {
	    "pendingRecords": 12,
	    "pendingBytes": 34567,
	    "degraded": true,
	    "lastFailure": "writeback: flush stalled: no watermark progress",
	    "delegations": [
	      {"scope": "a/b", "draining": false,
	       "drainError": "writeback: frontend handoff start \"a/b\": kernel publication barrier did not settle"}
	    ],
	    "parkedWals": []
	  }
	}`

	var status cliAttachStatus
	if err := json.Unmarshal([]byte(daemonStatus), &status); err != nil {
		t.Fatal(err)
	}
	if status.LastError == "" {
		t.Error("cliAttachStatus dropped the daemon's lastError")
	}
	if status.WriteBack == nil {
		t.Fatal("cliAttachStatus dropped the whole writeBack view")
	}
	if !status.WriteBack.Degraded {
		t.Error(
			"cliWriteBackStatus dropped writeBack.degraded: a latched stall " +
				"verdict is invisible in `portablefs mounts --json`",
		)
	}
	if status.WriteBack.LastFailure == "" {
		t.Error(
			"cliWriteBackStatus dropped writeBack.lastFailure: the reason " +
				"behind a degraded engine is invisible in --json",
		)
	}
	if len(status.WriteBack.Delegations) != 1 {
		t.Fatalf("delegations = %+v", status.WriteBack.Delegations)
	}
	if status.WriteBack.Delegations[0].DrainError == "" {
		t.Error(
			"cliDelegationView dropped delegations[].drainError: a scope whose " +
				"release definitively failed is indistinguishable from an idle " +
				"held grant in --json, including the one an unmount refusal names",
		)
	}

	// The presentation row must carry them through, not merely decode them.
	round, err := json.Marshal(status.WriteBack)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(round, &back); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"degraded", "lastFailure"} {
		if _, ok := back[key]; !ok {
			t.Errorf("re-encoded writeBack view omits %q", key)
		}
	}
	dels, _ := back["delegations"].([]any)
	if len(dels) != 1 {
		t.Fatalf("re-encoded delegations = %v", back["delegations"])
	}
	if _, ok := dels[0].(map[string]any)["drainError"]; !ok {
		t.Error("re-encoded delegation view omits drainError")
	}
}
