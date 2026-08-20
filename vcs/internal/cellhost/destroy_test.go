package cellhost

import (
	"errors"
	"testing"
)

const testCellID = "11111111-1111-4111-8111-111111111111"

// pinnedDestroyProof is the destroy proof of completeDestroyRecord. The Linux
// destroy test drives a real placement to exactly this record, so the two ends
// of the contract - what the host verifies and what the manager stores - are
// pinned to one constant.
const pinnedDestroyProof = "1e9e36dfda1ac64e8558f9e8600a9a52c893b42e650ab500cb9b04d675f8b565"

const testAuthorityName = "v-22222222222242228222222222222222-p3.cells.example"

func completeDestroyRecord() DestroyRecord {
	return DestroyRecord{
		AuthorityEpoch:      7,
		AuthorityID:         testAuthorityName,
		AuthorityServerName: testAuthorityName,
		CellID:              testCellID,
		ListenPort:          9443,
		PlacementSequence:   3,
		Postconditions: DestroyPostconditions{
			ConfigRootAbsent: true, DropInsAbsent: true, QuotaCleared: true,
			StateRootAbsent: true, SysusersConfAbsent: true, TreeAbsent: true,
		},
		ProjectID:  43001,
		ServiceGID: 210000,
		ServiceUID: 210000,
		VolumeID:   testVolumeID,
	}
}

// TestDestroyProofPreimageIsPinned is the contract test for the destroy proof.
// The manager stores this hash durably and later matches a RELEASE against it,
// so the preimage is a wire format: exactly these keys, sorted, no whitespace.
// A field reordering, a renamed key, or an encoder that pretty-prints would
// silently invalidate every stored proof, and this test is what catches it.
func TestDestroyProofPreimageIsPinned(t *testing.T) {
	const canonical = `{"authority_epoch":7,` +
		`"authority_id":"v-22222222222242228222222222222222-p3.cells.example",` +
		`"authority_server_name":"v-22222222222242228222222222222222-p3.cells.example",` +
		`"cell_id":"11111111-1111-4111-8111-111111111111",` +
		`"listen_port":9443,"placement_sequence":3,"postconditions":{"config_root_absent":true,` +
		`"dropins_absent":true,"quota_cleared":true,"state_root_absent":true,` +
		`"sysusers_conf_absent":true,"tree_absent":true},"project_id":43001,"service_gid":210000,` +
		`"service_uid":210000,"volume_id":"22222222-2222-4222-8222-222222222222"}`
	payload, err := completeDestroyRecord().CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != canonical {
		t.Fatalf("canonical destroy JSON =\n%s\nwant\n%s", payload, canonical)
	}
	hash, err := completeDestroyRecord().ProofSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if hash != pinnedDestroyProof {
		t.Fatalf("destroy proof = %s, want %s", hash, pinnedDestroyProof)
	}
}

// TestDestroyProofBindsToOnePlacement: the proof exists to stop a stale plan
// replay from touching a newer incarnation, so every identity field must move
// the hash.
func TestDestroyProofBindsToOnePlacement(t *testing.T) {
	base, err := completeDestroyRecord().ProofSHA256()
	if err != nil {
		t.Fatal(err)
	}
	variants := map[string]DestroyRecord{}
	epoch := completeDestroyRecord()
	epoch.AuthorityEpoch++
	variants["authority epoch"] = epoch
	sequence := completeDestroyRecord()
	sequence.PlacementSequence++
	variants["placement sequence"] = sequence
	project := completeDestroyRecord()
	project.ProjectID++
	variants["project id"] = project
	uid := completeDestroyRecord()
	uid.ServiceUID++
	variants["service uid"] = uid
	port := completeDestroyRecord()
	port.ListenPort++
	variants["listen port"] = port
	gid := completeDestroyRecord()
	gid.ServiceGID++
	variants["service gid"] = gid
	authority := completeDestroyRecord()
	authority.AuthorityID = "v-other-p3.cells.example"
	variants["authority id"] = authority
	serverName := completeDestroyRecord()
	serverName.AuthorityServerName = "v-other-p3.cells.example"
	variants["authority server name"] = serverName
	cell := completeDestroyRecord()
	cell.CellID = "11111111-1111-4111-8111-111111111112"
	variants["cell id"] = cell
	volume := completeDestroyRecord()
	volume.VolumeID = "22222222-2222-4222-8222-222222222223"
	variants["volume id"] = volume
	for name, record := range variants {
		hash, err := record.ProofSHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if hash == base {
			t.Fatalf("changing the %s did not change the destroy proof", name)
		}
	}
}

func TestDestroyProofRefusesUnboundIdentity(t *testing.T) {
	for name, mutate := range map[string]func(*DestroyRecord){
		"zero epoch":       func(record *DestroyRecord) { record.AuthorityEpoch = 0 },
		"zero sequence":    func(record *DestroyRecord) { record.PlacementSequence = 0 },
		"zero project":     func(record *DestroyRecord) { record.ProjectID = 0 },
		"zero uid":         func(record *DestroyRecord) { record.ServiceUID = 0 },
		"zero port":        func(record *DestroyRecord) { record.ListenPort = 0 },
		"zero gid":         func(record *DestroyRecord) { record.ServiceGID = 0 },
		"unset cell":       func(record *DestroyRecord) { record.CellID = "" },
		"unset volume":     func(record *DestroyRecord) { record.VolumeID = "" },
		"non-uuid volume":  func(record *DestroyRecord) { record.VolumeID = "../escape" },
		"non-uuid cell id": func(record *DestroyRecord) { record.CellID = "cell-one" },
		"unset authority":  func(record *DestroyRecord) { record.AuthorityID = "" },
		"unset name":       func(record *DestroyRecord) { record.AuthorityServerName = "" },
		// A name the encoder would escape, or one carrying a path separator,
		// can never enter the preimage.
		"escaping name": func(record *DestroyRecord) { record.AuthorityServerName = "v-<a>&b.cells.example" },
		"path in name":  func(record *DestroyRecord) { record.AuthorityID = "../../etc/passwd" },
	} {
		record := completeDestroyRecord()
		mutate(&record)
		if _, err := record.ProofSHA256(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: proof error = %v, want ErrInvalid", name, err)
		}
	}
}

func TestUnsatisfiedNamesTheFailingPostconditionInCanonicalOrder(t *testing.T) {
	if unsatisfied := completeDestroyRecord().Postconditions.Unsatisfied(); unsatisfied != "" {
		t.Fatalf("complete postconditions reported %q unsatisfied", unsatisfied)
	}
	for want, mutate := range map[string]func(*DestroyPostconditions){
		"config_root_absent":   func(p *DestroyPostconditions) { p.ConfigRootAbsent = false },
		"dropins_absent":       func(p *DestroyPostconditions) { p.DropInsAbsent = false },
		"quota_cleared":        func(p *DestroyPostconditions) { p.QuotaCleared = false },
		"state_root_absent":    func(p *DestroyPostconditions) { p.StateRootAbsent = false },
		"sysusers_conf_absent": func(p *DestroyPostconditions) { p.SysusersConfAbsent = false },
		"tree_absent":          func(p *DestroyPostconditions) { p.TreeAbsent = false },
	} {
		postconditions := completeDestroyRecord().Postconditions
		mutate(&postconditions)
		if got := postconditions.Unsatisfied(); got != want {
			t.Fatalf("Unsatisfied() = %q, want %q", got, want)
		}
	}
}
