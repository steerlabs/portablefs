package directstoreharness

import (
	"bytes"
	"os"
	"testing"
)

// phaseOneCatalog mirrors only the mutation and exact-reply rows consumed from
// the sibling Phase 0 table. Production callers pass that table through
// Catalog; the harness has no built-in authoritative list.
var phaseOneCatalog = Catalog{
	{ID: pointLeaderObject, Kind: PersistenceCut, Scenario: "mutation", Actors: []string{"leader"}},
	{ID: pointLeaderStateCommit, Kind: PersistenceCut, Scenario: "mutation", Actors: []string{"leader"}},
	{ID: pointLeaderEntry, Kind: PersistenceCut, Scenario: "mutation", Actors: []string{"leader"}},
	{ID: pointFollowerObject, Kind: PersistenceCut, Scenario: "mutation", Actors: []string{"follower"}},
	{ID: pointFollowerStateCommit, Kind: PersistenceCut, Scenario: "mutation", Actors: []string{"follower"}},
	{ID: pointFollowerEntry, Kind: PersistenceCut, Scenario: "mutation", Actors: []string{"follower"}},
	{ID: pointLeaderCommit, Kind: PersistenceCut, Scenario: "mutation", Actors: []string{"leader"}},
	{ID: pointFollowerCommit, Kind: PersistenceCut, Scenario: "mutation", Actors: []string{"follower"}},
	{ID: pointLeaderApply, Kind: PersistenceCut, Scenario: "mutation", Actors: []string{"leader"}},
	{ID: pointFollowerApply, Kind: PersistenceCut, Scenario: "mutation", Actors: []string{"follower"}},
	{ID: pointProposal, Kind: MessageCut, Scenario: "mutation", Actors: []string{"leader", "follower"}},
	{ID: pointAppendResponse, Kind: MessageCut, Scenario: "mutation", Actors: []string{"follower", "leader"}},
	{ID: pointCommitNotice, Kind: MessageCut, Scenario: "mutation", Actors: []string{"leader", "follower"}},
	{ID: pointSuccessReply, Kind: MessageCut, Scenario: "exact_reply", Actors: []string{"leader", "client"}},
}

func fixtureFactory(defect FixtureDefect) TargetFactory {
	return func(environment *Environment) Target { return NewFixture(environment, defect) }
}

func TestSeedReplaysByteForByte(t *testing.T) {
	config := RunConfig{Seed: 0x5eedc0de, Operations: 200, Catalog: phaseOneCatalog}
	var first, second bytes.Buffer
	config.Trace = &first
	one := RunRandom(fixtureFactory(FixtureCorrect), config)
	if one.Violation != nil {
		t.Fatal(one.Violation)
	}
	config.Trace = &second
	two := RunRandom(fixtureFactory(FixtureCorrect), config)
	if two.Violation != nil {
		t.Fatal(two.Violation)
	}
	if one.TraceHash != two.TraceHash || !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatalf("seed %d did not replay byte-for-byte: %s != %s", config.Seed, one.TraceHash, two.TraceHash)
	}
	header, events, err := DecodeTrace(bytes.NewReader(first.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if header.Seed != config.Seed || header.Operations != config.Operations || header.Catalog != catalogDigest(config.Catalog) || len(events) == 0 {
		t.Fatalf("decoded trace header/events = %+v/%d", header, len(events))
	}
}

func TestCrashRetainsOnlySyncedBytes(t *testing.T) {
	recorder := NewRecorder(nil, TraceHeader{Seed: 1, Operations: 1, Mode: "unit"})
	environment := NewEnvironment(recorder)
	if err := environment.Persist(0, pointLeaderObject, "record", []byte("synced")); err != nil {
		t.Fatal(err)
	}
	record := encodeRecord([]byte("not-synced"))
	environment.disks[0].truncate("record")
	if err := environment.disks[0].writeAt("record", 0, record); err != nil {
		t.Fatal(err)
	}
	environment.Crash(0, "unit-crash")
	environment.Restart(0)
	got, err := environment.Read(0, "record")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "synced" {
		t.Fatalf("restart retained %q, want only declared-synced bytes", got)
	}
}

func TestEveryPhaseOneCutAndDirectedLink(t *testing.T) {
	cases := RunExhaustive(fixtureFactory(FixtureCorrect), phaseOneCatalog, 9000)
	if len(cases) == 0 {
		t.Fatal("no exhaustive cases generated")
	}
	partitions := make(map[uint8]bool)
	for _, testCase := range cases {
		if testCase.Fault.Kind == PartitionLink {
			partitions[testCase.Fault.Links] = true
		}
		if testCase.Result.Violation != nil {
			t.Fatalf("%s: %v", testCase.Name, testCase.Result.Violation)
		}
		if testCase.Result.FaultsInjected != 1 {
			t.Fatalf("%s injected %d faults, want exactly one", testCase.Name, testCase.Result.FaultsInjected)
		}
	}
	wantPartitions := (1 << len(directedReplicaLinks)) - 1
	if len(partitions) != wantPartitions {
		t.Fatalf("enumerated %d directed partition matrices, want %d", len(partitions), wantPartitions)
	}
	if !partitions[directedLinkBit(0, 1)] || !partitions[directedLinkBit(1, 0)] {
		t.Fatal("asymmetric directions 0->1 and 1->0 were not independently enumerated")
	}
}

func TestExhaustiveFaultPositionAcrossSmallHistory(t *testing.T) {
	onePosition := len(EnumerateFaults(phaseOneCatalog))
	cases := RunExhaustiveHistories(fixtureFactory(FixtureCorrect), phaseOneCatalog, 12_000, 2)
	if len(cases) != 2*onePosition {
		t.Fatalf("generated %d cases, want %d", len(cases), 2*onePosition)
	}
	for _, testCase := range cases {
		if testCase.Result.Violation != nil {
			t.Fatalf("%s: %v", testCase.Name, testCase.Result.Violation)
		}
		if testCase.Result.Operations != 2 || testCase.Result.FaultsInjected != 1 {
			t.Fatalf("%s operations/faults = %d/%d", testCase.Name, testCase.Result.Operations, testCase.Result.FaultsInjected)
		}
	}
}

func TestRandomFaultRunMaintainsReferenceModel(t *testing.T) {
	result := RunRandom(fixtureFactory(FixtureCorrect), RunConfig{
		Seed: 0xd15ea5e, Operations: 10_000, Catalog: phaseOneCatalog,
	})
	if result.Violation != nil {
		t.Fatal(result.Violation)
	}
	if result.FaultsInjected != result.Operations {
		t.Fatalf("injected %d faults across %d operations", result.FaultsInjected, result.Operations)
	}
}

func TestProgressWithOneReplicaOrItsAZLinksFailed(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		breakCluster func(*Environment)
	}{
		{
			name: "leader process",
			breakCluster: func(environment *Environment) {
				environment.Crash(0, "test.single-replica")
			},
		},
		{
			name: "leader AZ links",
			breakCluster: func(environment *Environment) {
				mask := directedLinkBit(0, 1) | directedLinkBit(1, 0) | directedLinkBit(0, 2) | directedLinkBit(2, 0)
				environment.Arm(Fault{Kind: PartitionLink, Point: "network.link", Node: AnyNode, Links: mask})
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := NewRecorder(nil, TraceHeader{Seed: 77, Operations: 1, Mode: "liveness"})
			environment := NewEnvironment(recorder)
			fixture := NewFixture(environment, FixtureCorrect)
			testCase.breakCluster(environment)
			reply := fixture.Mutate(Mutation{ID: ExactID{Client: 1, Sequence: 1}, Value: 99})
			if reply.Status != MutationSuccess {
				t.Fatalf("mutation with one failed replica/AZ returned %d", reply.Status)
			}
		})
	}
}

func TestNoMajorityFailsClosed(t *testing.T) {
	recorder := NewRecorder(nil, TraceHeader{Seed: 88, Operations: 1, Mode: "availability"})
	environment := NewEnvironment(recorder)
	fixture := NewFixture(environment, FixtureCorrect)
	environment.Arm(Fault{Kind: PartitionLink, Point: "network.link", Node: AnyNode, Links: (1 << len(directedReplicaLinks)) - 1})
	if reply := fixture.Mutate(Mutation{ID: ExactID{Client: 1, Sequence: 1}, Value: 1}); reply.Status == MutationSuccess {
		t.Fatal("mutation succeeded with no majority")
	}
	if reply := fixture.LinearizableRead(0); reply.Status == ReadSuccess {
		t.Fatal("linearizable read succeeded with no majority")
	}
}

func TestPlantedAcknowledgeBeforeQuorumIsDetected(t *testing.T) {
	const seed = 101
	result := RunRandom(fixtureFactory(FixtureAcknowledgeBeforeQuorum), RunConfig{Seed: seed, Operations: 10, Catalog: phaseOneCatalog})
	assertViolation(t, result, seed, "commit-without-quorum")
}

func TestPlantedTwoCommitsAtOneIndexIsDetected(t *testing.T) {
	const seed = 202
	result := RunRandom(fixtureFactory(FixtureTwoCommitsAtOneIndex), RunConfig{Seed: seed, Operations: 10, Catalog: phaseOneCatalog})
	assertViolation(t, result, seed, "two-commits-at-one-index")
}

func TestPlantedStaleFollowerReadIsDetected(t *testing.T) {
	const seed = 303
	result := RunRandom(fixtureFactory(FixtureStaleFollowerRead), RunConfig{Seed: seed, Operations: 100, Catalog: phaseOneCatalog})
	assertViolation(t, result, seed, "stale-linearizable-read")
}

func TestMillionFaultedOperations(t *testing.T) {
	if os.Getenv("PORTABLEFS_DIRECTSTORE_MILLION") != "1" {
		t.Skip("set PORTABLEFS_DIRECTSTORE_MILLION=1 to run the Phase 1 scale gate")
	}
	result := RunRandom(fixtureFactory(FixtureCorrect), RunConfig{
		Seed: 1_000_003, Operations: 1_000_000, Catalog: phaseOneCatalog,
	})
	if result.Violation != nil {
		t.Fatal(result.Violation)
	}
	if result.FaultsInjected != 1_000_000 {
		t.Fatalf("injected %d faults, want 1000000", result.FaultsInjected)
	}
	t.Logf("seed=%d operations=%d events=%d trace=%s", result.Seed, result.Operations, result.Events, result.TraceHash)
}

func assertViolation(t *testing.T, result RunResult, seed uint64, property string) {
	t.Helper()
	if result.Violation == nil {
		t.Fatalf("seed %d did not detect planted %s defect", seed, property)
	}
	if result.Violation.Property != property || result.Violation.Seed != seed {
		t.Fatalf("seed %d violation = %v, want %s", seed, result.Violation, property)
	}
	t.Logf("replay seed=%d trace=%s: %v", seed, result.TraceHash, result.Violation)
}
