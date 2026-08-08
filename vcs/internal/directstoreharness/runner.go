package directstoreharness

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

type RunConfig struct {
	Seed       uint64
	Operations uint64
	Catalog    Catalog
	Trace      io.Writer
}

type RunResult struct {
	Seed           uint64
	Operations     uint64
	FaultsInjected uint64
	Events         uint64
	TraceHash      Digest
	Coverage       []string
	Violation      *Violation
}

func RunRandom(factory TargetFactory, config RunConfig) RunResult {
	rng := NewRNG(config.Seed)
	schedule := func(_ uint64) Fault { return randomFault(rng, config.Catalog) }
	return run(factory, config, "random", schedule)
}

func run(factory TargetFactory, config RunConfig, mode string, schedule func(uint64) Fault) RunResult {
	if config.Operations == 0 {
		config.Operations = 1
	}
	recorder := NewRecorder(config.Trace, TraceHeader{Seed: config.Seed, Operations: config.Operations, Catalog: catalogDigest(config.Catalog), Mode: mode})
	environment := NewEnvironment(recorder)
	target := factory(environment)
	checker := newChecker(config.Seed)
	coverage := make(map[string]struct{}, 64)
	result := RunResult{Seed: config.Seed}

	for operationNumber := uint64(1); operationNumber <= config.Operations; operationNumber++ {
		result.Operations = operationNumber
		environment.SetOperation(operationNumber)
		checker.setOperation(operationNumber)
		fault := schedule(operationNumber)
		environment.Arm(fault)
		operation := Mutation{ID: ExactID{Client: 1, Sequence: operationNumber}, Value: operationNumber ^ config.Seed}
		reply := target.Mutate(operation)
		if environment.FaultFired() {
			result.FaultsInjected++
			coverage[fault.Kind.String()+":"+fault.Point] = struct{}{}
		}
		if violation := checker.observe(target.Audit()); violation != nil {
			result.Violation = violation
			break
		}
		if reply.Status == MutationSuccess {
			if violation := checker.acknowledge(operation, reply, target.Audit()); violation != nil {
				violation.Detail += fmt.Sprintf("; fault=%+v initial-reply", fault)
				result.Violation = violation
				break
			}
			if violation := checker.optionalRead(target.LinearizableRead(checker.model.index)); violation != nil {
				result.Violation = violation
				break
			}
		}

		environment.ClearFault()
		if err := target.Recover(); err != nil {
			result.Violation = checker.violation("recovery-failed", err.Error())
			break
		}
		if violation := checker.observe(target.Audit()); violation != nil {
			result.Violation = violation
			break
		}
		if reply.Status != MutationSuccess {
			reply = target.Mutate(operation)
			if violation := checker.observe(target.Audit()); violation != nil {
				result.Violation = violation
				break
			}
			if reply.Status != MutationSuccess {
				result.Violation = checker.violation("exact-retry-did-not-complete", fmt.Sprintf("status %d after fault %s at %s", reply.Status, fault.Kind, fault.Point))
				break
			}
			if violation := checker.acknowledge(operation, reply, target.Audit()); violation != nil {
				violation.Detail += fmt.Sprintf("; fault=%+v exact-retry", fault)
				result.Violation = violation
				break
			}
		}
		read := target.LinearizableRead(checker.model.index)
		if violation := checker.read(read); violation != nil {
			result.Violation = violation
			break
		}
	}
	if result.Violation != nil {
		environment.emit(TraceEvent{Kind: EventViolation, Point: result.Violation.Property, Detail: result.Violation.Detail})
	}
	result.Events = recorder.Events()
	digest, err := recorder.Finish()
	result.TraceHash = digest
	if result.Violation != nil {
		result.Violation.TraceHash = digest
	} else if err != nil {
		result.Violation = &Violation{Property: "trace-write-failed", Detail: err.Error(), Seed: config.Seed, Operation: result.Operations, TraceHash: digest}
	}
	for item := range coverage {
		result.Coverage = append(result.Coverage, item)
	}
	sort.Strings(result.Coverage)
	return result
}

func catalogDigest(catalog Catalog) Digest {
	h := sha256.New()
	var number [8]byte
	for _, point := range catalog {
		binary.LittleEndian.PutUint64(number[:], uint64(len(point.ID)))
		_, _ = h.Write(number[:])
		_, _ = h.Write([]byte(point.ID))
		_, _ = h.Write([]byte{byte(point.Kind)})
		binary.LittleEndian.PutUint64(number[:], uint64(len(point.Scenario)))
		_, _ = h.Write(number[:])
		_, _ = h.Write([]byte(point.Scenario))
		for _, actor := range point.Actors {
			binary.LittleEndian.PutUint64(number[:], uint64(len(actor)))
			_, _ = h.Write(number[:])
			_, _ = h.Write([]byte(actor))
		}
		_, _ = h.Write([]byte{0})
	}
	var digest Digest
	copy(digest[:], h.Sum(nil))
	return digest
}

func randomFault(rng *RNG, catalog Catalog) Fault {
	persistence, messages := catalogByKind(catalog)
	kinds := [...]FaultKind{KillBefore, KillAfter, PartitionLink, DropMessage, DuplicateMessage, ShortWrite, NoSpace, ChecksumFailure}
	kind := kinds[rng.Bounded(uint64(len(kinds)))]
	fault := Fault{Kind: kind, Node: AnyNode, From: AnyNode, To: AnyNode}
	switch kind {
	case PartitionLink:
		fault.Point = "network.link"
		fault.Links = uint8(rng.Bounded((1<<len(directedReplicaLinks))-1) + 1)
	case DropMessage, DuplicateMessage:
		if len(messages) == 0 {
			return Fault{Kind: PartitionLink, Point: "network.link", Node: AnyNode, Links: 1}
		}
		fault.Point = messages[rng.Bounded(uint64(len(messages)))].ID
	case ShortWrite, NoSpace, ChecksumFailure:
		if len(persistence) == 0 {
			return Fault{Kind: PartitionLink, Point: "network.link", Node: AnyNode, Links: 1}
		}
		fault.Point = persistence[rng.Bounded(uint64(len(persistence)))].ID
	case KillBefore, KillAfter:
		eligible := append(append(make([]CutPoint, 0, len(persistence)+len(messages)), persistence...), messages...)
		if len(eligible) == 0 {
			return Fault{Kind: PartitionLink, Point: "network.link", Node: AnyNode, Links: 1}
		}
		fault.Point = eligible[rng.Bounded(uint64(len(eligible)))].ID
	}
	return fault
}

func catalogByKind(catalog Catalog) (persistence, messages []CutPoint) {
	for _, point := range catalog {
		if point.Scenario != "mutation" && point.Scenario != "exact_reply" {
			continue
		}
		if point.Kind == PersistenceCut {
			persistence = append(persistence, point)
		} else {
			messages = append(messages, point)
		}
	}
	return persistence, messages
}
