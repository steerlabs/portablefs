package directstoreharness

import "fmt"

type ExhaustiveCase struct {
	Name   string
	Fault  Fault
	Result RunResult
}

func EnumerateFaults(catalog Catalog) []Fault {
	persistence, messages := catalogByKind(catalog)
	faults := make([]Fault, 0, len(persistence)*10+len(messages)*12+ReplicaCount*(ReplicaCount-1))
	for _, point := range persistence {
		for _, node := range persistenceActors(point) {
			for _, kind := range []FaultKind{KillBefore, KillAfter, ShortWrite, NoSpace, ChecksumFailure} {
				faults = append(faults, Fault{Kind: kind, Point: point.ID, Node: node, From: AnyNode, To: AnyNode})
			}
		}
	}
	for _, point := range messages {
		for _, link := range messageActors(point) {
			for _, node := range []NodeID{link[0], link[1]} {
				if node < ReplicaCount {
					for _, kind := range []FaultKind{KillBefore, KillAfter} {
						faults = append(faults, Fault{Kind: kind, Point: point.ID, Node: node, From: link[0], To: link[1]})
					}
				}
			}
			for _, kind := range []FaultKind{DropMessage, DuplicateMessage} {
				faults = append(faults, Fault{Kind: kind, Point: point.ID, Node: AnyNode, From: link[0], To: link[1]})
			}
		}
	}
	for mask := uint8(1); mask < 1<<len(directedReplicaLinks); mask++ {
		faults = append(faults, Fault{Kind: PartitionLink, Point: "network.link", Node: AnyNode, From: AnyNode, To: AnyNode, Links: mask})
	}
	return faults
}

func persistenceActors(point CutPoint) []NodeID {
	var nodes []NodeID
	for _, actor := range point.Actors {
		switch actor {
		case "leader", "candidate":
			nodes = append(nodes, 0)
		case "follower", "voter":
			nodes = append(nodes, 1, 2)
		case "client":
			nodes = append(nodes, ClientNode)
		}
	}
	if len(nodes) == 0 {
		return []NodeID{AnyNode}
	}
	return nodes
}

func messageActors(point CutPoint) [][2]NodeID {
	if len(point.Actors) != 2 {
		return [][2]NodeID{{AnyNode, AnyNode}}
	}
	from := actorNodes(point.Actors[0])
	to := actorNodes(point.Actors[1])
	links := make([][2]NodeID, 0, len(from)*len(to))
	for _, source := range from {
		for _, destination := range to {
			if source != destination {
				links = append(links, [2]NodeID{source, destination})
			}
		}
	}
	return links
}

func actorNodes(actor string) []NodeID {
	switch actor {
	case "leader", "candidate":
		return []NodeID{0}
	case "follower", "voter":
		return []NodeID{1, 2}
	case "client":
		return []NodeID{ClientNode}
	default:
		return []NodeID{AnyNode}
	}
}

func RunExhaustive(factory TargetFactory, catalog Catalog, seed uint64) []ExhaustiveCase {
	return RunExhaustiveHistories(factory, catalog, seed, 1)
}

// RunExhaustiveHistories injects every enumerated fault at each position in a
// sequential history. Keeping historyLength small explores retry/state
// interactions exhaustively; RunRandom covers long histories cheaply.
func RunExhaustiveHistories(factory TargetFactory, catalog Catalog, seed, historyLength uint64) []ExhaustiveCase {
	if historyLength == 0 {
		historyLength = 1
	}
	faults := EnumerateFaults(catalog)
	cases := make([]ExhaustiveCase, 0, len(faults)*int(historyLength))
	ordinal := uint64(0)
	for faultAt := uint64(1); faultAt <= historyLength; faultAt++ {
		for _, fault := range faults {
			config := RunConfig{Seed: seed + ordinal, Operations: historyLength, Catalog: catalog}
			result := run(factory, config, "exhaustive", func(operation uint64) Fault {
				if operation == faultAt {
					return fault
				}
				return Fault{}
			})
			cases = append(cases, ExhaustiveCase{
				Name:  fault.Kind.String() + ":" + fault.Point + fmt.Sprintf(":operation-%d", faultAt),
				Fault: fault, Result: result,
			})
			ordinal++
		}
	}
	return cases
}
