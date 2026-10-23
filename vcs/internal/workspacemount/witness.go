package workspacemount

import "errors"

// Witness grows monotonically from the durable startup intent. Empty fields
// denote unknown ownership, never resource absence.
type Witness struct {
	Intent, Source, Target               string
	Process, Kernel, Session, Enrollment string
	RoutesRevision                       [32]byte
}

func MergeWitness(old, next Witness) (Witness, error) {
	var err error
	for _, pair := range [][2]*string{
		{&old.Intent, &next.Intent}, {&old.Source, &next.Source}, {&old.Target, &next.Target},
		{&old.Process, &next.Process}, {&old.Kernel, &next.Kernel},
		{&old.Session, &next.Session}, {&old.Enrollment, &next.Enrollment},
	} {
		if *pair[1] == "" {
			continue
		}
		if *pair[0] != "" && *pair[0] != *pair[1] {
			err = errors.New("bound witness field changed")
			continue
		}
		*pair[0] = *pair[1]
	}
	if next.RoutesRevision != [32]byte{} {
		if old.RoutesRevision != [32]byte{} && old.RoutesRevision != next.RoutesRevision {
			err = errors.New("bound route witness changed")
		} else {
			old.RoutesRevision = next.RoutesRevision
		}
	}
	return old, err
}
