// Package workspacecontrol defines the unreleased, exact workspace control 8
// stream. It carries supervision only; authority permissions remain protocol 8.
package workspacecontrol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const Version = 8
const MaxFrame = 1 << 20
const MaxMounts = 64
const MaxRetiredBatch = 16
const MaxDrainBudget = 15 * time.Second

// At most 80 mount ledgers and 80 current or retired terminal jobs.
// The paired maximum-payload tests prove every reply fits the 1 MiB frame.
const MaxLosses = 32
const MaxReason = 256
const AggregateReason = "additional accepted-tail loss (aggregated)"

func BoundedReason(reason string) string {
	reason = strings.ToValidUTF8(reason, "?")
	if len(reason) <= MaxReason {
		return reason
	}
	reason = reason[:MaxReason]
	for !utf8.ValidString(reason) {
		reason = reason[:len(reason)-1]
	}
	return reason
}
func saturatingAdd(a, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}

// BoundLoss folds excess cumulative records into one monotone final summary.
// The driver retains exact barrier outcomes; only wire reporting is compacted.
func BoundLoss(snapshot []*pb.Loss) ([]*pb.Loss, bool, error) {
	out := make([]*pb.Loss, 0, min(len(snapshot), MaxLosses))
	var sequence uint64
	overflow := len(snapshot) > MaxLosses
	for i, l := range snapshot {
		if l == nil || l.Sequence <= sequence || l.Reason == "" || l.Aggregated {
			return nil, false, fmt.Errorf("driver cumulative loss sequence %d: %w", i, ErrGrammar)
		}
		sequence = l.Sequence
		if !overflow || i < MaxLosses-1 {
			copy := proto.Clone(l).(*pb.Loss)
			copy.Reason = BoundedReason(copy.Reason)
			out = append(out, copy)
			continue
		}
		if len(out) < MaxLosses {
			out = append(out, &pb.Loss{Reason: AggregateReason, Aggregated: true})
		}
		summary := out[MaxLosses-1]
		summary.Sequence = l.Sequence
		summary.AcceptedEntries = saturatingAdd(summary.AcceptedEntries, l.AcceptedEntries)
		summary.AcceptedBytes = saturatingAdd(summary.AcceptedBytes, l.AcceptedBytes)
	}
	return out, overflow, nil
}

// RetainsLoss permits only appending exact records or advancing the final
// aggregate. A summary cannot erase an earlier reported counter or outcome.
func RetainsLoss(current, prior []*pb.Loss) bool {
	if len(current) < len(prior) {
		return false
	}
	for i, old := range prior {
		next := current[i]
		if proto.Equal(old, next) {
			continue
		}
		if i != MaxLosses-1 || !next.Aggregated || next.Reason != AggregateReason ||
			next.Sequence < old.Sequence || next.AcceptedEntries < old.AcceptedEntries ||
			next.AcceptedBytes < old.AcceptedBytes {
			return false
		}
	}
	return true
}

// Provision has no private-key field or import operation. The guest must compare
// the public bytes with its locally generated identity before persisting it.
func ProvisionForKey(p *pb.Provision, publicKey []byte) error {
	if err := Provision(p); err != nil {
		return fmt.Errorf("provision grammar: %w", err)
	}
	if len(publicKey) == 0 || !bytes.Equal(p.PublicKey, publicKey) {
		return invalid("provision guest public key mismatch")
	}
	return nil
}
func Provision(p *pb.Provision) error {
	if p == nil || len(p.AuthorityEndpoint) == 0 || len(p.AuthorityEndpoint) > 4096 || !utf8.ValidString(p.AuthorityEndpoint) || !Digest(p.RoutesRevision) || len(p.ServerName) == 0 || len(p.ServerName) > 4096 || !utf8.ValidString(p.ServerName) {
		return invalid("provision endpoint or route revision")
	}
	for name, raw := range map[string][]byte{"CA": p.CaCertificate, "certificate": p.ClientCertificate, "capability": p.Capability, "public key": p.PublicKey} {
		if len(raw) == 0 || len(raw) > 65536 {
			return invalid("provision " + name + " length")
		}
	}
	if h := p.HostedEnrollment; h != nil {
		for _, v := range []string{h.ManagerOrigin, h.ManagerServerName, h.EnrollmentId} {
			if len(v) == 0 || len(v) > 4096 || !utf8.ValidString(v) {
				return invalid("hosted identity")
			}
		}
		if len(h.ManagerCa) == 0 || len(h.ManagerCa) > 65536 || len(h.EnrollmentCertificate) == 0 || len(h.EnrollmentCertificate) > 65536 || h.AuthorityGeneration == 0 || h.AuthorizationDeadlineUnix == 0 || h.AuthorizationDeadlineUnix > math.MaxInt64 {
			return invalid("hosted material")
		}
	}
	return Mount(p.Mount)
}
func IdentityRequest(r *pb.IdentityRequest) error {
	if r == nil {
		return invalid("missing identity request")
	}
	return Mount(&pb.MountID{AuthorityId: r.AuthorityId, VolumeId: r.VolumeId, Incarnation: append([]byte{1}, make([]byte, 15)...)})
}
func IdentityReply(r *pb.IdentityReply) error {
	if r == nil || !ID(r.GuestUuid) || !ID(r.IdentityIncarnation) || r.RenewalEpoch == 0 || r.RenewalEpoch > 1<<53-1 || len(r.PublicKey) == 0 || len(r.PublicKey) > 65536 || len(r.Csr) == 0 || len(r.Csr) > 65536 {
		return invalid("identity reply")
	}
	return Mount(r.Mount)
}

var ErrGrammar = errors.New("workspace control: invalid exact grammar")

func invalid(why string) error { return fmt.Errorf("%s: %w", why, ErrGrammar) }
func valid(ok bool) error {
	if !ok {
		return fmt.Errorf("invalid workspace field: %w", ErrGrammar)
	}
	return nil
}
func ID(b []byte) bool     { return len(b) == 16 && !bytes.Equal(b, make([]byte, 16)) }
func Digest(b []byte) bool { return len(b) == 32 && !bytes.Equal(b, make([]byte, 32)) }
func Mount(m *pb.MountID) error {
	if m == nil {
		return invalid("Mount: invalid field or state combination")
	}
	for _, c := range []byte(m.VolumeId) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return invalid("Mount: invalid field or state combination")
		}
	}
	return valid(Digest(m.AuthorityId) && ID(m.Incarnation) &&
		len(m.VolumeId) > 0 && len(m.VolumeId) <= 128 && m.VolumeId != "." && m.VolumeId != "..")
}
func MountKey(m *pb.MountID) string {
	if m == nil {
		return ""
	}
	return fmt.Sprintf("%x/%s/%x", m.AuthorityId, m.VolumeId, m.Incarnation)
}
func Roster(ms []*pb.MountID) error {
	if len(ms) > MaxMounts {
		return invalid("Roster: invalid field or state combination")
	}
	prior := ""
	volumes := map[string]bool{}
	for _, m := range ms {
		if err := Mount(m); err != nil {
			return fmt.Errorf("Roster: %w", err)
		}
		key := MountKey(m)
		volume := fmt.Sprintf("%x/%s", m.AuthorityId, m.VolumeId)
		if key <= prior || volumes[volume] {
			return invalid("Roster: invalid field or state combination")
		}
		prior = key
		volumes[volume] = true
	}
	return nil
}
func Suspension(s *pb.Suspension) error {
	if s == nil || !ID(s.BootId) || !ID(s.HostServiceId) || !ID(s.GuestServiceId) || s.Generation == 0 || !ID(s.Nonce) {
		return invalid("Suspension: invalid field or state combination")
	}
	return Roster(s.Roster)
}

// MatchesSuspension permits only the guest to add the fixed roster.
func MatchesSuspension(fixed, request *pb.Suspension) bool {
	if fixed == nil || request == nil || len(request.Roster) != 0 {
		return false
	}
	identity := proto.Clone(fixed).(*pb.Suspension)
	identity.Roster = nil
	return proto.Equal(identity, request)
}
func Token(t *pb.ResumeToken) error {
	if t == nil || !ID(t.WakeNonce) {
		return invalid("Token: invalid field or state combination")
	}
	return Suspension(t.Suspension)
}
func Release(r *pb.Release) error {
	if r == nil || r.AuthorityMajor != 8 || len(r.AppVersion) == 0 || len(r.AppVersion) > 128 || len(r.Commit) != 40 || !Digest(r.ImageDigest) {
		return invalid("Release: invalid field or state combination")
	}
	for _, c := range []byte(r.AppVersion) {
		if c < 0x21 || c > 0x7e {
			return invalid("Release: invalid field or state combination")
		}
	}
	for _, c := range r.Commit {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return invalid("Release: invalid field or state combination")
		}
	}
	return nil
}

// Losses validates a persisted or wire-bounded cumulative ledger, including its
// final aggregate. BoundLoss accepts the unbounded, unaggregated source ledger.
func Losses(ls []*pb.Loss) error { return losses(ls) }

func losses(ls []*pb.Loss) error {
	if len(ls) > MaxLosses {
		return invalid("losses: invalid field or state combination")
	}
	var seq uint64
	for i, l := range ls {
		if l == nil || l.Sequence <= seq || len(l.Reason) == 0 ||
			len(l.Reason) > MaxReason || !utf8.ValidString(l.Reason) {
			return invalid("loss sequence or reason")
		}
		if l.Aggregated && (i != len(ls)-1 || i != MaxLosses-1 || l.Reason != AggregateReason) {
			return invalid("losses: invalid field or state combination")
		}
		seq = l.Sequence
	}
	return nil
}

// Renewal validates typed evidence; only the mount owner can establish that a
// not-required result belongs to an explicitly standalone mount.
func Renewal(r *pb.RenewalReadiness) error {
	if r == nil {
		return invalid("missing renewal evidence")
	}
	switch r.State {
	case "pending", "not-required":
		return valid(r.InstalledSequence == 0)
	case "installed":
		return valid(r.InstalledSequence > 0)
	default:
		return invalid("renewal state")
	}
}
func Outcome(o *pb.MountOutcome) error {
	if o == nil {
		return invalid("missing outcome evidence")
	}
	if o.Durability != "durable" && o.Durability != "lost" && o.Durability != "unresolved" {
		return invalid("durability outcome")
	}
	if o.Observation != "observed" && o.Observation != "unobserved" {
		return invalid("outcome observation")
	}
	if o.Release != "released" && o.Release != "expired" && o.Release != "abandoned" && o.Release != "unresolved" {
		return invalid("release outcome")
	}
	if o.Observation == "unobserved" && (o.Durability != "unresolved" || o.Release != "unresolved") {
		return invalid("unobserved outcome cannot certify disposition")
	}
	return nil
}
func UnknownOutcome() *pb.MountOutcome {
	return &pb.MountOutcome{Durability: "unresolved", Observation: "unobserved", Release: "unresolved"}
}
func ColdAck(a *pb.SuspendAck) error {
	if a == nil {
		return invalid("ColdAck: invalid field or state combination")
	}
	if err := Suspension(a.Suspension); err != nil {
		return fmt.Errorf("ColdAck: %w", err)
	}
	if len(a.Mounts) != len(a.Suspension.Roster) {
		return invalid("ColdAck: invalid field or state combination")
	}
	for i, m := range a.Mounts {
		if m == nil || !proto.Equal(m.Mount, a.Suspension.Roster[i]) {
			return invalid("ColdAck: invalid field or state combination")
		}
		if err := Outcome(m.Outcome); err != nil {
			return err
		}
		if err := losses(m.Loss); err != nil {
			return fmt.Errorf("ColdAck: %w", err)
		}
	}
	return nil
}
func statuses(ms []*pb.MountStatus) error {
	roster := make([]*pb.MountID, 0, len(ms))
	for _, m := range ms {
		if m == nil {
			return invalid("statuses: invalid field or state combination")
		}
		if m.Renewal != nil {
			if err := Renewal(m.Renewal); err != nil {
				return err
			}
		}
		if m.State == "ready" && (m.Renewal == nil || m.Renewal.State == "pending") {
			return invalid("ready requires renewal evidence")
		}
		roster = append(roster, m.Mount)
		switch m.State {
		case "closed", "ready", "suspended-cold", "recovering", "terminal", "authorization-required":
		default:
			return invalid("statuses: invalid field or state combination")
		}
		switch m.Cleanup {
		case "retained", "process-exited", "kernel-absent", "complete":
		default:
			return invalid("statuses: invalid field or state combination")
		}
		terminal := m.State == "terminal" || m.State == "authorization-required"
		if len(m.Reason) > MaxReason || !utf8.ValidString(m.Reason) ||
			(terminal != (m.Reason != "") && m.State != "closed") || (m.Cleanup != "retained" && !terminal) {
			return invalid("statuses: invalid field or state combination")
		}
		if err := Outcome(m.Outcome); err != nil {
			return err
		}
		if err := losses(m.Loss); err != nil {
			return fmt.Errorf("statuses: %w", err)
		}
	}
	return Roster(roster)
}

// One contiguous sequence carries mount cleanup and joined job evidence.
func RetiredStatuses(outcomes []*pb.RetiredOutcome) error {
	if len(outcomes) > MaxRetiredBatch {
		return invalid("retired outcome batch exceeds limit")
	}
	var sequence uint64
	mounts := map[string]bool{}
	jobs := map[string]bool{}
	for _, outcome := range outcomes {
		if outcome == nil || outcome.RetirementSequence == 0 || (sequence != 0 && (sequence == math.MaxUint64 || outcome.RetirementSequence != sequence+1)) || (outcome.MountStatus == nil && outcome.Job == nil) {
			return invalid("retired outcome sequence or missing evidence")
		}
		if m := outcome.MountStatus; m != nil {
			if err := statuses([]*pb.MountStatus{m}); err != nil {
				return err
			}
			key := MountKey(m.Mount)
			if mounts[key] || m.Cleanup != "complete" || (m.State != "terminal" && m.State != "authorization-required") {
				return invalid("retired mount requires unique, exactly cleaned terminal incarnation")
			}
			mounts[key] = true
		}
		if j := outcome.Job; j != nil {
			if err := Jobs([]*pb.MountJob{j}, nil, math.MaxUint64); err != nil {
				return err
			}
			key := fmt.Sprintf("%s/%d", MountKey(j.Mount), j.RequestId)
			if jobs[key] || (j.Phase != "complete" && j.Phase != "failed") || (outcome.MountStatus != nil && !proto.Equal(outcome.MountStatus.Mount, j.Mount)) {
				return invalid("retired job requires unique joined matching owner")
			}
			jobs[key] = true
		}
		sequence = outcome.RetirementSequence
	}
	return nil
}
func ResumeAck(a *pb.ResumeAck) error {
	if a == nil {
		return fmt.Errorf("resume acknowledgement missing: %w", ErrGrammar)
	}
	if err := Token(a.Token); err != nil {
		return fmt.Errorf("resume acknowledgement token: %w", err)
	}
	if len(a.Mounts) != len(a.Token.Suspension.Roster) {
		return fmt.Errorf("resume acknowledgement roster length: %w", ErrGrammar)
	}
	for i, m := range a.Mounts {
		if m == nil || !proto.Equal(m.Mount, a.Token.Suspension.Roster[i]) {
			return fmt.Errorf("resume acknowledgement roster member %d: %w", i, ErrGrammar)
		}
	}
	if err := statuses(a.Mounts); err != nil {
		return fmt.Errorf("resume statuses: %w", err)
	}
	for _, m := range a.Mounts {
		if m.State == "suspended-cold" {
			return invalid("resume status cannot remain suspended-cold")
		}
	}
	return nil
}

// Jobs and registered mounts share desired-volume capacity, but only registered
// mounts belong to the cold roster. A start intent is never readiness evidence.
func Jobs(jobs []*pb.MountJob, mounts []*pb.MountStatus, generation uint64) error {
	ids := make([]*pb.MountID, 0, len(jobs))
	volumes := map[string]string{}
	for _, m := range mounts {
		volumes[fmt.Sprintf("%x/%s", m.Mount.AuthorityId, m.Mount.VolumeId)] = MountKey(m.Mount)
	}
	for _, j := range jobs {
		if j == nil || Mount(j.Mount) != nil || j.RequestId == 0 || j.Generation > generation {
			return invalid("job identity")
		}
		ids = append(ids, j.Mount)
		volume := fmt.Sprintf("%x/%s", j.Mount.AuthorityId, j.Mount.VolumeId)
		if old, ok := volumes[volume]; ok && old != MountKey(j.Mount) {
			return invalid("job incarnation conflicts with registered mount")
		}
		volumes[volume] = MountKey(j.Mount)
		if j.Operation != "provision" && j.Operation != "mount" && j.Operation != "umount" {
			return invalid("job operation")
		}
		switch j.Phase {
		case "offered", "running", "complete":
			if j.Failure != "" || j.Reason != "" {
				return invalid("unfinished or complete job with failure")
			}
		case "failed":
			switch j.Failure {
			case "unavailable", "refused", "authorization-required", "stopped", "deadline", "handler-failed", "busy":
			default:
				return invalid("job failure")
			}
			if j.Reason == "" || len(j.Reason) > MaxReason || !utf8.ValidString(j.Reason) {
				return invalid("job failure reason")
			}
		default:
			return invalid("job phase")
		}
	}
	if len(volumes) > MaxMounts {
		return invalid("desired mount capacity")
	}
	return Roster(ids)
}

func Validate(e *pb.Envelope) error {
	if e == nil || e.Version != Version || e.RequestId == 0 {
		return invalid("Validate: invalid field or state combination")
	}
	if _, suspend := e.Body.(*pb.Envelope_Suspend); suspend {
		if e.DrainBudgetNanos == 0 || e.DrainBudgetNanos > uint64(MaxDrainBudget) {
			return invalid("suspend remaining drain budget")
		}
	} else if e.DrainBudgetNanos != 0 {
		return invalid("drain budget outside Suspend")
	}
	switch b := e.Body.(type) {
	case *pb.Envelope_Hello:
		if b.Hello == nil || len(b.Hello.GuestServiceId) != 0 {
			return invalid("Validate: invalid field or state combination")
		}
		return hello(b.Hello)
	case *pb.Envelope_HelloAck:
		if b.HelloAck == nil || !ID(b.HelloAck.GuestServiceId) {
			return invalid("Validate: invalid field or state combination")
		}
		return hello(b.HelloAck)
	case *pb.Envelope_Suspend:
		if err := Suspension(b.Suspend); err != nil {
			return fmt.Errorf("suspend request: %w", err)
		}
		if b.Suspend.AwakeRecovery || len(b.Suspend.Roster) != 0 {
			return invalid("suspend request roster is guest-owned")
		}
		return nil
	case *pb.Envelope_SuspendAck:
		return ColdAck(b.SuspendAck)
	case *pb.Envelope_Resume:
		if b.Resume == nil || b.Resume.Suspension == nil || b.Resume.Suspension.AwakeRecovery {
			return invalid("awake recovery outside AwakeRecover")
		}
		return Token(b.Resume)
	case *pb.Envelope_AwakeRecover:
		if err := Token(b.AwakeRecover); err != nil {
			return err
		}
		if !b.AwakeRecover.Suspension.AwakeRecovery || len(b.AwakeRecover.Suspension.Roster) != 0 {
			return invalid("awake recovery request mode or roster")
		}
		return nil
	case *pb.Envelope_ResumeAck:
		return ResumeAck(b.ResumeAck)
	case *pb.Envelope_Status:
		return valid(b.Status != nil)
	case *pb.Envelope_StatusReply:
		s := b.StatusReply
		if s == nil || !ID(s.BootId) || !ID(s.HostServiceId) || !ID(s.GuestServiceId) {
			return invalid("Validate: invalid field or state combination")
		}
		switch s.State {
		case "running", "suspending", "suspended-cold", "discard-only":
		default:
			return invalid("Validate: invalid field or state combination")
		}
		if err := RetiredStatuses(s.Retired); err != nil {
			return fmt.Errorf("status retired: %w", err)
		}
		if err := statuses(s.Mounts); err != nil {
			return fmt.Errorf("status mounts: %w", err)
		}
		if err := Jobs(s.Jobs, s.Mounts, s.Generation); err != nil {
			return fmt.Errorf("status jobs: %w", err)
		}
		keys := map[string]bool{}
		for _, m := range s.Mounts {
			keys[MountKey(m.Mount)] = true
		}
		for _, j := range s.Jobs {
			if j != nil {
				keys[MountKey(j.Mount)] = true
			}
		}
		if len(keys) > MaxMounts {
			return invalid("active and retired capacity")
		}
		for _, outcome := range s.Retired {
			if outcome.Job != nil && outcome.Job.Generation > s.Generation {
				return invalid("retired job generation")
			}
		}
		if (s.State == "suspending" || s.State == "suspended-cold") && s.Generation == 0 {
			return fmt.Errorf("status missing suspension generation: %w", ErrGrammar)
		}
		for _, m := range s.Mounts {
			terminal := m.State == "terminal" || m.State == "authorization-required"
			if terminal {
				continue
			}
			inconsistent := false
			switch s.State {
			case "suspended-cold":
				inconsistent = m.State != "suspended-cold"
			case "suspending":
				inconsistent = m.State != "closed" && m.State != "suspended-cold"
			case "discard-only":
				inconsistent = m.State != "closed"
			case "running":
				inconsistent = m.State == "suspended-cold"
			}
			if inconsistent {
				return fmt.Errorf("status phase/mount state combination: %w", ErrGrammar)
			}
		}
		return nil
	case *pb.Envelope_RetireAck:
		if b.RetireAck == nil || b.RetireAck.ThroughSequence == 0 {
			return invalid("retire acknowledgement missing sequence")
		}
		return nil
	case *pb.Envelope_IdentityRequest:
		return IdentityRequest(b.IdentityRequest)
	case *pb.Envelope_IdentityReply:
		return IdentityReply(b.IdentityReply)
	case *pb.Envelope_Provision:
		return Provision(b.Provision)
	case *pb.Envelope_Mount:
		if b.Mount == nil {
			return invalid("Validate: invalid field or state combination")
		}
		return Mount(b.Mount.Mount)
	case *pb.Envelope_Umount:
		if b.Umount == nil {
			return invalid("Validate: invalid field or state combination")
		}
		return Mount(b.Umount.Mount)
	case *pb.Envelope_Result:
		if b.Result == nil || len(b.Result.Reason) > MaxReason {
			return invalid("Validate: invalid field or state combination")
		}
		switch b.Result.Code {
		case "predecessor-unobserved":
			return valid(b.Result.Reason == "observe predecessor result with Status before retry")
		case "accepted", "unavailable", "authorization-required", "refused":
			return nil
		}
		return invalid("Validate: invalid field or state combination")
	default:
		return invalid("Validate: invalid field or state combination")
	}
}
func hello(h *pb.Hello) error {
	if !ID(h.BootId) || !ID(h.HostServiceId) {
		return invalid("hello: invalid field or state combination")
	}
	return Release(h.Release)
}

// Check the descriptor before decoding, bounding repeated-message allocations
// and rejecting duplicate/unknown fields rather than protobuf's last-one-wins.
func grammar(raw []byte, d protoreflect.MessageDescriptor, depth int) error {
	if depth > 16 {
		return invalid("grammar: invalid field or state combination")
	}
	seen := map[protoreflect.FieldNumber]int{}
	oneofs := map[protoreflect.FullName]bool{}
	var prior protowire.Number
	for len(raw) > 0 {
		n, t, k := protowire.ConsumeTag(raw)
		if k < 0 || n < prior {
			return invalid("grammar: invalid field or state combination")
		}
		prior = n
		raw = raw[k:]
		f := d.Fields().ByNumber(n)
		if f == nil {
			return invalid("grammar: invalid field or state combination")
		}
		seen[n]++
		if (!f.IsList() && seen[n] > 1) || seen[n] > 128 {
			return invalid("grammar: invalid field or state combination")
		}
		if o := f.ContainingOneof(); o != nil {
			if oneofs[o.FullName()] {
				return invalid("grammar: invalid field or state combination")
			}
			oneofs[o.FullName()] = true
		}
		switch f.Kind() {
		case protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.BoolKind:
			if t != protowire.VarintType {
				return invalid("grammar: invalid field or state combination")
			}
			_, k = protowire.ConsumeVarint(raw)
		case protoreflect.StringKind, protoreflect.BytesKind, protoreflect.MessageKind:
			if t != protowire.BytesType {
				return invalid("grammar: invalid field or state combination")
			}
			var b []byte
			b, k = protowire.ConsumeBytes(raw)
			if k >= 0 {
				if f.Kind() == protoreflect.MessageKind {
					if err := grammar(b, f.Message(), depth+1); err != nil {
						return fmt.Errorf("grammar: %w", err)
					}
				} else if len(b) > 65536 {
					return invalid("grammar: invalid field or state combination")
				}
			}
		default:
			return invalid("grammar: invalid field or state combination")
		}
		if k < 0 {
			return invalid("grammar: invalid field or state combination")
		}
		raw = raw[k:]
	}
	return nil
}
func Encode(e *pb.Envelope) ([]byte, error) {
	if err := Validate(e); err != nil {
		return nil, fmt.Errorf("workspace codec: %w", err)
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("workspace encode: %w", err)
	}
	if len(raw) == 0 || len(raw) > MaxFrame {
		return nil, fmt.Errorf("invalid workspace frame: %w", ErrGrammar)
	}
	if err := grammar(raw, e.ProtoReflect().Descriptor(), 0); err != nil {
		return nil, fmt.Errorf("workspace codec: %w", err)
	}
	out := make([]byte, 4, len(raw)+4)
	binary.BigEndian.PutUint32(out, uint32(len(raw)))
	return append(out, raw...), nil
}

// DecodeBody applies the same canonical scanner to a local fixed-roster body.
// The caller applies its body validator, independently of host Envelope rules.
func DecodeBody(raw []byte, m proto.Message) error {
	if len(raw) == 0 || len(raw) > 65536 {
		return ErrGrammar
	}
	if err := grammar(raw, m.ProtoReflect().Descriptor(), 0); err != nil {
		return err
	}
	if err := (proto.UnmarshalOptions{RecursionLimit: 16}).Unmarshal(raw, m); err != nil {
		return err
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrGrammar
	}
	return nil
}
func Decode(frame []byte) (*pb.Envelope, error) {
	if len(frame) < 4 {
		return nil, fmt.Errorf("invalid workspace frame: %w", ErrGrammar)
	}
	n := binary.BigEndian.Uint32(frame)
	if n == 0 || n > MaxFrame || int(n) != len(frame)-4 {
		return nil, fmt.Errorf("invalid workspace frame: %w", ErrGrammar)
	}
	e := new(pb.Envelope)
	raw := frame[4:]
	if err := grammar(raw, e.ProtoReflect().Descriptor(), 0); err != nil {
		return nil, fmt.Errorf("workspace codec: %w", err)
	}
	if err := (proto.UnmarshalOptions{RecursionLimit: 16}).Unmarshal(raw, e); err != nil {
		return nil, fmt.Errorf("workspace decode: %w", err)
	}
	canonical, err := Encode(e)
	if err != nil {
		return nil, fmt.Errorf("workspace codec: %w", err)
	}
	if !bytes.Equal(frame, canonical) {
		return nil, fmt.Errorf("invalid workspace frame: %w", ErrGrammar)
	}
	return e, nil
}
func Read(r io.Reader) (*pb.Envelope, error) {
	e, _, err := ReadReceived(r)
	return e, err
}

// ReadReceived anchors the allowance at the first received frame byte. Time
// spent framing, decoding or waiting for dispatch must not renew that budget.
// Idle time before a peer starts a frame consumes no new request's allowance.
func ReadReceived(r io.Reader) (*pb.Envelope, time.Time, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:1]); err != nil {
		return nil, time.Time{}, fmt.Errorf("workspace header: %w", err)
	}
	receivedAt := time.Now()
	if _, err := io.ReadFull(r, h[1:]); err != nil {
		return nil, receivedAt, fmt.Errorf("workspace header: %w", err)
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > MaxFrame {
		return nil, receivedAt, fmt.Errorf("invalid workspace frame: %w", ErrGrammar)
	}
	frame := make([]byte, 4+int(n))
	copy(frame, h[:])
	if _, err := io.ReadFull(r, frame[4:]); err != nil {
		return nil, receivedAt, fmt.Errorf("workspace payload: %w", err)
	}
	e, err := Decode(frame)
	return e, receivedAt, err
}
func Write(w io.Writer, e *pb.Envelope) error {
	frame, err := Encode(e)
	if err != nil {
		return fmt.Errorf("workspace write encode: %w", err)
	}
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if n < 0 || n > len(frame) {
			return fmt.Errorf("workspace write: %w", io.ErrShortWrite)
		}
		frame = frame[n:]
		if err != nil {
			return fmt.Errorf("workspace write: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("workspace write: %w", io.ErrShortWrite)
		}
	}
	return nil
}

// Pair binds a channel to the app-owned VM and exact release before requests.
// A guest restart changes GuestServiceId and invalidates every previous token.
func Pair(host, guest *pb.Hello) error {
	if host == nil || guest == nil || hello(host) != nil || hello(guest) != nil ||
		len(host.GuestServiceId) != 0 || !ID(guest.GuestServiceId) ||
		!proto.Equal(host.Release, guest.Release) || !bytes.Equal(host.BootId, guest.BootId) ||
		!bytes.Equal(host.HostServiceId, guest.HostServiceId) {
		return invalid("Pair: invalid field or state combination")
	}
	return nil
}
