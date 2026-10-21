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

// At most (64 + 16) * 32 * (256 + 40) bytes of loss plus <64 KiB of identities,
// statuses and envelope overhead: every status/cold/resume reply fits MaxFrame.
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
	if p == nil || len(p.AuthorityEndpoint) == 0 || len(p.AuthorityEndpoint) > 4096 || !utf8.ValidString(p.AuthorityEndpoint) || !Digest(p.RoutesRevision) {
		return invalid("provision endpoint or route revision")
	}
	for name, raw := range map[string][]byte{"CA": p.CaCertificate, "certificate": p.ClientCertificate, "capability": p.Capability, "public key": p.PublicKey} {
		if len(raw) == 0 || len(raw) > 65536 {
			return invalid("provision " + name + " length")
		}
	}
	return Mount(p.Mount)
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
		if err := losses(m.Loss); err != nil {
			return fmt.Errorf("statuses: %w", err)
		}
	}
	return Roster(roster)
}

// Retired outcomes can include repeated volumes, but never repeated incarnations.
func RetiredStatuses(ms []*pb.MountStatus) error {
	if len(ms) > MaxRetiredBatch {
		return invalid("retired outcome batch exceeds limit")
	}
	seen := map[string]bool{}
	for _, m := range ms {
		if err := statuses([]*pb.MountStatus{m}); err != nil {
			return fmt.Errorf("retired outcome: %w", err)
		}
		key := MountKey(m.Mount)
		if seen[key] || m.Cleanup != "complete" || (m.State != "terminal" && m.State != "authorization-required") {
			return invalid("retired outcome requires unique, exactly cleaned terminal incarnation")
		}
		seen[key] = true
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
func Validate(e *pb.Envelope) error {
	if e == nil || e.Version != Version || e.RequestId == 0 {
		return invalid("Validate: invalid field or state combination")
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
		if len(b.Suspend.Roster) != 0 {
			return invalid("suspend request roster is guest-owned")
		}
		return nil
	case *pb.Envelope_SuspendAck:
		return ColdAck(b.SuspendAck)
	case *pb.Envelope_Resume:
		return Token(b.Resume)
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
		if b.RetireAck == nil || len(b.RetireAck.Outcomes) == 0 {
			return invalid("retire acknowledgement missing outcomes")
		}
		return RetiredStatuses(b.RetireAck.Outcomes)
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
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, fmt.Errorf("workspace header: %w", err)
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > MaxFrame {
		return nil, fmt.Errorf("invalid workspace frame: %w", ErrGrammar)
	}
	frame := make([]byte, 4+int(n))
	copy(frame, h[:])
	if _, err := io.ReadFull(r, frame[4:]); err != nil {
		return nil, fmt.Errorf("workspace payload: %w", err)
	}
	return Decode(frame)
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
