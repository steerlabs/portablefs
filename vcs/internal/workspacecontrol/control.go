// Package workspacecontrol defines the unreleased, exact workspace control 8
// stream. It carries supervision only; authority permissions remain protocol 8.
package workspacecontrol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const Version = 8
const MaxFrame = 1 << 20
const MaxMounts = 64

var ErrGrammar = errors.New("workspace control: invalid exact grammar")

func valid(ok bool) error {
	if !ok {
		return ErrGrammar
	}
	return nil
}
func ID(b []byte) bool     { return len(b) == 16 && !bytes.Equal(b, make([]byte, 16)) }
func Digest(b []byte) bool { return len(b) == 32 && !bytes.Equal(b, make([]byte, 32)) }
func Mount(m *pb.MountID) error {
	if m == nil {
		return ErrGrammar
	}
	for _, c := range []byte(m.VolumeId) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return ErrGrammar
		}
	}
	return valid(Digest(m.AuthorityId) && ID(m.Incarnation) && len(m.VolumeId) > 0 && len(m.VolumeId) <= 128 && m.VolumeId != "." && m.VolumeId != ".." && !strings.ContainsAny(m.VolumeId, "/\x00"))
}
func MountKey(m *pb.MountID) string {
	if m == nil {
		return ""
	}
	return fmt.Sprintf("%x/%s/%x", m.AuthorityId, m.VolumeId, m.Incarnation)
}
func Roster(ms []*pb.MountID) error {
	if len(ms) > MaxMounts {
		return ErrGrammar
	}
	prior := ""
	volumes := map[string]bool{}
	for _, m := range ms {
		if err := Mount(m); err != nil {
			return err
		}
		key := MountKey(m)
		volume := fmt.Sprintf("%x/%s", m.AuthorityId, m.VolumeId)
		if key <= prior || volumes[volume] {
			return ErrGrammar
		}
		prior = key
		volumes[volume] = true
	}
	return nil
}
func Suspension(s *pb.Suspension) error {
	if s == nil || !ID(s.BootId) || !ID(s.HostServiceId) || !ID(s.GuestServiceId) || s.Generation == 0 || !ID(s.Nonce) {
		return ErrGrammar
	}
	return Roster(s.Roster)
}
func Token(t *pb.ResumeToken) error {
	if t == nil || !ID(t.WakeNonce) {
		return ErrGrammar
	}
	return Suspension(t.Suspension)
}
func Release(r *pb.Release) error {
	if r == nil || r.AuthorityMajor != 8 || len(r.AppVersion) == 0 || len(r.AppVersion) > 128 || len(r.Commit) != 40 || !Digest(r.ImageDigest) {
		return ErrGrammar
	}
	for _, c := range []byte(r.AppVersion) {
		if c < 0x21 || c > 0x7e {
			return ErrGrammar
		}
	}
	for _, c := range r.Commit {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ErrGrammar
		}
	}
	return nil
}
func losses(ls []*pb.Loss) error {
	if len(ls) > 128 {
		return ErrGrammar
	}
	var seq uint64
	for _, l := range ls {
		if l == nil || l.Sequence <= seq || len(l.Reason) == 0 || len(l.Reason) > 4096 {
			return ErrGrammar
		}
		seq = l.Sequence
	}
	return nil
}
func ColdAck(a *pb.SuspendAck) error {
	if a == nil {
		return ErrGrammar
	}
	if err := Suspension(a.Suspension); err != nil {
		return err
	}
	if len(a.Mounts) != len(a.Suspension.Roster) {
		return ErrGrammar
	}
	for i, m := range a.Mounts {
		if m == nil || !proto.Equal(m.Mount, a.Suspension.Roster[i]) {
			return ErrGrammar
		}
		if err := losses(m.Loss); err != nil {
			return err
		}
	}
	return nil
}
func statuses(ms []*pb.MountStatus) error {
	roster := make([]*pb.MountID, 0, len(ms))
	for _, m := range ms {
		if m == nil {
			return ErrGrammar
		}
		roster = append(roster, m.Mount)
		switch m.State {
		case "closed", "ready", "suspended-cold", "recovering", "terminal", "authorization-required":
		default:
			return ErrGrammar
		}
		switch m.Cleanup {
		case "retained", "process-exited", "kernel-absent", "complete":
		default:
			return ErrGrammar
		}
		if len(m.Reason) > 4096 {
			return ErrGrammar
		}
		if err := losses(m.Loss); err != nil {
			return err
		}
	}
	return Roster(roster)
}
func Validate(e *pb.Envelope) error {
	if e == nil || e.Version != Version || e.RequestId == 0 {
		return ErrGrammar
	}
	switch b := e.Body.(type) {
	case *pb.Envelope_Hello:
		if b.Hello == nil || len(b.Hello.GuestServiceId) != 0 {
			return ErrGrammar
		}
		return hello(b.Hello)
	case *pb.Envelope_HelloAck:
		if b.HelloAck == nil || !ID(b.HelloAck.GuestServiceId) {
			return ErrGrammar
		}
		return hello(b.HelloAck)
	case *pb.Envelope_Suspend:
		return Suspension(b.Suspend)
	case *pb.Envelope_SuspendAck:
		return ColdAck(b.SuspendAck)
	case *pb.Envelope_Resume:
		return Token(b.Resume)
	case *pb.Envelope_ResumeAck:
		if b.ResumeAck == nil {
			return ErrGrammar
		}
		if err := Token(b.ResumeAck.Token); err != nil {
			return err
		}
		if len(b.ResumeAck.Mounts) != len(b.ResumeAck.Token.Suspension.Roster) {
			return ErrGrammar
		}
		for i, m := range b.ResumeAck.Mounts {
			if m == nil || !proto.Equal(m.Mount, b.ResumeAck.Token.Suspension.Roster[i]) {
				return ErrGrammar
			}
		}
		return statuses(b.ResumeAck.Mounts)
	case *pb.Envelope_Status:
		return valid(b.Status != nil)
	case *pb.Envelope_StatusReply:
		s := b.StatusReply
		if s == nil || !ID(s.BootId) || !ID(s.HostServiceId) || !ID(s.GuestServiceId) {
			return ErrGrammar
		}
		switch s.State {
		case "running", "suspending", "suspended-cold", "recovering", "discard-only":
		default:
			return ErrGrammar
		}
		return statuses(s.Mounts)
	case *pb.Envelope_Provision:
		p := b.Provision
		if p == nil || len(p.AuthorityEndpoint) == 0 || len(p.AuthorityEndpoint) > 4096 || len(p.CaCertificate) == 0 || len(p.ClientCertificate) == 0 || len(p.Capability) == 0 || len(p.PublicKey) == 0 || !Digest(p.RoutesRevision) {
			return ErrGrammar
		}
		for _, raw := range [][]byte{p.CaCertificate, p.ClientCertificate, p.Capability, p.PublicKey} {
			if len(raw) > 65536 || bytes.Contains(raw, []byte("PRIVATE KEY")) {
				return ErrGrammar
			}
		}
		return Mount(p.Mount)
	case *pb.Envelope_Mount:
		if b.Mount == nil {
			return ErrGrammar
		}
		return Mount(b.Mount.Mount)
	case *pb.Envelope_Umount:
		if b.Umount == nil {
			return ErrGrammar
		}
		return Mount(b.Umount.Mount)
	case *pb.Envelope_Result:
		if b.Result == nil || len(b.Result.Reason) > 4096 {
			return ErrGrammar
		}
		switch b.Result.Code {
		case "accepted", "unavailable", "authorization-required", "refused":
			return nil
		}
		return ErrGrammar
	default:
		return ErrGrammar
	}
}
func hello(h *pb.Hello) error {
	if !ID(h.BootId) || !ID(h.HostServiceId) {
		return ErrGrammar
	}
	return Release(h.Release)
}

// Check the descriptor before decoding, bounding repeated-message allocations
// and rejecting duplicate/unknown fields rather than protobuf's last-one-wins.
func grammar(raw []byte, d protoreflect.MessageDescriptor, depth int) error {
	if depth > 16 {
		return ErrGrammar
	}
	seen := map[protoreflect.FieldNumber]int{}
	oneofs := map[protoreflect.FullName]bool{}
	var prior protowire.Number
	for len(raw) > 0 {
		n, t, k := protowire.ConsumeTag(raw)
		if k < 0 || n < prior {
			return ErrGrammar
		}
		prior = n
		raw = raw[k:]
		f := d.Fields().ByNumber(n)
		if f == nil {
			return ErrGrammar
		}
		seen[n]++
		if (!f.IsList() && seen[n] > 1) || seen[n] > 128 {
			return ErrGrammar
		}
		if o := f.ContainingOneof(); o != nil {
			if oneofs[o.FullName()] {
				return ErrGrammar
			}
			oneofs[o.FullName()] = true
		}
		switch f.Kind() {
		case protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.BoolKind:
			if t != protowire.VarintType {
				return ErrGrammar
			}
			_, k = protowire.ConsumeVarint(raw)
		case protoreflect.StringKind, protoreflect.BytesKind, protoreflect.MessageKind:
			if t != protowire.BytesType {
				return ErrGrammar
			}
			var b []byte
			b, k = protowire.ConsumeBytes(raw)
			if k >= 0 {
				if f.Kind() == protoreflect.MessageKind {
					if err := grammar(b, f.Message(), depth+1); err != nil {
						return err
					}
				} else if len(b) > 65536 {
					return ErrGrammar
				}
			}
		default:
			return ErrGrammar
		}
		if k < 0 {
			return ErrGrammar
		}
		raw = raw[k:]
	}
	return nil
}
func Encode(e *pb.Envelope) ([]byte, error) {
	if err := Validate(e); err != nil {
		return nil, err
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("workspace encode: %w", err)
	}
	if len(raw) == 0 || len(raw) > MaxFrame {
		return nil, ErrGrammar
	}
	if err := grammar(raw, e.ProtoReflect().Descriptor(), 0); err != nil {
		return nil, err
	}
	out := make([]byte, 4, len(raw)+4)
	binary.BigEndian.PutUint32(out, uint32(len(raw)))
	return append(out, raw...), nil
}
func Decode(frame []byte) (*pb.Envelope, error) {
	if len(frame) < 4 {
		return nil, ErrGrammar
	}
	n := binary.BigEndian.Uint32(frame)
	if n == 0 || n > MaxFrame || int(n) != len(frame)-4 {
		return nil, ErrGrammar
	}
	e := new(pb.Envelope)
	raw := frame[4:]
	if err := grammar(raw, e.ProtoReflect().Descriptor(), 0); err != nil {
		return nil, err
	}
	if err := (proto.UnmarshalOptions{RecursionLimit: 16}).Unmarshal(raw, e); err != nil {
		return nil, fmt.Errorf("workspace decode: %w", err)
	}
	canonical, err := Encode(e)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(frame, canonical) {
		return nil, ErrGrammar
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
		return nil, ErrGrammar
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
		return err
	}
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if n < 0 || n > len(frame) {
			return io.ErrShortWrite
		}
		frame = frame[n:]
		if err != nil {
			return fmt.Errorf("workspace write: %w", err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// Pair binds a channel to the app-owned VM and exact release before requests.
// A guest restart changes GuestServiceId and invalidates every previous token.
func Pair(host, guest *pb.Hello) error {
	if host == nil || guest == nil || hello(host) != nil || hello(guest) != nil || len(host.GuestServiceId) != 0 || !ID(guest.GuestServiceId) || !proto.Equal(host.Release, guest.Release) || !bytes.Equal(host.BootId, guest.BootId) || !bytes.Equal(host.HostServiceId, guest.HostServiceId) {
		return ErrGrammar
	}
	return nil
}
