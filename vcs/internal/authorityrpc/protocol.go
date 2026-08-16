package authorityrpc

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ProtocolMajor is intentionally incompatible with every earlier authority
// data path. Version 5 makes one DATA and one CONTROL transport mandatory and
// activates a provisional attach only after both authenticated bindings exist.
// There is no single-connection compatibility path: peers that disagree must
// fail at Hello, not mix transport or session lifecycles.
const ProtocolMajor uint32 = 5

// ProtocolALPN is exported so the production authority listener and the RPC
// server package cannot drift onto different exact protocols.
const ProtocolALPN = "portablefs-authority-v5"

const protocolALPN = ProtocolALPN

// FramePayloadReserve leaves deterministic room for the response envelope,
// handles, attributes, and protobuf length tags around a negotiated data chunk.
// It straddles the process boundary: the client checks the authority's
// advertised read/write bounds against it, the authority validates its own
// configuration against it, and both read the same constant.
const FramePayloadReserve uint32 = 1024

// responseEnvelopeReserve bounds the bytes writeFrame adds back to a retained
// replay body. A retained outcome is marshaled with request_id, epoch and
// mutation stripped and errno already present; the reply that finally reaches
// the wire restores them:
//
//	request_id  field 1 varint : 1 tag +           10 =  11
//	epoch       field 2 bytes  : 1 tag + 1 len  + 16 =  18
//	errno       field 3 varint : 1 tag +           10 =  11
//	mutation    field 6 msg    : 1 tag + 1 len  + (1+5 slot) + (1+10 sequence) = 19
//	terminal_delivery_token
//	            field 9 bytes  : 1 tag + 1 len  + 16 = 18
//
// 77 bytes worst case. TestRetainedReplyEnvelopeFitsReserve measures the real
// delta against this bound so the arithmetic cannot drift from the schema.
const responseEnvelopeReserve uint32 = 80

// fixedMutationReplyBytes bounds every mutation reply whose body has a fixed
// shape (an Item, an Attr, a handle, a byte count). It is also the floor for a
// directory-listing budget, which guarantees at least one directory entry fits.
const fixedMutationReplyBytes uint32 = 4096

// maxDirentBytes bounds one encoded directory entry: a name of at most
// NAME_MAX (255) bytes, one Attr, one 8-byte cookie, and an optional Item whose
// nested Attr is intentionally duplicated for a self-contained capability.
const maxDirentBytes uint32 = 768

// MinimumFrameBytes is the smallest frame an authority may be configured with.
// Below it a legal fixed-shape mutation reply could not be written, so a
// volume would be unusable rather than merely constrained.
const MinimumFrameBytes uint32 = fixedMutationReplyBytes + responseEnvelopeReserve

const peerCompleteFIFOFeedbackFeature = "peer-complete-fifo-feedback"
const sessionReauthorizationFeature = "session-reauthorization-v1"
const mountEnrollmentReauthorizationFeature = "mount-enrollment-reauthorization-v1"
const strictWriteTransactionFeature = "transactional-shared-write-v1"

// strictLinuxMutationSuiteFeature proves the authority implements every
// operation the indivisible patched-kernel profile can issue beyond the write
// transaction itself: exact fallocate, server-side copy_file_range, and
// O_TMPFILE capability acquisition. A kernel must not discover an older
// protocol-5 authority only when the first such syscall would otherwise fence
// the mount.
const strictLinuxMutationSuiteFeature = "strict-linux-mutation-suite-v1"

// terminalAppliedDeliveryFeature proves that a fenced authority retains a
// terminal applied-state response until the frontend confirms its local kernel
// publication boundary. Without it, connection teardown can overtake the one
// reply that carries the exact post-mutation state.
const terminalAppliedDeliveryFeature = "terminal-applied-delivery-receipt-v1"

// sequencedItemVisibilityRetryFeature proves both sides implement the exact
// Linux item-only handoff: the authority returns the blocking peer sequence and
// the frontend waits for that local repair before resubmitting with an
// authority-authenticated, replay-bound proof. The proof lets the retried DATA
// request wait behind an in-flight CONTROL ACK without reopening the source-gate
// cycle. Without this negotiation, an older protocol-5 frontend could leak the
// internal EINTR to an application or spin across those independent lanes.
const sequencedItemVisibilityRetryFeature = "sequenced-item-visibility-retry-v1"

// RequiredWriteTransactionBytes is Linux MAX_RW_COUNT on the smallest
// supported page size. Larger-page kernels have a slightly smaller bound, so
// this fixed authority contract can stage every legal write_iter without a
// page-size negotiation or a silent clamp.
const RequiredWriteTransactionBytes uint64 = 0x7ffff000

var (
	requiredHelloFeatures        = []string{"xfs-current-state", "session-exact-epoch", "direct-write", "framed-bulk-data-v1", "authority-keyed-replay-fingerprint-v1", "visibility-ack-next-v1", "mandatory-dual-transport-v1", "strict-two-phase-visibility", "exact-parent-repair-interruption", "classified-visibility-interruption", sequencedItemVisibilityRetryFeature, "namespace-post-binding-identity", "source-publication-gate-v1", "exact-resource-acquisition", strictWriteTransactionFeature, strictLinuxMutationSuiteFeature, terminalAppliedDeliveryFeature}
	requiredAttachFeatures       = []string{"write-through", "no-history", "no-branches", "direct-io-no-file-mmap", "user-xattr-readonly", "single-principal", "distributed-posix-locks", "stable-item-identity", "readdir-plus-items", "volume-syncfs-barrier", "exact-resource-acquisition", strictWriteTransactionFeature}
	requiredStrictAttachFeatures = []string{"strict-two-phase-visibility", "exact-parent-repair-interruption", "classified-visibility-interruption", sequencedItemVisibilityRetryFeature, "namespace-post-binding-identity", "source-publication-gate-v1"}
)

func hasFeatures(advertised, required []string) bool {
	set := make(map[string]struct{}, len(advertised))
	for _, feature := range advertised {
		set[feature] = struct{}{}
	}
	for _, feature := range required {
		if _, ok := set[feature]; !ok {
			return false
		}
	}
	return true
}

// blockingWait reports whether a request may park server-side for an unbounded
// time waiting on another session's POSIX lock. Such requests get their own
// admission lane on both peers so they can never consume the last ordinary
// execution slot, which is what a keepalive needs to stay live.
func blockingWait(req *authoritypb.Request) bool {
	lock := req.GetSetLock()
	return lock != nil && lock.GetWait() && !lock.GetUnlock()
}

// terminalQuiesceCancelable identifies requests which can park indefinitely
// without having applied filesystem state. A terminal storage failure cancels
// these so the response drain cannot wait forever, while an already-applied
// source mutation remains alive to finish visibility COMPLETE and register its
// exact terminal delivery receipt.
func terminalQuiesceCancelable(req *authoritypb.Request) bool {
	if req == nil {
		return false
	}
	if blockingWait(req) || req.GetNextVisibility() != nil || req.GetApplyRoutes() != nil {
		return true
	}
	return false
}

// blockingWaitLane splits one in-flight bound into an ordinary lane and a
// blocking-lock-wait lane. Both peers derive their lanes from this one
// function, and it is monotonic, so a client sized at or below the authority's
// advertised bound always has lanes at or below the authority's own.
func blockingWaitLane(maxInFlight int) (ordinary, blocking int) {
	blocking = maxInFlight / 2
	return maxInFlight - blocking, blocking
}

// requestRequiresWrite classifies an operation against the signed access grant.
// It is protocol-level, not storage-level: a read-only mount must be able to
// refuse a write before any authority state is touched.
func requestRequiresWrite(req *authoritypb.Request) bool {
	switch body := req.GetBody().(type) {
	case *authoritypb.Request_Create, *authoritypb.Request_Mkdir,
		*authoritypb.Request_Unlink, *authoritypb.Request_Rename,
		*authoritypb.Request_Link, *authoritypb.Request_Symlink,
		*authoritypb.Request_SetAttr, *authoritypb.Request_Fallocate,
		*authoritypb.Request_CopyFileRange, *authoritypb.Request_Tmpfile,
		*authoritypb.Request_SetXattr, *authoritypb.Request_RemoveXattr,
		*authoritypb.Request_SyncFs:
		return true
	case *authoritypb.Request_Open:
		flags := body.Open.GetFlags()
		return flags != nil && (flags.GetWrite() || flags.GetAppend() || flags.GetTruncate())
	case *authoritypb.Request_SetLock:
		return !body.SetLock.GetUnlock() && body.SetLock.GetLock() != nil && body.SetLock.GetLock().GetWrite()
	case *authoritypb.Request_WriteTransaction:
		// ABORT only releases already-reserved inert state. It remains legal
		// after a grant is downgraded so cleanup can never be held hostage by
		// current write authorization.
		return body.WriteTransaction.GetPhase() != authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_ABORT
	default:
		return false
	}
}

// requestIsVisibleMutation is the single protocol-level classification of
// operations whose ordinary callback can publish state another mount must
// repair. Every one carries an exact source publication gate under the one
// coherent protocol-5 mount contract. Non-visible operations must omit it.
func requestIsVisibleMutation(req *authoritypb.Request) bool {
	switch body := req.GetBody().(type) {
	case *authoritypb.Request_SetAttr,
		*authoritypb.Request_Fallocate,
		*authoritypb.Request_CopyFileRange,
		*authoritypb.Request_Create,
		*authoritypb.Request_Mkdir,
		*authoritypb.Request_Unlink,
		*authoritypb.Request_Rename,
		*authoritypb.Request_Symlink,
		*authoritypb.Request_Link,
		*authoritypb.Request_SetXattr,
		*authoritypb.Request_RemoveXattr:
		return true
	case *authoritypb.Request_Open:
		return body.Open.GetFlags() != nil && body.Open.GetFlags().GetTruncate()
	case *authoritypb.Request_WriteTransaction:
		return body.WriteTransaction.GetPhase() == authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT
	default:
		return false
	}
}

func validSourcePublicationGatePresence(req *authoritypb.Request) bool {
	return (req.GetSourcePublicationGate() != nil) == requestIsVisibleMutation(req)
}

// validVisibilityRetryRequestShape is the wire-level half of the item retry
// proof. The visibility coordinator validates the stateful half against the
// exact one-shot debt it issued. Keeping the cheap structural checks here
// prevents a retry proof from entering lifecycle, read-only, namespace, or
// callback-serialized paths where it has no meaning.
func validVisibilityRetryRequestShape(req *authoritypb.Request, gate *volumeserver.SourcePublicationGate) bool {
	if req == nil {
		return false
	}
	if req.GetVisibilityRetryAfterSequence() == 0 {
		return true
	}
	if !requestIsVisibleMutation(req) || req.GetFrontendOperationId() == 0 || gate == nil || len(gate.Targets) == 0 {
		return false
	}
	for _, target := range gate.Targets {
		if target.ParentIdentity != ([16]byte{}) {
			return false
		}
	}
	return true
}

// decodeSourcePublicationGate validates the one canonical wire declaration
// before replay identity is computed. In particular, a sender cannot make an
// exact replay depend on protobuf repeated-field order or duplicate merging:
// both are rejected, never normalized after fingerprinting.
func decodeSourcePublicationGate(req *authoritypb.Request) (*volumeserver.SourcePublicationGate, error) {
	wire := req.GetSourcePublicationGate()
	if wire == nil {
		return nil, nil
	}
	if len(wire.ProtoReflect().GetUnknown()) != 0 || len(wire.GetTargets()) == 0 || len(wire.GetTargets()) > 16 {
		return nil, fmt.Errorf("%w: malformed source publication gate", errNonCanonical)
	}
	gate := &volumeserver.SourcePublicationGate{Targets: make([]volumeserver.SourcePublicationTarget, 0, len(wire.GetTargets()))}
	for _, encoded := range wire.GetTargets() {
		if encoded == nil || len(encoded.ProtoReflect().GetUnknown()) != 0 {
			return nil, fmt.Errorf("%w: malformed source publication target", errNonCanonical)
		}
		var target volumeserver.SourcePublicationTarget
		switch coordinate := encoded.GetCoordinate().(type) {
		case *authoritypb.SourcePublicationTarget_Item:
			item := coordinate.Item
			if item == nil || len(item.ProtoReflect().GetUnknown()) != 0 || len(item.GetIdentity()) != len(target.Identity) ||
				!item.GetAttributes() || item.GetData() && !item.GetAttributes() {
				return nil, fmt.Errorf("%w: malformed source item target", errNonCanonical)
			}
			copy(target.Identity[:], item.GetIdentity())
			if target.Identity == ([16]byte{}) {
				return nil, fmt.Errorf("%w: source item identity is zero", errNonCanonical)
			}
			target.Attributes, target.Data = item.GetAttributes(), item.GetData()
		case *authoritypb.SourcePublicationTarget_Namespace:
			namespace := coordinate.Namespace
			if namespace == nil || len(namespace.ProtoReflect().GetUnknown()) != 0 ||
				len(namespace.GetParentIdentity()) != len(target.ParentIdentity) ||
				!validProtocolNamespaceName(namespace.GetName()) ||
				namespace.GetBoundData() && !namespace.GetBoundAttributes() {
				return nil, fmt.Errorf("%w: malformed source namespace target", errNonCanonical)
			}
			copy(target.ParentIdentity[:], namespace.GetParentIdentity())
			if target.ParentIdentity == ([16]byte{}) {
				return nil, fmt.Errorf("%w: source namespace parent identity is zero", errNonCanonical)
			}
			target.Name = append([]byte(nil), namespace.GetName()...)
			target.BoundAttributes, target.BoundData = namespace.GetBoundAttributes(), namespace.GetBoundData()
		default:
			return nil, fmt.Errorf("%w: source target has no coordinate", errNonCanonical)
		}
		if len(gate.Targets) != 0 && compareSourcePublicationTarget(gate.Targets[len(gate.Targets)-1], target) >= 0 {
			return nil, fmt.Errorf("%w: source targets are duplicate or out of order", errNonCanonical)
		}
		gate.Targets = append(gate.Targets, target)
	}
	return gate, nil
}

func validProtocolNamespaceName(name []byte) bool {
	return len(name) != 0 && len(name) <= 255 && !bytes.Equal(name, []byte(".")) && !bytes.Equal(name, []byte("..")) &&
		bytes.IndexByte(name, 0) < 0 && bytes.IndexByte(name, '/') < 0
}

func compareSourcePublicationTarget(left, right volumeserver.SourcePublicationTarget) int {
	leftNamespace := left.ParentIdentity != ([16]byte{})
	rightNamespace := right.ParentIdentity != ([16]byte{})
	if leftNamespace != rightNamespace {
		if leftNamespace {
			return 1
		}
		return -1
	}
	if !leftNamespace {
		return bytes.Compare(left.Identity[:], right.Identity[:])
	}
	if compared := bytes.Compare(left.ParentIdentity[:], right.ParentIdentity[:]); compared != 0 {
		return compared
	}
	return bytes.Compare(left.Name, right.Name)
}

// requestRequiresAdmin classifies an operation as volume-wide configuration
// rather than filesystem work. Write access covers file contents; it does not
// cover the declaration that decides which subtrees exist for every machine at
// once, so that one is gated separately and explicitly.
func requestRequiresAdmin(req *authoritypb.Request) bool {
	_, admin := req.GetBody().(*authoritypb.Request_ApplyRoutes)
	return admin
}

// requestUsesTopology reports whether a request is a filesystem operation whose
// path ownership was decided by the mount's active machine-local routes. Those
// requests hold the coordinator's topology read guard from revision admission
// through their final result. Session and visibility control must not take the
// guard: ApplyRoutes waits for visibility acknowledgments while holding the
// writer, so making Ack depend on the read side would deadlock the barrier.
func requestUsesTopology(req *authoritypb.Request) bool {
	switch body := req.GetBody().(type) {
	case *authoritypb.Request_Resume, *authoritypb.Request_Activate, *authoritypb.Request_AbortAttach,
		*authoritypb.Request_KeepAlive,
		*authoritypb.Request_Reauthorize,
		*authoritypb.Request_Detach, *authoritypb.Request_Cancel,
		*authoritypb.Request_TerminalDeliveryReceipt,
		*authoritypb.Request_NextVisibility, *authoritypb.Request_AckVisibility,
		*authoritypb.Request_ApplyRoutes:
		return false
	case *authoritypb.Request_SetLock:
		// A blocking lock wait never reaches XFS: the lock table is
		// authority-epoch runtime state, so the topology invariant — no
		// filesystem operation reaches XFS under a stale routing revision —
		// does not apply to the wait. Holding the read guard across an
		// unbounded F_SETLKW would let one waiter plus one queued ApplyRoutes
		// writer stall every guarded request on the volume (a Go RWMutex
		// admits no new readers once a writer is queued), so the wait is
		// admitted through the ordinary session-routes check instead.
		// Non-blocking lock calls keep the guard: they are cheap and complete
		// immediately, so uniformity there costs nothing.
		return body.SetLock.GetUnlock() || !body.SetLock.GetWait()
	case *authoritypb.Request_WriteTransaction:
		// BEGIN/DATA/ABORT are session-local staging operations. COMMIT is the
		// one filesystem mutation and owns the ordinary topology read cut.
		return body.WriteTransaction.GetPhase() == authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT
	default:
		// Unknown future filesystem operations fail closed into the guarded side.
		return true
	}
}

// canonicalFingerprint is the authority-private replay identity of a mutation.
// The authority applies its per-epoch secret to the request body with the wire
// envelope (request ID, epoch, session proof, mutation header) stripped. The
// encoding is this package's own canonical form, not protobuf-go's
// Deterministic option, which is documented as unstable across library
// versions. A replay with different content is therefore rejected without
// making every client hash a large payload before it can send it.
func canonicalFingerprint(runtime *volumeserver.Authority, req *authoritypb.Request) (volumeserver.RequestFingerprint, error) {
	if runtime == nil {
		return volumeserver.RequestFingerprint{}, fmt.Errorf("%w: authority runtime is required", errNonCanonical)
	}
	if req == nil {
		return volumeserver.RequestFingerprint{}, fmt.Errorf("%w: nil request", errNonCanonical)
	}
	if len(req.ProtoReflect().GetUnknown()) != 0 {
		return volumeserver.RequestFingerprint{}, fmt.Errorf("%w: unknown fields are not part of this protocol", errNonCanonical)
	}
	// SessionProof and Mutation are intentionally stripped from the replay
	// identity, but they are still part of the exact request grammar. The frame
	// validator rejects their unknown fields before decode; repeat that invariant
	// here so direct handler callers cannot bypass it merely because these two
	// messages do not enter the canonical stream.
	if session := req.GetSession(); session != nil && len(session.ProtoReflect().GetUnknown()) != 0 {
		return volumeserver.RequestFingerprint{}, fmt.Errorf("%w: unknown session-proof fields are not part of this protocol", errNonCanonical)
	}
	if mutation := req.GetMutation(); mutation != nil && len(mutation.ProtoReflect().GetUnknown()) != 0 {
		return volumeserver.RequestFingerprint{}, fmt.Errorf("%w: unknown mutation fields are not part of this protocol", errNonCanonical)
	}
	if _, err := decodeSourcePublicationGate(req); err != nil {
		return volumeserver.RequestFingerprint{}, err
	}
	// The body is already immutable for the duration of dispatch. Stream the
	// canonical form directly into the keyed fingerprint instead of recursively
	// materializing one payload-sized byte slice at every protobuf nesting level.
	// The tiny envelope below deliberately shares the body; canonicalWrite only
	// reads it.
	body := &authoritypb.Request{
		SourcePublicationGate:        req.GetSourcePublicationGate(),
		VisibilityRetryAfterSequence: req.GetVisibilityRetryAfterSequence(),
		Body:                         req.GetBody(),
	}
	return runtime.ReplayFingerprint(func(writer io.Writer) error {
		return canonicalWrite(writer, body.ProtoReflect())
	})
}

var errNonCanonical = errors.New("authorityrpc: request cannot be canonicalized")

// canonicalWrite emits the exact byte stream canonicalBytes defines without
// constructing that stream in memory. Large WriteTransactionRequest.Data fields dominate
// the data plane; recursively appending a 1 MiB field once per enclosing
// message used to allocate and copy more than 4 MiB on both the client and the
// authority before XFS saw one byte. Streaming preserves the frozen digest
// while keeping payload memory O(1).
func canonicalWrite(writer io.Writer, message protoreflect.Message) error {
	fields, err := canonicalPresentFields(message)
	if err != nil {
		return err
	}
	for _, field := range fields {
		value := message.Get(field)
		if field.IsMap() {
			return fmt.Errorf("%w: map fields have no canonical order", errNonCanonical)
		}
		if field.IsList() {
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				if err := canonicalWriteField(writer, field, list.Get(i)); err != nil {
					return err
				}
			}
			continue
		}
		if err := canonicalWriteField(writer, field, value); err != nil {
			return err
		}
	}
	return nil
}

func canonicalPresentFields(message protoreflect.Message) ([]protoreflect.FieldDescriptor, error) {
	if len(message.GetUnknown()) != 0 {
		return nil, fmt.Errorf("%w: unknown fields are not part of this protocol", errNonCanonical)
	}
	fields := message.Descriptor().Fields()
	present := make([]protoreflect.FieldDescriptor, 0, fields.Len())
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)
		if message.Has(field) {
			present = append(present, field)
		}
	}
	for i := 1; i < len(present); i++ {
		for j := i; j > 0 && present[j].Number() < present[j-1].Number(); j-- {
			present[j], present[j-1] = present[j-1], present[j]
		}
	}
	return present, nil
}

func canonicalMessageSize(message protoreflect.Message) (int, error) {
	fields, err := canonicalPresentFields(message)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, field := range fields {
		value := message.Get(field)
		if field.IsMap() {
			return 0, fmt.Errorf("%w: map fields have no canonical order", errNonCanonical)
		}
		if field.IsList() {
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				size, err := canonicalFieldSize(field, list.Get(i))
				if err != nil {
					return 0, err
				}
				total += size
			}
			continue
		}
		size, err := canonicalFieldSize(field, value)
		if err != nil {
			return 0, err
		}
		total += size
	}
	return total, nil
}

func canonicalFieldSize(field protoreflect.FieldDescriptor, value protoreflect.Value) (int, error) {
	tag := protowire.SizeTag(field.Number())
	switch field.Kind() {
	case protoreflect.BoolKind:
		return tag + protowire.SizeVarint(protowire.EncodeBool(value.Bool())), nil
	case protoreflect.EnumKind:
		return tag + protowire.SizeVarint(uint64(value.Enum())), nil
	case protoreflect.Int32Kind, protoreflect.Int64Kind:
		return tag + protowire.SizeVarint(uint64(value.Int())), nil
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind:
		return tag + protowire.SizeVarint(value.Uint()), nil
	case protoreflect.Sint32Kind, protoreflect.Sint64Kind:
		return tag + protowire.SizeVarint(protowire.EncodeZigZag(value.Int())), nil
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind,
		protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return 0, fmt.Errorf("%w: fixed-width fields are not used by this protocol", errNonCanonical)
	case protoreflect.StringKind:
		return tag + protowire.SizeBytes(len(value.String())), nil
	case protoreflect.BytesKind:
		return tag + protowire.SizeBytes(len(value.Bytes())), nil
	case protoreflect.MessageKind:
		nested, err := canonicalMessageSize(value.Message())
		if err != nil {
			return 0, err
		}
		return tag + protowire.SizeBytes(nested), nil
	default:
		return 0, fmt.Errorf("%w: unsupported field kind %v", errNonCanonical, field.Kind())
	}
}

func canonicalWriteField(writer io.Writer, field protoreflect.FieldDescriptor, value protoreflect.Value) error {
	var storage [20]byte
	prefix := storage[:0]
	number := field.Number()
	switch field.Kind() {
	case protoreflect.BoolKind:
		prefix = protowire.AppendVarint(protowire.AppendTag(prefix, number, protowire.VarintType), protowire.EncodeBool(value.Bool()))
	case protoreflect.EnumKind:
		prefix = protowire.AppendVarint(protowire.AppendTag(prefix, number, protowire.VarintType), uint64(value.Enum()))
	case protoreflect.Int32Kind, protoreflect.Int64Kind:
		prefix = protowire.AppendVarint(protowire.AppendTag(prefix, number, protowire.VarintType), uint64(value.Int()))
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind:
		prefix = protowire.AppendVarint(protowire.AppendTag(prefix, number, protowire.VarintType), value.Uint())
	case protoreflect.Sint32Kind, protoreflect.Sint64Kind:
		prefix = protowire.AppendVarint(protowire.AppendTag(prefix, number, protowire.VarintType), protowire.EncodeZigZag(value.Int()))
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind,
		protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return fmt.Errorf("%w: fixed-width fields are not used by this protocol", errNonCanonical)
	case protoreflect.StringKind:
		text := value.String()
		prefix = protowire.AppendVarint(protowire.AppendTag(prefix, number, protowire.BytesType), uint64(len(text)))
		if err := writeAll(writer, prefix); err != nil {
			return err
		}
		_, err := io.WriteString(writer, text)
		return err
	case protoreflect.BytesKind:
		data := value.Bytes()
		prefix = protowire.AppendVarint(protowire.AppendTag(prefix, number, protowire.BytesType), uint64(len(data)))
		if err := writeAll(writer, prefix); err != nil {
			return err
		}
		return writeAll(writer, data)
	case protoreflect.MessageKind:
		nested, err := canonicalMessageSize(value.Message())
		if err != nil {
			return err
		}
		prefix = protowire.AppendVarint(protowire.AppendTag(prefix, number, protowire.BytesType), uint64(nested))
		if err := writeAll(writer, prefix); err != nil {
			return err
		}
		return canonicalWrite(writer, value.Message())
	default:
		return fmt.Errorf("%w: unsupported field kind %v", errNonCanonical, field.Kind())
	}
	return writeAll(writer, prefix)
}

// canonicalBytes encodes a message as protobuf with fields emitted in strictly
// ascending field number, no unknown fields, and no packed-repeated ambiguity.
// The result depends only on the schema and the message value.
func canonicalBytes(message protoreflect.Message) ([]byte, error) {
	var encoded bytes.Buffer
	if err := canonicalWrite(&encoded, message); err != nil {
		return nil, err
	}
	return encoded.Bytes(), nil
}
