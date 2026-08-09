package authorityrpc

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ProtocolMajor is intentionally incompatible with every earlier
// fsproto/pfslocal data path. Version 3 makes every resource-acquiring request
// (including Lookup) an exact-replay operation and requires explicit frontend
// disposition of reply resources. An older peer can otherwise leak the first
// capability when a successful reply is lost, so it must fail at Hello.
const ProtocolMajor uint32 = 3

// ProtocolALPN is exported so the production authority listener and the RPC
// server package cannot drift onto different exact protocols.
const ProtocolALPN = "portablefs-authority-v3"

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
//
// 59 bytes worst case. TestRetainedReplyEnvelopeFitsReserve measures the real
// delta against this bound so the arithmetic cannot drift from the schema.
const responseEnvelopeReserve uint32 = 64

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

var (
	requiredHelloFeatures        = []string{"xfs-current-state", "session-exact-epoch", "direct-write", "strict-two-phase-visibility", "exact-parent-repair-interruption", "classified-visibility-interruption", "source-phase-queueability", "namespace-post-binding-identity", "exact-resource-acquisition"}
	requiredAttachFeatures       = []string{"write-through", "no-history", "no-branches", "direct-io-no-file-mmap", "user-xattr-readonly", "single-principal", "distributed-posix-locks", "stable-item-identity", "readdir-plus-items", "volume-syncfs-barrier", "exact-resource-acquisition"}
	requiredStrictAttachFeatures = []string{"strict-two-phase-visibility", "exact-parent-repair-interruption", "classified-visibility-interruption", "source-phase-queueability", "namespace-post-binding-identity"}
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
		*authoritypb.Request_Write, *authoritypb.Request_SetAttr,
		*authoritypb.Request_SetXattr, *authoritypb.Request_RemoveXattr,
		*authoritypb.Request_SyncFs:
		return true
	case *authoritypb.Request_Open:
		flags := body.Open.GetFlags()
		return flags != nil && (flags.GetWrite() || flags.GetAppend() || flags.GetTruncate())
	case *authoritypb.Request_SetLock:
		return !body.SetLock.GetUnlock() && body.SetLock.GetLock() != nil && body.SetLock.GetLock().GetWrite()
	default:
		return false
	}
}

// requestIsVisibleOrderedMutation is the authority-side trust boundary for the
// source-phase queueability proof. These are exactly the request bodies routed
// through VolumeHandler.mutateVisible, and exactly the FSKit operations whose
// frontend tickets can be classified as ordered-only. A directly authenticated
// client must not be able to put an ordinary request or a non-visible replayed
// mutation onto the exception path merely by setting the envelope bit.
func requestIsVisibleOrderedMutation(req *authoritypb.Request) bool {
	switch req.GetBody().(type) {
	case *authoritypb.Request_SetAttr,
		*authoritypb.Request_Write,
		*authoritypb.Request_Create,
		*authoritypb.Request_Mkdir,
		*authoritypb.Request_Unlink,
		*authoritypb.Request_Rename,
		*authoritypb.Request_Symlink,
		*authoritypb.Request_Link,
		*authoritypb.Request_SetXattr,
		*authoritypb.Request_RemoveXattr:
		return true
	default:
		return false
	}
}

func validSourcePhaseQueueability(req *authoritypb.Request) bool {
	return !req.GetSourcePhaseQueueable() ||
		(req.GetFrontendOperationId() != 0 && requestIsVisibleOrderedMutation(req))
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
	case *authoritypb.Request_Resume, *authoritypb.Request_KeepAlive,
		*authoritypb.Request_Reauthorize,
		*authoritypb.Request_Detach, *authoritypb.Request_Cancel,
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
	default:
		// Unknown future filesystem operations fail closed into the guarded side.
		return true
	}
}

// canonicalHash is the replay identity of a mutation: SHA-256 over the request
// with the envelope (request ID, epoch, session proof, mutation header)
// stripped. The encoding is this package's own canonical form, not
// protobuf-go's Deterministic option, which is documented as unstable across
// library versions; peers built against different protobuf releases must agree
// on this hash or every session would fence.
func canonicalHash(req *authoritypb.Request) (volumeserver.RequestHash, error) {
	if len(req.ProtoReflect().GetUnknown()) != 0 {
		return volumeserver.RequestHash{}, fmt.Errorf("%w: unknown fields are not part of this protocol", errNonCanonical)
	}
	clone := &authoritypb.Request{Body: req.GetBody()}
	encoded, err := canonicalBytes(clone.ProtoReflect())
	if err != nil {
		return volumeserver.RequestHash{}, err
	}
	return sha256.Sum256(encoded), nil
}

var errNonCanonical = errors.New("authorityrpc: request cannot be canonicalized")

// canonicalBytes encodes a message as protobuf with fields emitted in strictly
// ascending field number, no unknown fields, and no packed-repeated ambiguity.
// The result depends only on the schema and the message value.
func canonicalBytes(message protoreflect.Message) ([]byte, error) {
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
	// Descriptor order follows declaration order, which is not field-number
	// order. Insertion sort keeps the emitted stream strictly ascending.
	for i := 1; i < len(present); i++ {
		for j := i; j > 0 && present[j].Number() < present[j-1].Number(); j-- {
			present[j], present[j-1] = present[j-1], present[j]
		}
	}
	var out []byte
	for _, field := range present {
		value := message.Get(field)
		switch {
		case field.IsMap():
			return nil, fmt.Errorf("%w: map fields have no canonical order", errNonCanonical)
		case field.IsList():
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				encoded, err := canonicalField(field, list.Get(i))
				if err != nil {
					return nil, err
				}
				out = append(out, encoded...)
			}
		default:
			encoded, err := canonicalField(field, value)
			if err != nil {
				return nil, err
			}
			out = append(out, encoded...)
		}
	}
	return out, nil
}

func canonicalField(field protoreflect.FieldDescriptor, value protoreflect.Value) ([]byte, error) {
	number := field.Number()
	switch field.Kind() {
	case protoreflect.BoolKind:
		return protowire.AppendVarint(protowire.AppendTag(nil, number, protowire.VarintType), protowire.EncodeBool(value.Bool())), nil
	case protoreflect.EnumKind:
		return protowire.AppendVarint(protowire.AppendTag(nil, number, protowire.VarintType), uint64(value.Enum())), nil
	case protoreflect.Int32Kind, protoreflect.Int64Kind:
		return protowire.AppendVarint(protowire.AppendTag(nil, number, protowire.VarintType), uint64(value.Int())), nil
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind:
		return protowire.AppendVarint(protowire.AppendTag(nil, number, protowire.VarintType), value.Uint()), nil
	case protoreflect.Sint32Kind, protoreflect.Sint64Kind:
		return protowire.AppendVarint(protowire.AppendTag(nil, number, protowire.VarintType), protowire.EncodeZigZag(value.Int())), nil
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind,
		protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return nil, fmt.Errorf("%w: fixed-width fields are not used by this protocol", errNonCanonical)
	case protoreflect.StringKind:
		return protowire.AppendString(protowire.AppendTag(nil, number, protowire.BytesType), value.String()), nil
	case protoreflect.BytesKind:
		return protowire.AppendBytes(protowire.AppendTag(nil, number, protowire.BytesType), value.Bytes()), nil
	case protoreflect.MessageKind:
		nested, err := canonicalBytes(value.Message())
		if err != nil {
			return nil, err
		}
		return protowire.AppendBytes(protowire.AppendTag(nil, number, protowire.BytesType), nested), nil
	default:
		return nil, fmt.Errorf("%w: unsupported field kind %v", errNonCanonical, field.Kind())
	}
}
