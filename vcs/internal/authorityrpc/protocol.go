package authorityrpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ProtocolMajor is the exact authority grammar and semantic baseline.
// There is no negotiated downgrade or mixed-major execution.
const ProtocolMajor uint32 = 8

// ProtocolALPN is exported so the production authority listener and the RPC
// server package cannot drift onto different exact protocols.
const ProtocolALPN = "portablefs-authority-v8"

const protocolALPN = ProtocolALPN

// FramePayloadReserve leaves deterministic room for the response envelope,
// handles, attributes, and protobuf length tags around a negotiated data chunk.
// It straddles the process boundary: the client checks the authority's
// advertised read/write bounds against it, the authority validates its own
// configuration against it, and both read the same constant.
const FramePayloadReserve uint32 = 1024

// responseEnvelopeReserve is the protocol-8 retained-response allowance. It
// covers the maximum four-object post-state envelope, including field 45's
// two-byte tag, as well as the request, epoch, errno, mutation state, and
// terminal-delivery token restored around a retained outcome.
const responseEnvelopeReserve uint32 = 2048

// fixedMutationReplyBytes bounds fixed-shape mutation replies and the bounded
// 128-result CloseBatch reply. It is also the floor for a
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

// MaxCloseBatch bounds both the request and its retained per-handle outcome.
const MaxCloseBatch = 128

// MaxCacheProof is the frozen ceiling of one FSKit KeepAlive proof. A
// restarted authority waits this bound plus its epsilon
// before clearing a prior writer fence, so no proof may promise more.
const MaxCacheProof = volumeserver.MaxCacheProof

const (
	// MaxReadDirHeldIdentities is the largest page-local capability reuse hint.
	MaxReadDirHeldIdentities = 4096
	// MaxReclaimBatch bounds one exact cleanup mutation.
	MaxReclaimBatch = 4096
)

// blockingWait reports whether a request may park server-side for an unbounded
// time waiting on another session's POSIX lock. Such requests get their own
// admission lane on both peers so they can never consume the last ordinary
// execution slot, which is what a keepalive needs to stay live.
func blockingWait(req *authoritypb.Request) bool {
	if req.GetWaitVisibility() != nil {
		return true
	}
	lock := req.GetSetLock()
	return lock != nil && lock.GetWait() && !lock.GetUnlock()
}

// terminalQuiesceCancelable identifies requests which can park indefinitely
// without having applied filesystem state. A terminal storage failure cancels
// these so the response drain cannot wait forever, while an already-applied
// source mutation remains alive to finish withdrawal and durability and register its
// exact terminal delivery receipt.
func terminalQuiesceCancelable(req *authoritypb.Request) bool {
	if req == nil {
		return false
	}
	if blockingWait(req) || req.GetNextControlEvent() != nil || req.GetApplyRoutes() != nil {
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
		return body.Open.GetWriteIntent() || flags != nil && (flags.GetWrite() || flags.GetAppend() || flags.GetTruncate())
	case *authoritypb.Request_SetLock:
		return !body.SetLock.GetUnlock() && body.SetLock.GetLock() != nil && body.SetLock.GetLock().GetWrite()
	case *authoritypb.Request_Write:
		return true
	default:
		return false
	}
}

func requestAllowedForFrontend(req *authoritypb.Request, profile authoritypb.FrontendProfile) bool {
	if req == nil {
		return false
	}
	common := func() bool {
		switch req.GetBody().(type) {
		case *authoritypb.Request_Hello, *authoritypb.Request_Attach,
			*authoritypb.Request_Resume, *authoritypb.Request_Activate,
			*authoritypb.Request_AbortAttach, *authoritypb.Request_TerminalDeliveryReceipt,
			*authoritypb.Request_KeepAlive, *authoritypb.Request_Detach,
			*authoritypb.Request_Cancel, *authoritypb.Request_Reauthorize,
			*authoritypb.Request_ApplyRoutes,
			*authoritypb.Request_Lookup, *authoritypb.Request_GetAttr,
			*authoritypb.Request_SetAttr, *authoritypb.Request_Create,
			*authoritypb.Request_Mkdir, *authoritypb.Request_Unlink,
			*authoritypb.Request_Rename, *authoritypb.Request_Link,
			*authoritypb.Request_Symlink, *authoritypb.Request_Readlink,
			*authoritypb.Request_Open, *authoritypb.Request_Close,
			*authoritypb.Request_Read, *authoritypb.Request_Fsync,
			*authoritypb.Request_ReadDir, *authoritypb.Request_Reclaim,
			*authoritypb.Request_GetXattr, *authoritypb.Request_SetXattr,
			*authoritypb.Request_ListXattr, *authoritypb.Request_RemoveXattr,
			*authoritypb.Request_StatFs, *authoritypb.Request_SyncFs:
			return true
		default:
			return false
		}
	}
	switch profile {
	case authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER:
		switch req.GetBody().(type) {
		case *authoritypb.Request_Hello, *authoritypb.Request_Attach,
			*authoritypb.Request_Resume, *authoritypb.Request_Activate,
			*authoritypb.Request_AbortAttach, *authoritypb.Request_TerminalDeliveryReceipt,
			*authoritypb.Request_KeepAlive, *authoritypb.Request_Detach,
			*authoritypb.Request_Cancel, *authoritypb.Request_Reauthorize,
			*authoritypb.Request_Lookup, *authoritypb.Request_GetAttr,
			*authoritypb.Request_Close, *authoritypb.Request_Read,
			*authoritypb.Request_ReadDir, *authoritypb.Request_Reclaim:
			return true
		case *authoritypb.Request_Open:
			return !requestRequiresWrite(req) && !req.GetOpen().GetWriteIntent() && !req.GetOpen().GetCacheCapable()
		default:
			return false
		}
	case authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX:
		switch req.GetBody().(type) {
		case *authoritypb.Request_CloseBatch, *authoritypb.Request_Flush, *authoritypb.Request_Fallocate,
			*authoritypb.Request_CopyFileRange, *authoritypb.Request_Tmpfile,
			*authoritypb.Request_GetLock, *authoritypb.Request_SetLock,
			*authoritypb.Request_Write,
			*authoritypb.Request_Subscribe, *authoritypb.Request_RenewSubscription,
			*authoritypb.Request_NextControlEvent, *authoritypb.Request_ChangeAck,
			*authoritypb.Request_DelegationRecallAck, *authoritypb.Request_DelegationBreakAck,
			*authoritypb.Request_DelegationModeChangeAck, *authoritypb.Request_DelegationRelease,
			*authoritypb.Request_Barrier, *authoritypb.Request_WaitVisibility:
			return true
		default:
			return common()
		}
	case authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE:
		switch req.GetBody().(type) {
		case *authoritypb.Request_Close:
			return false
		case *authoritypb.Request_CloseBatch, *authoritypb.Request_Write:
			return true
		default:
			return common()
		}
	default:
		return false
	}
}

// requestIsVisibleMutation classifies callbacks that can publish new state to
// another mount. The authority derives the dependency footprint independently.
func requestIsVisibleMutation(req *authoritypb.Request) bool {
	switch body := req.GetBody().(type) {
	case *authoritypb.Request_SetAttr,
		*authoritypb.Request_Write,
		*authoritypb.Request_Fallocate,
		*authoritypb.Request_CopyFileRange,
		*authoritypb.Request_Create,
		*authoritypb.Request_Mkdir,
		*authoritypb.Request_Unlink,
		*authoritypb.Request_Rename,
		*authoritypb.Request_Symlink,
		*authoritypb.Request_Link,
		*authoritypb.Request_Tmpfile,
		*authoritypb.Request_SetXattr,
		*authoritypb.Request_RemoveXattr:
		return true
	case *authoritypb.Request_Open:
		return body.Open.GetFlags() != nil && body.Open.GetFlags().GetTruncate()
	default:
		return false
	}
}

// Only operations which enter the replay runtime may defer coherence admission.
// A mutation header on a read cannot confer a retained outcome on that read.
func requestHasMutationReplay(req *authoritypb.Request) bool {
	if req.GetMutation() == nil {
		return false
	}
	if requestIsVisibleMutation(req) {
		return true
	}
	switch req.GetBody().(type) {
	case *authoritypb.Request_Lookup, *authoritypb.Request_ReadDir,
		*authoritypb.Request_Open, *authoritypb.Request_Close, *authoritypb.Request_CloseBatch,
		*authoritypb.Request_Reclaim, *authoritypb.Request_SyncFs,
		*authoritypb.Request_SetLock, *authoritypb.Request_Barrier:
		return true
	default:
		return false
	}
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
// through their final result. Session and coherence control bypass the guard
// so acknowledgments and terminal cleanup can progress independently of a
// topology transition. ApplyRoutes does not wait for visibility acknowledgments.
func requestUsesTopology(req *authoritypb.Request) bool {
	switch body := req.GetBody().(type) {
	case *authoritypb.Request_Resume, *authoritypb.Request_Activate, *authoritypb.Request_AbortAttach,
		*authoritypb.Request_KeepAlive,
		*authoritypb.Request_Reauthorize,
		*authoritypb.Request_Detach, *authoritypb.Request_Cancel,
		*authoritypb.Request_TerminalDeliveryReceipt,
		*authoritypb.Request_Subscribe, *authoritypb.Request_RenewSubscription,
		*authoritypb.Request_NextControlEvent, *authoritypb.Request_ChangeAck,
		*authoritypb.Request_DelegationRecallAck, *authoritypb.Request_DelegationBreakAck,
		*authoritypb.Request_DelegationModeChangeAck, *authoritypb.Request_DelegationRelease,
		*authoritypb.Request_WaitVisibility,
		*authoritypb.Request_ApplyRoutes:
		return false
	case *authoritypb.Request_SetLock:
		// A blocking lock wait never reaches XFS: the lock table is
		// authority-epoch runtime state, so the topology invariant — no
		// filesystem operation reaches XFS under a stale routing revision —
		// does not apply to the wait. Holding the read guard across an
		// unbounded F_SETLKW would prevent clean-absence route transitions from
		// acquiring exclusion to interrupt old lock waiters. Registration uses
		// its own short admission gate instead.
		// Non-blocking lock calls keep the guard: they are cheap and complete
		// immediately, so uniformity there costs nothing.
		return body.SetLock.GetUnlock() || !body.SetLock.GetWait()
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
	if body := req.GetWrite(); body != nil {
		digest := sha256.Sum256(body.GetData())
		return canonicalFingerprintWithWriteDataDigest(runtime, req, digest)
	}
	return canonicalFingerprintWithOptions(runtime, req, canonicalWriteOptions{})
}

type framePayloadDigestKey struct{}

func withFramePayloadDigest(ctx context.Context, digest *[sha256.Size]byte) context.Context {
	if digest == nil {
		return ctx
	}
	return context.WithValue(ctx, framePayloadDigestKey{}, *digest)
}

func framePayloadDigest(ctx context.Context, req *authoritypb.Request) ([sha256.Size]byte, bool) {
	if ctx == nil || req == nil || req.GetWrite() == nil {
		return [sha256.Size]byte{}, false
	}
	digest, ok := ctx.Value(framePayloadDigestKey{}).([sha256.Size]byte)
	return digest, ok
}

// canonicalFingerprintFromFrame uses the digest produced while the transport
// copied an out-of-line write body into its retained frame. Direct handler
// callers have no transport digest and hash the payload directly.
func canonicalFingerprintFromFrame(ctx context.Context, runtime *volumeserver.Authority, req *authoritypb.Request) (volumeserver.RequestFingerprint, error) {
	if digest, ok := framePayloadDigest(ctx, req); ok {
		return canonicalFingerprintWithWriteDataDigest(runtime, req, digest)
	}
	return canonicalFingerprint(runtime, req)
}

type canonicalWriteOptions struct {
	writeDataDigest *[sha256.Size]byte
}

func canonicalFingerprintWithWriteDataDigest(runtime *volumeserver.Authority, req *authoritypb.Request, digest [sha256.Size]byte) (volumeserver.RequestFingerprint, error) {
	return canonicalFingerprintWithOptions(runtime, req, canonicalWriteOptions{writeDataDigest: &digest})
}

func canonicalFingerprintWithOptions(runtime *volumeserver.Authority, req *authoritypb.Request, options canonicalWriteOptions) (volumeserver.RequestFingerprint, error) {
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
	// Only the operation body enters the keyed replay identity. Transport and
	// session envelopes are validated separately and stripped.
	body := &authoritypb.Request{Body: req.GetBody()}
	return runtime.ReplayFingerprint(func(writer io.Writer) error {
		return canonicalWriteWithOptions(writer, body.ProtoReflect(), options)
	})
}

var errNonCanonical = errors.New("authorityrpc: request cannot be canonicalized")

// canonicalWrite emits the exact byte stream canonicalBytes defines without
// constructing that stream in memory. Large WriteRequest.Data fields dominate
// the data plane; recursively appending a 1 MiB field once per enclosing
// message used to allocate and copy more than 4 MiB on both the client and the
// authority before XFS saw one byte. Streaming preserves the frozen digest
// while keeping payload memory O(1).
func canonicalWrite(writer io.Writer, message protoreflect.Message) error {
	return canonicalWriteWithOptions(writer, message, canonicalWriteOptions{})
}

func canonicalWriteWithOptions(writer io.Writer, message protoreflect.Message, options canonicalWriteOptions) error {
	fields, err := canonicalOrderedFields(message)
	if err != nil {
		return err
	}
	for _, field := range fields {
		if !message.Has(field) {
			continue
		}
		value := message.Get(field)
		if field.IsMap() {
			return fmt.Errorf("%w: map fields have no canonical order", errNonCanonical)
		}
		if field.IsList() {
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				if err := canonicalWriteField(writer, field, list.Get(i), options); err != nil {
					return err
				}
			}
			continue
		}
		if err := canonicalWriteField(writer, field, value, options); err != nil {
			return err
		}
	}
	return nil
}

// Descriptors are immutable and come from the fixed protocol schema, not peer
// input. Cache their numeric order once; presence remains message-specific.
var canonicalFieldOrder sync.Map // protoreflect.MessageDescriptor -> []protoreflect.FieldDescriptor

func canonicalOrderedFields(message protoreflect.Message) ([]protoreflect.FieldDescriptor, error) {
	if len(message.GetUnknown()) != 0 {
		return nil, fmt.Errorf("%w: unknown fields are not part of this protocol", errNonCanonical)
	}
	descriptor := message.Descriptor()
	if cached, ok := canonicalFieldOrder.Load(descriptor); ok {
		return cached.([]protoreflect.FieldDescriptor), nil
	}
	fields := descriptor.Fields()
	ordered := make([]protoreflect.FieldDescriptor, fields.Len())
	for i := range ordered {
		ordered[i] = fields.Get(i)
	}
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && ordered[j].Number() < ordered[j-1].Number(); j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	cached, _ := canonicalFieldOrder.LoadOrStore(descriptor, ordered)
	return cached.([]protoreflect.FieldDescriptor), nil
}

func canonicalMessageSize(message protoreflect.Message, options canonicalWriteOptions) (int, error) {
	fields, err := canonicalOrderedFields(message)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, field := range fields {
		if !message.Has(field) {
			continue
		}
		value := message.Get(field)
		if field.IsMap() {
			return 0, fmt.Errorf("%w: map fields have no canonical order", errNonCanonical)
		}
		if field.IsList() {
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				size, err := canonicalFieldSize(field, list.Get(i), options)
				if err != nil {
					return 0, err
				}
				total += size
			}
			continue
		}
		size, err := canonicalFieldSize(field, value, options)
		if err != nil {
			return 0, err
		}
		total += size
	}
	return total, nil
}

func canonicalFieldSize(field protoreflect.FieldDescriptor, value protoreflect.Value, options canonicalWriteOptions) (int, error) {
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
		if options.writeDataDigest != nil && isCanonicalWriteDataField(field) {
			return tag + protowire.SizeBytes(len(options.writeDataDigest)), nil
		}
		return tag + protowire.SizeBytes(len(value.Bytes())), nil
	case protoreflect.MessageKind:
		nested, err := canonicalMessageSize(value.Message(), options)
		if err != nil {
			return 0, err
		}
		return tag + protowire.SizeBytes(nested), nil
	default:
		return 0, fmt.Errorf("%w: unsupported field kind %v", errNonCanonical, field.Kind())
	}
}

func canonicalWriteField(writer io.Writer, field protoreflect.FieldDescriptor, value protoreflect.Value, options canonicalWriteOptions) error {
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
		if options.writeDataDigest != nil && isCanonicalWriteDataField(field) {
			data = options.writeDataDigest[:]
		}
		prefix = protowire.AppendVarint(protowire.AppendTag(prefix, number, protowire.BytesType), uint64(len(data)))
		if err := writeAll(writer, prefix); err != nil {
			return err
		}
		return writeAll(writer, data)
	case protoreflect.MessageKind:
		nested, err := canonicalMessageSize(value.Message(), options)
		if err != nil {
			return err
		}
		prefix = protowire.AppendVarint(protowire.AppendTag(prefix, number, protowire.BytesType), uint64(nested))
		if err := writeAll(writer, prefix); err != nil {
			return err
		}
		return canonicalWriteWithOptions(writer, value.Message(), options)
	default:
		return fmt.Errorf("%w: unsupported field kind %v", errNonCanonical, field.Kind())
	}
	return writeAll(writer, prefix)
}

func isCanonicalWriteDataField(field protoreflect.FieldDescriptor) bool {
	switch field.FullName() {
	case "portablefs.authority.v1.WriteRequest.data":
		return true
	default:
		return false
	}
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

// Linux DATA keeps four ordered flushes independent of ordinary and blocking
// work. CONTROL retains ordinary acknowledgment and liveness capacity.
// Admission rejects smaller bounds before these lanes are constructed.
const MinimumLinuxInFlight = 9

func executionLanes(maxInFlight int, profile authoritypb.FrontendProfile, role authoritypb.TransportRole) (ordinary, blocking, flush int) {
	ordinary, blocking = blockingWaitLane(maxInFlight)
	if profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX && role == authoritypb.TransportRole_TRANSPORT_ROLE_DATA {
		flush = volumeserver.OrderedFlushWindow
		ordinary -= flush
	}
	return ordinary, blocking, flush
}

func validateProtocolMajor(major uint32) error {
	if major != ProtocolMajor {
		return fmt.Errorf("%w: unequal authority protocol major %d", ErrTransportBinding, major)
	}
	return nil
}
