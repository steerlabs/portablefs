package authorityrpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ProtocolMajor 6 is the stock-kernel lease architecture. It is intentionally
// incompatible with the previous private-kernel publication profile; there is no
// negotiated downgrade or second execution path.
const ProtocolMajor uint32 = 6

// ProtocolALPN is exported so the production authority listener and the RPC
// server package cannot drift onto different exact protocols.
const ProtocolALPN = "portablefs-authority-v6"

const protocolALPN = ProtocolALPN

// FramePayloadReserve leaves deterministic room for the response envelope,
// handles, attributes, and protobuf length tags around a negotiated data chunk.
// It straddles the process boundary: the client checks the authority's
// advertised read/write bounds against it, the authority validates its own
// configuration against it, and both read the same constant.
const FramePayloadReserve uint32 = 1024

// responseEnvelopeReserve is the protocol-6 retained-response allowance. It
// covers the maximum four-object post-state envelope, including field 45's
// two-byte tag, as well as the request, epoch, errno, mutation state, and
// terminal-delivery token restored around a retained outcome.
const responseEnvelopeReserve uint32 = 2048

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

// RequiredFskitWriteBytes is the largest one-callback write FSKit can deliver.
// The authority may transport it in bounded DATA fragments but must stage the
// complete callback before its single COMMIT mutation.
const RequiredFskitWriteBytes uint64 = 0x7ffff000

const peerCompleteFIFOFeedbackFeature = "peer-complete-fifo-feedback"
const sessionReauthorizationFeature = "session-reauthorization-v1"
const mountEnrollmentReauthorizationFeature = "mount-enrollment-reauthorization-v1"
const leaseCoherenceFeature = "lease-coherence-v1"
const leaseRecallFeature = "lease-recall-v1"
const leaseRenewalFeature = "lease-renewal-v1"
const directoryEnumerationLeaseFeature = "directory-enumeration-lease-v1"
const openByIdentityFeature = "open-by-identity-v1"
const fskitSyncRepairFeature = "fskit-sync-repair-v1"
const fskitSourcePublicationFeature = "fskit-source-publication-v1"
const fskitFragmentedWriteFeature = "fskit-fragmented-write-v1"

var (
	requiredCommonHelloFeatures = []string{
		"xfs-current-state", "session-exact-epoch", "framed-bulk-data-v1",
		"authority-keyed-replay-fingerprint-v1", "mandatory-dual-transport-v1", "exact-resource-acquisition",
	}
	requiredLinuxHelloFeatures = []string{
		"direct-write",
		leaseCoherenceFeature, directoryEnumerationLeaseFeature,
	}
	requiredFskitHelloFeatures = []string{
		fskitSyncRepairFeature, fskitSourcePublicationFeature, fskitFragmentedWriteFeature,
	}
	requiredCommonAttachFeatures = []string{
		"write-through", "no-history", "no-branches", "user-xattr-readonly",
		"single-principal", "stable-item-identity", "volume-syncfs-barrier",
		"exact-resource-acquisition",
	}
	requiredLinuxAttachFeatures = []string{
		"direct-io-no-file-mmap", "distributed-posix-locks",
		leaseRenewalFeature, leaseRecallFeature, openByIdentityFeature,
	}
	requiredFskitAttachFeatures = []string{
		fskitSyncRepairFeature, fskitSourcePublicationFeature, fskitFragmentedWriteFeature,
		peerCompleteFIFOFeedbackFeature,
	}
	// These aliases are the exact Linux profile and remain package-local so the
	// stock-FUSE client and its tests share one frozen feature set.
	requiredHelloFeatures        = append(append([]string(nil), requiredCommonHelloFeatures...), requiredLinuxHelloFeatures...)
	requiredAttachFeatures       = append([]string(nil), requiredCommonAttachFeatures...)
	requiredStrictAttachFeatures = append([]string(nil), requiredLinuxAttachFeatures...)
)

func helloFeatures(profile authoritypb.FrontendProfile) ([]string, bool) {
	features := append([]string(nil), requiredCommonHelloFeatures...)
	switch profile {
	case authoritypb.FrontendProfile_FRONTEND_PROFILE_UNSPECIFIED:
		return features, true
	case authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES:
		return append(features, requiredLinuxHelloFeatures...), true
	case authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR:
		return append(features, requiredFskitHelloFeatures...), true
	default:
		return nil, false
	}
}

func activateFeatures(profile authoritypb.FrontendProfile) ([]string, bool) {
	features := append([]string(nil), requiredCommonAttachFeatures...)
	switch profile {
	case authoritypb.FrontendProfile_FRONTEND_PROFILE_UNSPECIFIED:
		return features, true
	case authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES:
		return append(features, requiredLinuxAttachFeatures...), true
	case authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR:
		return append(features, requiredFskitAttachFeatures...), true
	default:
		return nil, false
	}
}

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
	if blockingWait(req) || req.GetNextLeaseEvent() != nil || req.GetNextFskitRepair() != nil || req.GetApplyRoutes() != nil {
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
	case *authoritypb.Request_Write:
		return true
	case *authoritypb.Request_FskitWrite:
		switch body.FskitWrite.GetPhase() {
		case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN,
			authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA,
			authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_COMMIT:
			return true
		default:
			// ABORT remains available after an authorization downgrade so the
			// frontend can retire bytes staged while it still had write access.
			return false
		}
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
	case authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES:
		if req.GetFskitSourcePublication() != nil || req.GetFskitFrontendOperationId() != 0 {
			return false
		}
		switch req.GetBody().(type) {
		case *authoritypb.Request_Flush, *authoritypb.Request_Fallocate,
			*authoritypb.Request_CopyFileRange, *authoritypb.Request_Tmpfile,
			*authoritypb.Request_GetLock, *authoritypb.Request_SetLock,
			*authoritypb.Request_Write, *authoritypb.Request_NextLeaseEvent,
			*authoritypb.Request_AcknowledgeLeaseEvent, *authoritypb.Request_RenewLeases,
			*authoritypb.Request_AcknowledgeSourceLeaseDischarge:
			return true
		default:
			return common()
		}
	case authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR:
		if (req.GetFskitSourcePublication() != nil || req.GetFskitFrontendOperationId() != 0) && !requestIsVisibleMutation(req) {
			return false
		}
		switch req.GetBody().(type) {
		case *authoritypb.Request_NextFskitRepair, *authoritypb.Request_AckFskitRepair,
			*authoritypb.Request_FskitWrite:
			return true
		default:
			return common()
		}
	default:
		return false
	}
}

// requestIsVisibleMutation classifies callbacks that can publish new state to
// another mount. FSKit requires an exact source-publication declaration for
// this set; Linux derives its lease obligations entirely at the authority.
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
	case *authoritypb.Request_FskitWrite:
		return body.FskitWrite.GetPhase() == authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_COMMIT
	default:
		return false
	}
}

func validFskitSourcePublicationPresence(req *authoritypb.Request) bool {
	return (req.GetFskitSourcePublication() != nil) == requestIsVisibleMutation(req)
}

// decodeFskitSourcePublication refuses noncanonical target order and shape
// before replay fingerprinting or mutation admission. The authority derives
// the same gate independently from the operation before apply.
func decodeFskitSourcePublication(req *authoritypb.Request) (*volumeserver.SourcePublicationGate, error) {
	wire := req.GetFskitSourcePublication()
	if wire == nil {
		return nil, nil
	}
	if len(wire.ProtoReflect().GetUnknown()) != 0 || len(wire.GetTargets()) == 0 || len(wire.GetTargets()) > 16 {
		return nil, fmt.Errorf("%w: malformed FSKit source publication", errNonCanonical)
	}
	gate := &volumeserver.SourcePublicationGate{Targets: make([]volumeserver.SourcePublicationTarget, 0, len(wire.GetTargets()))}
	for _, encoded := range wire.GetTargets() {
		if encoded == nil || len(encoded.ProtoReflect().GetUnknown()) != 0 {
			return nil, fmt.Errorf("%w: malformed FSKit source publication target", errNonCanonical)
		}
		var target volumeserver.SourcePublicationTarget
		switch coordinate := encoded.GetCoordinate().(type) {
		case *authoritypb.FskitSourcePublicationTarget_Item:
			item := coordinate.Item
			if item == nil || len(item.ProtoReflect().GetUnknown()) != 0 || len(item.GetIdentity()) != len(target.Identity) ||
				!item.GetAttributes() || item.GetData() && !item.GetAttributes() {
				return nil, fmt.Errorf("%w: malformed FSKit source item target", errNonCanonical)
			}
			copy(target.Identity[:], item.GetIdentity())
			if target.Identity == ([16]byte{}) {
				return nil, fmt.Errorf("%w: FSKit source item identity is zero", errNonCanonical)
			}
			target.Attributes, target.Data = item.GetAttributes(), item.GetData()
		case *authoritypb.FskitSourcePublicationTarget_Namespace:
			namespace := coordinate.Namespace
			if namespace == nil || len(namespace.ProtoReflect().GetUnknown()) != 0 ||
				len(namespace.GetParentIdentity()) != len(target.ParentIdentity) ||
				!validProtocolNamespaceName(namespace.GetName()) || namespace.GetBoundData() && !namespace.GetBoundAttributes() {
				return nil, fmt.Errorf("%w: malformed FSKit source namespace target", errNonCanonical)
			}
			copy(target.ParentIdentity[:], namespace.GetParentIdentity())
			if target.ParentIdentity == ([16]byte{}) {
				return nil, fmt.Errorf("%w: FSKit source namespace parent identity is zero", errNonCanonical)
			}
			target.Name = append([]byte(nil), namespace.GetName()...)
			target.BoundAttributes, target.BoundData = namespace.GetBoundAttributes(), namespace.GetBoundData()
		default:
			return nil, fmt.Errorf("%w: FSKit source target has no coordinate", errNonCanonical)
		}
		if len(gate.Targets) != 0 && compareSourcePublicationTarget(gate.Targets[len(gate.Targets)-1], target) >= 0 {
			return nil, fmt.Errorf("%w: FSKit source targets are duplicate or out of order", errNonCanonical)
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
		*authoritypb.Request_NextLeaseEvent, *authoritypb.Request_AcknowledgeLeaseEvent,
		*authoritypb.Request_RenewLeases,
		*authoritypb.Request_AcknowledgeSourceLeaseDischarge,
		*authoritypb.Request_NextFskitRepair, *authoritypb.Request_AckFskitRepair,
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
	if ctx == nil || req == nil || req.GetWrite() == nil && req.GetFskitWrite() == nil {
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
	if _, err := decodeFskitSourcePublication(req); err != nil {
		return volumeserver.RequestFingerprint{}, err
	}
	// The body is already immutable for the duration of dispatch. Stream the
	// canonical form directly into the keyed fingerprint instead of recursively
	// materializing one payload-sized byte slice at every protobuf nesting level.
	// The tiny envelope below deliberately shares the body and FSKit publication
	// declaration; canonicalWrite only reads them. Request/session/mutation
	// transport fields remain stripped, while the frontend operation identity
	// and source cache coordinates are part of the syscall's exact replay identity.
	body := &authoritypb.Request{
		Body: req.GetBody(), FskitSourcePublication: req.GetFskitSourcePublication(),
		FskitFrontendOperationId: req.GetFskitFrontendOperationId(),
	}
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

func canonicalMessageSize(message protoreflect.Message, options canonicalWriteOptions) (int, error) {
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
	case "portablefs.authority.v1.WriteRequest.data", "portablefs.authority.v1.FskitWriteRequest.data":
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
