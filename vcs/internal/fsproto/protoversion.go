package fsproto

import "fmt"

// Protocol version negotiation.
//
// The PortableFS v2 baseline is ONE protocol version: v8. Requests use the
// allocation-safe, size-framed PFRQ2 codec; responses remain gob. Exact mount
// sessions, journaled coordination, parent-version stamping, fused open
// registration, xattrs, hard links, and atomic append are all MANDATORY parts
// of the baseline. Optional optimizations that preserve those baseline
// semantics are selected by the probe's Features bitmap.
//
// Both sides fail closed against an older peer:
//
//   - A v8 client probes first (OpProtocolVersion carries its own version in
//     Request.Size) and refuses any authority that does not answer OK with
//     ProtoVersion == 8. A peer that understands PFRQ2 returns both versions
//     in the typed mismatch; a PFRQ1 peer rejects the newer frame and the
//     client reports that framing error. There is no legacy probe lane.
//   - A v8 server answers a probe carrying any other client version with
//     EINVAL (its own version still in the response, so a newer client can
//     report the mismatch), and refuses every envelope-less mutation, so an
//     old client that ignores the probe outcome fails closed on its first
//     write.
//
// PFRQ2 cannot be rolling-upgraded against an older request-wire peer: the
// first request fails closed at framing. Upgrade authorities and clients
// together.
//
// Version history (all retired; no arm below v8 is accepted):
//
//	1: pre-negotiation builds. 2: the probe. 3: exact mount sessions.
//	4: journaled coordination. 5: the v2 baseline — v4 with every
//	   formerly-optional capability mandatory and the legacy arms removed.
//	6: allocation-safe PFRQ1 requests; responses remain gob.
//	7: globally ordered write-back batches carry explicit scope/epoch runs.
//	8: delegation release prepares bounded open-path pins before checkin.
//
// Future protocol changes that are not wire-compatible must bump
// ProtocolVersion and gate the new behavior on the negotiated value; additive
// response gob fields do not require a bump (gob decoders ignore unknown fields).
const ProtocolVersion uint32 = 8

// Optional protocol features. A client selects these lanes only from the
// version probe; an older authority's zero bitmap is a definite pre-mutation
// decision, never a failed-operation downgrade.
const (
	FeatureDelegatedXattrs uint64 = 1 << iota
	// FeatureFlagPersistence advertises that this authority DURABLY stores
	// per-inode BSD file flags (Darwin st_flags, set through OpSetattr's
	// SetFlags group) and a per-inode birth time, both as fields of the PFT2
	// inode record. Without the bit a client must keep refusing chflags(2)
	// honestly and keep deriving a birth time by convention; with it, chflags
	// persists and getattr/readdir serve the stored values.
	//
	// A capability BIT rather than an attr sniff: zero is a legitimate value
	// for both fields (no flags set; an inode from a pre-revision tree), so no
	// observed attribute can distinguish "unsupported" from "genuinely zero".
	FeatureFlagPersistence
	// FeatureMutationAttrs advertises that this authority carries the post-op
	// attributes of every name a mutation's version stamp covers on the
	// mutation reply itself (Response.PostAttrs), anchored to the reply's
	// Version/Gen. A client that sees the bit INSTALLS those attributes in its
	// version-gated caches instead of self-invalidating and re-reading them;
	// without the bit it keeps evicting, exactly as before.
	//
	// A capability BIT rather than an empty-slice sniff, for the same reason as
	// the bit above: an empty PostAttrs is a legitimate answer (a mutation
	// whose stamp covers no nameable path — a handle- or orphan-addressed
	// write), so the observed reply cannot distinguish "this authority does not
	// speak it" from "there was nothing to report". Selecting the lane from the
	// probe makes the difference a pre-mutation decision, never a
	// failed-operation downgrade.
	FeatureMutationAttrs
)

// OpProtocolVersion is the version probe. Its value is deliberately far above the
// sequential op block so ops added there (including on parallel branches) can never
// collide with it. The request carries the client's own version in Request.Size.
const OpProtocolVersion Op = 200

// ErrProtocolVersionMismatch wraps every version-mismatch refusal so callers
// can classify it (it is definitive: redialing cannot change the answer).
type ErrProtocolVersionMismatch struct {
	ServerVersion uint32
}

func (e *ErrProtocolVersionMismatch) Error() string {
	if e.ServerVersion == 0 {
		return fmt.Sprintf("fsproto: authority predates protocol negotiation; this client requires exactly protocol version %d (PortableFS v2 baseline) — upgrade the authority", ProtocolVersion)
	}
	return fmt.Sprintf("fsproto: authority speaks protocol version %d; this client requires exactly %d (PortableFS v2 baseline) — upgrade the %s",
		e.ServerVersion, ProtocolVersion, mismatchSide(e.ServerVersion))
}

func mismatchSide(server uint32) string {
	if server < ProtocolVersion {
		return "authority"
	}
	return "client"
}

// NegotiateProtocolVersion probes the authority and returns its protocol
// version, failing with ErrProtocolVersionMismatch unless it is exactly
// ProtocolVersion. Transport failures are returned as-is.
func (c *Client) NegotiateProtocolVersion() (uint32, error) {
	resp, err := c.Do(&Request{Op: OpProtocolVersion, Size: int64(ProtocolVersion)})
	if err != nil {
		return 0, err
	}
	if resp.Status != OK || resp.ProtoVersion != ProtocolVersion {
		return resp.ProtoVersion, &ErrProtocolVersionMismatch{ServerVersion: resp.ProtoVersion}
	}
	return resp.ProtoVersion, nil
}
