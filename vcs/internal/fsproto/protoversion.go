package fsproto

import "fmt"

// Protocol version negotiation.
//
// The PortableFS v2 baseline is ONE protocol version: v6. Requests use the
// allocation-safe, size-framed PFRQ1 codec; responses remain gob. Exact mount
// sessions, journaled coordination, parent-version stamping, fused open
// registration, xattrs, hard links, and atomic append are all MANDATORY parts
// of the baseline — none of them is capability-negotiated. The probe's
// Features field remains on the wire for genuinely optional FUTURE semantics
// and is zero today.
//
// Both sides fail closed against an older peer:
//
//   - A v6 client probes first (OpProtocolVersion carries its own version in
//     Request.Size) and refuses any authority that does not answer OK with
//     ProtoVersion == 6 — with an error that names both versions.
//   - A v6 server answers a probe carrying any other client version with
//     EINVAL (its own version still in the response, so a newer client can
//     report the mismatch), and refuses every envelope-less mutation, so an
//     old client that ignores the probe outcome fails closed on its first
//     write.
//
// PFRQ1 cannot be rolling-upgraded against a v5 gob-request peer: the first
// request fails closed at framing. Upgrade authorities and clients together.
//
// Version history (all retired; no arm below v6 is accepted):
//
//	1: pre-negotiation builds. 2: the probe. 3: exact mount sessions.
//	4: journaled coordination. 5: the v2 baseline — v4 with every
//	   formerly-optional capability mandatory and the legacy arms removed.
//	6: allocation-safe PFRQ1 requests; responses remain gob.
//
// Future protocol changes that are not wire-compatible must bump
// ProtocolVersion and gate the new behavior on the negotiated value; additive
// response gob fields do not require a bump (gob decoders ignore unknown fields).
const ProtocolVersion uint32 = 6

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
