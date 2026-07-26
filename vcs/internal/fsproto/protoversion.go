package fsproto

// Protocol version negotiation.
//
// Historically a mount client and its VCS were always built from the same commit, so
// the wire protocol needed no version handshake. Once clients and servers ship on
// independent release trains (bundled desktop binaries vs hosted authorities), skew
// becomes normal and must be detectable up front rather than surfacing as a mysterious
// EINVAL mid-session.
//
// The negotiation is a single optional probe, fully compatible in both directions:
//
//   - A NEW client sends OpProtocolVersion once after connecting. A NEW server replies
//     with its ProtocolVersion in Response.ProtoVersion.
//   - An OLD server hits the dispatch default case and replies EINVAL without dropping
//     the connection; the client records the server as legacy (version 1) and proceeds.
//   - An OLD client never sends the probe; a NEW server's behavior is unchanged.
//
// Version history:
//
//	1: every protocol build before the probe existed (implicit).
//	2: the probe itself (OpProtocolVersion + Response.ProtoVersion).
//	3: exact mount sessions — the session ops (OpSessionOpen/Resume/Attach/
//	   Expire, OpReclaimDone), the exact-once mutation envelope (Request.Env),
//	   and the probe response's Features/LeaseMs fields. A server advertises
//	   version 3 whether or not its filesystem supports sessions; the client
//	   additionally requires FeatExactSessions in the probe's Features before
//	   establishing one, and falls back to v1/v2 behavior otherwise.
//	4: journaled coordination — advertised (with FeatJournaledCoordination)
//	   by an authority whose session store journals through a fenced remote
//	   journal generation. Session and exact-once semantics are version 3's;
//	   what changes is the recovery model (exact cold replay: no reclaim
//	   grace, no wall-time outcome pruning) and the removal of the public
//	   reap op from the mutation surface.
//
// Future protocol changes that are not wire-compatible must bump ProtocolVersion and
// gate the new behavior on the negotiated value; additive gob fields do not require a
// bump (gob decoders ignore unknown fields).
const ProtocolVersion uint32 = 3

// ProtoVersionExactSessions is the first protocol version with exact mount
// sessions. A client never sends session ops or envelopes to a server that
// negotiated below it.
const ProtoVersionExactSessions uint32 = 3

// ProtoVersionJournaledSessions is the protocol version a managed (journaled)
// authority advertises alongside FeatJournaledCoordination. It is additive
// over version 3: a version-3 client interoperates for reads and exact
// mutations; the journaled coordination surface itself arrives with the
// journal integration.
const ProtoVersionJournaledSessions uint32 = 4

// legacyProtocolVersion is attributed to servers that predate the probe.
const legacyProtocolVersion uint32 = 1

// OpProtocolVersion is the version probe. Its value is deliberately far above the
// sequential op block so ops added there (including on parallel branches) can never
// collide with it. The request carries the client's own version in Request.Size.
const OpProtocolVersion Op = 200

// NegotiateProtocolVersion probes the server's protocol version. It returns the
// server's version, mapping a legacy server (which rejects the unknown op with
// EINVAL) to version 1. Transport failures are returned as errors.
func (c *Client) NegotiateProtocolVersion() (uint32, error) {
	resp, err := c.Do(&Request{Op: OpProtocolVersion, Size: int64(ProtocolVersion)})
	if err != nil {
		return 0, err
	}
	c.recordProbe(resp) // the probe carries the capability bits; cache them
	return interpretVersionResponse(resp), nil
}

// interpretVersionResponse maps a probe response to a protocol version. Any
// non-OK status or a zero ProtoVersion means the server predates negotiation.
func interpretVersionResponse(resp *Response) uint32 {
	if resp.Status != OK || resp.ProtoVersion == 0 {
		return legacyProtocolVersion
	}
	return resp.ProtoVersion
}
