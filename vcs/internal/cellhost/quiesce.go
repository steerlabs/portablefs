package cellhost

import (
	"encoding/hex"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
)

// The quiesce handshake files. The request lives in the volume's ConfigRoot,
// which the authority sees read-only at /run/portablefs-volume; the proof
// lives in the volume's StateRoot, which the authority owns and can write.
// Neither name is ever derived from anything but these constants.
const (
	quiesceRequestName = "quiesce-request.json"
	quiesceProofName   = "quiesce-proof.json"
	// quiesceNonceBytes is the request's freshness. It is not a secret: it is
	// an unpredictable value that a proof written before this request - by an
	// earlier archive attempt, or replayed from a stale file - cannot contain.
	quiesceNonceBytes = 32
	// wireSessionEpochBytes matches volumeserver.Epoch (session.go:31): the
	// random per-process protocol epoch. Recording it in the proof pins the
	// proof to the exact authority process that observed the empty membership,
	// so a proof cannot survive a restart it did not witness.
	wireSessionEpochBytes = 16
	// quiesceProofMaxBytes bounds the read. The record is a handful of fields;
	// anything larger has stopped being one.
	quiesceProofMaxBytes = 4 << 10
)

// quiesceRequest is what the helper writes for the authority to read.
type quiesceRequest struct {
	Nonce         string `json:"nonce"`
	RequestedUnix int64  `json:"requested_unix"`
}

// QuiesceProof is the authority's durable answer: at the named epoch, in the
// named wire session, with strict-attach admission closed, the strict-mount
// membership was empty. The helper cannot produce this itself - only the
// process holding the membership lock can say it, and only while it is still
// serving - which is precisely why the archive gate asks for it.
type QuiesceProof struct {
	VolumeID            string `json:"volume_id"`
	AuthorityEpoch      uint64 `json:"authority_epoch"`
	WireSessionEpochHex string `json:"wire_session_epoch_hex"`
	Nonce               string `json:"nonce"`
	MembershipEmpty     bool   `json:"membership_empty"`
	WrittenUnix         int64  `json:"written_unix"`
}

// Proves states the whole acceptance rule in one place so no caller has to
// reassemble it: the proof must be for this volume, at this epoch, must answer
// this request's nonce, and must actually claim emptiness. A proof that fails
// any part is not a weaker proof, it is not a proof.
//
// The nonce comparison is exact on the lowercase hex WriteQuiesceRequest
// emitted; the authority echoes the request's own string.
func (proof QuiesceProof) Proves(volumeID string, authorityEpoch uint64, nonce string) bool {
	if !cellplan.ValidID(volumeID) || volumeID != proof.VolumeID {
		return false
	}
	if authorityEpoch == 0 || authorityEpoch != proof.AuthorityEpoch {
		return false
	}
	if !validQuiesceNonce(nonce) || nonce != proof.Nonce {
		return false
	}
	return proof.MembershipEmpty
}

func validQuiesceNonce(nonce string) bool {
	raw, err := hex.DecodeString(nonce)
	return err == nil && len(raw) == quiesceNonceBytes && nonce == hex.EncodeToString(raw)
}

func validWireSessionEpoch(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == wireSessionEpochBytes && value == hex.EncodeToString(raw)
}
