package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/pft2"
)

const (
	maxProvenanceBytes = 64 << 10
	maxHistoryObject   = pft2.MaxPackBytes
)

var (
	canonicalDecimal = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,18})$`)
	boundedHistoryID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,256}$`)
	canonicalDigest  = regexp.MustCompile(`^[0-9a-f]{64}$`)

	// ErrBaseProvenanceNotFound is definitive tenant-scoped absence. Callers
	// must not reinterpret it as a manifest_v1 proof.
	ErrBaseProvenanceNotFound = errors.New("backend: exact base provenance not found")
)

// BaseProvenanceRequest is the exact tuple returned by the already-claimed
// journal. The API/database must restate every field before startup can pick
// a base constructor.
type BaseProvenanceRequest struct {
	TenantID     string
	CommitID     string
	GenerationID string
	BaseSeq      uint64
	BaseDigest   string
	RecordCodec  string
	ControlCodec string
}

// Pft2Root is the user filesystem root of a proven PFT2 commit.
type Pft2Root struct {
	Digest     string `json:"digest"`
	Size       string `json:"size"`
	MaxInoSeen string `json:"maxInoSeen"`
}

// Pft2Anchor is the separate internal recovery anchor. It is absent only for
// an explicitly proven branch-from-cut fork.
type Pft2Anchor struct {
	AnchorID           string `json:"anchorId"`
	AsOfSeq            string `json:"asOfSeq"`
	RecoveryRootDigest string `json:"recoveryRootDigest"`
	RecoveryRootSize   string `json:"recoveryRootSize"`
	ControlRootDigest  string `json:"controlRootDigest"`
	ControlRootSize    string `json:"controlRootSize"`
	OrphanIndexDigest  string `json:"orphanIndexDigest,omitempty"`
	OrphanIndexSize    string `json:"orphanIndexSize,omitempty"`
	InodeNamespace     string `json:"inodeNamespace"`
	NextLocal          string `json:"nextLocal"`
	MaxInoSeen         string `json:"maxInoSeen"`
}

// Pft2Allocator is the NEW branch's DB-issued never-reused inode namespace
// row. It is present exactly for a fork proof: a fork reuses the source
// filesystem arm (whose ids live in the SOURCE branch's namespaces, far
// beyond the flat 2^32 cap) and must allocate fresh identities in its own
// namespace from the first create. Conversion/adopted bases carry these
// facts inside the recovery anchor instead.
type Pft2Allocator struct {
	InodeNamespace string `json:"inodeNamespace"`
	NextLocal      string `json:"nextLocal"`
	MaxInoSeen     string `json:"maxInoSeen"`
}

// BaseProvenance is a positive, exact family decision. Kind is either
// manifest_v1 or pft2; absence/timeouts are errors and never select legacy.
type BaseProvenance struct {
	V            string         `json:"v"`
	Kind         string         `json:"kind"`
	BaseMode     string         `json:"baseMode,omitempty"`
	TenantID     string         `json:"tenantId"`
	CommitID     string         `json:"commitId"`
	VolumeID     string         `json:"volumeId"`
	BranchID     string         `json:"branchId"`
	GenerationID string         `json:"generationId"`
	BaseSeq      string         `json:"baseSeq"`
	BaseDigest   string         `json:"baseDigest"`
	RecordCodec  string         `json:"recordCodec"`
	ControlCodec string         `json:"controlCodec"`
	Root         *Pft2Root      `json:"root,omitempty"`
	Anchor       *Pft2Anchor    `json:"anchor,omitempty"`
	Allocator    *Pft2Allocator `json:"allocator,omitempty"`
}

// RootRef decodes and bounds the PFT2 user root reference.
func (p *BaseProvenance) RootRef() (pft2.Ref, error) {
	if p == nil || p.Root == nil {
		return pft2.Ref{}, fmt.Errorf("backend: PFT2 provenance has no root")
	}
	return nodeRef(p.Root.Digest, p.Root.Size, "root")
}

// RecoveryRootRef decodes and bounds the internal recovery root reference.
func (p *BaseProvenance) RecoveryRootRef() (pft2.Ref, error) {
	if p == nil || p.Anchor == nil {
		return pft2.Ref{}, fmt.Errorf("backend: PFT2 provenance has no recovery anchor")
	}
	return nodeRef(p.Anchor.RecoveryRootDigest, p.Anchor.RecoveryRootSize, "recovery root")
}

// RootMaxInoSeen returns the bounded user-root allocation high-water.
func (p *BaseProvenance) RootMaxInoSeen() (uint64, error) {
	if p == nil || p.Root == nil {
		return 0, fmt.Errorf("backend: PFT2 provenance has no root")
	}
	return decimalBound("root maxInoSeen", p.Root.MaxInoSeen, 1, pft2.MaxIno)
}

// AnchorFacts returns the bounded allocator facts used by WorkFS.
func (p *BaseProvenance) AnchorFacts() (maxIno uint64, namespace uint32, nextLocal uint64, err error) {
	if p == nil || p.Anchor == nil {
		return 0, 0, 0, fmt.Errorf("backend: PFT2 provenance has no recovery anchor")
	}
	return allocatorFacts("anchor", p.Anchor.MaxInoSeen, p.Anchor.InodeNamespace, p.Anchor.NextLocal)
}

// AnchorAsOf returns the bounded anchor as-of sequence.
func (p *BaseProvenance) AnchorAsOf() (uint64, error) {
	if p == nil || p.Anchor == nil {
		return 0, fmt.Errorf("backend: PFT2 provenance has no recovery anchor")
	}
	return decimalBound("anchor asOfSeq", p.Anchor.AsOfSeq, 0, math.MaxInt64)
}

// ForkAllocatorFacts returns the bounded fresh-branch allocator facts a fork
// proof must carry (the NEW branch's DB-issued namespace row).
func (p *BaseProvenance) ForkAllocatorFacts() (maxIno uint64, namespace uint32, nextLocal uint64, err error) {
	if p == nil || p.Allocator == nil {
		return 0, 0, 0, fmt.Errorf("backend: fork PFT2 provenance has no branch allocator")
	}
	return allocatorFacts("fork allocator", p.Allocator.MaxInoSeen, p.Allocator.InodeNamespace, p.Allocator.NextLocal)
}

func allocatorFacts(what, maxDec, namespaceDec, nextLocalDec string) (maxIno uint64, namespace uint32, nextLocal uint64, err error) {
	maxIno, err = decimalBound(what+" maxInoSeen", maxDec, 1, pft2.MaxIno)
	if err != nil {
		return 0, 0, 0, err
	}
	ns, err := decimalBound(what+" inode namespace", namespaceDec, 1, uint64(pft2.MaxInodeNamespace))
	if err != nil {
		return 0, 0, 0, err
	}
	nextLocal, err = decimalBound(what+" next local", nextLocalDec, 1, pft2.MaxInodeLocalCounter+1)
	if err != nil {
		return 0, 0, 0, err
	}
	return maxIno, uint32(ns), nextLocal, nil
}

// BaseProvenance resolves and strictly validates the exact journal-base
// family. The idempotent GET is retried once for a lost response or a
// transient 503; 404 remains a typed definitive failure, never a downgrade.
func (c *Client) BaseProvenance(ctx context.Context, want BaseProvenanceRequest) (*BaseProvenance, error) {
	if err := validateProvenanceRequest(want); err != nil {
		return nil, err
	}
	values := url.Values{}
	values.Set("generationId", want.GenerationID)
	values.Set("baseSeq", strconv.FormatUint(want.BaseSeq, 10))
	values.Set("baseDigest", want.BaseDigest)
	values.Set("recordCodec", want.RecordCodec)
	values.Set("controlCodec", want.ControlCodec)
	path := "/v1/history/base-provenance/" + url.PathEscape(want.CommitID) + "?" + values.Encode()

	var last error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := c.get(ctx, path)
		if err != nil {
			last = fmt.Errorf("base provenance request: %w", err)
			if ctx.Err() != nil {
				return nil, last
			}
			continue
		}
		proof, retry, err := decodeBaseProvenanceResponse(resp, want)
		resp.Body.Close()
		if err == nil {
			return proof, nil
		}
		if errors.Is(err, ErrBaseProvenanceNotFound) {
			return nil, err
		}
		last = err
		if !retry || ctx.Err() != nil {
			return nil, err
		}
	}
	return nil, last
}

func decodeBaseProvenanceResponse(resp *http.Response, want BaseProvenanceRequest) (*BaseProvenance, bool, error) {
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
		return nil, false, fmt.Errorf("%w: commit/generation tuple", ErrBaseProvenanceNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		err := fmt.Errorf("base provenance: http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		return nil, resp.StatusCode == http.StatusServiceUnavailable, err
	}
	if resp.ContentLength > maxProvenanceBytes {
		return nil, false, fmt.Errorf("backend: base provenance response exceeds %d bytes", maxProvenanceBytes)
	}
	var envelope struct {
		Provenance BaseProvenance `json:"provenance"`
	}
	limited := &io.LimitedReader{R: resp.Body, N: maxProvenanceBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		if limited.N == 0 {
			return nil, false, fmt.Errorf("backend: base provenance response exceeds %d bytes", maxProvenanceBytes)
		}
		return nil, true, fmt.Errorf("backend: decode base provenance: %w", err)
	}
	var trailing any
	trailingErr := decoder.Decode(&trailing)
	if limited.N == 0 {
		return nil, false, fmt.Errorf("backend: base provenance response exceeds %d bytes", maxProvenanceBytes)
	}
	if trailingErr != io.EOF {
		return nil, false, fmt.Errorf("backend: base provenance contains trailing JSON")
	}
	if err := validateBaseProvenance(&envelope.Provenance, want); err != nil {
		return nil, false, err
	}
	return &envelope.Provenance, false, nil
}

func validateProvenanceRequest(want BaseProvenanceRequest) error {
	if want.TenantID == "" || len(want.TenantID) > 512 ||
		!boundedHistoryID.MatchString(want.CommitID) || !boundedHistoryID.MatchString(want.GenerationID) ||
		want.BaseSeq > math.MaxInt64 || !canonicalDigest.MatchString(want.BaseDigest) ||
		!validCodecPair(want.RecordCodec, want.ControlCodec) {
		return fmt.Errorf("backend: exact base provenance request is invalid")
	}
	return nil
}

func validateBaseProvenance(got *BaseProvenance, want BaseProvenanceRequest) error {
	wantSeq := strconv.FormatUint(want.BaseSeq, 10)
	if got == nil || got.V != "1" || got.TenantID != want.TenantID || got.CommitID != want.CommitID ||
		got.GenerationID != want.GenerationID || got.BaseSeq != wantSeq || got.BaseDigest != want.BaseDigest ||
		got.RecordCodec != want.RecordCodec || got.ControlCodec != want.ControlCodec ||
		!boundedHistoryID.MatchString(got.VolumeID) || !boundedHistoryID.MatchString(got.BranchID) {
		return fmt.Errorf("backend: base provenance contradicted the requested tenant/journal tuple")
	}
	switch got.Kind {
	case "manifest_v1":
		if got.BaseMode != "" || got.Root != nil || got.Anchor != nil || got.Allocator != nil {
			return fmt.Errorf("backend: manifest_v1 provenance contains PFT2 fields")
		}
		return nil
	case "pft2":
		if got.RecordCodec != "pfj3" || got.ControlCodec != "pfc2" || got.Root == nil {
			return fmt.Errorf("backend: PFT2 provenance requires PFJ3/PFC2 and a root")
		}
		if _, err := got.RootRef(); err != nil {
			return err
		}
		if _, err := got.RootMaxInoSeen(); err != nil {
			return err
		}
		switch got.BaseMode {
		case "fork":
			// A fork REQUIRES the fresh branch allocator and must not carry
			// a recovery anchor: controls/orphans intentionally start empty
			// and the allocator is the NEW branch's namespace row, never the
			// source branch's.
			if got.Anchor != nil {
				return fmt.Errorf("backend: fork provenance unexpectedly contains a recovery anchor")
			}
			if got.Allocator == nil {
				return fmt.Errorf("backend: fork provenance is missing the fresh branch allocator")
			}
			if want.BaseSeq != 0 {
				return fmt.Errorf("backend: fork provenance requires a seq-0 generation origin, base is %d", want.BaseSeq)
			}
			if _, _, _, err := got.ForkAllocatorFacts(); err != nil {
				return err
			}
		case "conversion", "adopted":
			if got.Anchor == nil {
				return fmt.Errorf("backend: live PFT2 base is missing its recovery anchor")
			}
			if got.Allocator != nil {
				// The anchor already carries the allocator facts; a second,
				// fork-only object contradicts the mode.
				return fmt.Errorf("backend: %s provenance unexpectedly contains a fork allocator", got.BaseMode)
			}
			if !boundedHistoryID.MatchString(got.Anchor.AnchorID) {
				return fmt.Errorf("backend: PFT2 anchor id is invalid")
			}
			asOf, err := got.AnchorAsOf()
			if err != nil {
				return err
			}
			if got.BaseMode == "adopted" && asOf != want.BaseSeq {
				return fmt.Errorf("backend: adopted PFT2 anchor sequence %d does not equal base %d", asOf, want.BaseSeq)
			}
			if _, err := got.RecoveryRootRef(); err != nil {
				return err
			}
			if _, err := nodeRef(got.Anchor.ControlRootDigest, got.Anchor.ControlRootSize, "control root"); err != nil {
				return err
			}
			if (got.Anchor.OrphanIndexDigest == "") != (got.Anchor.OrphanIndexSize == "") {
				return fmt.Errorf("backend: orphan-index digest/size must appear together")
			}
			if got.Anchor.OrphanIndexDigest != "" {
				if _, err := nodeRef(got.Anchor.OrphanIndexDigest, got.Anchor.OrphanIndexSize, "orphan index"); err != nil {
					return err
				}
			}
			if _, _, _, err := got.AnchorFacts(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("backend: PFT2 provenance has unknown base mode %q", got.BaseMode)
		}
		return nil
	default:
		return fmt.Errorf("backend: base provenance has unknown commit family %q", got.Kind)
	}
}

func validCodecPair(record, control string) bool {
	return (record == "pfr1" && control == "pfc1") || (record == "pfj3" && control == "pfc2")
}

func nodeRef(digestHex, sizeDec, what string) (pft2.Ref, error) {
	var out pft2.Ref
	if !canonicalDigest.MatchString(digestHex) {
		return out, fmt.Errorf("backend: %s digest is not canonical SHA-256", what)
	}
	raw, _ := hex.DecodeString(digestHex)
	copy(out.Digest[:], raw)
	size, err := decimalBound(what+" size", sizeDec, pft2.MinNodeBytes, pft2.MaxNodeBytes)
	if err != nil {
		return out, err
	}
	out.Size = size
	return out, nil
}

func decimalBound(what, value string, min, max uint64) (uint64, error) {
	if !canonicalDecimal.MatchString(value) {
		return 0, fmt.Errorf("backend: %s %q is not canonical decimal", what, value)
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed < min || parsed > max {
		return 0, fmt.Errorf("backend: %s %q is outside %d..%d", what, value, min, max)
	}
	return parsed, nil
}

// HistoryObject fetches and verifies one exact PFT2 object. expectedSize is
// both the allocation/read hard bound and an exact response invariant; no
// io.ReadAll or server-supplied unbounded allocation is used.
func (c *Client) HistoryObject(ctx context.Context, digest string, expectedSize uint64) ([]byte, error) {
	if !strings.HasPrefix(digest, "sha256:") || !canonicalDigest.MatchString(strings.TrimPrefix(digest, "sha256:")) ||
		expectedSize == 0 || expectedSize > maxHistoryObject {
		return nil, fmt.Errorf("backend: history object request is outside PFT2 bounds")
	}
	seg := strings.ReplaceAll(digest, ":", "%3A")
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := c.get(ctx, "/v1/history/objects/"+seg)
		if err != nil {
			last = fmt.Errorf("history object request: %w", err)
			if ctx.Err() != nil {
				return nil, last
			}
			continue
		}
		data, retry, err := decodeHistoryObject(resp, digest, expectedSize)
		resp.Body.Close()
		if err == nil {
			return data, nil
		}
		last = err
		if !retry || ctx.Err() != nil {
			return nil, err
		}
	}
	return nil, last
}

func decodeHistoryObject(resp *http.Response, digest string, expectedSize uint64) ([]byte, bool, error) {
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		err := fmt.Errorf("history object %s: http %d: %s", digest, resp.StatusCode, strings.TrimSpace(string(body)))
		return nil, resp.StatusCode == http.StatusServiceUnavailable, err
	}
	if resp.ContentLength >= 0 && uint64(resp.ContentLength) != expectedSize {
		return nil, false, fmt.Errorf("history object %s: content length %d, want %d", digest, resp.ContentLength, expectedSize)
	}
	data := make([]byte, int(expectedSize))
	n, err := io.ReadFull(resp.Body, data)
	if err != nil {
		return nil, true, fmt.Errorf("history object %s: bounded read: %w", digest, err)
	}
	if uint64(n) != expectedSize {
		return nil, true, fmt.Errorf("history object %s: read %d bytes, want %d", digest, n, expectedSize)
	}
	var extra [1]byte
	if extraN, extraErr := io.ReadFull(resp.Body, extra[:]); extraN != 0 {
		return nil, false, fmt.Errorf("history object %s: response exceeds expected size %d", digest, expectedSize)
	} else if extraErr != io.EOF {
		return nil, true, fmt.Errorf("history object %s: bounded trailing-byte read: %w", digest, extraErr)
	}
	want := strings.TrimPrefix(digest, "sha256:")
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != want {
		return nil, true, fmt.Errorf("history object %s: checksum mismatch", digest)
	}
	return data, false, nil
}

type historyObjectClient interface {
	HistoryObject(context.Context, string, uint64) ([]byte, error)
}

// Pft2Fetcher adapts the exact history-object endpoint to pft2.Fetcher.
type Pft2Fetcher struct {
	client historyObjectClient
}

// NewPft2Fetcher wraps a bounded exact-object client.
func NewPft2Fetcher(client historyObjectClient) *Pft2Fetcher { return &Pft2Fetcher{client: client} }

// Fetch implements pft2.Fetcher. Ref.Size is the hard allocation/read bound.
func (f *Pft2Fetcher) Fetch(ctx context.Context, ref pft2.Ref) ([]byte, error) {
	if ref.Size == 0 || ref.Size > pft2.MaxPackBytes {
		return nil, fmt.Errorf("backend: PFT2 ref size %d exceeds object bounds", ref.Size)
	}
	data, err := f.client.HistoryObject(ctx, "sha256:"+ref.Hex(), ref.Size)
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) != ref.Size {
		return nil, fmt.Errorf("history object sha256:%s is %d bytes, want %d", ref.Hex(), len(data), ref.Size)
	}
	if pft2.RefOf(data) != ref {
		return nil, fmt.Errorf("history object sha256:%s does not match its exact reference", ref.Hex())
	}
	return data, nil
}
