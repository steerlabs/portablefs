package lifecycle

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/steerlabs/portablefs/vcs/internal/opstate"
)

// Route paths served by Handler (mounted on the VCS metrics/admin listener).
const (
	CheckpointPath   = "/v1/ops/checkpoint"
	EvictPath        = "/v1/ops/evict"
	QuiescePath      = "/v1/ops/quiesce"
	ReleaseLeasePath = "/v1/ops/release-lease"
)

const maxOpBodyBytes = 64 << 10

// CodeNotPrimary is returned while this process has no writable controller
// (read-only role, standby before promotion, or still starting).
const CodeNotPrimary = "VCS_NOT_PRIMARY"

// Holder atomically publishes the serving controller to the admin HTTP
// handler. main wires the handler at startup (before a role is chosen) and the
// writable serving path stores the controller once it exists.
type Holder struct{ ptr atomic.Pointer[Controller] }

// Set publishes c as the current controller.
func (h *Holder) Set(c *Controller) { h.ptr.Store(c) }

// Get returns the current controller, or nil.
func (h *Holder) Get() *Controller { return h.ptr.Load() }

type opRequestBody struct {
	OperationID         string `json:"operationId"`
	VolumeID            string `json:"volumeId"`
	Branch              string `json:"branch"`
	AuthorityInstanceID string `json:"authorityInstanceId"`
}

type opResponseBody struct {
	OperationID         string `json:"operationId"`
	Kind                string `json:"kind"`
	VolumeID            string `json:"volumeId"`
	Branch              string `json:"branch"`
	AuthorityInstanceID string `json:"authorityInstanceId,omitempty"`
	HeadCommitID        string `json:"headCommitId,omitempty"`
	TreeHash            string `json:"treeHash,omitempty"`
	Committed           bool   `json:"committed"`
	MutationCount       int64  `json:"mutationCount"`
	ByteCount           int64  `json:"byteCount"`
	CompletedAtMs       int64  `json:"completedAtMs"`
	State               string `json:"state"`
	LeaseID             string `json:"leaseId,omitempty"`
	LeaseReleased       bool   `json:"leaseReleased,omitempty"`
	WALEpoch            string `json:"walEpoch,omitempty"`
	AppliedLSN          string `json:"appliedLsn,omitempty"`
	CoherenceGeneration string `json:"coherenceGeneration,omitempty"`
	WALPoisoned         *bool  `json:"walPoisoned,omitempty"`
	// Managed evicts: the exact receipted journal_suspend_exact step-down
	// facts, verbatim decimal strings (never JS-rounded numbers).
	JournalSuspended *bool  `json:"journalSuspended,omitempty"`
	JournalNextSeq   string `json:"journalNextSeq,omitempty"`
	JournalTipDigest string `json:"journalTipDigest,omitempty"`
	// ReconciliationRequired is explicit when WALPoisoned is true: the revision
	// still proves the acknowledged prefix, but a manager must reconcile the
	// authoritative journal before releasing/promoting. It is always present on
	// evict responses, including false, so consumers cannot confuse omission with
	// a healthy verdict.
	ReconciliationRequired *bool `json:"reconciliationRequired,omitempty"`
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Handler serves the fenced lifecycle admin API. adminToken guards the
// endpoints when non-empty. It is the CONTROL-PLANE credential (VCS_ADMIN_TOKEN),
// distinct from the data-plane mount token: a data-plane bearer must never be
// able to quiesce the volume, and the admin bearer must never authenticate a
// mount. The surrounding metrics endpoints stay unauthenticated for scraping.
// HandlerOptions makes unauthenticated lifecycle control an explicit dev-only
// choice. Handler itself defaults fail closed even on loopback; main opts in
// only after it has verified a loopback bind.
type HandlerOptions struct {
	AllowUnauthenticatedDevelopment bool
}

func Handler(holder *Holder, adminToken string) http.Handler {
	return HandlerWithOptions(holder, adminToken, HandlerOptions{})
}

func HandlerWithOptions(holder *Holder, adminToken string, options HandlerOptions) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(CheckpointPath, opHandler(holder, adminToken, options, func(ctx context.Context, c *Controller, req OpRequest) (opstate.Operation, *OpError) {
		return c.Checkpoint(ctx, req)
	}))
	mux.HandleFunc(EvictPath, opHandler(holder, adminToken, options, func(ctx context.Context, c *Controller, req OpRequest) (opstate.Operation, *OpError) {
		return c.EvictOperation(ctx, req)
	}))
	mux.HandleFunc(QuiescePath, opHandler(holder, adminToken, options, func(ctx context.Context, c *Controller, req OpRequest) (opstate.Operation, *OpError) {
		return c.Quiesce(ctx, req)
	}))
	mux.HandleFunc(ReleaseLeasePath, opHandler(holder, adminToken, options, func(ctx context.Context, c *Controller, req OpRequest) (opstate.Operation, *OpError) {
		return c.ReleaseLease(ctx, req)
	}))
	return mux
}

func opHandler(
	holder *Holder,
	authToken string,
	options HandlerOptions,
	run func(ctx context.Context, c *Controller, req OpRequest) (opstate.Operation, *OpError),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("cache-control", "no-store")
		if r.Method != http.MethodPost {
			w.Header().Set("allow", http.MethodPost)
			writeOpError(w, opErrorf(CodeMethodNotAllowed, http.StatusMethodNotAllowed, "method %s not allowed; use POST", r.Method))
			return
		}
		if authToken == "" && !options.AllowUnauthenticatedDevelopment {
			writeOpError(w, opErrorf(CodeUnauthorized, http.StatusForbidden, "lifecycle control is locked because no admin token is configured"))
			return
		}
		if !authorized(r, authToken) {
			writeOpError(w, opErrorf(CodeUnauthorized, http.StatusUnauthorized, "missing or invalid bearer token"))
			return
		}
		controller := holder.Get()
		if controller == nil {
			writeOpError(w, opErrorf(CodeNotPrimary, http.StatusServiceUnavailable, "this node is not a writable primary"))
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxOpBodyBytes+1))
		if err != nil || len(raw) > maxOpBodyBytes {
			writeOpError(w, opErrorf(CodeInvalidRequest, http.StatusBadRequest, "unreadable or oversized request body"))
			return
		}
		var body opRequestBody
		if err := rejectDuplicateRequestFields(raw); err != nil {
			writeOpError(w, opErrorf(CodeInvalidRequest, http.StatusBadRequest, "request body must be unambiguous JSON: %v", err))
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			writeOpError(w, opErrorf(CodeInvalidRequest, http.StatusBadRequest, "request body must be one strict JSON object: %v", err))
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			writeOpError(w, opErrorf(CodeInvalidRequest, http.StatusBadRequest, "request body must contain exactly one JSON object"))
			return
		}
		op, oerr := run(r.Context(), controller, OpRequest{
			OperationID:         strings.TrimSpace(body.OperationID),
			VolumeID:            strings.TrimSpace(body.VolumeID),
			Branch:              strings.TrimSpace(body.Branch),
			AuthorityInstanceID: strings.TrimSpace(body.AuthorityInstanceID),
		})
		if oerr != nil {
			writeOpError(w, oerr)
			return
		}
		resp := opResponseBody{
			OperationID:         op.ID,
			Kind:                op.Kind,
			VolumeID:            op.VolumeID,
			Branch:              op.Branch,
			AuthorityInstanceID: op.AuthorityInstanceID,
			HeadCommitID:        op.HeadCommitID,
			TreeHash:            op.TreeHash,
			Committed:           op.Committed,
			MutationCount:       op.MutationCount,
			ByteCount:           op.ByteCount,
			CompletedAtMs:       op.CompletedAtMs,
			State:               op.State,
			LeaseID:             op.LeaseID,
			LeaseReleased:       op.LeaseReleased,
		}
		if resp.State == "" { // version-2 checkpoint/quiesce compatibility
			resp.State = string(controller.State())
		}
		if op.Kind == opstate.KindEvict {
			resp.WALEpoch = strconv.FormatUint(op.WALEpoch, 10)
			resp.AppliedLSN = strconv.FormatUint(op.AppliedLSN, 10)
			resp.CoherenceGeneration = strconv.FormatUint(op.CoherenceGeneration, 10)
			resp.WALPoisoned = &op.WALPoisoned
			reconciliationRequired := op.WALPoisoned
			resp.ReconciliationRequired = &reconciliationRequired
			if op.JournalSuspended {
				suspended := true
				resp.JournalSuspended = &suspended
				resp.JournalNextSeq = strconv.FormatUint(op.JournalNextSeq, 10)
				resp.JournalTipDigest = op.JournalTipDigest
			}
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&resp)
	}
}

func rejectDuplicateRequestFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return fmt.Errorf("top-level value must be an object")
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := nameToken.(string)
		if !ok {
			return fmt.Errorf("object member name is not a string")
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("duplicate field %q", name)
		}
		seen[name] = struct{}{}
		// Every supported request field is scalar. Decode unknown/nested values
		// into RawMessage here; DisallowUnknownFields below remains authoritative.
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	closeToken, err := decoder.Token()
	if err != nil || closeToken != json.Delim('}') {
		return fmt.Errorf("invalid object close: %v", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func authorized(r *http.Request, token string) bool {
	if token == "" {
		return true
	}
	header := r.Header.Get("Authorization")
	presented, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(token)) == 1
}

func writeOpError(w http.ResponseWriter, oerr *OpError) {
	var body errorBody
	body.Error.Code = oerr.Code
	body.Error.Message = oerr.Message
	w.Header().Set("content-type", "application/json")
	status := oerr.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(&body)
}
