package controlplane

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
)

type Role string

const (
	RoleOperator Role = "operator"
	RoleProduct  Role = "product"
	RoleCell     Role = "cell"
	RoleMount    Role = "mount"
)

type Principal struct {
	Role Role
	ID   string
}

type Authenticator func(*http.Request) (Principal, error)

type HTTPHandler struct {
	Manager      *Manager
	Authenticate Authenticator
}

func (handler *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler.Manager == nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "manager unavailable")
		return
	}
	authenticate := handler.Authenticate
	if authenticate == nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "manager mTLS authenticator unavailable")
		return
	}
	principal, err := authenticate(request)
	if err != nil {
		writeAPIError(writer, http.StatusUnauthorized, "mutual TLS identity required")
		return
	}
	path := strings.Trim(request.URL.Path, "/")
	parts := strings.Split(path, "/")
	switch {
	case request.Method == http.MethodGet && path == "healthz":
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok", "release_id": handler.Manager.ReleaseIdentity()})
	case request.Method == http.MethodGet && path == "v1/release":
		writeJSON(writer, http.StatusOK, map[string]string{"release_id": handler.Manager.ReleaseIdentity()})
	case request.Method == http.MethodPost && path == "v1/cells":
		handler.requireRole(writer, request, principal, RoleOperator, func() (any, error) {
			var body RegisterCellRequest
			if err := decodeJSON(request, &body); err != nil {
				return nil, err
			}
			return handler.Manager.RegisterCell(idempotencyKey(request), body)
		})
	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "cells" && parts[3] == "capacity" && request.Method == http.MethodPatch:
		handler.requireRole(writer, request, principal, RoleOperator, func() (any, error) {
			var body UpdateCellCapacityRequest
			if err := decodeJSON(request, &body); err != nil {
				return nil, err
			}
			return handler.Manager.UpdateCellCapacity(idempotencyKey(request), parts[2], body)
		})
	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "cells" && parts[3] == "decommission" && request.Method == http.MethodPost:
		handler.requireRole(writer, request, principal, RoleOperator, func() (any, error) {
			var body DecommissionCellRequest
			if err := decodeJSON(request, &body); err != nil {
				return nil, err
			}
			return handler.Manager.DecommissionCell(idempotencyKey(request), parts[2], body)
		})
	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "cells" && parts[3] == "abandon" && request.Method == http.MethodPost:
		handler.requireRole(writer, request, principal, RoleOperator, func() (any, error) {
			var body AbandonCellRequest
			if err := decodeJSON(request, &body); err != nil {
				return nil, err
			}
			return handler.Manager.AbandonCell(idempotencyKey(request), parts[2], body)
		})
	case request.Method == http.MethodGet && path == "v1/capacity":
		if principal.Role != RoleOperator && principal.Role != RoleProduct && principal.Role != RoleCell {
			writeAPIError(writer, http.StatusForbidden, "role not permitted")
			return
		}
		result, err := handler.Manager.Capacity()
		handler.writeResult(writer, result, err)
	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "cells" && parts[3] == "plan" && request.Method == http.MethodGet:
		cellID := parts[2]
		if principal.Role != RoleCell || principal.ID != cellID {
			writeAPIError(writer, http.StatusForbidden, "cell identity mismatch")
			return
		}
		plan, err := handler.Manager.CellPlan(cellID)
		handler.writeResult(writer, plan, err)
	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "cells" && parts[3] == "observations" && request.Method == http.MethodPost:
		cellID := parts[2]
		if principal.Role != RoleCell || principal.ID != cellID {
			writeAPIError(writer, http.StatusForbidden, "cell identity mismatch")
			return
		}
		var body CellObservation
		if err := decodeJSONLimit(request, &body, 2<<20); err != nil {
			handler.writeResult(writer, nil, err)
			return
		}
		if body.CellID != cellID {
			handler.writeResult(writer, nil, ErrInvalid)
			return
		}
		if idempotencyKey(request) == "" {
			writeAPIError(writer, http.StatusBadRequest, "Idempotency-Key is required")
			return
		}
		result, err := handler.Manager.ObserveCell(idempotencyKey(request), body)
		handler.writeResult(writer, result, err)
	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "cells" && parts[3] == "heartbeat" && request.Method == http.MethodPost:
		cellID := parts[2]
		if principal.Role != RoleCell || principal.ID != cellID {
			writeAPIError(writer, http.StatusForbidden, "cell identity mismatch")
			return
		}
		var body CellHeartbeat
		if err := decodeJSON(request, &body); err != nil {
			handler.writeResult(writer, nil, err)
			return
		}
		if body.CellID != cellID {
			handler.writeResult(writer, nil, ErrInvalid)
			return
		}
		err := handler.Manager.HeartbeatCell(body)
		if err != nil {
			handler.writeResult(writer, nil, err)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	case request.Method == http.MethodPost && path == "v1/volumes":
		handler.requireRole(writer, request, principal, RoleProduct, func() (any, error) {
			var body CreateVolumeRequest
			if err := decodeJSON(request, &body); err != nil {
				return nil, err
			}
			if strings.TrimSpace(body.ProductIssuer) != principal.ID {
				return nil, ErrNotFound
			}
			return handler.Manager.CreateVolume(idempotencyKey(request), body)
		})
	case len(parts) == 3 && parts[0] == "v1" && parts[1] == "volumes" && request.Method == http.MethodGet:
		if principal.Role != RoleProduct && principal.Role != RoleOperator {
			writeAPIError(writer, http.StatusForbidden, "role not permitted")
			return
		}
		result, err := handler.Manager.GetVolume(parts[2])
		if err == nil && principal.Role == RoleProduct && result.ProductIssuer != principal.ID {
			err = ErrNotFound
		}
		handler.writeResult(writer, result, err)
	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "volumes" && parts[3] == "restart" && request.Method == http.MethodPost:
		handler.requireRole(writer, request, principal, RoleProduct, func() (any, error) {
			var body RestartVolumeRequest
			if err := decodeJSON(request, &body); err != nil {
				return nil, err
			}
			if body.VolumeID != parts[2] {
				return nil, ErrInvalid
			}
			if err := handler.requireProductVolume(principal, body.VolumeID); err != nil {
				return nil, err
			}
			return handler.Manager.RestartVolume(idempotencyKey(request), body)
		})
	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "volumes" && parts[3] == "strict-fence" && request.Method == http.MethodPost:
		handler.requireRole(writer, request, principal, RoleOperator, func() (any, error) {
			var body ConfirmStrictFenceRequest
			if err := decodeJSON(request, &body); err != nil {
				return nil, err
			}
			if body.VolumeID != parts[2] {
				return nil, ErrInvalid
			}
			return handler.Manager.ConfirmStrictMountsFenced(idempotencyKey(request), body)
		})
	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "volumes" && parts[3] == "archive" && request.Method == http.MethodPost:
		handler.requireRole(writer, request, principal, RoleProduct, func() (any, error) {
			var body ArchiveVolumeRequest
			if err := decodeJSON(request, &body); err != nil {
				return nil, err
			}
			if body.VolumeID != parts[2] {
				return nil, ErrInvalid
			}
			if err := handler.requireProductVolume(principal, body.VolumeID); err != nil {
				return nil, err
			}
			return handler.Manager.ArchiveVolume(idempotencyKey(request), body)
		})
	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "volumes" && parts[3] == "wake" && request.Method == http.MethodPost:
		if principal.Role != RoleProduct {
			writeAPIError(writer, http.StatusForbidden, "role not permitted")
			return
		}
		if idempotencyKey(request) == "" {
			writeAPIError(writer, http.StatusBadRequest, "Idempotency-Key is required")
			return
		}
		var body WakeVolumeRequest
		if err := decodeJSON(request, &body); err != nil {
			handler.writeResult(writer, nil, err)
			return
		}
		if body.VolumeID != parts[2] {
			handler.writeResult(writer, nil, ErrInvalid)
			return
		}
		if err := handler.requireProductVolume(principal, body.VolumeID); err != nil {
			handler.writeResult(writer, nil, err)
			return
		}
		result, err := handler.Manager.WakeVolume(idempotencyKey(request), body)
		if err == nil && result.WakeRequested {
			writeJSON(writer, http.StatusAccepted, result)
			return
		}
		handler.writeResult(writer, result, err)
	case len(parts) == 3 && parts[0] == "v1" && parts[1] == "volumes" && request.Method == http.MethodDelete:
		handler.requireRole(writer, request, principal, RoleProduct, func() (any, error) {
			var body DestroyVolumeRequest
			if err := decodeJSON(request, &body); err != nil {
				return nil, err
			}
			if body.VolumeID != parts[2] {
				return nil, ErrInvalid
			}
			if err := handler.requireProductVolume(principal, body.VolumeID); err != nil {
				return nil, err
			}
			return handler.Manager.DestroyVolume(idempotencyKey(request), body)
		})
	case request.Method == http.MethodPost && path == "v1/mount-authorizations":
		handler.requireRole(writer, request, principal, RoleProduct, func() (any, error) {
			var body IssueMountRequest
			if err := decodeJSON(request, &body); err != nil {
				return nil, err
			}
			if err := handler.requireProductVolume(principal, body.VolumeID); err != nil {
				return nil, err
			}
			return handler.Manager.IssueMount(idempotencyKey(request), body)
		})
	case request.Method == http.MethodPost && path == "v1/mount-reauthorizations":
		handler.requireRole(writer, request, principal, RoleProduct, func() (any, error) {
			var body ReauthorizeMountRequest
			if err := decodeJSON(request, &body); err != nil {
				return nil, err
			}
			if err := handler.requireProductVolume(principal, body.VolumeID); err != nil {
				return nil, err
			}
			return handler.Manager.ReauthorizeMount(idempotencyKey(request), body)
		})
	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "mount-enrollments" && parts[3] == "reauthorizations" && request.Method == http.MethodPost:
		enrollmentID := parts[2]
		if principal.Role != RoleMount || principal.ID != enrollmentID {
			writeAPIError(writer, http.StatusForbidden, "mount enrollment identity mismatch")
			return
		}
		var body RefreshMountEnrollmentRequest
		if err := decodeJSON(request, &body); err != nil {
			handler.writeResult(writer, nil, err)
			return
		}
		if idempotencyKey(request) == "" {
			writeAPIError(writer, http.StatusBadRequest, "Idempotency-Key is required")
			return
		}
		result, err := handler.Manager.RefreshMountEnrollment(idempotencyKey(request), enrollmentID, body)
		handler.writeResult(writer, result, err)
	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "mount-enrollments" && parts[3] == "close" && request.Method == http.MethodPost:
		enrollmentID := parts[2]
		if principal.Role != RoleMount || principal.ID != enrollmentID {
			writeAPIError(writer, http.StatusForbidden, "mount enrollment identity mismatch")
			return
		}
		var body TerminateMountEnrollmentRequest
		if err := decodeJSON(request, &body); err != nil {
			handler.writeResult(writer, nil, err)
			return
		}
		if idempotencyKey(request) == "" {
			writeAPIError(writer, http.StatusBadRequest, "Idempotency-Key is required")
			return
		}
		result, err := handler.Manager.CloseMountEnrollment(idempotencyKey(request), enrollmentID, body)
		handler.writeResult(writer, result, err)
	case len(parts) == 6 && parts[0] == "v1" && parts[1] == "volumes" && parts[3] == "mount-enrollments" && parts[5] == "revocation" && request.Method == http.MethodPut:
		handler.requireConvergentRole(writer, request, principal, RoleProduct, func() (any, error) {
			var body TerminateMountEnrollmentRequest
			if err := decodeJSON(request, &body); err != nil {
				return nil, err
			}
			return handler.Manager.RevokeVolumeMountEnrollment(principal.ID, parts[2], parts[4], body)
		})
	case request.Method == http.MethodPut && path == "v1/renewal-fences":
		handler.requireConvergentRole(writer, request, principal, RoleProduct, func() (any, error) {
			var body AdvanceRenewalFencesRequest
			if err := decodeJSON(request, &body); err != nil {
				return nil, err
			}
			return handler.Manager.AdvanceRenewalFences(principal.ID, body)
		})
	default:
		writeAPIError(writer, http.StatusNotFound, "not found")
	}
}

func (handler *HTTPHandler) requireProductVolume(principal Principal, volumeID string) error {
	if principal.Role != RoleProduct {
		return ErrNotFound
	}
	volume, err := handler.Manager.GetVolume(volumeID)
	if err != nil {
		return err
	}
	if volume.ProductIssuer != principal.ID {
		return ErrNotFound
	}
	return nil
}

func AuthenticateMTLS(request *http.Request) (Principal, error) {
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 {
		return Principal{}, errors.New("verified client certificate required")
	}
	leaf := request.TLS.PeerCertificates[0]
	if len(leaf.URIs) != 1 {
		return Principal{}, errors.New("one control identity URI is required")
	}
	identity := leaf.URIs[0]
	if identity.Scheme != "spiffe" || identity.Host != "portablefs" || identity.User != nil || identity.Opaque != "" ||
		identity.RawQuery != "" || identity.ForceQuery || identity.Fragment != "" {
		return Principal{}, errors.New("invalid control identity URI")
	}
	escapedPath := identity.EscapedPath()
	if !strings.HasPrefix(escapedPath, "/") || strings.HasSuffix(escapedPath, "/") {
		return Principal{}, errors.New("invalid control identity path")
	}
	parts := strings.Split(escapedPath[1:], "/")
	if len(parts) == 2 && parts[0] == "mount-enrollment" && parts[1] != "" {
		decodedID, err := url.PathUnescape(parts[1])
		if err != nil || !cellplan.ValidID(decodedID) {
			return Principal{}, errors.New("invalid mount enrollment identity")
		}
		return Principal{Role: RoleMount, ID: decodedID}, nil
	}
	if len(parts) != 3 || parts[0] != "control" || parts[2] == "" {
		return Principal{}, errors.New("invalid control identity path")
	}
	role := Role(parts[1])
	if role != RoleOperator && role != RoleProduct && role != RoleCell {
		return Principal{}, errors.New("unknown control role")
	}
	decodedID, err := url.PathUnescape(parts[2])
	if err != nil || !validIdentity(decodedID) || role == RoleCell && !cellplan.ValidID(decodedID) {
		return Principal{}, errors.New("invalid control identity")
	}
	return Principal{Role: role, ID: decodedID}, nil
}

// NewRoleBoundMTLSAuthenticator binds the identity URI to the CA realm that
// issued it. The Manager listener trusts both realms at the TLS layer, so URI
// parsing alone would let a mistakenly issued enrollment certificate claim a
// control role (or vice versa).
func NewRoleBoundMTLSAuthenticator(controlCAPEM, enrollmentCAPEM []byte) (Authenticator, error) {
	controlRoots, err := certificateFingerprints(controlCAPEM)
	if err != nil {
		return nil, fmt.Errorf("control client CA bundle: %w", err)
	}
	enrollmentRoots, err := certificateFingerprints(enrollmentCAPEM)
	if err != nil {
		return nil, fmt.Errorf("mount enrollment CA bundle: %w", err)
	}
	for fingerprint := range controlRoots {
		if _, overlaps := enrollmentRoots[fingerprint]; overlaps {
			return nil, errors.New("control and mount enrollment CA realms must be disjoint")
		}
	}
	return func(request *http.Request) (Principal, error) {
		principal, err := AuthenticateMTLS(request)
		if err != nil {
			return Principal{}, err
		}
		expected := controlRoots
		if principal.Role == RoleMount {
			expected = enrollmentRoots
		}
		for _, chain := range request.TLS.VerifiedChains {
			if len(chain) == 0 {
				continue
			}
			fingerprint := sha256.Sum256(chain[len(chain)-1].Raw)
			if _, trusted := expected[fingerprint]; trusted {
				return principal, nil
			}
		}
		return Principal{}, errors.New("client identity was issued by the wrong Manager trust realm")
	}, nil
}

func certificateFingerprints(bundle []byte) (map[[32]byte]struct{}, error) {
	fingerprints := make(map[[32]byte]struct{})
	remaining := bytes.TrimSpace(bundle)
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("bundle must contain only CERTIFICATE PEM blocks")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("bundle contains a certificate that is not a signing CA")
		}
		fingerprints[sha256.Sum256(certificate.Raw)] = struct{}{}
		remaining = bytes.TrimSpace(rest)
	}
	if len(fingerprints) == 0 {
		return nil, errors.New("bundle contains no CA certificates")
	}
	return fingerprints, nil
}

func (handler *HTTPHandler) requireRole(writer http.ResponseWriter, request *http.Request, principal Principal, role Role, operation func() (any, error)) {
	if principal.Role != role {
		writeAPIError(writer, http.StatusForbidden, "role not permitted")
		return
	}
	if idempotencyKey(request) == "" {
		writeAPIError(writer, http.StatusBadRequest, "Idempotency-Key is required")
		return
	}
	result, err := operation()
	handler.writeResult(writer, result, err)
}

func (handler *HTTPHandler) requireConvergentRole(writer http.ResponseWriter, request *http.Request, principal Principal, role Role, operation func() (any, error)) {
	if principal.Role != role {
		writeAPIError(writer, http.StatusForbidden, "role not permitted")
		return
	}
	if len(request.Header.Values("Idempotency-Key")) != 0 {
		writeAPIError(writer, http.StatusBadRequest, "Idempotency-Key is not accepted")
		return
	}
	result, err := operation()
	handler.writeResult(writer, result, err)
}

func (handler *HTTPHandler) writeResult(writer http.ResponseWriter, result any, err error) {
	if err == nil {
		writeJSON(writer, http.StatusOK, result)
		return
	}
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrIdempotencyReuse):
		status = http.StatusBadRequest
	case errors.Is(err, ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrConflict), errors.Is(err, ErrCapacity), errors.Is(err, ErrEnrollmentCapacity), errors.Is(err, ErrRenewalFenceCapacity), errors.Is(err, ErrQuarantined):
		status = http.StatusConflict
	case errors.Is(err, ErrRenewalScopeFenced):
		status = http.StatusConflict
	case errors.Is(err, ErrEnrollmentEnded):
		status = http.StatusGone
	// Both 503s are "the request was correct, retry it unchanged": the archive
	// store is down, or every eligible cell is at its archive/restore
	// concurrency cap. Neither is a client-visible conflict in the durable
	// state, so neither is 409.
	case errors.Is(err, ErrArchiveStoreUnavailable), errors.Is(err, ErrBusy):
		status = http.StatusServiceUnavailable
	// 501 is "this deployment cannot do that at all" — a cell without archive
	// configuration or a Manager without its archive component. Retrying is
	// useless and hiding it behind 409/503 would let a misconfigured
	// deployment fail every sweep silently forever, so it gets a status a
	// client can route to an operator.
	case errors.Is(err, ErrArchiveUnsupported):
		status = http.StatusNotImplemented
	}
	writeAPIError(writer, status, err.Error())
}

func decodeJSON(request *http.Request, target any) error {
	return decodeJSONLimit(request, target, 1<<20)
}

func decodeJSONLimit(request *http.Request, target any, limit int64) error {
	defer request.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	if err != nil || int64(len(payload)) > limit {
		return fmt.Errorf("%w: JSON body exceeds %d bytes", ErrInvalid, limit)
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: malformed JSON", ErrInvalid)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON", ErrInvalid)
	}
	return nil
}

func idempotencyKey(request *http.Request) string {
	return strings.TrimSpace(request.Header.Get("Idempotency-Key"))
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeAPIError(writer http.ResponseWriter, status int, detail string) {
	writeJSON(writer, status, map[string]string{"error": detail})
}
