// Package cellagent implements the unprivileged, outbound-only storage-cell
// control loop. It verifies manager plans before sending them across the local
// privilege boundary; the root helper independently verifies the same plan.
package cellagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

var ErrInvalid = errors.New("cellagent: invalid configuration or response")

type Config struct {
	CellID        string
	ManagerURL    string
	PlanPublicKey ed25519.PublicKey
	PlanLifetime  time.Duration
	ClockSkew     time.Duration
	PollInterval  time.Duration
	ReleaseID     string
	ManagerClient *http.Client
	HelperClient  *http.Client
	Now           func() time.Time
	ReportError   func(error)
}

type Agent struct {
	cfg                Config
	baseURL            *url.URL
	runMu              sync.Mutex
	lastObservation    [32]byte
	hasLastObservation bool
	lastObservationAt  time.Time
}

func New(config Config) (*Agent, error) {
	managerURL, err := url.Parse(config.ManagerURL)
	if err != nil || managerURL.Scheme != "https" || managerURL.Host == "" || managerURL.User != nil ||
		managerURL.RawQuery != "" || managerURL.Fragment != "" || (managerURL.Path != "" && managerURL.Path != "/") ||
		!cellplan.ValidID(config.CellID) || len(config.PlanPublicKey) != ed25519.PublicKeySize || config.PlanLifetime <= 0 ||
		config.ClockSkew < 0 || config.PollInterval <= 0 || config.ReleaseID == "" || config.ManagerClient == nil || config.HelperClient == nil {
		return nil, ErrInvalid
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	managerURL.Path = ""
	return &Agent{cfg: config, baseURL: managerURL}, nil
}

func (agent *Agent) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	for {
		if err := agent.RunOnce(ctx); err != nil && agent.cfg.ReportError != nil && !errors.Is(err, context.Canceled) {
			agent.cfg.ReportError(err)
		}
		timer := time.NewTimer(agent.cfg.PollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

func (agent *Agent) RunOnce(ctx context.Context) error {
	agent.runMu.Lock()
	defer agent.runMu.Unlock()
	envelope, plan, err := agent.fetchPlan(ctx)
	if err != nil {
		return err
	}
	observation, err := agent.reconcile(ctx, envelope)
	if err != nil {
		return err
	}
	if observation.CellID != agent.cfg.CellID || observation.PlanGeneration != plan.Generation ||
		observation.ManagerReleaseID != plan.ReleaseID || observation.HelperReleaseID == "" || observation.AgentReleaseID != "" {
		return fmt.Errorf("%w: helper observation does not match the verified plan", ErrInvalid)
	}
	if !observationMatchesPlan(observation.Volumes, plan.Volumes) {
		return fmt.Errorf("%w: helper observation changed or omitted a signed volume assignment", ErrInvalid)
	}
	observation.AgentReleaseID = agent.cfg.ReleaseID
	digest, err := observationDigest(observation)
	if err != nil {
		return err
	}
	now := agent.cfg.Now().UTC()
	refreshAfter := time.Duration(plan.UsageRefreshSeconds) * time.Second / 3
	// Usage timestamps are durable admission evidence. Refresh them well before
	// the manager's bound even when reconciliation found no state change.
	refreshDue := agent.hasLastObservation && (now.Before(agent.lastObservationAt) || now.Sub(agent.lastObservationAt) >= refreshAfter)
	if !agent.hasLastObservation || digest != agent.lastObservation || refreshDue {
		if err := agent.observe(ctx, observation); err != nil {
			return err
		}
		agent.lastObservation = digest
		agent.hasLastObservation = true
		agent.lastObservationAt = now
		return nil
	}
	return agent.heartbeat(ctx, controlplane.CellHeartbeat{
		CellID: observation.CellID, PlanGeneration: observation.PlanGeneration,
		ManagerReleaseID: observation.ManagerReleaseID, AgentReleaseID: observation.AgentReleaseID,
		HelperReleaseID: observation.HelperReleaseID, ObservedUnix: observation.ObservedUnix,
	})
}

func observationMatchesPlan(observed []controlplane.VolumeObservation, planned []cellplan.VolumePlan) bool {
	if len(observed) != len(planned) {
		return false
	}
	byID := make(map[string]controlplane.VolumeObservation, len(observed))
	for _, volume := range observed {
		if _, duplicate := byID[volume.VolumeID]; duplicate {
			return false
		}
		byID[volume.VolumeID] = volume
	}
	for _, plan := range planned {
		volume, ok := byID[plan.VolumeID]
		if !ok || volume.AuthorityGeneration != plan.AuthorityGeneration || volume.ProjectID != plan.ProjectID ||
			volume.ServiceUID != plan.ServiceUID || volume.ServiceGID != plan.ServiceGID || volume.ListenPort != plan.ListenPort {
			return false
		}
		if plan.Phase == cellplan.PhaseRelease && !volume.Released {
			return false
		}
	}
	return true
}

func (agent *Agent) heartbeat(ctx context.Context, heartbeat controlplane.CellHeartbeat) error {
	payload, err := json.Marshal(heartbeat)
	if err != nil {
		return err
	}
	endpoint := *agent.baseURL
	endpoint.Path = "/v1/cells/" + url.PathEscape(agent.cfg.CellID) + "/heartbeat"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := agent.cfg.ManagerClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return responseError("report cell heartbeat", response)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	return err
}

func observationDigest(observation controlplane.CellObservation) ([32]byte, error) {
	observation.ObservedUnix = 0
	payload, err := json.Marshal(observation)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

func (agent *Agent) fetchPlan(ctx context.Context) (cellplan.Envelope, cellplan.Plan, error) {
	endpoint := *agent.baseURL
	endpoint.Path = "/v1/cells/" + url.PathEscape(agent.cfg.CellID) + "/plan"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return cellplan.Envelope{}, cellplan.Plan{}, err
	}
	response, err := agent.cfg.ManagerClient.Do(request)
	if err != nil {
		return cellplan.Envelope{}, cellplan.Plan{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return cellplan.Envelope{}, cellplan.Plan{}, responseError("fetch manager plan", response)
	}
	var envelope cellplan.Envelope
	if err := decodeStrict(response.Body, 4<<20, &envelope); err != nil {
		return cellplan.Envelope{}, cellplan.Plan{}, err
	}
	plan, _, err := cellplan.Verify(agent.cfg.PlanPublicKey, envelope, agent.cfg.CellID, agent.cfg.Now().UTC(), agent.cfg.ClockSkew, agent.cfg.PlanLifetime)
	if err != nil {
		return cellplan.Envelope{}, cellplan.Plan{}, fmt.Errorf("verify manager plan: %w", err)
	}
	return envelope, plan, nil
}

func (agent *Agent) reconcile(ctx context.Context, envelope cellplan.Envelope) (controlplane.CellObservation, error) {
	payload, err := json.Marshal(envelope)
	if err != nil {
		return controlplane.CellObservation{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/reconcile", bytes.NewReader(payload))
	if err != nil {
		return controlplane.CellObservation{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := agent.cfg.HelperClient.Do(request)
	if err != nil {
		return controlplane.CellObservation{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return controlplane.CellObservation{}, responseError("reconcile local cell", response)
	}
	var observation controlplane.CellObservation
	if err := decodeStrict(response.Body, 4<<20, &observation); err != nil {
		return controlplane.CellObservation{}, err
	}
	return observation, nil
}

func (agent *Agent) observe(ctx context.Context, observation controlplane.CellObservation) error {
	payload, err := json.Marshal(observation)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	endpoint := *agent.baseURL
	endpoint.Path = "/v1/cells/" + url.PathEscape(agent.cfg.CellID) + "/observations"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "cell-observation-"+hex.EncodeToString(digest[:]))
	response, err := agent.cfg.ManagerClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return responseError("report cell observation", response)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	return err
}

func decodeStrict(reader io.Reader, limit int64, target any) error {
	if limit <= 0 {
		return ErrInvalid
	}
	payload, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || int64(len(payload)) > limit {
		return fmt.Errorf("%w: JSON body exceeds limit", ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: malformed JSON", ErrInvalid)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON", ErrInvalid)
	}
	return nil
}

func responseError(operation string, response *http.Response) error {
	detail, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	message := strings.TrimSpace(string(detail))
	if message == "" {
		message = http.StatusText(response.StatusCode)
	}
	return fmt.Errorf("cellagent: %s: HTTP %d: %s", operation, response.StatusCode, message)
}
