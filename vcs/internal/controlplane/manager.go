package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/productauth"
	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
)

type ManagerConfig struct {
	Store                 *Store
	PlanPrivateKey        ed25519.PrivateKey
	CapabilityPrivateKey  ed25519.PrivateKey
	ProductIssuers        map[string]ed25519.PublicKey
	AuthorityCA           *CertificateAuthority
	ClientCA              *CertificateAuthority
	EnrollmentCA          *CertificateAuthority
	Now                   func() time.Time
	ReleaseID             string
	PlanLifetime          time.Duration
	GrantLifetime         time.Duration
	EnrollmentLifetime    time.Duration
	ProductMaxLifetime    time.Duration
	ClientCertLifetime    time.Duration
	AuthorityCertLifetime time.Duration
	ObservedStaleAfter    time.Duration
	ClockSkew             time.Duration
}

type Manager struct {
	cfg                    ManagerConfig
	planPublicKeyPEM       string
	capabilityPublicKeyPEM string
	heartbeatMu            sync.RWMutex
	heartbeats             map[string]CellHeartbeat
}

const mountEnrollmentRetention = 15 * time.Minute

func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Store == nil || len(cfg.PlanPrivateKey) != ed25519.PrivateKeySize ||
		len(cfg.CapabilityPrivateKey) != ed25519.PrivateKeySize || len(cfg.ProductIssuers) == 0 ||
		cfg.AuthorityCA == nil || cfg.AuthorityCA.Certificate == nil || cfg.AuthorityCA.Signer == nil ||
		cfg.ClientCA == nil || cfg.ClientCA.Certificate == nil || cfg.ClientCA.Signer == nil || !validIdentity(cfg.ReleaseID) ||
		cfg.EnrollmentCA == nil || cfg.EnrollmentCA.Certificate == nil || cfg.EnrollmentCA.Signer == nil ||
		len(cfg.AuthorityCA.CertificatePEM) == 0 || len(cfg.AuthorityCA.CertificatePEM) > 4096 ||
		len(cfg.ClientCA.CertificatePEM) == 0 || len(cfg.ClientCA.CertificatePEM) > 4096 ||
		len(cfg.EnrollmentCA.CertificatePEM) == 0 || len(cfg.EnrollmentCA.CertificatePEM) > 4096 ||
		cfg.PlanLifetime <= 0 || cfg.GrantLifetime <= 0 || cfg.EnrollmentLifetime <= cfg.GrantLifetime || cfg.ProductMaxLifetime <= 0 ||
		cfg.ClientCertLifetime <= 0 || cfg.AuthorityCertLifetime <= 0 || cfg.ObservedStaleAfter <= 0 || cfg.ClockSkew < 0 {
		return nil, ErrInvalid
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	now := cfg.Now().UTC()
	if now.IsZero() || now.Before(cfg.AuthorityCA.Certificate.NotBefore) || !now.Before(cfg.AuthorityCA.Certificate.NotAfter) ||
		now.Before(cfg.ClientCA.Certificate.NotBefore) || !now.Before(cfg.ClientCA.Certificate.NotAfter) {
		return nil, ErrInvalid
	}
	if now.Before(cfg.EnrollmentCA.Certificate.NotBefore) || !now.Before(cfg.EnrollmentCA.Certificate.NotAfter) {
		return nil, ErrInvalid
	}
	for issuer, key := range cfg.ProductIssuers {
		if !validIdentity(issuer) || len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
	}
	planPEM, err := PublicKeyPEM(cfg.PlanPrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	capabilityPEM, err := PublicKeyPEM(cfg.CapabilityPrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	return &Manager{cfg: cfg, planPublicKeyPEM: planPEM, capabilityPublicKeyPEM: capabilityPEM, heartbeats: make(map[string]CellHeartbeat)}, nil
}

func (manager *Manager) RegisterCell(requestID string, request RegisterCellRequest) (Cell, error) {
	request.AvailabilityZone = strings.TrimSpace(request.AvailabilityZone)
	request.AuthorityHost = strings.ToLower(strings.TrimSpace(request.AuthorityHost))
	request.AuthorityDNSZone = strings.ToLower(strings.TrimSpace(request.AuthorityDNSZone))
	if request.ID == "" {
		request.ID = newUUID()
	}
	if !cellplan.ValidID(request.ID) || !validIdentity(request.AvailabilityZone) ||
		net.ParseIP(request.AuthorityHost) == nil && !validDNSName(request.AuthorityHost) ||
		!validDNSName(request.AuthorityDNSZone) || request.CapacityBytes == 0 || request.CapacityInodes == 0 {
		return Cell{}, ErrInvalid
	}
	if request.FirstProjectID == 0 {
		request.FirstProjectID = 10_000
	}
	if request.FirstServiceUID == 0 {
		request.FirstServiceUID = 200_000
	}
	if request.FirstPort == 0 {
		request.FirstPort = 20_000
	}
	now := nowUnix(manager.cfg.Now)
	raw, _, err := manager.cfg.Store.Transact(requestID, "register-cell", request, now, func(state *State) (any, error) {
		if _, exists := state.Cells[request.ID]; exists {
			return nil, ErrConflict
		}
		cell := Cell{
			ID: request.ID, AvailabilityZone: request.AvailabilityZone, AuthorityHost: request.AuthorityHost,
			AuthorityDNSZone: request.AuthorityDNSZone, CapacityBytes: request.CapacityBytes, CapacityInodes: request.CapacityInodes,
			NextProjectID: request.FirstProjectID, NextServiceUID: request.FirstServiceUID, NextPort: request.FirstPort,
			PlanGeneration: 1, PlanReleaseID: manager.cfg.ReleaseID,
			PlanIssuedUnix: now, PlanExpiresUnix: now + int64(manager.cfg.PlanLifetime/time.Second),
			Health: CellUnknown,
		}
		state.Cells[cell.ID] = cell
		return cell, nil
	})
	if err != nil {
		return Cell{}, err
	}
	return decode[Cell](raw)
}

// HeartbeatCell refreshes live admission health without appending a durable
// full-state record. Desired/observed changes still use ObserveCell; after a
// manager restart, mounts fail closed until the next authenticated heartbeat.
func (manager *Manager) HeartbeatCell(heartbeat CellHeartbeat) error {
	now := manager.cfg.Now().UTC()
	if !cellplan.ValidID(heartbeat.CellID) || heartbeat.PlanGeneration == 0 || heartbeat.ManagerReleaseID != manager.cfg.ReleaseID ||
		!validIdentity(heartbeat.AgentReleaseID) || !validIdentity(heartbeat.HelperReleaseID) || heartbeat.ObservedUnix <= 0 ||
		time.Unix(heartbeat.ObservedUnix, 0).After(now.Add(manager.cfg.ClockSkew)) {
		return ErrInvalid
	}
	if err := manager.cfg.Store.View(func(state State) error {
		cell, ok := state.Cells[heartbeat.CellID]
		if !ok {
			return ErrNotFound
		}
		if cell.PlanGeneration != heartbeat.PlanGeneration || cell.Health == CellQuarantined {
			return ErrConflict
		}
		return nil
	}); err != nil {
		return err
	}
	manager.recordHeartbeat(heartbeat)
	return nil
}

func (manager *Manager) recordHeartbeat(heartbeat CellHeartbeat) {
	manager.heartbeatMu.Lock()
	defer manager.heartbeatMu.Unlock()
	previous := manager.heartbeats[heartbeat.CellID]
	if heartbeat.ObservedUnix >= previous.ObservedUnix {
		manager.heartbeats[heartbeat.CellID] = heartbeat
	}
}

func (manager *Manager) cellFresh(cell Cell, now int64) bool {
	manager.heartbeatMu.RLock()
	heartbeat := manager.heartbeats[cell.ID]
	manager.heartbeatMu.RUnlock()
	return heartbeat.CellID == cell.ID && heartbeat.PlanGeneration == cell.PlanGeneration &&
		heartbeat.ManagerReleaseID == manager.cfg.ReleaseID && heartbeat.AgentReleaseID != "" && heartbeat.HelperReleaseID != "" &&
		now-heartbeat.ObservedUnix <= int64(manager.cfg.ObservedStaleAfter/time.Second)
}

func (manager *Manager) CreateVolume(requestID string, request CreateVolumeRequest) (VolumeView, error) {
	request.AuthorizationDomain = strings.TrimSpace(request.AuthorizationDomain)
	request.Owner = strings.TrimSpace(request.Owner)
	request.ProductIssuer = strings.TrimSpace(request.ProductIssuer)
	productKey := manager.cfg.ProductIssuers[request.ProductIssuer]
	if !validIdentity(request.AuthorizationDomain) || !validIdentity(request.Owner) || !validIdentity(request.ProductIssuer) || len(productKey) != ed25519.PublicKeySize ||
		request.QuotaBytes == 0 || request.QuotaBytes%1024 != 0 || request.QuotaInodes == 0 {
		return VolumeView{}, ErrInvalid
	}
	productPEM, err := PublicKeyPEM(productKey)
	if err != nil {
		return VolumeView{}, err
	}
	now := nowUnix(manager.cfg.Now)
	raw, _, err := manager.cfg.Store.Transact(requestID, "create-volume", request, now, func(state *State) (any, error) {
		volumeCounts := make(map[string]int, len(state.Cells))
		for _, volume := range state.Volumes {
			volumeCounts[volume.CellID]++
		}
		var selected *Cell
		for _, id := range sortedCellIDs(state.Cells) {
			cell := state.Cells[id]
			if cell.Health == CellQuarantined || cell.CapacityBytes-cell.AllocatedBytes < request.QuotaBytes ||
				cell.CapacityInodes-cell.AllocatedInodes < request.QuotaInodes || cell.NextProjectID == ^uint32(0) ||
				cell.NextServiceUID == ^uint32(0) || cell.NextPort == ^uint16(0) || volumeCounts[id] >= MaxVolumesPerCell {
				continue
			}
			selected = &cell
			break
		}
		if selected == nil {
			return nil, ErrCapacity
		}
		id := newUUID()
		compactID := strings.ReplaceAll(id, "-", "")
		serverName := "v-" + compactID + "." + selected.AuthorityDNSZone
		volume := Volume{
			ID: id, AuthorizationDomain: request.AuthorizationDomain, Owner: request.Owner,
			ProductIssuer: request.ProductIssuer, ProductPublicKeyPEM: productPEM, CellID: selected.ID,
			QuotaBytes: request.QuotaBytes, QuotaInodes: request.QuotaInodes,
			ProjectID: selected.NextProjectID, ServiceUID: selected.NextServiceUID, ServiceGID: selected.NextServiceUID,
			ListenPort: selected.NextPort, AuthorityID: serverName, AuthorityServerName: serverName,
			AuthorityGeneration: 1, State: VolumeProvisioning, CreatedUnix: now, UpdatedUnix: now,
		}
		selected.NextProjectID++
		selected.NextServiceUID++
		selected.NextPort++
		selected.AllocatedBytes += request.QuotaBytes
		selected.AllocatedInodes += request.QuotaInodes
		manager.bumpPlan(selected, now)
		state.Cells[selected.ID] = *selected
		state.Volumes[id] = volume
		return state.volumeView(volume), nil
	})
	if err != nil {
		return VolumeView{}, err
	}
	return decode[VolumeView](raw)
}

func (manager *Manager) GetVolume(id string) (VolumeView, error) {
	var result VolumeView
	err := manager.cfg.Store.View(func(state State) error {
		volume, ok := state.Volumes[id]
		if !ok {
			return ErrNotFound
		}
		result = state.volumeView(volume)
		return nil
	})
	return result, err
}

func (manager *Manager) RestartVolume(requestID string, request RestartVolumeRequest) (VolumeView, error) {
	if !cellplan.ValidID(request.VolumeID) || strings.TrimSpace(request.Reason) == "" {
		return VolumeView{}, ErrInvalid
	}
	return manager.updateVolume(requestID, "restart-volume", request, func(state *State, volume *Volume, now int64) error {
		if volume.State != VolumeReady {
			return ErrConflict
		}
		volume.State = VolumeFencing
		volume.PriorStrictFenced = false
		volume.StrictFenceEvidence = ""
		volume.UpdatedUnix = now
		terminateVolumeEnrollments(state, volume.ID, "authority restart", now)
		cell := state.Cells[volume.CellID]
		manager.bumpPlan(&cell, now)
		state.Cells[cell.ID] = cell
		return nil
	})
}

func (manager *Manager) ConfirmStrictMountsFenced(requestID string, request ConfirmStrictFenceRequest) (VolumeView, error) {
	if !cellplan.ValidID(request.VolumeID) || len(request.EvidenceSHA256) != 64 {
		return VolumeView{}, ErrInvalid
	}
	if _, err := hex.DecodeString(request.EvidenceSHA256); err != nil || strings.ToLower(request.EvidenceSHA256) != request.EvidenceSHA256 {
		return VolumeView{}, ErrInvalid
	}
	return manager.updateVolume(requestID, "confirm-strict-fence", request, func(state *State, volume *Volume, now int64) error {
		if volume.State != VolumeFencing {
			return ErrConflict
		}
		volume.PriorStrictFenced = true
		volume.StrictFenceEvidence = request.EvidenceSHA256
		volume.UpdatedUnix = now
		cell := state.Cells[volume.CellID]
		manager.bumpPlan(&cell, now)
		state.Cells[cell.ID] = cell
		return nil
	})
}

func (manager *Manager) RetireVolume(requestID string, request RetireVolumeRequest) (VolumeView, error) {
	if !cellplan.ValidID(request.VolumeID) || strings.TrimSpace(request.Reason) == "" {
		return VolumeView{}, ErrInvalid
	}
	return manager.updateVolume(requestID, "retire-volume", request, func(state *State, volume *Volume, now int64) error {
		if volume.State == VolumeRetired {
			return ErrConflict
		}
		volume.State = VolumeRetired
		volume.UpdatedUnix = now
		terminateVolumeEnrollments(state, volume.ID, "volume retired", now)
		cell := state.Cells[volume.CellID]
		manager.bumpPlan(&cell, now)
		state.Cells[cell.ID] = cell
		return nil
	})
}

func (manager *Manager) updateVolume(requestID, operation string, request any, apply func(*State, *Volume, int64) error) (VolumeView, error) {
	now := nowUnix(manager.cfg.Now)
	raw, _, err := manager.cfg.Store.Transact(requestID, operation, request, now, func(state *State) (any, error) {
		pruneMountEnrollments(state, now)
		volumeID := ""
		switch typed := request.(type) {
		case RestartVolumeRequest:
			volumeID = typed.VolumeID
		case ConfirmStrictFenceRequest:
			volumeID = typed.VolumeID
		case RetireVolumeRequest:
			volumeID = typed.VolumeID
		}
		volume, ok := state.Volumes[volumeID]
		if !ok {
			return nil, ErrNotFound
		}
		if err := apply(state, &volume, now); err != nil {
			return nil, err
		}
		state.Volumes[volume.ID] = volume
		return state.volumeView(volume), nil
	})
	if err != nil {
		return VolumeView{}, err
	}
	return decode[VolumeView](raw)
}

func (manager *Manager) ObserveCell(requestID string, observation CellObservation) (Cell, error) {
	if !cellplan.ValidID(observation.CellID) || observation.PlanGeneration == 0 || !validIdentity(observation.ManagerReleaseID) ||
		!validIdentity(observation.AgentReleaseID) || !validIdentity(observation.HelperReleaseID) || observation.ObservedUnix <= 0 {
		return Cell{}, ErrInvalid
	}
	nowTime := manager.cfg.Now().UTC()
	if time.Unix(observation.ObservedUnix, 0).After(nowTime.Add(manager.cfg.ClockSkew)) {
		return Cell{}, ErrInvalid
	}
	now := nowTime.Unix()
	raw, _, err := manager.cfg.Store.Transact(requestID, "observe-cell", observation, now, func(state *State) (any, error) {
		cell, ok := state.Cells[observation.CellID]
		if !ok {
			return nil, ErrNotFound
		}
		cell.LastObservedUnix = observation.ObservedUnix
		cell.LastManagerRelease = observation.ManagerReleaseID
		cell.LastAgentRelease = observation.AgentReleaseID
		cell.LastHelperRelease = observation.HelperReleaseID
		cell.Health = CellHealthy
		cell.QuarantineReason = ""
		if observation.PlanGeneration > cell.PlanGeneration {
			cell.Health = CellQuarantined
			cell.QuarantineReason = "cell reported a plan generation the manager never issued"
			state.Cells[cell.ID] = cell
			return cell, nil
		}
		if observation.PlanGeneration < cell.PlanGeneration || observation.ManagerReleaseID != manager.cfg.ReleaseID {
			cell.Health = CellDegraded
			if observation.ManagerReleaseID != manager.cfg.ReleaseID {
				cell.QuarantineReason = "cell applied a plan from a different manager release"
			}
			state.Cells[cell.ID] = cell
			return cell, nil
		}
		seen := make(map[string]struct{}, len(observation.Volumes))
		for _, observed := range observation.Volumes {
			volume, exists := state.Volumes[observed.VolumeID]
			if !exists || volume.CellID != cell.ID {
				cell.Health = CellQuarantined
				cell.QuarantineReason = "cell reported an unassigned volume"
				for id, assigned := range state.Volumes {
					if assigned.CellID == cell.ID && assigned.State != VolumeRetired {
						manager.quarantineVolume(state, &assigned, "cell reported an unassigned volume", now)
						state.Volumes[id] = assigned
					}
				}
				manager.bumpPlan(&cell, now)
				continue
			}
			if _, duplicate := seen[volume.ID]; duplicate {
				cell.Health = CellQuarantined
				cell.QuarantineReason = "cell reported a duplicate volume observation"
				manager.quarantineVolume(state, &volume, "cell reported a duplicate volume observation", now)
				manager.bumpPlan(&cell, now)
				state.Volumes[volume.ID] = volume
				continue
			}
			seen[volume.ID] = struct{}{}
			if observed.ProjectID != volume.ProjectID || observed.ServiceUID != volume.ServiceUID ||
				observed.ServiceGID != volume.ServiceGID || observed.ListenPort != volume.ListenPort {
				manager.quarantineVolume(state, &volume, "observed isolation identifiers differ from the signed assignment", now)
				manager.bumpPlan(&cell, now)
				state.Volumes[volume.ID] = volume
				cell.Health = CellQuarantined
				continue
			}
			if observed.AuthorityGeneration != volume.AuthorityGeneration || observed.AuthorityRunning && !observed.Provisioned ||
				observed.AuthorityRunning && observed.AuthorityAbsent {
				manager.quarantineVolume(state, &volume, "observed authority identity or lifecycle state is impossible", now)
				manager.bumpPlan(&cell, now)
				state.Volumes[volume.ID] = volume
				cell.Health = CellQuarantined
				continue
			}
			if observed.Error != "" {
				// Host-operation failures fail closed and remain retryable. Identity
				// substitutions are quarantined by the exact checks above; treating a
				// transient xfs_quota/systemd failure as identity corruption would
				// strand the volume with no safe reconciliation path.
				if volume.State == VolumeReady {
					volume.State = VolumeFencing
					volume.PriorStrictFenced = false
					volume.StrictFenceEvidence = ""
					volume.UpdatedUnix = now
					manager.bumpPlan(&cell, now)
				}
				state.Volumes[volume.ID] = volume
				cell.Health = CellDegraded
				continue
			}
			volume.LastObservedUnix = observation.ObservedUnix
			if volume.State == VolumeProvisioning || volume.State == VolumeReady {
				if observed.AuthorityCSRPEM != "" && volume.AuthorityCSRPEM != "" && observed.AuthorityCSRPEM != volume.AuthorityCSRPEM {
					manager.quarantineVolume(state, &volume, "authority CSR changed within one authority generation", now)
					manager.bumpPlan(&cell, now)
					cell.Health = CellQuarantined
					state.Volumes[volume.ID] = volume
					continue
				}
				certificateNeedsRenewal := volume.AuthorityCertificate == "" ||
					volume.AuthorityCertExpires <= now+int64(manager.cfg.AuthorityCertLifetime/3/time.Second)
				if observed.AuthorityCSRPEM != "" && certificateNeedsRenewal {
					certificate, expires, err := manager.cfg.AuthorityCA.SignCSR([]byte(observed.AuthorityCSRPEM), volume.AuthorityID,
						[]string{volume.AuthorityServerName}, false, nowTime, manager.cfg.AuthorityCertLifetime)
					if err != nil {
						manager.quarantineVolume(state, &volume, "authority CSR proof of possession is invalid", now)
						manager.bumpPlan(&cell, now)
						cell.Health = CellQuarantined
						state.Volumes[volume.ID] = volume
						continue
					}
					volume.AuthorityCSRPEM = observed.AuthorityCSRPEM
					volume.AuthorityCertificate = certificate
					volume.AuthorityCertExpires = expires.Unix()
					volume.UpdatedUnix = now
					manager.bumpPlan(&cell, now)
				}
			}
			switch volume.State {
			case VolumeProvisioning:
				if volume.AuthorityCertificate != "" && observed.Provisioned && observed.AuthorityRunning {
					volume.State = VolumeReady
					volume.UpdatedUnix = now
				}
			case VolumeReady:
				if observed.AuthorityGeneration != volume.AuthorityGeneration || !observed.AuthorityRunning {
					volume.State = VolumeFencing
					volume.PriorStrictFenced = false
					volume.StrictFenceEvidence = ""
					volume.UpdatedUnix = now
					manager.bumpPlan(&cell, now)
					cell.Health = CellDegraded
				}
			case VolumeFencing:
				if observed.AuthorityRunning {
					break
				}
				if observed.AuthorityAbsent && volume.PriorStrictFenced {
					terminateVolumeEnrollments(state, volume.ID, "authority generation changed", now)
					volume.AuthorityGeneration++
					volume.AuthorityCSRPEM = ""
					volume.AuthorityCertificate = ""
					volume.AuthorityCertExpires = 0
					volume.State = VolumeProvisioning
					volume.UpdatedUnix = now
					manager.bumpPlan(&cell, now)
				}
			}
			state.Volumes[volume.ID] = volume
		}
		for id, volume := range state.Volumes {
			if volume.CellID != cell.ID {
				continue
			}
			if _, present := seen[id]; !present {
				cell.Health = CellQuarantined
				cell.QuarantineReason = "cell omitted an assigned volume observation"
				manager.quarantineVolume(state, &volume, "cell omitted an assigned volume observation", now)
				manager.bumpPlan(&cell, now)
				state.Volumes[id] = volume
			}
		}
		state.Cells[cell.ID] = cell
		return cell, nil
	})
	if err != nil {
		return Cell{}, err
	}
	cell, err := decode[Cell](raw)
	if err == nil {
		manager.recordHeartbeat(CellHeartbeat{
			CellID: observation.CellID, PlanGeneration: observation.PlanGeneration,
			ManagerReleaseID: observation.ManagerReleaseID, AgentReleaseID: observation.AgentReleaseID,
			HelperReleaseID: observation.HelperReleaseID, ObservedUnix: observation.ObservedUnix,
		})
	}
	return cell, err
}

func (manager *Manager) CellPlan(cellID string) (cellplan.Envelope, error) {
	if !cellplan.ValidID(cellID) {
		return cellplan.Envelope{}, ErrInvalid
	}
	now := nowUnix(manager.cfg.Now)
	// Refreshing an expiring plan or changing the manager release is durable
	// desired-state evolution. A release is part of the signed plan, so signing
	// a new release under an old generation would look like equivocation to the
	// helper and correctly be refused. The deterministic key makes concurrent
	// agent polls converge on one exact generation and one exact signed payload.
	var current Cell
	if err := manager.cfg.Store.View(func(state State) error {
		cell, ok := state.Cells[cellID]
		if !ok {
			return ErrNotFound
		}
		current = cell
		return nil
	}); err != nil {
		return cellplan.Envelope{}, err
	}
	if current.PlanReleaseID != manager.cfg.ReleaseID ||
		now+int64(manager.cfg.PlanLifetime/time.Second)/3 >= current.PlanExpiresUnix {
		requestID := fmt.Sprintf("internal-plan-refresh:%s:%d:%s", cellID, current.PlanGeneration, manager.cfg.ReleaseID)
		_, _, err := manager.cfg.Store.Transact(requestID, "refresh-cell-plan", struct {
			CellID     string `json:"cell_id"`
			Generation uint64 `json:"generation"`
			ReleaseID  string `json:"release_id"`
		}{cellID, current.PlanGeneration, manager.cfg.ReleaseID}, now, func(state *State) (any, error) {
			cell, ok := state.Cells[cellID]
			if !ok {
				return nil, ErrNotFound
			}
			if cell.PlanGeneration == current.PlanGeneration &&
				(cell.PlanReleaseID != manager.cfg.ReleaseID ||
					now+int64(manager.cfg.PlanLifetime/time.Second)/3 >= cell.PlanExpiresUnix) {
				manager.bumpPlan(&cell, now)
				state.Cells[cellID] = cell
			}
			for id := range state.Receipts {
				if strings.HasPrefix(id, "internal-plan-refresh:"+cellID+":") {
					delete(state.Receipts, id)
				}
			}
			return cell, nil
		})
		if err != nil {
			return cellplan.Envelope{}, err
		}
	}
	var plan cellplan.Plan
	err := manager.cfg.Store.View(func(state State) error {
		cell, ok := state.Cells[cellID]
		if !ok {
			return ErrNotFound
		}
		plan = cellplan.Plan{
			Version: cellplan.Version, CellID: cell.ID, Generation: cell.PlanGeneration,
			IssuedAt: cell.PlanIssuedUnix, ExpiresAt: cell.PlanExpiresUnix, ReleaseID: manager.cfg.ReleaseID,
		}
		for _, volume := range state.Volumes {
			if volume.CellID != cellID {
				continue
			}
			phase := cellplan.PhaseProvision
			switch volume.State {
			case VolumeReady:
				phase = cellplan.PhaseServe
			case VolumeProvisioning:
				if volume.AuthorityCertificate != "" {
					phase = cellplan.PhaseServe
				}
			case VolumeFencing, VolumeQuarantined:
				phase = cellplan.PhaseFence
			case VolumeRetired:
				phase = cellplan.PhaseRetire
			}
			plan.Volumes = append(plan.Volumes, cellplan.VolumePlan{
				VolumeID: volume.ID, Phase: phase, AuthorizationDomain: volume.AuthorizationDomain, Owner: volume.Owner,
				ProductIssuer: volume.ProductIssuer, ProductPublicKeyPEM: volume.ProductPublicKeyPEM,
				AuthorityID: volume.AuthorityID, AuthorityGeneration: volume.AuthorityGeneration,
				ProjectID: volume.ProjectID, ServiceUID: volume.ServiceUID, ServiceGID: volume.ServiceGID,
				ListenPort: volume.ListenPort, QuotaBytes: volume.QuotaBytes, QuotaInodes: volume.QuotaInodes,
				AuthorityServerName: volume.AuthorityServerName, AuthorityCertificate: volume.AuthorityCertificate,
				AuthorityCAPEM: manager.cfg.AuthorityCA.CertificatePEM, ClientCAPEM: manager.cfg.ClientCA.CertificatePEM,
				CapabilityPublicKey: manager.capabilityPublicKeyPEM, PriorStrictFenced: volume.PriorStrictFenced,
			})
		}
		slicesSortVolumePlans(plan.Volumes)
		return nil
	})
	if err != nil {
		return cellplan.Envelope{}, err
	}
	return cellplan.Sign(manager.cfg.PlanPrivateKey, plan)
}

func (manager *Manager) IssueMount(requestID string, request IssueMountRequest) (MountAuthorization, error) {
	return manager.issueMount(requestID, "issue-mount", request.VolumeID, request.ProductAuthorization, request.ClientCSRPEM, request.Access, "", 0, request, request.AutomaticReauthorization)
}

func (manager *Manager) ReauthorizeMount(requestID string, request ReauthorizeMountRequest) (MountAuthorization, error) {
	if request.Sequence == 0 {
		return MountAuthorization{}, ErrInvalid
	}
	session, err := base64.RawURLEncoding.DecodeString(request.SessionID)
	if err != nil || len(session) != 16 {
		return MountAuthorization{}, ErrInvalid
	}
	return manager.issueMount(requestID, "reauthorize-mount", request.VolumeID, request.ProductAuthorization, request.ClientCSRPEM, request.Access, request.SessionID, request.Sequence, request, false)
}

func (manager *Manager) issueMount(requestID, operation, volumeID, productToken, csrPEM string, access []string, sessionID string, sequence uint64, request any, createEnrollment bool) (MountAuthorization, error) {
	if !cellplan.ValidID(volumeID) || productToken == "" || csrPEM == "" || !validAccess(access) {
		return MountAuthorization{}, ErrInvalid
	}
	peer, err := ParseCSRSPKI([]byte(csrPEM))
	if err != nil {
		return MountAuthorization{}, err
	}
	nowTime := manager.cfg.Now().UTC()
	now := nowTime.Unix()
	raw, _, err := manager.cfg.Store.Transact(requestID, operation, request, now, func(state *State) (any, error) {
		pruneMountEnrollments(state, now)
		for key, nonce := range state.AuthorizationNonces {
			if nonce.ExpiresUnix <= now {
				delete(state.AuthorizationNonces, key)
			}
		}
		volume, ok := state.Volumes[volumeID]
		if !ok {
			return nil, ErrNotFound
		}
		cell := state.Cells[volume.CellID]
		if volume.State != VolumeReady || cell.Health != CellHealthy || !manager.cellFresh(cell, now) {
			return nil, ErrConflict
		}
		// Once an enrollment binds sequence one, Manager refuses another issuer
		// for that exact session. An unbound enrollment cannot identify a session;
		// treating it as volume-wide ownership would let an abandoned enrollment
		// deny renewal to every unrelated mount. The authority already pins the
		// enrollment ID at initial attach and refuses a wrong issuer without
		// fencing, which closes that pre-bind race without a volume-wide lockout.
		if sessionID != "" {
			for _, enrollment := range state.MountEnrollments {
				if enrollment.State == MountEnrollmentActive && now < enrollment.ExpiresUnix &&
					enrollment.VolumeID == volumeID && enrollment.SessionID == sessionID {
					return nil, ErrConflict
				}
			}
		}
		productKey := manager.cfg.ProductIssuers[volume.ProductIssuer]
		verified, err := productauth.Verify(productKey, []byte(productToken), productauth.Expectations{
			Issuer: volume.ProductIssuer, Audience: "portablefs-manager", AuthorizationDomain: volume.AuthorizationDomain,
			Owner: volume.Owner, VolumeID: volume.ID, PeerSPKI: peer, Now: nowTime,
			ClockSkew: manager.cfg.ClockSkew, MaxLifetime: manager.cfg.ProductMaxLifetime,
		})
		if err != nil || !productauth.Allows(verified.Claims.Access, access) {
			return nil, ErrInvalid
		}
		if verified.Claims.RenewalScope != "" {
			key := renewalFenceKey(volume.ProductIssuer, verified.Claims.RenewalScope)
			highWater := state.RenewalFences[key]
			if verified.Claims.RenewalEpoch < highWater {
				return nil, ErrRenewalScopeFenced
			}
			if verified.Claims.RenewalEpoch > highWater {
				var err error
				highWater, _, err = advanceRenewalFenceHighWater(state, key, verified.Claims.RenewalEpoch)
				if err != nil {
					return nil, err
				}
			}
			if createEnrollment {
				supersedeRenewalScopeEnrollments(state, volume.ProductIssuer, verified.Claims.RenewalScope, "renewal-scope-superseded", now)
			} else {
				revokeRenewalScopeEnrollmentsBeforeEpoch(state, volume.ProductIssuer, verified.Claims.RenewalScope, highWater, "renewal-scope-superseded", now)
			}
		}
		nonceKey := volume.ProductIssuer + "\x00" + verified.Claims.Nonce
		if previous := state.AuthorizationNonces[nonceKey]; previous.RequestID != "" && previous.RequestID != requestID {
			return nil, ErrConflict
		}
		state.AuthorizationNonces[nonceKey] = AuthorizationNonce{RequestID: requestID, ExpiresUnix: verified.Claims.Expires}
		expires := nowTime.Add(manager.cfg.GrantLifetime)
		if productExpiry := time.Unix(verified.Claims.Expires, 0); productExpiry.Before(expires) {
			expires = productExpiry
		}
		var enrollmentID, enrollmentCertificate string
		var enrollmentExpires time.Time
		if createEnrollment {
			if err := admitMountEnrollment(state, volume); err != nil {
				return nil, err
			}
			enrollmentID = newUUID()
			identity, err := url.Parse("spiffe://portablefs/mount-enrollment/" + enrollmentID)
			if err != nil {
				return nil, err
			}
			enrollmentCertificate, enrollmentExpires, err = manager.cfg.EnrollmentCA.SignClientCSR(
				[]byte(csrPEM), enrollmentID, identity, nowTime, manager.cfg.EnrollmentLifetime,
			)
			if err != nil {
				return nil, err
			}
			if !enrollmentExpires.After(expires) {
				return nil, errors.New("mount enrollment CA cannot issue an enrollment that outlives the initial grant")
			}
		}
		clientName := base64.RawURLEncoding.EncodeToString(peer[:])
		certificate, certificateExpires, err := manager.cfg.ClientCA.SignCSR([]byte(csrPEM), clientName, nil, true, nowTime, manager.cfg.ClientCertLifetime)
		if err != nil {
			return nil, err
		}
		claims := volumecap.Claims{
			VolumeID: volume.ID, Subject: verified.Claims.Subject, Access: append([]string(nil), access...),
			NotBefore: nowTime.Add(-manager.cfg.ClockSkew).Unix(), Expires: expires.Unix(),
			PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: newNonce(),
			CellID: volume.CellID, AuthorityID: volume.AuthorityID, AuthorityGeneration: volume.AuthorityGeneration,
			ProductAuthorization: productToken, MountEnrollmentID: enrollmentID, SessionID: sessionID, Sequence: sequence,
		}
		capability, err := volumecap.Sign(manager.cfg.CapabilityPrivateKey, claims)
		if err != nil {
			return nil, err
		}
		authorization := MountAuthorization{
			VolumeID: volume.ID, AuthorityEndpoint: net.JoinHostPort(cell.AuthorityHost, fmt.Sprint(volume.ListenPort)),
			AuthorityServerName: volume.AuthorityServerName, AuthorityCAPEM: manager.cfg.AuthorityCA.CertificatePEM,
			ClientCertificatePEM: certificate, Capability: string(capability), Access: append([]string(nil), access...),
			ExpiresUnix: expires.Unix(), CertificateExpiresUnix: certificateExpires.Unix(), AuthorityGeneration: volume.AuthorityGeneration,
			SessionID: sessionID, Sequence: sequence, ReleaseID: manager.cfg.ReleaseID,
		}
		if createEnrollment {
			if state.MountEnrollments == nil {
				state.MountEnrollments = make(map[string]MountEnrollment)
			}
			state.MountEnrollments[enrollmentID] = MountEnrollment{
				ID: enrollmentID, VolumeID: volume.ID, Subject: verified.Claims.Subject, Owner: volume.Owner,
				Access: append([]string(nil), access...), PeerSPKI: hex.EncodeToString(peer[:]),
				AuthorizationDomain: volume.AuthorizationDomain, ProductIssuer: volume.ProductIssuer,
				CellID: volume.CellID, AuthorityID: volume.AuthorityID, AuthorityGeneration: volume.AuthorityGeneration,
				CreatedUnix: now, ExpiresUnix: enrollmentExpires.Unix(), State: MountEnrollmentActive, UpdatedUnix: now,
				RenewalScope: verified.Claims.RenewalScope, RenewalEpoch: verified.Claims.RenewalEpoch,
			}
			authorization.EnrollmentID = enrollmentID
			authorization.EnrollmentCertificatePEM = enrollmentCertificate
			authorization.EnrollmentExpiresUnix = enrollmentExpires.Unix()
		}
		return authorization, nil
	})
	if err != nil {
		return MountAuthorization{}, err
	}
	return decode[MountAuthorization](raw)
}

// RefreshMountEnrollment mints the exact next short-lived grant for one live
// session. The durable (session, sequence, request digest) tuple is the
// idempotency boundary, so an HTTP retry remains safe even if its transport
// idempotency key changes.
func (manager *Manager) RefreshMountEnrollment(requestID, enrollmentID string, request RefreshMountEnrollmentRequest) (MountAuthorization, error) {
	if !validIdentity(requestID) || !cellplan.ValidID(enrollmentID) || request.ClientCSRPEM == "" || request.Sequence == 0 {
		return MountAuthorization{}, ErrInvalid
	}
	session, err := base64.RawURLEncoding.DecodeString(request.SessionID)
	if err != nil || len(session) != 16 {
		return MountAuthorization{}, ErrInvalid
	}
	peer, err := ParseCSRSPKI([]byte(request.ClientCSRPEM))
	if err != nil {
		return MountAuthorization{}, err
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return MountAuthorization{}, err
	}
	requestSHA := sha256.Sum256(requestBytes)
	requestDigest := hex.EncodeToString(requestSHA[:])
	nowTime := manager.cfg.Now().UTC()
	now := nowTime.Unix()
	raw, err := manager.cfg.Store.TransactNatural("refresh-mount-enrollment", now, func(state *State) (any, bool, error) {
		pruned := pruneMountEnrollments(state, now)
		enrollment, ok := state.MountEnrollments[enrollmentID]
		if !ok {
			return nil, false, ErrNotFound
		}
		volume, volumeOK := state.Volumes[enrollment.VolumeID]
		cell, cellOK := state.Cells[enrollment.CellID]
		if enrollment.State != MountEnrollmentActive || now >= enrollment.ExpiresUnix || !volumeOK ||
			volume.AuthorityGeneration != enrollment.AuthorityGeneration || volume.AuthorityID != enrollment.AuthorityID {
			return nil, false, ErrEnrollmentEnded
		}
		if !cellOK || volume.State != VolumeReady || cell.Health != CellHealthy || !manager.cellFresh(cell, now) {
			return nil, false, ErrConflict
		}
		if enrollment.PeerSPKI != hex.EncodeToString(peer[:]) {
			return nil, false, ErrInvalid
		}
		if enrollment.SessionID == "" {
			if request.Sequence != 1 {
				return nil, false, ErrConflict
			}
			enrollment.SessionID = request.SessionID
		} else if enrollment.SessionID != request.SessionID {
			return nil, false, ErrConflict
		}
		if request.Sequence == enrollment.LastSequence {
			if enrollment.LastRequestSHA256 != requestDigest || enrollment.LastAuthorization == nil {
				return nil, false, ErrConflict
			}
			context, ok := state.MountAuthorizationContexts[enrollment.LastAuthorizationContext]
			if !ok {
				return nil, false, ErrInvalid
			}
			return replayMountAuthorization(enrollment, *enrollment.LastAuthorization, context), pruned, nil
		}
		if request.Sequence != enrollment.LastSequence+1 {
			return nil, false, ErrConflict
		}
		if request.Sequence > 1 && now < enrollment.UpdatedUnix+minimumEnrollmentRefreshInterval(manager.cfg.GrantLifetime) {
			return nil, false, ErrConflict
		}
		expires := nowTime.Add(manager.cfg.GrantLifetime)
		if enrollmentExpiry := time.Unix(enrollment.ExpiresUnix, 0); enrollmentExpiry.Before(expires) {
			expires = enrollmentExpiry
		}
		clientName := base64.RawURLEncoding.EncodeToString(peer[:])
		certificate, certificateExpires, err := manager.cfg.ClientCA.SignCSR(
			[]byte(request.ClientCSRPEM), clientName, nil, true, nowTime, manager.cfg.ClientCertLifetime,
		)
		if err != nil {
			return nil, false, err
		}
		claims := volumecap.Claims{
			VolumeID: enrollment.VolumeID, Subject: enrollment.Subject, Access: append([]string(nil), enrollment.Access...),
			NotBefore: nowTime.Add(-manager.cfg.ClockSkew).Unix(), Expires: expires.Unix(),
			PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: newNonce(),
			CellID: enrollment.CellID, AuthorityID: enrollment.AuthorityID, AuthorityGeneration: enrollment.AuthorityGeneration,
			MountEnrollmentID: enrollment.ID, SessionID: request.SessionID, Sequence: request.Sequence,
		}
		capability, err := volumecap.Sign(manager.cfg.CapabilityPrivateKey, claims)
		if err != nil {
			return nil, false, err
		}
		authorization := MountAuthorization{
			VolumeID: enrollment.VolumeID, AuthorityEndpoint: net.JoinHostPort(cell.AuthorityHost, fmt.Sprint(volume.ListenPort)),
			AuthorityServerName: volume.AuthorityServerName, AuthorityCAPEM: manager.cfg.AuthorityCA.CertificatePEM,
			ClientCertificatePEM: certificate, Capability: string(capability), Access: append([]string(nil), enrollment.Access...),
			ExpiresUnix: expires.Unix(), CertificateExpiresUnix: certificateExpires.Unix(), AuthorityGeneration: enrollment.AuthorityGeneration,
			SessionID: request.SessionID, Sequence: request.Sequence, ReleaseID: manager.cfg.ReleaseID,
		}
		enrollment.LastSequence = request.Sequence
		enrollment.LastRequestSHA256 = requestDigest
		replay := MountAuthorizationReplay{
			AuthorityEndpoint: authorization.AuthorityEndpoint, AuthorityServerName: authorization.AuthorityServerName,
			ClientCertificatePEM: authorization.ClientCertificatePEM, Capability: authorization.Capability,
			ExpiresUnix: authorization.ExpiresUnix, CertificateExpiresUnix: authorization.CertificateExpiresUnix,
			SessionID: authorization.SessionID, Sequence: authorization.Sequence,
		}
		context := MountAuthorizationContext{AuthorityCAPEM: authorization.AuthorityCAPEM, ReleaseID: authorization.ReleaseID}
		contextID := mountAuthorizationContextID(context)
		if state.MountAuthorizationContexts == nil {
			state.MountAuthorizationContexts = make(map[string]MountAuthorizationContext)
		}
		state.MountAuthorizationContexts[contextID] = context
		enrollment.LastAuthorization = &replay
		enrollment.LastAuthorizationContext = contextID
		enrollment.UpdatedUnix = now
		state.MountEnrollments[enrollmentID] = enrollment
		pruneMountAuthorizationContexts(state)
		return authorization, true, nil
	})
	if err != nil {
		return MountAuthorization{}, err
	}
	return decode[MountAuthorization](raw)
}

func (manager *Manager) CloseMountEnrollment(requestID, enrollmentID string, request TerminateMountEnrollmentRequest) (MountEnrollment, error) {
	return manager.terminateMountEnrollment(requestID, enrollmentID, request)
}

func (manager *Manager) RevokeVolumeMountEnrollment(productIssuer, volumeID, enrollmentID string, request TerminateMountEnrollmentRequest) (MountEnrollmentRevocation, error) {
	if !validIdentity(productIssuer) || !cellplan.ValidID(volumeID) || !cellplan.ValidID(enrollmentID) || !validIdentity(request.Reason) {
		return MountEnrollmentRevocation{}, ErrInvalid
	}
	now := nowUnix(manager.cfg.Now)
	raw, err := manager.cfg.Store.TransactNatural("revoke-volume-mount-enrollment", now, func(state *State) (any, bool, error) {
		pruned := pruneMountEnrollments(state, now)
		volume, ok := state.Volumes[volumeID]
		if !ok || volume.ProductIssuer != productIssuer {
			return nil, false, ErrNotFound
		}
		result := MountEnrollmentRevocation{VolumeID: volumeID, EnrollmentID: enrollmentID}
		enrollment, ok := state.MountEnrollments[enrollmentID]
		if !ok {
			result.Outcome = MountEnrollmentRevocationAbsent
			return result, pruned, nil
		}
		if enrollment.VolumeID != volumeID {
			return nil, false, ErrNotFound
		}
		switch enrollment.State {
		case MountEnrollmentClosed:
			result.Outcome = MountEnrollmentRevocationClosed
			return result, pruned, nil
		case MountEnrollmentRevoked:
			result.Outcome = MountEnrollmentRevocationRevoked
			return result, pruned, nil
		case MountEnrollmentActive:
			enrollment.State = MountEnrollmentRevoked
			enrollment.TerminationReason = request.Reason
			enrollment.UpdatedUnix = now
			state.MountEnrollments[enrollmentID] = enrollment
			result.Outcome = MountEnrollmentRevocationRevoked
			return result, true, nil
		default:
			return nil, false, ErrInvalid
		}
	})
	if err != nil {
		return MountEnrollmentRevocation{}, err
	}
	return decode[MountEnrollmentRevocation](raw)
}

func (manager *Manager) AdvanceRenewalFences(productIssuer string, request AdvanceRenewalFencesRequest) (AdvanceRenewalFencesResponse, error) {
	if !validIdentity(productIssuer) || len(manager.cfg.ProductIssuers[productIssuer]) != ed25519.PublicKeySize || !validIdentity(request.Reason) ||
		len(request.Fences) == 0 || len(request.Fences) > MaxRenewalFenceBatchEntries {
		return AdvanceRenewalFencesResponse{}, ErrInvalid
	}
	requestedHighWater := make(map[string]uint64, len(request.Fences))
	for _, fence := range request.Fences {
		if !validRenewalScope(fence.Scope) || fence.Epoch == 0 || fence.Epoch > productauth.MaxRenewalEpoch {
			return AdvanceRenewalFencesResponse{}, ErrInvalid
		}
		if fence.Epoch > requestedHighWater[fence.Scope] {
			requestedHighWater[fence.Scope] = fence.Epoch
		}
	}
	now := nowUnix(manager.cfg.Now)
	raw, err := manager.cfg.Store.TransactNatural("advance-renewal-fences", now, func(state *State) (any, bool, error) {
		newFences := 0
		for scope := range requestedHighWater {
			if _, exists := state.RenewalFences[renewalFenceKey(productIssuer, scope)]; !exists {
				newFences++
			}
		}
		if len(state.RenewalFences)+newFences > MaxRenewalFences {
			return nil, false, ErrRenewalFenceCapacity
		}
		changed := pruneMountEnrollments(state, now)
		for scope, epoch := range requestedHighWater {
			key := renewalFenceKey(productIssuer, scope)
			highWater, advanced, err := advanceRenewalFenceHighWater(state, key, epoch)
			if err != nil {
				return nil, false, err
			}
			changed = changed || advanced
			if revokeRenewalScopeEnrollmentsBeforeEpoch(state, productIssuer, scope, highWater, request.Reason, now) {
				changed = true
			}
		}
		response := AdvanceRenewalFencesResponse{Fences: make([]RenewalFence, 0, len(request.Fences))}
		for _, fence := range request.Fences {
			response.Fences = append(response.Fences, RenewalFence{
				Scope: fence.Scope, Epoch: state.RenewalFences[renewalFenceKey(productIssuer, fence.Scope)],
			})
		}
		return response, changed, nil
	})
	if err != nil {
		return AdvanceRenewalFencesResponse{}, err
	}
	return decode[AdvanceRenewalFencesResponse](raw)
}

func (manager *Manager) terminateMountEnrollment(requestID, enrollmentID string, request TerminateMountEnrollmentRequest) (MountEnrollment, error) {
	if !validIdentity(requestID) || !cellplan.ValidID(enrollmentID) || !validIdentity(request.Reason) {
		return MountEnrollment{}, ErrInvalid
	}
	now := nowUnix(manager.cfg.Now)
	raw, err := manager.cfg.Store.TransactNatural("terminate-mount-enrollment", now, func(state *State) (any, bool, error) {
		pruned := pruneMountEnrollments(state, now)
		enrollment, ok := state.MountEnrollments[enrollmentID]
		if !ok {
			return nil, false, ErrNotFound
		}
		if enrollment.State != MountEnrollmentActive {
			// The first terminal decision and reason are the durable audit fact.
			// Later close/revoke retries are hygiene and return that exact fact
			// without another state record or a reason-dependent conflict.
			return enrollment, pruned, nil
		}
		enrollment.State = MountEnrollmentClosed
		enrollment.TerminationReason = request.Reason
		enrollment.UpdatedUnix = now
		state.MountEnrollments[enrollmentID] = enrollment
		return enrollment, true, nil
	})
	if err != nil {
		return MountEnrollment{}, err
	}
	return decode[MountEnrollment](raw)
}

func (manager *Manager) ReleaseIdentity() string  { return manager.cfg.ReleaseID }
func (manager *Manager) PlanPublicKeyPEM() string { return manager.planPublicKeyPEM }

func (manager *Manager) bumpPlan(cell *Cell, now int64) {
	cell.PlanGeneration++
	cell.PlanReleaseID = manager.cfg.ReleaseID
	cell.PlanIssuedUnix = now
	cell.PlanExpiresUnix = now + int64(manager.cfg.PlanLifetime/time.Second)
}

func (manager *Manager) quarantineVolume(state *State, volume *Volume, reason string, now int64) {
	terminateVolumeEnrollments(state, volume.ID, reason, now)
	volume.State = VolumeQuarantined
	volume.QuarantineReason = reason
	volume.UpdatedUnix = now
}

func terminateVolumeEnrollments(state *State, volumeID, reason string, now int64) {
	for id, enrollment := range state.MountEnrollments {
		if enrollment.VolumeID != volumeID || enrollment.State != MountEnrollmentActive {
			continue
		}
		enrollment.State = MountEnrollmentRevoked
		enrollment.TerminationReason = reason
		enrollment.UpdatedUnix = now
		state.MountEnrollments[id] = enrollment
	}
}

func advanceRenewalFenceHighWater(state *State, key string, epoch uint64) (uint64, bool, error) {
	highWater, exists := state.RenewalFences[key]
	if epoch <= highWater {
		return highWater, false, nil
	}
	if !exists && len(state.RenewalFences) >= MaxRenewalFences {
		return 0, false, ErrRenewalFenceCapacity
	}
	if state.RenewalFences == nil {
		state.RenewalFences = make(map[string]uint64)
	}
	state.RenewalFences[key] = epoch
	return epoch, true, nil
}

func supersedeRenewalScopeEnrollments(state *State, productIssuer, scope, reason string, now int64) bool {
	changed := false
	for id, enrollment := range state.MountEnrollments {
		if enrollment.ProductIssuer != productIssuer || enrollment.RenewalScope != scope || enrollment.State != MountEnrollmentActive {
			continue
		}
		enrollment.State = MountEnrollmentRevoked
		enrollment.TerminationReason = reason
		enrollment.UpdatedUnix = now
		state.MountEnrollments[id] = enrollment
		changed = true
	}
	return changed
}

func revokeRenewalScopeEnrollmentsBeforeEpoch(state *State, productIssuer, scope string, epoch uint64, reason string, now int64) bool {
	changed := false
	for id, enrollment := range state.MountEnrollments {
		if enrollment.ProductIssuer != productIssuer || enrollment.RenewalScope != scope ||
			enrollment.RenewalEpoch >= epoch || enrollment.State != MountEnrollmentActive {
			continue
		}
		enrollment.State = MountEnrollmentRevoked
		enrollment.TerminationReason = reason
		enrollment.UpdatedUnix = now
		state.MountEnrollments[id] = enrollment
		changed = true
	}
	return changed
}

func admitMountEnrollment(state *State, volume Volume) error {
	activeTotal, activeAuthorizationDomain, activeVolume := 0, 0, 0
	for _, enrollment := range state.MountEnrollments {
		if enrollment.State != MountEnrollmentActive {
			continue
		}
		activeTotal++
		if enrollment.AuthorizationDomain == volume.AuthorizationDomain {
			activeAuthorizationDomain++
		}
		if enrollment.VolumeID == volume.ID {
			activeVolume++
		}
	}
	if activeTotal >= MaxActiveMountEnrollments || activeAuthorizationDomain >= MaxActiveMountEnrollmentsPerAuthorizationDomain ||
		activeVolume >= MaxActiveMountEnrollmentsPerVolume {
		return ErrEnrollmentCapacity
	}
	for len(state.MountEnrollments) >= MaxRetainedMountEnrollments {
		oldestID := ""
		var oldestUpdated int64
		for id, enrollment := range state.MountEnrollments {
			if enrollment.State == MountEnrollmentActive {
				continue
			}
			if oldestID == "" || enrollment.UpdatedUnix < oldestUpdated ||
				enrollment.UpdatedUnix == oldestUpdated && id < oldestID {
				oldestID, oldestUpdated = id, enrollment.UpdatedUnix
			}
		}
		if oldestID == "" {
			return ErrEnrollmentCapacity
		}
		delete(state.MountEnrollments, oldestID)
	}
	pruneMountAuthorizationContexts(state)
	return nil
}

func replayMountAuthorization(
	enrollment MountEnrollment,
	replay MountAuthorizationReplay,
	context MountAuthorizationContext,
) MountAuthorization {
	return MountAuthorization{
		VolumeID: enrollment.VolumeID, AuthorityEndpoint: replay.AuthorityEndpoint,
		AuthorityServerName: replay.AuthorityServerName, AuthorityCAPEM: context.AuthorityCAPEM,
		ClientCertificatePEM: replay.ClientCertificatePEM, Capability: replay.Capability,
		Access: append([]string(nil), enrollment.Access...), ExpiresUnix: replay.ExpiresUnix,
		CertificateExpiresUnix: replay.CertificateExpiresUnix, AuthorityGeneration: enrollment.AuthorityGeneration,
		SessionID: replay.SessionID, Sequence: replay.Sequence, ReleaseID: context.ReleaseID,
	}
}

func pruneMountEnrollments(state *State, now int64) bool {
	retention := int64(mountEnrollmentRetention / time.Second)
	changed := false
	for id, enrollment := range state.MountEnrollments {
		if enrollment.State == MountEnrollmentActive && enrollment.ExpiresUnix <= now ||
			enrollment.State != MountEnrollmentActive && enrollment.UpdatedUnix+retention <= now {
			delete(state.MountEnrollments, id)
			changed = true
		}
	}
	return pruneMountAuthorizationContexts(state) || changed
}

func pruneMountAuthorizationContexts(state *State) bool {
	referenced := make(map[string]struct{})
	for _, enrollment := range state.MountEnrollments {
		if enrollment.LastAuthorizationContext != "" {
			referenced[enrollment.LastAuthorizationContext] = struct{}{}
		}
	}
	changed := false
	for id := range state.MountAuthorizationContexts {
		if _, ok := referenced[id]; !ok {
			delete(state.MountAuthorizationContexts, id)
			changed = true
		}
	}
	return changed
}

func minimumEnrollmentRefreshInterval(grantLifetime time.Duration) int64 {
	seconds := int64(grantLifetime / (4 * time.Second))
	if seconds < 1 {
		return 1
	}
	return seconds
}

func validAccess(access []string) bool {
	if len(access) == 0 || len(access) > 3 {
		return false
	}
	for _, permission := range access {
		switch permission {
		case "read", "write", "admin":
		default:
			return false
		}
	}
	return true
}

func slicesSortVolumePlans(plans []cellplan.VolumePlan) {
	for i := 1; i < len(plans); i++ {
		for j := i; j > 0 && plans[j].VolumeID < plans[j-1].VolumeID; j-- {
			plans[j], plans[j-1] = plans[j-1], plans[j]
		}
	}
}

func newUUID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic("cryptographic random source unavailable: " + err.Error())
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	hexValue := hex.EncodeToString(raw[:])
	return hexValue[0:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:32]
}

func newNonce() string {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic("cryptographic random source unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func decode[T any](raw json.RawMessage) (T, error) {
	var value T
	err := json.Unmarshal(raw, &value)
	return value, err
}

func EvidenceHash(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
