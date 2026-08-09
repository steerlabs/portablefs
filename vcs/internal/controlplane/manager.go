package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
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
	Now                   func() time.Time
	ReleaseID             string
	PlanLifetime          time.Duration
	GrantLifetime         time.Duration
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

func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Store == nil || len(cfg.PlanPrivateKey) != ed25519.PrivateKeySize ||
		len(cfg.CapabilityPrivateKey) != ed25519.PrivateKeySize || len(cfg.ProductIssuers) == 0 ||
		cfg.AuthorityCA == nil || cfg.AuthorityCA.Certificate == nil || cfg.AuthorityCA.Signer == nil ||
		cfg.ClientCA == nil || cfg.ClientCA.Certificate == nil || cfg.ClientCA.Signer == nil || !validIdentity(cfg.ReleaseID) ||
		len(cfg.AuthorityCA.CertificatePEM) == 0 || len(cfg.AuthorityCA.CertificatePEM) > 4096 ||
		len(cfg.ClientCA.CertificatePEM) == 0 || len(cfg.ClientCA.CertificatePEM) > 4096 ||
		cfg.PlanLifetime <= 0 || cfg.GrantLifetime <= 0 || cfg.ProductMaxLifetime <= 0 ||
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
		cell := state.Cells[volume.CellID]
		manager.bumpPlan(&cell, now)
		state.Cells[cell.ID] = cell
		return nil
	})
}

func (manager *Manager) updateVolume(requestID, operation string, request any, apply func(*State, *Volume, int64) error) (VolumeView, error) {
	now := nowUnix(manager.cfg.Now)
	raw, _, err := manager.cfg.Store.Transact(requestID, operation, request, now, func(state *State) (any, error) {
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
						manager.quarantineVolume(&assigned, "cell reported an unassigned volume", now)
						state.Volumes[id] = assigned
					}
				}
				manager.bumpPlan(&cell, now)
				continue
			}
			if _, duplicate := seen[volume.ID]; duplicate {
				cell.Health = CellQuarantined
				cell.QuarantineReason = "cell reported a duplicate volume observation"
				manager.quarantineVolume(&volume, "cell reported a duplicate volume observation", now)
				manager.bumpPlan(&cell, now)
				state.Volumes[volume.ID] = volume
				continue
			}
			seen[volume.ID] = struct{}{}
			if observed.ProjectID != volume.ProjectID || observed.ServiceUID != volume.ServiceUID ||
				observed.ServiceGID != volume.ServiceGID || observed.ListenPort != volume.ListenPort {
				manager.quarantineVolume(&volume, "observed isolation identifiers differ from the signed assignment", now)
				manager.bumpPlan(&cell, now)
				state.Volumes[volume.ID] = volume
				cell.Health = CellQuarantined
				continue
			}
			if observed.AuthorityGeneration != volume.AuthorityGeneration || observed.AuthorityRunning && !observed.Provisioned ||
				observed.AuthorityRunning && observed.AuthorityAbsent {
				manager.quarantineVolume(&volume, "observed authority identity or lifecycle state is impossible", now)
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
					manager.quarantineVolume(&volume, "authority CSR changed within one authority generation", now)
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
						manager.quarantineVolume(&volume, "authority CSR proof of possession is invalid", now)
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
				manager.quarantineVolume(&volume, "cell omitted an assigned volume observation", now)
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
	return manager.issueMount(requestID, "issue-mount", request.VolumeID, request.ProductAuthorization, request.ClientCSRPEM, request.Access, "", 0, request)
}

func (manager *Manager) ReauthorizeMount(requestID string, request ReauthorizeMountRequest) (MountAuthorization, error) {
	if request.Sequence == 0 {
		return MountAuthorization{}, ErrInvalid
	}
	session, err := base64.RawURLEncoding.DecodeString(request.SessionID)
	if err != nil || len(session) != 16 {
		return MountAuthorization{}, ErrInvalid
	}
	return manager.issueMount(requestID, "reauthorize-mount", request.VolumeID, request.ProductAuthorization, request.ClientCSRPEM, request.Access, request.SessionID, request.Sequence, request)
}

func (manager *Manager) issueMount(requestID, operation, volumeID, productToken, csrPEM string, access []string, sessionID string, sequence uint64, request any) (MountAuthorization, error) {
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
		productKey := manager.cfg.ProductIssuers[volume.ProductIssuer]
		verified, err := productauth.Verify(productKey, []byte(productToken), productauth.Expectations{
			Issuer: volume.ProductIssuer, Audience: "portablefs-manager", AuthorizationDomain: volume.AuthorizationDomain,
			Owner: volume.Owner, VolumeID: volume.ID, PeerSPKI: peer, Now: nowTime,
			ClockSkew: manager.cfg.ClockSkew, MaxLifetime: manager.cfg.ProductMaxLifetime,
		})
		if err != nil || !productauth.Allows(verified.Claims.Access, access) {
			return nil, ErrInvalid
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
			ProductAuthorization: productToken, SessionID: sessionID, Sequence: sequence,
		}
		capability, err := volumecap.Sign(manager.cfg.CapabilityPrivateKey, claims)
		if err != nil {
			return nil, err
		}
		return MountAuthorization{
			VolumeID: volume.ID, AuthorityEndpoint: net.JoinHostPort(cell.AuthorityHost, fmt.Sprint(volume.ListenPort)),
			AuthorityServerName: volume.AuthorityServerName, AuthorityCAPEM: manager.cfg.AuthorityCA.CertificatePEM,
			ClientCertificatePEM: certificate, Capability: string(capability), Access: append([]string(nil), access...),
			ExpiresUnix: expires.Unix(), CertificateExpiresUnix: certificateExpires.Unix(), AuthorityGeneration: volume.AuthorityGeneration,
			SessionID: sessionID, Sequence: sequence, ReleaseID: manager.cfg.ReleaseID,
		}, nil
	})
	if err != nil {
		return MountAuthorization{}, err
	}
	return decode[MountAuthorization](raw)
}

func (manager *Manager) ReleaseIdentity() string  { return manager.cfg.ReleaseID }
func (manager *Manager) PlanPublicKeyPEM() string { return manager.planPublicKeyPEM }

func (manager *Manager) bumpPlan(cell *Cell, now int64) {
	cell.PlanGeneration++
	cell.PlanReleaseID = manager.cfg.ReleaseID
	cell.PlanIssuedUnix = now
	cell.PlanExpiresUnix = now + int64(manager.cfg.PlanLifetime/time.Second)
}

func (manager *Manager) quarantineVolume(volume *Volume, reason string, now int64) {
	volume.State = VolumeQuarantined
	volume.QuarantineReason = reason
	volume.UpdatedUnix = now
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
