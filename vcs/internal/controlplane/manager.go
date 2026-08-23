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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/productauth"
	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
)

type ManagerConfig struct {
	Store                   *Store
	PlanPrivateKey          ed25519.PrivateKey
	CapabilityPrivateKey    ed25519.PrivateKey
	ProductIssuers          map[string]ed25519.PublicKey
	AuthorityCA             *CertificateAuthority
	ClientCA                *CertificateAuthority
	EnrollmentCA            *CertificateAuthority
	Now                     func() time.Time
	ReleaseID               string
	PlanLifetime            time.Duration
	GrantLifetime           time.Duration
	EnrollmentLease         time.Duration
	ProductMaxLifetime      time.Duration
	ClientCertLifetime      time.Duration
	AuthorityCertLifetime   time.Duration
	ObservedStaleAfter      time.Duration
	UsageStaleAfter         time.Duration
	ProvisionFloorBytes     uint64
	ProvisionFloorInodes    uint64
	CellReserveFraction     float64
	WakeBurstBytes          uint64
	RestoreOverheadFraction float64
	RestoreOverheadBytes    uint64
	RestoreOverheadInodes   uint64
	ArchiveKeyVersion       string
	ArchiveVerifier         ArchiveVerifier
	ArchivePurger           ArchivePurger
	// MaxArchivingPerCell and MaxRestoringPerCell bound how many archiver and
	// hydrator processes — each a full-tree I/O job colocated with live volume
	// authorities — one cell may run at once. Exceeding a cap is refused with
	// ErrBusy and no state change, never queued.
	MaxArchivingPerCell int
	MaxRestoringPerCell int
	ClockSkew           time.Duration
}

type ArchiveVerifier interface{ Verify(ArchiveRecord) error }

// ArchivePurger implementations must be idempotent: a process can fail after
// object deletion but before the resulting state record is durable.
type ArchivePurger interface{ Purge(ArchiveRecord) error }

type Manager struct {
	cfg                    ManagerConfig
	planPublicKeyPEM       string
	capabilityPublicKeyPEM string
	heartbeatMu            sync.RWMutex
	heartbeats             map[string]CellHeartbeat
	heartbeatConflictUnix  map[string]int64
}

const mountEnrollmentRetention = 15 * time.Minute

func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.UsageStaleAfter == 0 {
		cfg.UsageStaleAfter = 5 * time.Minute
	}
	if cfg.ProvisionFloorBytes == 0 {
		cfg.ProvisionFloorBytes = 64 << 20
	}
	if cfg.ProvisionFloorInodes == 0 {
		cfg.ProvisionFloorInodes = 1024
	}
	if cfg.CellReserveFraction == 0 {
		cfg.CellReserveFraction = 0.10
	}
	if cfg.WakeBurstBytes == 0 {
		cfg.WakeBurstBytes = 1 << 30
	}
	if cfg.RestoreOverheadFraction == 0 {
		cfg.RestoreOverheadFraction = 0.05
	}
	if cfg.RestoreOverheadBytes == 0 {
		cfg.RestoreOverheadBytes = 64 << 20
	}
	if cfg.RestoreOverheadInodes == 0 {
		cfg.RestoreOverheadInodes = 1024
	}
	if cfg.ArchiveKeyVersion == "" {
		cfg.ArchiveKeyVersion = "default"
	}
	if cfg.MaxArchivingPerCell == 0 {
		cfg.MaxArchivingPerCell = 2
	}
	if cfg.MaxRestoringPerCell == 0 {
		cfg.MaxRestoringPerCell = 4
	}
	if cfg.Store == nil || len(cfg.PlanPrivateKey) != ed25519.PrivateKeySize ||
		len(cfg.CapabilityPrivateKey) != ed25519.PrivateKeySize || len(cfg.ProductIssuers) == 0 ||
		cfg.AuthorityCA == nil || cfg.AuthorityCA.Certificate == nil || cfg.AuthorityCA.Signer == nil ||
		cfg.ClientCA == nil || cfg.ClientCA.Certificate == nil || cfg.ClientCA.Signer == nil || !validIdentity(cfg.ReleaseID) ||
		cfg.EnrollmentCA == nil || cfg.EnrollmentCA.Certificate == nil || cfg.EnrollmentCA.Signer == nil ||
		len(cfg.AuthorityCA.CertificatePEM) == 0 || len(cfg.AuthorityCA.CertificatePEM) > 4096 ||
		len(cfg.ClientCA.CertificatePEM) == 0 || len(cfg.ClientCA.CertificatePEM) > 4096 ||
		len(cfg.EnrollmentCA.CertificatePEM) == 0 || len(cfg.EnrollmentCA.CertificatePEM) > 4096 ||
		cfg.PlanLifetime <= 0 || cfg.GrantLifetime <= 0 || cfg.EnrollmentLease/2 < cfg.GrantLifetime || cfg.ProductMaxLifetime <= 0 ||
		cfg.ClientCertLifetime <= 0 || cfg.AuthorityCertLifetime <= 0 || cfg.ObservedStaleAfter <= 0 || cfg.UsageStaleAfter < time.Second ||
		cfg.ProvisionFloorBytes == 0 || cfg.ProvisionFloorInodes == 0 || cfg.CellReserveFraction <= 0 || cfg.CellReserveFraction >= 1 ||
		cfg.RestoreOverheadFraction < 0 || cfg.RestoreOverheadFraction > 1 || cfg.RestoreOverheadBytes == 0 || cfg.RestoreOverheadInodes == 0 ||
		!validIdentity(cfg.ArchiveKeyVersion) || cfg.MaxArchivingPerCell <= 0 || cfg.MaxRestoringPerCell <= 0 || cfg.ClockSkew < 0 {
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
	return &Manager{
		cfg: cfg, planPublicKeyPEM: planPEM, capabilityPublicKeyPEM: capabilityPEM,
		heartbeats: make(map[string]CellHeartbeat), heartbeatConflictUnix: make(map[string]int64),
	}, nil
}

func (manager *Manager) RegisterCell(requestID string, request RegisterCellRequest) (Cell, error) {
	var err error
	request, err = normalizeRegisterCellRequest(request, true)
	if err != nil {
		return Cell{}, err
	}
	now := nowUnix(manager.cfg.Now)
	raw, _, err := manager.cfg.Store.Transact(requestID, "register-cell", request, now, func(state *State) (any, error) {
		if previous, exists := state.Cells[request.ID]; exists {
			if previous.Abandoned {
				return nil, ErrQuarantined
			}
			return nil, ErrConflict
		}
		cell := manager.newCell(request, now)
		state.Cells[cell.ID] = cell
		return cell, nil
	})
	if err != nil {
		return Cell{}, err
	}
	return decode[Cell](raw)
}

// ConvergeCell registers one declaratively named cell. Reapplying the exact
// normalized declaration returns the live current Cell without replacing
// capacity raises, allocator progress, health, or desired-plan state.
func (manager *Manager) ConvergeCell(cellID string, request RegisterCellRequest) (Cell, error) {
	if !cellplan.ValidID(cellID) || request.ID != "" && request.ID != cellID {
		return Cell{}, ErrInvalid
	}
	request.ID = cellID
	var err error
	request, err = normalizeRegisterCellRequest(request, false)
	if err != nil {
		return Cell{}, err
	}
	now := nowUnix(manager.cfg.Now)
	raw, err := manager.cfg.Store.TransactNatural("converge-cell-registration", now, func(state *State) (any, bool, error) {
		current, exists := state.Cells[cellID]
		if !exists {
			cell := manager.newCell(request, now)
			state.Cells[cell.ID] = cell
			return cell, true, nil
		}
		if current.Abandoned {
			return nil, false, ErrQuarantined
		}
		fingerprint := registerCellFingerprint(request)
		if current.RegistrationSHA256 != "" {
			if current.RegistrationSHA256 != fingerprint {
				return nil, false, ErrConflict
			}
			return current, false, nil
		}
		// Schema-v2 cells written before convergent registration have no exact
		// declaration digest. The first compatible operator declaration pins it
		// without changing any live field. Capacity and allocator starts may only
		// describe floors the current cell has already advanced beyond.
		if current.ID != request.ID || current.AvailabilityZone != request.AvailabilityZone ||
			current.AuthorityHost != request.AuthorityHost || current.AuthorityDNSZone != request.AuthorityDNSZone || current.Pool != request.Pool ||
			request.CapacityBytes > current.CapacityBytes || request.CapacityInodes > current.CapacityInodes ||
			request.FirstProjectID > current.NextProjectID || request.FirstServiceUID > current.NextServiceUID || request.FirstPort > current.NextPort {
			return nil, false, ErrConflict
		}
		current.RegistrationSHA256 = fingerprint
		state.Cells[cellID] = current
		return current, true, nil
	})
	if err != nil {
		return Cell{}, err
	}
	return decode[Cell](raw)
}

// ListCells returns the complete operator inventory in stable ID order.
func (manager *Manager) ListCells() (CellList, error) {
	result := CellList{Cells: make([]Cell, 0)}
	err := manager.cfg.Store.View(func(state State) error {
		result.Cells = make([]Cell, 0, len(state.Cells))
		for _, id := range sortedCellIDs(state.Cells) {
			result.Cells = append(result.Cells, state.Cells[id])
		}
		return nil
	})
	return result, err
}

// ListVolumes returns the complete operator inventory in stable ID order.
func (manager *Manager) ListVolumes() (VolumeList, error) {
	result := VolumeList{Volumes: make([]VolumeView, 0)}
	err := manager.cfg.Store.View(func(state State) error {
		ids := make([]string, 0, len(state.Volumes))
		for id := range state.Volumes {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		result.Volumes = make([]VolumeView, 0, len(ids))
		for _, id := range ids {
			result.Volumes = append(result.Volumes, state.volumeView(state.Volumes[id]))
		}
		return nil
	})
	return result, err
}

func normalizeRegisterCellRequest(request RegisterCellRequest, generateID bool) (RegisterCellRequest, error) {
	request.AvailabilityZone = strings.TrimSpace(request.AvailabilityZone)
	request.AuthorityHost = strings.ToLower(strings.TrimSpace(request.AuthorityHost))
	request.AuthorityDNSZone = strings.ToLower(strings.TrimSpace(request.AuthorityDNSZone))
	request.Pool = strings.ToLower(strings.TrimSpace(request.Pool))
	if request.ID == "" && generateID {
		request.ID = newUUID()
	}
	if !cellplan.ValidID(request.ID) || !validIdentity(request.AvailabilityZone) ||
		net.ParseIP(request.AuthorityHost) == nil && !validDNSName(request.AuthorityHost) ||
		!validDNSName(request.AuthorityDNSZone) || request.CapacityBytes == 0 || request.CapacityInodes == 0 || !validPool(request.Pool) {
		return RegisterCellRequest{}, ErrInvalid
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
	if request.FirstProjectID == 0 || request.FirstServiceUID < 1000 || request.FirstPort < 1024 {
		return RegisterCellRequest{}, ErrInvalid
	}
	return request, nil
}

func registerCellFingerprint(request RegisterCellRequest) string {
	payload, _ := json.Marshal(request)
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func (manager *Manager) newCell(request RegisterCellRequest, now int64) Cell {
	return Cell{
		ID: request.ID, AvailabilityZone: request.AvailabilityZone, AuthorityHost: request.AuthorityHost,
		AuthorityDNSZone: request.AuthorityDNSZone, CapacityBytes: request.CapacityBytes, CapacityInodes: request.CapacityInodes, Pool: request.Pool,
		NextProjectID: request.FirstProjectID, NextServiceUID: request.FirstServiceUID, NextPort: request.FirstPort,
		PlanGeneration: 1, PlanReleaseID: manager.cfg.ReleaseID,
		PlanIssuedUnix: now, PlanExpiresUnix: now + int64(manager.cfg.PlanLifetime/time.Second),
		Health: CellUnknown, RegistrationSHA256: registerCellFingerprint(request),
	}
}

// HeartbeatCell refreshes process liveness without appending a durable
// full-state record. The applied generation may trail the Manager's complete
// desired plan while the cell converges, but it may never lead it. Exact
// convergence remains a separate mount-authorization gate. Desired/observed
// changes still use ObserveCell; after a manager restart, mounts fail closed
// until the next authenticated heartbeat.
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
		if heartbeat.PlanGeneration > cell.PlanGeneration || cell.Health == CellQuarantined {
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
	// The cell's observation time orders evidence. An older packet cannot
	// replace newer evidence, but a newer observation at a lower generation is
	// a real convergence regression and must be recorded.
	if heartbeat.ObservedUnix > previous.ObservedUnix {
		manager.heartbeats[heartbeat.CellID] = heartbeat
		if previous.PlanGeneration > 0 && heartbeat.PlanGeneration < previous.PlanGeneration {
			manager.heartbeatConflictUnix[heartbeat.CellID] = heartbeat.ObservedUnix
		} else {
			delete(manager.heartbeatConflictUnix, heartbeat.CellID)
		}
		return
	}
	if heartbeat.ObservedUnix < previous.ObservedUnix {
		return
	}
	if heartbeat.PlanGeneration < previous.PlanGeneration {
		// Generations may advance several times inside one timestamp second, but
		// they may not move backward. A same-time regression is therefore
		// ambiguous reordered evidence: retain its lower generation and refuse
		// to reopen convergence at that timestamp.
		manager.heartbeats[heartbeat.CellID] = heartbeat
		manager.heartbeatConflictUnix[heartbeat.CellID] = heartbeat.ObservedUnix
		return
	}
	if manager.heartbeatConflictUnix[heartbeat.CellID] == heartbeat.ObservedUnix {
		return
	}
	manager.heartbeats[heartbeat.CellID] = heartbeat
}

func (manager *Manager) cellHeartbeat(cellID string) CellHeartbeat {
	manager.heartbeatMu.RLock()
	heartbeat := manager.heartbeats[cellID]
	manager.heartbeatMu.RUnlock()
	return heartbeat
}

func (manager *Manager) heartbeatLive(cell Cell, heartbeat CellHeartbeat, now int64) bool {
	return heartbeat.CellID == cell.ID && heartbeat.PlanGeneration > 0 && heartbeat.PlanGeneration <= cell.PlanGeneration &&
		heartbeat.ManagerReleaseID == manager.cfg.ReleaseID && heartbeat.AgentReleaseID != "" && heartbeat.HelperReleaseID != "" &&
		now-heartbeat.ObservedUnix <= int64(manager.cfg.ObservedStaleAfter/time.Second)
}

func (manager *Manager) cellLive(cell Cell, now int64) bool {
	return manager.heartbeatLive(cell, manager.cellHeartbeat(cell.ID), now)
}

// cellConverged is stronger than liveness: the helper has applied the exact
// complete desired plan. Serving credentials require this; placement does not,
// because each transaction already reserves capacity and allocator identities
// in the next complete level-triggered plan.
func (manager *Manager) cellConverged(cell Cell, now int64) bool {
	heartbeat := manager.cellHeartbeat(cell.ID)
	return manager.heartbeatLive(cell, heartbeat, now) && heartbeat.PlanGeneration == cell.PlanGeneration
}

func (manager *Manager) CreateVolume(requestID string, request CreateVolumeRequest) (VolumeView, error) {
	request.AuthorizationDomain = strings.TrimSpace(request.AuthorizationDomain)
	request.Owner = strings.TrimSpace(request.Owner)
	request.ProductIssuer = strings.TrimSpace(request.ProductIssuer)
	request.Pool = strings.ToLower(strings.TrimSpace(request.Pool))
	if request.Pool == "" {
		request.Pool = PoolProduct
	}
	productKey := manager.cfg.ProductIssuers[request.ProductIssuer]
	if !validIdentity(request.AuthorizationDomain) || !validIdentity(request.Owner) || !validIdentity(request.ProductIssuer) || len(productKey) != ed25519.PublicKeySize ||
		request.QuotaBytes == 0 || request.QuotaBytes%1024 != 0 || request.QuotaInodes == 0 || !validPool(request.Pool) || request.Pool == PoolTest {
		return VolumeView{}, ErrInvalid
	}
	productPEM, err := PublicKeyPEM(productKey)
	if err != nil {
		return VolumeView{}, err
	}
	now := nowUnix(manager.cfg.Now)
	raw, _, err := manager.cfg.Store.Transact(requestID, "create-volume", request, now, func(state *State) (any, error) {
		selected, err := manager.admitPlacement(state, request.Pool, manager.cfg.ProvisionFloorBytes, manager.cfg.ProvisionFloorInodes, false, now)
		if err != nil {
			return nil, err
		}
		id := newUUID()
		compactID := strings.ReplaceAll(id, "-", "")
		serverName := "v-" + compactID + "." + selected.AuthorityDNSZone
		volume := Volume{
			ID: id, AuthorizationDomain: request.AuthorizationDomain, Owner: request.Owner,
			ProductIssuer: request.ProductIssuer, ProductPublicKeyPEM: productPEM,
			QuotaBytes: request.QuotaBytes, QuotaInodes: request.QuotaInodes,
			AuthorityEpoch: 1, PlacementSequence: 1, State: VolumeProvisioning, Pool: request.Pool,
			Placement: &Placement{CellID: selected.ID, Sequence: 1, ProjectID: selected.NextProjectID,
				ServiceUID: selected.NextServiceUID, ServiceGID: selected.NextServiceUID, ListenPort: selected.NextPort,
				AuthorityID: serverName, AuthorityServerName: serverName, CreatedUnix: now,
				PendingBytes: manager.cfg.ProvisionFloorBytes, PendingInodes: manager.cfg.ProvisionFloorInodes},
			CreatedUnix: now, UpdatedUnix: now,
		}
		selected.NextProjectID++
		selected.NextServiceUID++
		selected.NextPort++
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
		volume.Placement.PriorStrictFenced = false
		volume.Placement.StrictFenceEvidence = ""
		volume.UpdatedUnix = now
		terminateVolumeEnrollments(state, volume.ID, "authority restart", now)
		cell := state.Cells[volume.Placement.CellID]
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
		volume.Placement.PriorStrictFenced = true
		volume.Placement.StrictFenceEvidence = request.EvidenceSHA256
		volume.UpdatedUnix = now
		cell := state.Cells[volume.Placement.CellID]
		manager.bumpPlan(&cell, now)
		state.Cells[cell.ID] = cell
		return nil
	})
}

func (manager *Manager) ArchiveVolume(requestID string, request ArchiveVolumeRequest) (VolumeView, error) {
	if !cellplan.ValidID(request.VolumeID) {
		return VolumeView{}, ErrInvalid
	}
	// A Manager started without archive credentials can never verify a seal, so
	// an accepted cycle would wedge at cursor "verifying" with the volume no
	// longer serving. Refuse before any state change.
	if manager.cfg.ArchiveVerifier == nil {
		return VolumeView{}, ErrArchiveUnsupported
	}
	return manager.updateVolume(requestID, "archive-volume", request, func(state *State, volume *Volume, now int64) error {
		if volume.State != VolumeReady || volume.Placement == nil {
			return ErrConflict
		}
		cell := state.Cells[volume.Placement.CellID]
		if !cell.ArchiveConfigured {
			return ErrArchiveUnsupported
		}
		if archivingCellLoad(state, cell.ID) >= manager.cfg.MaxArchivingPerCell {
			return ErrBusy
		}
		terminateVolumeEnrollments(state, volume.ID, "volume archiving", now)
		volume.State = VolumeArchiving
		volume.ArchiveCycleStep = "quiescing"
		volume.ArchiveAttempt = newUUID()
		volume.UpdatedUnix = now
		manager.bumpPlan(&cell, now)
		state.Cells[cell.ID] = cell
		return nil
	})
}

func (manager *Manager) WakeVolume(requestID string, request WakeVolumeRequest) (VolumeView, error) {
	if !cellplan.ValidID(request.VolumeID) {
		return VolumeView{}, ErrInvalid
	}
	return manager.updateVolume(requestID, "wake-volume", request, func(state *State, volume *Volume, now int64) error {
		switch volume.State {
		case VolumeArchiving:
			cell := state.Cells[volume.Placement.CellID]
			if volume.ArchiveCycleStep == "quiescing" {
				volume.State = VolumeReady
			} else {
				volume.AuthorityEpoch++
				clearPlacementAuthority(volume.Placement)
				volume.State = VolumeProvisioning
			}
			volume.ArchiveCycleStep, volume.ArchiveAttempt, volume.PendingSeal = "", "", nil
			volume.WakeRequested = false
			volume.UpdatedUnix = now
			manager.bumpPlan(&cell, now)
			state.Cells[cell.ID] = cell
			return nil
		case VolumeArchived:
			if volume.ArchiveCycleStep != "released" {
				if !volume.WakeRequested {
					volume.WakeRequested = true
					volume.UpdatedUnix = now
					cell := state.Cells[volume.Placement.CellID]
					manager.bumpPlan(&cell, now)
					state.Cells[cell.ID] = cell
				}
				return nil
			}
			needBytes, needInodes, err := manager.restoreCharge(*volume.Archive)
			if err != nil {
				return err
			}
			cell, err := manager.admitPlacement(state, volume.Pool, needBytes, needInodes, true, now)
			if err != nil {
				return err
			}
			volume.PlacementSequence++
			volume.AuthorityEpoch++
			compactID := strings.ReplaceAll(volume.ID, "-", "")
			serverName := fmt.Sprintf("v-%s-p%d.%s", compactID, volume.PlacementSequence, cell.AuthorityDNSZone)
			volume.Placement = &Placement{CellID: cell.ID, Sequence: volume.PlacementSequence, ProjectID: cell.NextProjectID,
				ServiceUID: cell.NextServiceUID, ServiceGID: cell.NextServiceUID, ListenPort: cell.NextPort,
				AuthorityID: serverName, AuthorityServerName: serverName, CreatedUnix: now, PendingBytes: needBytes, PendingInodes: needInodes}
			cell.NextProjectID++
			cell.NextServiceUID++
			cell.NextPort++
			volume.State = VolumeRestoring
			volume.RestoreStep = "restoring-namespace"
			volume.RestoreConvergedUnix = 0
			volume.WakeRequested = false
			volume.UpdatedUnix = now
			manager.bumpPlan(cell, now)
			state.Cells[cell.ID] = *cell
			return nil
		case VolumeRestoring, VolumeReady:
			return nil
		case VolumeProvisioning, VolumeFencing, VolumeQuarantined, VolumeDestroying, VolumeDestroyed:
			return ErrConflict
		default:
			return ErrInvalid
		}
	})
}

func (manager *Manager) DestroyVolume(requestID string, request DestroyVolumeRequest) (VolumeView, error) {
	request.Reason = strings.TrimSpace(request.Reason)
	if !cellplan.ValidID(request.VolumeID) || !validIdentity(request.Reason) {
		return VolumeView{}, ErrInvalid
	}
	// A READY volume may hold a retained checkpoint archive from an earlier
	// cycle. Its purge is archive-store network I/O and must not run inside
	// the store transaction: snapshot it, purge unlocked (the purger is
	// idempotent), and let the transaction re-check the record was unchanged.
	var checkpoint *ArchiveRecord
	if err := manager.cfg.Store.View(func(state State) error {
		volume, ok := state.Volumes[request.VolumeID]
		if ok && volume.State == VolumeReady && volume.Archive != nil {
			record := *volume.Archive
			checkpoint = &record
		}
		return nil
	}); err != nil {
		return VolumeView{}, err
	}
	if checkpoint != nil {
		if manager.cfg.ArchivePurger == nil {
			return VolumeView{}, ErrArchiveUnsupported
		}
		if err := manager.cfg.ArchivePurger.Purge(*checkpoint); err != nil {
			return VolumeView{}, fmt.Errorf("%w: %v", ErrArchiveStoreUnavailable, err)
		}
	}
	view, err := manager.updateVolume(requestID, "destroy-volume", request, func(state *State, volume *Volume, now int64) error {
		switch volume.State {
		case VolumeReady:
			if volume.Archive != nil {
				if checkpoint == nil || !archiveRecordsEqual(*volume.Archive, *checkpoint) {
					return ErrConflict
				}
				volume.Archive = nil
			}
			terminateVolumeEnrollments(state, volume.ID, "volume deletion requested", now)
			volume.State = VolumeDestroying
			volume.DeletionRequested = true
			volume.ArchiveCycleStep = "quiescing"
			volume.UpdatedUnix = now
			cell := state.Cells[volume.Placement.CellID]
			manager.bumpPlan(&cell, now)
			state.Cells[cell.ID] = cell
		case VolumeArchived:
			if volume.ArchiveCycleStep != "released" || volume.Placement != nil {
				return ErrConflict
			}
			if manager.cfg.ArchivePurger == nil {
				return ErrArchiveUnsupported
			}
			volume.State = VolumeDestroying
			volume.DeletionRequested = true
			volume.ArchiveCycleStep = "purging-archive"
			volume.UpdatedUnix = now
		case VolumeDestroying:
			if volume.ArchiveCycleStep != "purging-archive" {
				return nil
			}
			if manager.cfg.ArchivePurger == nil {
				return ErrArchiveUnsupported
			}
		case VolumeDestroyed:
			return nil
		case VolumeProvisioning, VolumeFencing, VolumeQuarantined, VolumeArchiving, VolumeRestoring:
			return ErrConflict
		default:
			return ErrInvalid
		}
		return nil
	})
	if err != nil || view.State != VolumeDestroying || view.ArchiveCycleStep != "purging-archive" {
		return view, err
	}
	// The product view is sanitized (no archive record); the purge target is
	// read from the durable state, outside the store lock like every other
	// archive-store call.
	var purgeTarget *ArchiveRecord
	if err := manager.cfg.Store.View(func(state State) error {
		volume, ok := state.Volumes[request.VolumeID]
		if ok && volume.Archive != nil {
			record := *volume.Archive
			purgeTarget = &record
		}
		return nil
	}); err != nil {
		return view, err
	}
	if purgeTarget == nil {
		return view, ErrConflict
	}
	if err := manager.cfg.ArchivePurger.Purge(*purgeTarget); err != nil {
		return view, fmt.Errorf("%w: %v", ErrArchiveStoreUnavailable, err)
	}
	now := nowUnix(manager.cfg.Now)
	raw, err := manager.cfg.Store.TransactNatural("complete-archive-purge", now, func(state *State) (any, bool, error) {
		volume, ok := state.Volumes[request.VolumeID]
		if !ok {
			return nil, false, ErrNotFound
		}
		if volume.State == VolumeDestroyed {
			return state.volumeView(volume), false, nil
		}
		if volume.State != VolumeDestroying || volume.ArchiveCycleStep != "purging-archive" || volume.Placement != nil || volume.Archive == nil {
			return nil, false, ErrConflict
		}
		pruneVolumeEnrollments(state, volume.ID)
		pruneVolumeReceipts(state, volume.ID)
		volume.State = VolumeDestroyed
		volume.Archive = nil
		volume.ArchiveCycleStep = ""
		volume.DestroyedUnix = now
		volume.UpdatedUnix = now
		state.Volumes[volume.ID] = volume
		return state.volumeView(volume), true, nil
	})
	if err != nil {
		return VolumeView{}, err
	}
	return decode[VolumeView](raw)
}

func (manager *Manager) RetryVerification(requestID, volumeID string) (VolumeView, error) {
	if !cellplan.ValidID(volumeID) {
		return VolumeView{}, ErrInvalid
	}
	return manager.VerifyPendingSeal(requestID, volumeID)
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
		case ArchiveVolumeRequest:
			volumeID = typed.VolumeID
		case WakeVolumeRequest:
			volumeID = typed.VolumeID
		case DestroyVolumeRequest:
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
		if observation.ObservedUnix < cell.LastObservedUnix {
			return nil, ErrConflict
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
		// Archive capability is relayed verbatim from the helper's status pass;
		// losing it immediately stops new archive and restore placements without
		// disturbing cycles already in flight.
		cell.ArchiveConfigured = observation.ArchiveConfigured
		seen := make(map[string]struct{}, len(observation.Volumes))
		for _, observed := range observation.Volumes {
			volume, exists := state.Volumes[observed.VolumeID]
			if exists && volume.Placement == nil && observed.Released {
				continue
			}
			if !exists || volume.Placement == nil || volume.Placement.CellID != cell.ID {
				cell.Health = CellQuarantined
				cell.QuarantineReason = "cell reported an unassigned volume"
				for id, assigned := range state.Volumes {
					if assigned.Placement != nil && assigned.Placement.CellID == cell.ID {
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
			placement := volume.Placement
			if observed.ProjectID != placement.ProjectID || observed.ServiceUID != placement.ServiceUID ||
				observed.ServiceGID != placement.ServiceGID || observed.ListenPort != placement.ListenPort {
				manager.quarantineVolume(state, &volume, "observed isolation identifiers differ from the signed assignment", now)
				manager.bumpPlan(&cell, now)
				state.Volumes[volume.ID] = volume
				cell.Health = CellQuarantined
				continue
			}
			if observed.AuthorityGeneration != volume.AuthorityEpoch || observed.AuthorityRunning && !observed.Provisioned ||
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
					placement.PriorStrictFenced = false
					placement.StrictFenceEvidence = ""
					volume.UpdatedUnix = now
					manager.bumpPlan(&cell, now)
				}
				state.Volumes[volume.ID] = volume
				cell.Health = CellDegraded
				continue
			}
			placement.LastObservedUnix = observation.ObservedUnix
			placement.UsedBytes = observed.UsedBytes
			placement.UsedInodes = observed.UsedInodes
			placement.UsedObservedUnix = observation.ObservedUnix
			if volume.State != VolumeRestoring && volume.RestoreConvergedUnix == 0 && observation.ObservedUnix > placement.CreatedUnix {
				placement.PendingBytes, placement.PendingInodes = 0, 0
			} else if volume.RestoreConvergedUnix > 0 && observation.ObservedUnix > volume.RestoreConvergedUnix {
				placement.PendingBytes, placement.PendingInodes = 0, 0
				volume.RestoreConvergedUnix = 0
			}
			if volume.State == VolumeProvisioning || volume.State == VolumeReady || volume.State == VolumeRestoring {
				if observed.AuthorityCSRPEM != "" && placement.AuthorityCSRPEM != "" && observed.AuthorityCSRPEM != placement.AuthorityCSRPEM {
					manager.quarantineVolume(state, &volume, "authority CSR changed within one authority generation", now)
					manager.bumpPlan(&cell, now)
					cell.Health = CellQuarantined
					state.Volumes[volume.ID] = volume
					continue
				}
				certificateNeedsRenewal := placement.AuthorityCertificatePEM == "" ||
					placement.AuthorityCertExpires <= now+int64(manager.cfg.AuthorityCertLifetime/3/time.Second)
				if observed.AuthorityCSRPEM != "" && certificateNeedsRenewal {
					certificate, expires, err := manager.cfg.AuthorityCA.SignCSR([]byte(observed.AuthorityCSRPEM), placement.AuthorityID,
						[]string{placement.AuthorityServerName}, false, nowTime, manager.cfg.AuthorityCertLifetime)
					if err != nil {
						manager.quarantineVolume(state, &volume, "authority CSR proof of possession is invalid", now)
						manager.bumpPlan(&cell, now)
						cell.Health = CellQuarantined
						state.Volumes[volume.ID] = volume
						continue
					}
					placement.AuthorityCSRPEM = observed.AuthorityCSRPEM
					placement.AuthorityCertificatePEM = certificate
					placement.AuthorityCertExpires = expires.Unix()
					volume.UpdatedUnix = now
					manager.bumpPlan(&cell, now)
				}
			}
			switch volume.State {
			case VolumeProvisioning:
				if placement.AuthorityCertificatePEM != "" && observed.Provisioned && observed.AuthorityRunning {
					volume.State = VolumeReady
					volume.UpdatedUnix = now
				}
			case VolumeReady:
				if !observed.AuthorityRunning {
					volume.State = VolumeFencing
					placement.PriorStrictFenced = false
					placement.StrictFenceEvidence = ""
					volume.UpdatedUnix = now
					manager.bumpPlan(&cell, now)
					cell.Health = CellDegraded
				}
			case VolumeFencing:
				if observed.AuthorityRunning {
					break
				}
				if observed.AuthorityAbsent && placement.PriorStrictFenced {
					terminateVolumeEnrollments(state, volume.ID, "authority generation changed", now)
					volume.AuthorityEpoch++
					clearPlacementAuthority(placement)
					volume.State = VolumeProvisioning
					volume.UpdatedUnix = now
					manager.bumpPlan(&cell, now)
				}
			case VolumeArchiving:
				switch volume.ArchiveCycleStep {
				case "quiescing":
					if observed.AuthorityAbsent && observed.QuiesceProven {
						volume.ArchiveCycleStep = "exporting"
						volume.UpdatedUnix = now
						manager.bumpPlan(&cell, now)
					}
				case "exporting", "verifying":
					if observed.ArchiveSealed != nil {
						record, err := archiveRecordFromObservation(volume, observed.ArchiveSealed, now)
						if err != nil {
							manager.quarantineVolume(state, &volume, "archive seal observation is invalid", now)
							cell.Health = CellQuarantined
							manager.bumpPlan(&cell, now)
							break
						}
						if volume.PendingSeal != nil && !archiveRecordsEqual(*volume.PendingSeal, record) {
							manager.quarantineVolume(state, &volume, "archive seal equivocation", now)
							cell.Health = CellQuarantined
							manager.bumpPlan(&cell, now)
							break
						}
						// The seal is recorded durably at cursor "verifying"; the
						// archive-store verification itself runs outside the store
						// lock (VerifyPendingSeal, driven by the serve loop), never
						// inside this transaction.
						volume.PendingSeal = &record
						volume.ArchiveCycleStep = "verifying"
						volume.UpdatedUnix = now
					}
				default:
					return nil, ErrInvalid
				}
			case VolumeArchived:
				switch volume.ArchiveCycleStep {
				case "sealed":
					if observed.DestroyProofSHA256 != "" {
						if !validSHA256Hex(observed.DestroyProofSHA256) {
							manager.quarantineVolume(state, &volume, "destroy proof is invalid", now)
							cell.Health = CellQuarantined
							manager.bumpPlan(&cell, now)
							break
						}
						placement.DestroyProofSHA256 = observed.DestroyProofSHA256
						volume.ArchiveCycleStep = "destroyed"
						volume.UpdatedUnix = now
						manager.bumpPlan(&cell, now)
					}
				case "destroyed":
					if observed.Released {
						volume.Placement = nil
						volume.ArchiveCycleStep = "released"
						volume.UpdatedUnix = now
						pruneVolumeEnrollments(state, volume.ID)
						manager.bumpPlan(&cell, now)
					}
				case "released":
				default:
					return nil, ErrInvalid
				}
			case VolumeRestoring:
				volume.RestoreProgressPermille = observed.RestoreProgressPermille
				volume.RestoreState = observed.RestoreState
				if volume.RestoreStep == "restoring-namespace" && observed.RestoreNamespaceReady {
					volume.RestoreStep = "serving-restore"
					volume.UpdatedUnix = now
				}
				if observed.RestoreConverged && volume.RestoreStep != "serving-restore" {
					manager.quarantineVolume(state, &volume, "restore converged before namespace admission", now)
					cell.Health = CellQuarantined
					manager.bumpPlan(&cell, now)
				} else if observed.RestoreConverged {
					volume.State = VolumeReady
					volume.RestoreStep = ""
					volume.RestoreState = ""
					volume.RestoreProgressPermille = 1000
					volume.RestoreConvergedUnix = observation.ObservedUnix
					volume.ArchiveCycleStep = ""
					volume.UpdatedUnix = now
					manager.bumpPlan(&cell, now)
				} else if volume.RestoreStep == "serving-restore" && observed.AuthorityAbsent {
					manager.quarantineVolume(state, &volume, "restore authority disappeared after namespace admission", now)
					cell.Health = CellQuarantined
					manager.bumpPlan(&cell, now)
				}
			case VolumeDestroying:
				switch volume.ArchiveCycleStep {
				case "quiescing":
					if observed.AuthorityAbsent && observed.QuiesceProven {
						volume.ArchiveCycleStep = "destroying"
						volume.UpdatedUnix = now
						manager.bumpPlan(&cell, now)
					}
				case "destroying":
					if observed.DestroyProofSHA256 != "" {
						if !validSHA256Hex(observed.DestroyProofSHA256) {
							manager.quarantineVolume(state, &volume, "destroy proof is invalid", now)
							cell.Health = CellQuarantined
							manager.bumpPlan(&cell, now)
							break
						}
						placement.DestroyProofSHA256 = observed.DestroyProofSHA256
						volume.ArchiveCycleStep = "destroyed"
						volume.UpdatedUnix = now
						manager.bumpPlan(&cell, now)
					}
				case "destroyed":
					if observed.Released {
						volume.Placement = nil
						volume.State = VolumeDestroyed
						volume.ArchiveCycleStep = ""
						volume.DestroyedUnix = now
						volume.UpdatedUnix = now
						pruneVolumeEnrollments(state, volume.ID)
						pruneVolumeReceipts(state, volume.ID)
						manager.bumpPlan(&cell, now)
					}
				default:
					return nil, ErrInvalid
				}
			case VolumeQuarantined:
			case VolumeDestroyed:
			default:
				return nil, ErrInvalid
			}
			state.Volumes[volume.ID] = volume
		}
		for id, volume := range state.Volumes {
			if volume.Placement == nil || volume.Placement.CellID != cell.ID {
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
			UsageRefreshSeconds: uint64(manager.cfg.UsageStaleAfter / time.Second),
			AuthorityCAPEM:      manager.cfg.AuthorityCA.CertificatePEM, ClientCAPEM: manager.cfg.ClientCA.CertificatePEM,
			CapabilityPublicKey: manager.capabilityPublicKeyPEM,
		}
		for _, volume := range state.Volumes {
			if volume.Placement == nil || volume.Placement.CellID != cellID {
				continue
			}
			placement := volume.Placement
			phase := cellplan.PhaseProvision
			switch volume.State {
			case VolumeReady:
				phase = cellplan.PhaseServe
			case VolumeProvisioning:
				if placement.AuthorityCertificatePEM != "" {
					phase = cellplan.PhaseServe
				}
			case VolumeFencing, VolumeQuarantined:
				phase = cellplan.PhaseFence
			case VolumeArchiving:
				phase = cellplan.PhaseArchive
			case VolumeArchived:
				switch volume.ArchiveCycleStep {
				case "sealed":
					phase = cellplan.PhaseDestroy
				case "destroyed":
					phase = cellplan.PhaseRelease
				default:
					return fmt.Errorf("%w: archived plan cursor", ErrInvalid)
				}
			case VolumeRestoring:
				phase = cellplan.PhaseRestore
			case VolumeDestroying:
				switch volume.ArchiveCycleStep {
				case "quiescing":
					phase = cellplan.PhaseQuiesce
				case "destroying":
					phase = cellplan.PhaseDestroy
				case "destroyed":
					phase = cellplan.PhaseRelease
				default:
					return fmt.Errorf("%w: destroying plan cursor", ErrInvalid)
				}
			case VolumeDestroyed:
				continue
			default:
				return fmt.Errorf("%w: volume plan state", ErrInvalid)
			}
			entry := cellplan.VolumePlan{
				VolumeID: volume.ID, Phase: phase, AuthorizationDomain: volume.AuthorizationDomain, Owner: volume.Owner,
				ProductIssuer: volume.ProductIssuer, ProductPublicKeyPEM: volume.ProductPublicKeyPEM,
				AuthorityID: placement.AuthorityID, AuthorityGeneration: volume.AuthorityEpoch,
				ProjectID: placement.ProjectID, ServiceUID: placement.ServiceUID, ServiceGID: placement.ServiceGID,
				ListenPort: placement.ListenPort, QuotaBytes: volume.QuotaBytes, QuotaInodes: volume.QuotaInodes,
				AuthorityServerName: placement.AuthorityServerName, AuthorityCertificate: placement.AuthorityCertificatePEM,
				PriorStrictFenced: placement.PriorStrictFenced, PlacementSequence: placement.Sequence,
			}
			switch phase {
			case cellplan.PhaseArchive:
				entry.ArchiveTo = &cellplan.ArchiveTarget{Attempt: volume.ArchiveAttempt, KeyVersion: manager.cfg.ArchiveKeyVersion}
			case cellplan.PhaseRestore:
				entry.RestoreFrom = restoreSource(*volume.Archive)
			case cellplan.PhaseRelease:
				entry.ReleaseProof = &cellplan.ReleaseProof{PlacementSequence: placement.Sequence, AuthorityEpoch: volume.AuthorityEpoch, DestroyProofSHA256: placement.DestroyProofSHA256}
			case cellplan.PhaseProvision, cellplan.PhaseServe, cellplan.PhaseFence, cellplan.PhaseQuiesce, cellplan.PhaseDestroy:
			default:
				return fmt.Errorf("%w: cell plan phase", ErrInvalid)
			}
			plan.Volumes = append(plan.Volumes, entry)
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
		if volume.Placement == nil {
			return nil, ErrConflict
		}
		placement := volume.Placement
		cell := state.Cells[placement.CellID]
		if !mountableVolume(volume) || cell.Health != CellHealthy || !manager.cellConverged(cell, now) {
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
			revokeRenewalScopeEnrollmentsBeforeEpoch(state, volume.ProductIssuer, verified.Claims.RenewalScope, highWater, "renewal-scope-superseded", now)
			if createEnrollment {
				supersedeRenewalScopeEnrollments(state, volume.ProductIssuer, verified.Claims.RenewalScope, volume.ID, "renewal-scope-superseded", now)
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
		if createEnrollment {
			if err := admitMountEnrollment(state, volume); err != nil {
				return nil, err
			}
			enrollmentID = newUUID()
			identity, err := url.Parse("spiffe://portablefs/mount-enrollment/" + enrollmentID)
			if err != nil {
				return nil, err
			}
			enrollmentCertificate, _, err = manager.cfg.EnrollmentCA.SignClientCSR(
				[]byte(csrPEM), enrollmentID, identity, nowTime, manager.cfg.EnrollmentCA.Certificate.NotAfter.Sub(nowTime),
			)
			if err != nil {
				return nil, err
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
			CellID: placement.CellID, AuthorityID: placement.AuthorityID, AuthorityGeneration: volume.AuthorityEpoch,
			ProductAuthorization: productToken, MountEnrollmentID: enrollmentID, SessionID: sessionID, Sequence: sequence,
		}
		capability, err := volumecap.Sign(manager.cfg.CapabilityPrivateKey, claims)
		if err != nil {
			return nil, err
		}
		authorization := MountAuthorization{
			VolumeID: volume.ID, AuthorityEndpoint: net.JoinHostPort(cell.AuthorityHost, fmt.Sprint(placement.ListenPort)),
			AuthorityServerName: placement.AuthorityServerName, AuthorityCAPEM: manager.cfg.AuthorityCA.CertificatePEM,
			ClientCertificatePEM: certificate, Capability: string(capability), Access: append([]string(nil), access...),
			ExpiresUnix: expires.Unix(), CertificateExpiresUnix: certificateExpires.Unix(), AuthorityGeneration: volume.AuthorityEpoch,
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
				CellID: placement.CellID, AuthorityID: placement.AuthorityID, AuthorityGeneration: volume.AuthorityEpoch,
				CreatedUnix: now, ExpiresUnix: nowTime.Add(manager.cfg.EnrollmentLease).Unix(), State: MountEnrollmentActive, UpdatedUnix: now,
				RenewalScope: verified.Claims.RenewalScope, RenewalEpoch: verified.Claims.RenewalEpoch,
			}
			authorization.EnrollmentID = enrollmentID
			authorization.EnrollmentCertificatePEM = enrollmentCertificate
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
	enrollmentEnded := false
	raw, err := manager.cfg.Store.TransactNatural("refresh-mount-enrollment", now, func(state *State) (any, bool, error) {
		pruned := pruneMountEnrollments(state, now)
		enrollment, ok := state.MountEnrollments[enrollmentID]
		if !ok {
			return nil, false, ErrNotFound
		}
		volume, volumeOK := state.Volumes[enrollment.VolumeID]
		cell, cellOK := state.Cells[enrollment.CellID]
		if enrollment.State != MountEnrollmentActive || now >= enrollment.ExpiresUnix || !volumeOK || volume.Placement == nil ||
			volume.AuthorityEpoch != enrollment.AuthorityGeneration || volume.Placement.AuthorityID != enrollment.AuthorityID {
			enrollmentEnded = true
			return MountAuthorization{}, pruned, nil
		}
		if !cellOK || !mountableVolume(volume) || cell.Health != CellHealthy || !manager.cellConverged(cell, now) {
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
			VolumeID: enrollment.VolumeID, AuthorityEndpoint: net.JoinHostPort(cell.AuthorityHost, fmt.Sprint(volume.Placement.ListenPort)),
			AuthorityServerName: volume.Placement.AuthorityServerName, AuthorityCAPEM: manager.cfg.AuthorityCA.CertificatePEM,
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
		enrollment.ExpiresUnix = nowTime.Add(manager.cfg.EnrollmentLease).Unix()
		enrollment.UpdatedUnix = now
		state.MountEnrollments[enrollmentID] = enrollment
		pruneMountAuthorizationContexts(state)
		return authorization, true, nil
	})
	if err != nil {
		return MountAuthorization{}, err
	}
	if enrollmentEnded {
		return MountAuthorization{}, ErrEnrollmentEnded
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
		case MountEnrollmentExpired:
			result.Outcome = MountEnrollmentRevocationExpired
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

func (manager *Manager) UpdateCellCapacity(requestID, cellID string, request UpdateCellCapacityRequest) (Cell, error) {
	if !cellplan.ValidID(cellID) || request.CapacityBytes == 0 || request.CapacityInodes == 0 {
		return Cell{}, ErrInvalid
	}
	now := nowUnix(manager.cfg.Now)
	idempotencyRequest := struct {
		CellID  string                    `json:"cell_id"`
		Request UpdateCellCapacityRequest `json:"request"`
	}{CellID: cellID, Request: request}
	raw, _, err := manager.cfg.Store.Transact(requestID, "update-cell-capacity", idempotencyRequest, now, func(state *State) (any, error) {
		cell, ok := state.Cells[cellID]
		if !ok {
			return nil, ErrNotFound
		}
		if request.CapacityBytes < cell.CapacityBytes || request.CapacityInodes < cell.CapacityInodes ||
			request.CapacityBytes == cell.CapacityBytes && request.CapacityInodes == cell.CapacityInodes {
			return nil, ErrConflict
		}
		cell.CapacityBytes, cell.CapacityInodes = request.CapacityBytes, request.CapacityInodes
		state.Cells[cellID] = cell
		return cell, nil
	})
	if err != nil {
		return Cell{}, err
	}
	return decode[Cell](raw)
}

func (manager *Manager) DecommissionCell(requestID, cellID string, request DecommissionCellRequest) (Cell, error) {
	request.Reason = strings.TrimSpace(request.Reason)
	if !cellplan.ValidID(cellID) || !validIdentity(request.Reason) {
		return Cell{}, ErrInvalid
	}
	now := nowUnix(manager.cfg.Now)
	idempotencyRequest := struct {
		CellID  string                  `json:"cell_id"`
		Request DecommissionCellRequest `json:"request"`
	}{CellID: cellID, Request: request}
	raw, _, err := manager.cfg.Store.Transact(requestID, "decommission-cell", idempotencyRequest, now, func(state *State) (any, error) {
		cell, ok := state.Cells[cellID]
		if !ok {
			return nil, ErrNotFound
		}
		cell.Decommissioning = true
		state.Cells[cellID] = cell
		return cell, nil
	})
	if err != nil {
		return Cell{}, err
	}
	return decode[Cell](raw)
}

func (manager *Manager) AbandonCell(requestID, cellID string, request AbandonCellRequest) (Cell, error) {
	request.Reason = strings.TrimSpace(request.Reason)
	if !cellplan.ValidID(cellID) || !validIdentity(request.Reason) {
		return Cell{}, ErrInvalid
	}
	now := nowUnix(manager.cfg.Now)
	idempotencyRequest := struct {
		CellID  string             `json:"cell_id"`
		Request AbandonCellRequest `json:"request"`
	}{CellID: cellID, Request: request}
	raw, _, err := manager.cfg.Store.Transact(requestID, "abandon-cell", idempotencyRequest, now, func(state *State) (any, error) {
		cell, ok := state.Cells[cellID]
		if !ok {
			return nil, ErrNotFound
		}
		if cell.Abandoned {
			return cell, nil
		}
		for id, volume := range state.Volumes {
			if volume.Placement == nil || volume.Placement.CellID != cellID {
				continue
			}
			if volume.State == VolumeArchived && volume.Archive != nil && (volume.ArchiveCycleStep == "sealed" || volume.ArchiveCycleStep == "destroyed") {
				placement := volume.Placement
				state.OrphanedPlacements = append(state.OrphanedPlacements, OrphanedPlacement{VolumeID: id, CellID: cellID,
					Placement: OrphanedPlacementTuple{Sequence: placement.Sequence, ProjectID: placement.ProjectID, ServiceUID: placement.ServiceUID,
						ServiceGID: placement.ServiceGID, ListenPort: placement.ListenPort, AuthorityID: placement.AuthorityID,
						AuthorityServerName: placement.AuthorityServerName, DestroyProofSHA256: placement.DestroyProofSHA256},
					Epoch: volume.AuthorityEpoch, RecordedUnix: now, Reason: "data orphaned, not proven destroyed: " + request.Reason})
				if len(state.OrphanedPlacements) > MaxOrphanedPlacements {
					state.OrphanedPlacements = state.OrphanedPlacements[len(state.OrphanedPlacements)-MaxOrphanedPlacements:]
				}
				volume.Placement = nil
				volume.ArchiveCycleStep = "released"
				volume.WakeRequested = false
				volume.UpdatedUnix = now
			} else {
				manager.quarantineVolume(state, &volume, "cell abandoned: "+request.Reason, now)
			}
			state.Volumes[id] = volume
		}
		cell.Abandoned = true
		cell.Decommissioning = true
		cell.Health = CellQuarantined
		cell.QuarantineReason = "cell abandoned: " + request.Reason
		manager.bumpPlan(&cell, now)
		state.Cells[cellID] = cell
		return cell, nil
	})
	if err != nil {
		return Cell{}, err
	}
	return decode[Cell](raw)
}

func (manager *Manager) Capacity() (CapacityReport, error) {
	var report CapacityReport
	err := manager.cfg.Store.View(func(state State) error {
		byPool := map[string]*PoolCapacity{}
		for _, pool := range []string{PoolProduct, PoolSystem, PoolTest} {
			byPool[pool] = &PoolCapacity{Pool: pool}
		}
		for _, cell := range state.Cells {
			p := byPool[cell.Pool]
			p.CapacityBytes += cell.CapacityBytes
			p.CapacityInodes += cell.CapacityInodes
		}
		for _, volume := range state.Volumes {
			p := byPool[volume.Pool]
			if volume.State == VolumeArchived {
				p.ArchivedVolumes++
			}
			if volume.Placement == nil {
				continue
			}
			p.Placements++
			p.MeasuredUsedBytes += volume.Placement.UsedBytes
			p.MeasuredUsedInodes += volume.Placement.UsedInodes
			p.PendingBytes += volume.Placement.PendingBytes
			p.PendingInodes += volume.Placement.PendingInodes
		}
		now := nowUnix(manager.cfg.Now)
		for _, pool := range []string{PoolProduct, PoolSystem, PoolTest} {
			_, createErr := manager.admitPlacement(&state, pool, manager.cfg.ProvisionFloorBytes, manager.cfg.ProvisionFloorInodes, false, now)
			_, restoreErr := manager.admitPlacement(&state, pool, manager.cfg.ProvisionFloorBytes, manager.cfg.ProvisionFloorInodes, true, now)
			byPool[pool].CreateAdmissible = createErr == nil
			byPool[pool].RestoreAdmissible = restoreErr == nil
			byPool[pool].CreateStatus = admissionStatus(createErr)
			byPool[pool].RestoreStatus = admissionStatus(restoreErr)
			report.Pools = append(report.Pools, *byPool[pool])
		}
		return nil
	})
	return report, err
}

func (manager *Manager) NoteVerify(volumeID string) error {
	if !cellplan.ValidID(volumeID) {
		return ErrInvalid
	}
	var attempt string
	if err := manager.cfg.Store.View(func(state State) error {
		volume, ok := state.Volumes[volumeID]
		if !ok {
			return ErrNotFound
		}
		if volume.State != VolumeArchiving || volume.ArchiveCycleStep != "verifying" || volume.PendingSeal == nil {
			return ErrConflict
		}
		attempt = volume.PendingSeal.Attempt
		return nil
	}); err != nil {
		return err
	}
	_, err := manager.RetryVerification("internal-archive-verify:"+volumeID+":"+attempt, volumeID)
	return err
}

func (manager *Manager) admitPlacement(state *State, pool string, needBytes, needInodes uint64, isRestore bool, now int64) (*Cell, error) {
	var selected *Cell
	var selectedBytes, selectedInodes uint64
	// busySkipped records that some cell cleared every eligibility and capacity
	// gate and was passed over only for a concurrency cap. That distinction is
	// the caller's error: a saturated fleet is retryable, an exhausted one is not.
	busySkipped := false
	// unavailableSkipped means at least one durable cell could physically hold
	// the placement, but its current liveness or full-usage evidence is stale.
	// This is retryable without changing the request and is therefore distinct
	// from fleet capacity exhaustion.
	unavailableSkipped := false
	staleAfter := int64(manager.cfg.UsageStaleAfter / time.Second)
	for _, id := range sortedCellIDs(state.Cells) {
		cell := state.Cells[id]
		if cell.Pool != pool || cell.Health == CellQuarantined || cell.Decommissioning || cell.Abandoned || cell.NextProjectID == ^uint32(0) ||
			cell.NextServiceUID == ^uint32(0) || cell.NextPort == ^uint16(0) {
			continue
		}
		if isRestore && !cell.ArchiveConfigured {
			continue
		}
		loadBytes, loadInodes, placements := uint64(0), uint64(0), 0
		for _, volume := range state.Volumes {
			if volume.Placement == nil || volume.Placement.CellID != id {
				continue
			}
			placements++
			chargeBytes := max(volume.Placement.UsedBytes, volume.Placement.PendingBytes, manager.cfg.ProvisionFloorBytes)
			chargeInodes := max(volume.Placement.UsedInodes, volume.Placement.PendingInodes, manager.cfg.ProvisionFloorInodes)
			// The cell-level freshness gate below does not cover one placement
			// whose own measurement froze while its cell kept heartbeating. Past
			// UsageStaleAfter from the later of its last measurement and its
			// creation — the grace window a never-yet-measured placement gets —
			// charge the volume's quota ceiling instead of a stale reading.
			if now-max(volume.Placement.UsedObservedUnix, volume.Placement.CreatedUnix) > staleAfter {
				chargeBytes = max(volume.QuotaBytes, volume.Placement.PendingBytes, manager.cfg.ProvisionFloorBytes)
				chargeInodes = max(volume.QuotaInodes, volume.Placement.PendingInodes, manager.cfg.ProvisionFloorInodes)
			}
			var ok bool
			loadBytes, ok = addUint64(loadBytes, chargeBytes)
			if !ok {
				loadBytes = ^uint64(0)
			}
			loadInodes, ok = addUint64(loadInodes, chargeInodes)
			if !ok {
				loadInodes = ^uint64(0)
			}
		}
		if placements >= MaxVolumesPerCell {
			continue
		}
		reserveBytes := uint64(float64(cell.CapacityBytes)*manager.cfg.CellReserveFraction + 0.999999)
		reserveInodes := uint64(float64(cell.CapacityInodes)*manager.cfg.CellReserveFraction + 0.999999)
		postBytes, okB := addUint64(loadBytes, needBytes)
		totalBytes, okBR := addUint64(postBytes, reserveBytes)
		postInodes, okI := addUint64(loadInodes, needInodes)
		totalInodes, okIR := addUint64(postInodes, reserveInodes)
		if !okB || !okBR || !okI || !okIR || totalBytes > cell.CapacityBytes || totalInodes > cell.CapacityInodes {
			continue
		}
		if !isRestore && cell.CapacityBytes-postBytes < manager.cfg.WakeBurstBytes {
			continue
		}
		if !manager.cellLive(cell, now) || cell.LastObservedUnix == 0 || now-cell.LastObservedUnix > staleAfter {
			unavailableSkipped = true
			continue
		}
		// Checked last so a cell rejected here is known to be otherwise able to
		// hold the placement — merely busy, not out of room.
		if isRestore && restoringCellLoad(state, id) >= manager.cfg.MaxRestoringPerCell {
			busySkipped = true
			continue
		}
		if selected == nil || loadBytes < selectedBytes || loadBytes == selectedBytes && loadInodes < selectedInodes {
			copy := cell
			selected = &copy
			selectedBytes, selectedInodes = loadBytes, loadInodes
		}
	}
	if selected == nil {
		if busySkipped {
			return nil, ErrBusy
		}
		if unavailableSkipped {
			return nil, ErrCellUnavailable
		}
		return nil, ErrCapacity
	}
	return selected, nil
}

func admissionStatus(err error) AdmissionStatus {
	switch {
	case err == nil:
		return AdmissionAdmissible
	case errors.Is(err, ErrCellUnavailable):
		return AdmissionCellUnavailable
	case errors.Is(err, ErrBusy):
		return AdmissionBusy
	default:
		return AdmissionCapacity
	}
}

// archivingCellLoad counts archive cycles whose remaining work still runs on
// the cell. Cursors "quiescing" and "exporting" hold the authority-stop and the
// archiver unit; "verifying" does not — phase exit already proved the archiver
// absent and the only outstanding work is the Manager's own archive-store
// verification, which burdens the Manager, not the cell.
func archivingCellLoad(state *State, cellID string) int {
	count := 0
	for _, volume := range state.Volumes {
		if volume.State != VolumeArchiving || volume.Placement == nil || volume.Placement.CellID != cellID {
			continue
		}
		if volume.ArchiveCycleStep == "quiescing" || volume.ArchiveCycleStep == "exporting" {
			count++
		}
	}
	return count
}

func restoringCellLoad(state *State, cellID string) int {
	count := 0
	for _, volume := range state.Volumes {
		if volume.State == VolumeRestoring && volume.Placement != nil && volume.Placement.CellID == cellID {
			count++
		}
	}
	return count
}

func (manager *Manager) restoreCharge(record ArchiveRecord) (uint64, uint64, error) {
	// The archive's own sizing and the last measured allocation at seal time can
	// each understate the other (sparse trees, block rounding, pre-quiesce
	// measurement); admission charges the larger before overhead.
	base := max(record.SealedAllocatedBytes, record.SealedMeasuredBytes)
	baseInodes := max(record.SealedInodes, record.SealedMeasuredInodes)
	extra := uint64(float64(base)*manager.cfg.RestoreOverheadFraction + 0.999999)
	bytes, ok := addUint64(base, extra)
	if !ok {
		return 0, 0, ErrCapacity
	}
	bytes, ok = addUint64(bytes, manager.cfg.RestoreOverheadBytes)
	if !ok {
		return 0, 0, ErrCapacity
	}
	inodes, ok := addUint64(baseInodes, manager.cfg.RestoreOverheadInodes)
	if !ok {
		return 0, 0, ErrCapacity
	}
	return bytes, inodes, nil
}

func addUint64(left, right uint64) (uint64, bool) {
	result := left + right
	return result, result >= left
}

func mountableVolume(volume Volume) bool {
	return volume.State == VolumeReady || volume.State == VolumeRestoring && volume.RestoreStep == "serving-restore"
}
func clearPlacementAuthority(placement *Placement) {
	placement.AuthorityCSRPEM = ""
	placement.AuthorityCertificatePEM = ""
	placement.AuthorityCertExpires = 0
}
func pruneVolumeEnrollments(state *State, volumeID string) {
	for id, enrollment := range state.MountEnrollments {
		if enrollment.VolumeID == volumeID && enrollment.State != MountEnrollmentActive {
			delete(state.MountEnrollments, id)
		}
	}
	pruneMountAuthorizationContexts(state)
}

func pruneVolumeReceipts(state *State, volumeID string) {
	volumeViewOperations := map[string]struct{}{
		"create-volume": {}, "restart-volume": {}, "confirm-strict-fence": {},
		"archive-volume": {}, "wake-volume": {}, "destroy-volume": {}, "retry-archive-verification": {},
	}
	mountOperations := map[string]struct{}{"issue-mount": {}, "reauthorize-mount": {}}
	for requestID, receipt := range state.Receipts {
		if _, ok := volumeViewOperations[receipt.Operation]; ok {
			var response struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(receipt.Response, &response) == nil && response.ID == volumeID {
				delete(state.Receipts, requestID)
			}
			continue
		}
		if _, ok := mountOperations[receipt.Operation]; ok {
			var response struct {
				VolumeID string `json:"volume_id"`
			}
			if json.Unmarshal(receipt.Response, &response) == nil && response.VolumeID == volumeID {
				delete(state.Receipts, requestID)
			}
		}
	}
}

func archiveRecordFromObservation(volume Volume, sealed *ArchiveSealedObservation, now int64) (ArchiveRecord, error) {
	if sealed == nil || sealed.Attempt != volume.ArchiveAttempt {
		return ArchiveRecord{}, ErrInvalid
	}
	record := ArchiveRecord{FormatVersion: sealed.FormatVersion, ChunkSizeBytes: sealed.ChunkSizeBytes, Attempt: sealed.Attempt,
		SealedEpoch: volume.AuthorityEpoch, SealedUnix: now, Manifest: sealed.Manifest, Packs: append([]ObjectRef(nil), sealed.Packs...),
		RootDigest: sealed.RootDigest, LogicalBytes: sealed.LogicalBytes, LogicalInodes: sealed.LogicalInodes,
		SealedAllocatedBytes: sealed.SealedAllocatedBytes, SealedInodes: sealed.SealedInodes, KeyVersion: sealed.KeyVersion}
	if err := record.Validate(); err != nil {
		return ArchiveRecord{}, err
	}
	return record, nil
}

func archiveRecordsEqual(left, right ArchiveRecord) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return string(a) == string(b)
}

// applyVerifiedSeal is the pure durable commit of an already-verified seal.
// The archive-store verification and any checkpoint purge run OUTSIDE the
// store lock in VerifyPendingSeal; this function only mutates state.
func applyVerifiedSeal(manager *Manager, state *State, volume *Volume, now int64) {
	// The volume is quiesced for the whole cycle, so the placement's last
	// measurement is exact or a pre-quiesce lower bound. Either is safe: restore
	// admission charges max(this, the archive's own sizing).
	record := *volume.PendingSeal
	record.SealedMeasuredBytes = volume.Placement.UsedBytes
	record.SealedMeasuredInodes = volume.Placement.UsedInodes
	volume.Archive = &record
	volume.PendingSeal = nil
	volume.ArchiveAttempt = ""
	volume.State = VolumeArchived
	volume.ArchiveCycleStep = "sealed"
	volume.UpdatedUnix = now
	cell := state.Cells[volume.Placement.CellID]
	manager.bumpPlan(&cell, now)
	state.Cells[cell.ID] = cell
}

// VerifyPendingSeal runs the Manager's independent archive verification for
// one volume at cursor "verifying" and, on success, durably commits ARCHIVED.
// The store lock is never held across archive-store network I/O: the pending
// seal is snapshotted, verified (and any superseded checkpoint purged)
// unlocked, and the commit transaction re-checks that nothing moved while the
// network ran. Repeated calls converge; a concurrent wake-cancel or a changed
// pending seal makes the commit refuse with ErrConflict and the next
// verification pass starts over from the durable cursor.
func (manager *Manager) VerifyPendingSeal(requestID, volumeID string) (VolumeView, error) {
	if !validIdentity(requestID) || !cellplan.ValidID(volumeID) {
		return VolumeView{}, ErrInvalid
	}
	if manager.cfg.ArchiveVerifier == nil {
		return VolumeView{}, ErrArchiveUnsupported
	}
	var pending ArchiveRecord
	var checkpoint *ArchiveRecord
	if err := manager.cfg.Store.View(func(state State) error {
		volume, ok := state.Volumes[volumeID]
		if !ok {
			return ErrNotFound
		}
		if volume.State != VolumeArchiving || volume.ArchiveCycleStep != "verifying" || volume.PendingSeal == nil {
			return ErrConflict
		}
		pending = *volume.PendingSeal
		if volume.Archive != nil {
			record := *volume.Archive
			checkpoint = &record
		}
		return nil
	}); err != nil {
		return VolumeView{}, err
	}
	if err := manager.cfg.ArchiveVerifier.Verify(pending); err != nil {
		return VolumeView{}, fmt.Errorf("%w: %v", ErrArchiveStoreUnavailable, err)
	}
	if checkpoint != nil {
		if manager.cfg.ArchivePurger == nil {
			return VolumeView{}, ErrArchiveUnsupported
		}
		if err := manager.cfg.ArchivePurger.Purge(*checkpoint); err != nil {
			return VolumeView{}, fmt.Errorf("%w: %v", ErrArchiveStoreUnavailable, err)
		}
	}
	return manager.updateVolume(requestID, "retry-archive-verification", ArchiveVolumeRequest{VolumeID: volumeID},
		func(state *State, volume *Volume, now int64) error {
			if volume.State != VolumeArchiving || volume.ArchiveCycleStep != "verifying" || volume.PendingSeal == nil ||
				!archiveRecordsEqual(*volume.PendingSeal, pending) {
				return ErrConflict
			}
			if (volume.Archive == nil) != (checkpoint == nil) ||
				volume.Archive != nil && !archiveRecordsEqual(*volume.Archive, *checkpoint) {
				return ErrConflict
			}
			volume.Archive = nil
			applyVerifiedSeal(manager, state, volume, now)
			return nil
		})
}

// PendingVerifications lists volumes whose archive cycle is waiting on the
// Manager's verification pass. The serve loop drives them with NoteVerify.
func (manager *Manager) PendingVerifications() ([]string, error) {
	var ids []string
	err := manager.cfg.Store.View(func(state State) error {
		for id, volume := range state.Volumes {
			if volume.State == VolumeArchiving && volume.ArchiveCycleStep == "verifying" && volume.PendingSeal != nil {
				ids = append(ids, id)
			}
		}
		return nil
	})
	slices.Sort(ids)
	return ids, err
}

func restoreSource(record ArchiveRecord) *cellplan.RestoreSource {
	return &cellplan.RestoreSource{SealedEpoch: record.SealedEpoch, Attempt: record.Attempt, ManifestDigestSHA256: record.Manifest.SHA256,
		ManifestSizeBytes: record.Manifest.SizeBytes, ManifestCRC64NVME: record.Manifest.CRC64NVME, PackCount: uint32(len(record.Packs)),
		SealedAllocatedBytes: record.SealedAllocatedBytes, SealedInodes: record.SealedInodes}
}

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
	volume.ArchiveCycleStep = ""
	volume.ArchiveAttempt = ""
	volume.PendingSeal = nil
	volume.RestoreStep = ""
	volume.RestoreState = ""
	volume.RestoreProgressPermille = 0
	volume.WakeRequested = false
	volume.DeletionRequested = false
	volume.DestroyedUnix = 0
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

func supersedeRenewalScopeEnrollments(state *State, productIssuer, scope, volumeID, reason string, now int64) bool {
	changed := false
	for id, enrollment := range state.MountEnrollments {
		if enrollment.ProductIssuer != productIssuer || enrollment.RenewalScope != scope || enrollment.VolumeID != volumeID ||
			enrollment.State != MountEnrollmentActive {
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
		if enrollment.State == MountEnrollmentActive && enrollment.ExpiresUnix <= now {
			enrollment.State = MountEnrollmentExpired
			enrollment.TerminationReason = "lease-expired"
			enrollment.UpdatedUnix = now
			state.MountEnrollments[id] = enrollment
			changed = true
			continue
		}
		if enrollment.State != MountEnrollmentActive && enrollment.UpdatedUnix+retention <= now {
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
