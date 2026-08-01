package portablefsd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func (s *Server) ServeControl(ctx context.Context) error {
	if s.cfg.ControlSocket == "" {
		return fmt.Errorf("control socket is required")
	}
	ln, err := listenUnixSocket(s.cfg.ControlSocket)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/v1/identity", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, daemonctl.Identity{
			SchemaVersion:    daemonctl.IdentitySchemaVersion,
			ControlProtocol:  daemonctl.ControlProtocolVersion,
			DaemonVersion:    s.cfg.Version,
			ExecutableSHA256: s.cfg.ExecutableSHA256,
			PFSLocalMajor:    pfslocal.ProtocolMajor,
			PFSLocalMinor:    pfslocal.ProtocolMinor,
		})
	})
	mux.Handle("/v1/attaches", requireControlProtocol(http.HandlerFunc(s.handleAttaches)))
	mux.Handle("/v1/attaches/", requireControlProtocol(http.HandlerFunc(s.handleAttach)))
	mux.Handle("/v1/lifecycle/stop-if-idle", requireControlProtocol(http.HandlerFunc(s.handleStopIfIdle)))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = srv.Shutdown(shutCtx)
		cancel()
		_ = ln.Close()
	}()
	log.Printf("portablefsd control socket listening at %s", s.cfg.ControlSocket)
	err = srv.Serve(ln)
	if err == http.ErrServerClosed || ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) handleStopIfIdle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	idle, attachCount, err := s.registry.quiesceIfIdle()
	if err != nil {
		writeHTTPError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !idle {
		writeHTTPError(w, http.StatusConflict, fmt.Sprintf("daemon has %d attach(es); cleanly unmount all volumes before stopping it", attachCount))
		return
	}
	w.WriteHeader(http.StatusNoContent)
	go s.stopOnce.Do(func() { close(s.stopCh) })
}

func requireControlProtocol(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(daemonctl.ControlProtocolHeader) != strconv.Itoa(daemonctl.ControlProtocolVersion) {
			writeHTTPError(w, http.StatusUpgradeRequired, "incompatible or missing PortableFS daemon control protocol")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleAttaches(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req ensureAttachRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		a, _, err := s.registry.ensure(context.Background(), req)
		if err != nil {
			writeHTTPError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"attachRef":  a.ref,
			"volumeName": a.volumeName,
			"localDirs":  a.status().LocalDirs,
		})
	case http.MethodGet:
		var out []attachStatus
		for _, a := range s.registry.list() {
			out = append(out, a.status())
		}
		writeJSON(w, http.StatusOK, map[string]any{"attaches": out})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAttach(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/attaches/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeHTTPError(w, http.StatusNotFound, "missing attach ref")
		return
	}
	ref := parts[0]
	a := s.registry.get(ref)
	if a == nil {
		writeHTTPError(w, http.StatusNotFound, "unknown attach")
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			a.marshalJSONStatus(w)
		case http.MethodDelete:
			writeHTTPError(w, http.StatusMethodNotAllowed, "DELETE cannot prove exact FSKit kernel teardown; use POST /v1/attaches/{ref}/unmount")
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	switch strings.Join(parts[1:], "/") {
	case "unmount":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		force := r.URL.Query().Get("force") == "1"
		// The HTTP request's context bounds only THIS waiter: a client that
		// hangs up (or its own timeout) must never abandon a transaction that
		// owns durable state.
		found, jobID, err := s.registry.unmountFSKit(r.Context(), ref, force)
		if err != nil {
			writeHTTPError(w, http.StatusConflict, err.Error())
			return
		}
		if !found {
			writeHTTPError(w, http.StatusNotFound, "unknown attach")
			return
		}
		if force || jobID != "" {
			writeJSON(w, http.StatusOK, map[string]any{
				"forced":      force,
				"recoveryJob": jobID,
			})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "credential":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			AuthToken string `json:"authToken"`
			// AuthTokenExpiresAtMs is the access lease's OWN stated expiry for
			// this credential (unix ms). It is what bounds the UNPROVEN state:
			// past it a credential no handshake ever accepted or refused
			// hardens into the definite expired verdict instead of pending
			// forever. OPTIONAL and additive — an older CLI omits it, the zero
			// value states no deadline, and nothing hardens.
			AuthTokenExpiresAtMs int64 `json:"authTokenExpiresAtMs,omitempty"`
			OnlyIfPending        bool  `json:"onlyIfPending,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		found, activated, err := s.registry.activate(r.Context(), ref, req.AuthToken, req.AuthTokenExpiresAtMs, req.OnlyIfPending)
		if err != nil {
			writeHTTPError(w, http.StatusBadGateway, err.Error())
			return
		}
		if !found {
			writeHTTPError(w, http.StatusNotFound, "unknown attach")
			return
		}
		if activated {
			if eno := a.persistStateOrEIO("credential activation"); eno != 0 {
				writeHTTPError(w, httpStatusForErr(eno), errMessage("credential", eno))
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	case "flush":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		vol, eno := a.volOrErr()
		if eno != 0 {
			writeHTTPError(w, httpStatusForErr(eno), errMessage("flush", eno))
			return
		}
		if err := vol.FlushToAuthority(r.Context()); err != nil {
			writeHTTPError(w, http.StatusBadGateway, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "sync":
		// The unmount-class drain barrier, exposed so `portablefs umount`
		// drains BEFORE the kernel unmount. Success means authority-durable,
		// applied, and peer-acknowledged; failure is an HTTP error carrying
		// the unshipped backlog — the CLI then refuses the normal unmount.
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		vol, eno := a.volOrErr()
		if eno != 0 {
			writeHTTPError(w, httpStatusForErr(eno), errMessage("sync", eno))
			return
		}
		if err := vol.SyncVolume(); err != nil {
			recs, bytes := vol.WriteBackPending()
			writeHTTPError(w, http.StatusBadGateway, fmt.Sprintf("drain failed with %d records (%d bytes) unshipped: %v", recs, bytes, err))
			return
		}
		recs, bytes := vol.WriteBackPending()
		writeJSON(w, http.StatusOK, map[string]any{
			"pendingRecords": recs,
			"pendingBytes":   bytes,
		})
	case "local-dirs":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Dirs []string `json:"dirs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		merged, err := a.addLocalDirs(req.Dirs)
		if err != nil {
			writeHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"localDirs": merged})
	case "fs/list":
		s.controlFSList(w, r, a)
	case "fs/read":
		s.controlFSRead(w, r, a)
	case "fs/write":
		s.controlFSWrite(w, r, a)
	case "fs/stat":
		s.controlFSStat(w, r, a)
	default:
		writeHTTPError(w, http.StatusNotFound, "unknown attach endpoint")
	}
}

func (s *Server) controlFSList(w http.ResponseWriter, r *http.Request, a *attach) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path       string `json:"path"`
		MaxEntries int    `json:"maxEntries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeHTTPError(w, http.StatusBadRequest, err.Error())
		return
	}
	unlockNamespace := a.lockExternalNamespaceRead()
	defer unlockNamespace()
	if err := a.controlAdmissionError(); err != nil {
		writeHTTPError(w, http.StatusConflict, err.Error())
		return
	}
	p := cleanControlPath(req.Path)
	// freshDirListing is the same namespace the FSKit frontend serves: grafted
	// directories list machine-local backing, graft parents merge graft roots
	// over the authority listing, everything else is a plain volume readdir.
	ents, _, eno := a.freshDirListing(r.Context(), p)
	if eno != 0 {
		writeHTTPError(w, httpStatusForErr(eno), errMessage("fs/list", eno))
		return
	}
	if req.MaxEntries > 0 && len(ents) > req.MaxEntries {
		ents = ents[:req.MaxEntries]
	}
	type entry struct {
		Name string       `json:"name"`
		Attr pfslocalAttr `json:"attr"`
	}
	out := make([]entry, 0, len(ents))
	for _, e := range ents {
		out = append(out, entry{Name: e.Name, Attr: attrJSON(e.Attr)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

func (s *Server) controlFSRead(w http.ResponseWriter, r *http.Request, a *attach) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path   string `json:"path"`
		Offset int64  `json:"offset"`
		Length int    `json:"length"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeHTTPError(w, http.StatusBadRequest, err.Error())
		return
	}
	unlockNamespace := a.lockExternalNamespaceRead()
	defer unlockNamespace()
	if err := a.controlAdmissionError(); err != nil {
		writeHTTPError(w, http.StatusConflict, err.Error())
		return
	}
	p := cleanControlPath(req.Path)
	var data []byte
	if graft := a.localDirFor(p); graft != "" {
		local, eno := a.readLocalFile(p, req.Offset, req.Length)
		if eno != 0 {
			writeHTTPError(w, httpStatusForErr(eno), errMessage("fs/read", eno))
			return
		}
		data = local
	} else {
		vol, eno := a.volOrErr()
		if eno != 0 {
			writeHTTPError(w, httpStatusForErr(eno), errMessage("fs/read", eno))
			return
		}
		attr, st := vol.Lookup(r.Context(), p)
		if st != fsproto.OK {
			writeHTTPError(w, httpStatusForErr(toDarwinErr(st)), errMessage("fs/read lookup", toDarwinErr(st)))
			return
		}
		n := clientcore.NewNodeState(attr.Ino, attr.Ino != 0)
		volData, st := vol.Read(r.Context(), p, n, req.Offset, req.Length)
		if st != fsproto.OK {
			writeHTTPError(w, httpStatusForErr(toDarwinErr(st)), errMessage("fs/read", toDarwinErr(st)))
			return
		}
		data = volData
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-PortableFS-Path", p)
	w.Header().Set("X-PortableFS-Offset", strconv.FormatInt(req.Offset, 10))
	w.Header().Set("X-PortableFS-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// reservedIdentity is the pathname identity a control write resolved BEFORE the
// namespace gate and took its item-scoped size reservation against.
//
// ── WHY THE RESERVATION IS ABOUT AN IDENTITY, NOT A PATHNAME ────────────────
//
// The reservation must be taken pre-lock, holding nothing (refreshpin.go), so
// it is necessarily taken against a sample. A concurrent create or rename-over
// then moves the name from A to B — or from absent to B — before the handler
// reaches the lock, and a reservation held on A proves nothing whatever about
// B: if B is pinned, the whole of this write's bracket (begin the sequence,
// commit, publish, settle) can open and close inside the exact gap the pin
// protocol exists to close, and the refresh's ftruncate lands after a commit the
// caller has already been told succeeded.
//
// So the sample is carried into phase 3 and COMPARED with what the name
// resolves to under the lock. The generation is part of the identity because an
// item can be retired and reincarnated at the same ID; the zero value is the
// honest representation of "absent", which is what makes absent-to-present a
// mismatch rather than a match against nothing.
//
// The NodeState is part of it for the same reason and one more: it is the
// object every authority call in the handler runs THROUGH, so a sample that did
// not include it could compare equal while the handler mutated a node the
// registry had already replaced. One reading answers both questions.
//
// ── AND WHY THE LOCAL REGISTRY IS ONLY HALF THE ANSWER ──────────────────────
//
// Every field here is read from this daemon's registry, and the registry is
// exactly what a REMOTE namespace change makes wrong: nsMu and the name stripes
// fence this daemon's own frontends and nothing else. A peer that renames B
// over p — or a registry that is simply behind — leaves this comparison
// perfectly consistent while vol.Lookup(p) answers B. The authority's own
// answer is therefore the FINAL step of target resolution, and it is proved
// against this identity before anything is opened or mutated; see
// authorityTargetProvenLocked.
type reservedIdentity struct {
	itemID     uint64
	generation uint64
	state      *clientcore.NodeState
}

// reservedIdentityForPath resolves the identity currently bound to p, or the
// zero value if the name is unbound.
func (a *attach) reservedIdentityForPath(p string) reservedIdentity {
	rec := a.itemByPath(p)
	if rec == nil {
		return reservedIdentity{}
	}
	return reservedIdentity{
		itemID:     rec.item.ItemID,
		generation: rec.item.ItemGeneration,
		state:      rec.state,
	}
}

// authorityTargetProvenLocked reports whether the identity the AUTHORITY has
// just named for p is the frontend item this attempt reserved. Callers hold
// a.mu in either mode.
//
// It asks the phase-3 identity question and one more that only the authority
// can answer: does the reserved item already CARRY this authority identity?
// Anything else — a pathname the registry no longer binds the same way, a
// different inode, or a reserved NodeState with no authority identity at all —
// is an observation this daemon has yet to record, and the one thing it must
// not do is adopt it in passing and mutate through it.
func (a *attach) authorityTargetProvenLocked(
	p string,
	reserved reservedIdentity,
	authorityIno uint64,
) bool {
	rec := a.paths[p]
	if rec == nil {
		// The name is unbound here, so nothing local claims the object the
		// authority just named.
		return reserved == reservedIdentity{} && authorityIno == 0
	}
	if (reservedIdentity{
		itemID:     rec.item.ItemID,
		generation: rec.item.ItemGeneration,
		state:      rec.state,
	}) != reserved {
		return false
	}
	if authorityIno == 0 {
		// An authority that names no inode cannot be proved against — and
		// cannot be confused either, because there is no second identity to
		// mistake this one for.
		return true
	}
	return rec.state.AuthorityIno() == authorityIno
}

// registerAuthorityTarget records the identity the authority named for p and
// publishes the invalidations that identity change owes the kernel.
//
// It is not a repair and not a fallback: a control write that reaches it has
// LEARNED something true about the namespace — the object at this name is not
// the one this daemon had — and the registry is where that belongs. Publishing
// it here is also what lets the caller unwind without losing anything: the
// namespace invalidation a create would otherwise have published is published
// from here instead, and the re-admission reserves the item that is really
// there.
func (a *attach) registerAuthorityTarget(
	ctx context.Context,
	vol *clientcore.Volume,
	p string,
	attr fsproto.Attr,
) int32 {
	a.mu.Lock()
	savedOwner := a.beginReincarnationOwnerLocked(nil)
	rec := a.registerLocked(p, attr)
	ticket := a.endReincarnationOwnerLocked(savedOwner)
	if rec == nil {
		a.mu.Unlock()
		return darwinEIO
	}
	// The name carries an identity no live vnode has been told about, and its
	// contents are that object's, not the one the kernel has cached.
	a.publishNamespaceInvalidationLocked(p, 0, 0)
	a.publishContentInvalidationLocked(p, 0, 0)
	a.mu.Unlock()
	if eno, _ := ticket.settle(ctx, vol); eno != 0 {
		return eno
	}
	return a.flushBindingDelta()
}

func (s *Server) controlFSWrite(w http.ResponseWriter, r *http.Request, a *attach) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path       string `json:"path"`
		DataBase64 string `json:"dataBase64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeHTTPError(w, http.StatusBadRequest, err.Error())
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.DataBase64)
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, err.Error())
		return
	}
	p := cleanControlPath(req.Path)

	// The graft arm (controlGraftWriteOnce), which is machine-local and needs
	// the namespace gate and nothing else.
	if graft := a.localDirFor(p); graft != "" {
		// One absolute deadline for the whole arm, re-admissions included: it is
		// what terminates the loop below, exactly as it does on the authority
		// arm. Deriving a fresh one per attempt would give the retry an
		// unbounded budget.
		graftCtx, cancelGraft := clientcore.WithOperationDeadline(r.Context())
		defer cancelGraft()
		var refreshItemID uint64
		for {
			readmit, status, message, itemID := a.controlGraftWriteOnce(graftCtx, p, graft, data)
			if readmit {
				// PHASE 3 refused to mutate under the locks because the name no
				// longer names the identity this attempt reserved. Every lock
				// and the reservation are released by now, so re-admit out here
				// against the identity that is actually there — the same unwind
				// discipline a lane change runs.
				if graftCtx.Err() != nil {
					writeHTTPError(
						w,
						httpStatusForErr(creditErrno(graftCtx.Err())),
						errMessage("fs/write admission", creditErrno(graftCtx.Err())),
					)
					return
				}
				continue
			}
			if status != 0 {
				writeHTTPError(w, status, message)
				return
			}
			refreshItemID = itemID
			break
		}
		refreshCtx, cancelRefresh := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Minute)
		err := a.exactKernelRefresh(refreshCtx, refreshItemID)
		cancelRefresh()
		if err != nil {
			a.failCoherence(err)
			writeHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	vol, eno := a.volOrErr()
	if eno != 0 {
		writeHTTPError(w, httpStatusForErr(eno), errMessage("fs/write", eno))
		return
	}

	// The control plane is a FRONTEND. It mutates the same namespace the FSKit
	// and FUSE frontends mutate, through the same clientcore entry points, so it
	// obeys the same dispatcher-ordering contract (frontend.go) rather than a
	// private one of its own:
	//
	//	PHASE 0  one absolute operation deadline — the raw HTTP context carries
	//	         none, so before this a control write could hold the EXCLUSIVE
	//	         namespace gate for as long as the uplink took;
	//	PHASE 1  pre-lock admission: the delegation transition claim and the
	//	         release of every operand scope, taken holding nothing;
	//	PHASE 2  the namespace gate;
	//	PHASE 3  nonblocking token revalidation plus the mutation itself.
	//
	// Taking the claim under lockExternalNamespaceWrite (which is
	// frontendSerial.Lock + nsMu.Lock, mount-wide and exclusive) was not merely
	// slow: it inverted the one global lock order the whole daemon depends on.
	// Every frontend request holds the mirrors while its handler runs, and the
	// pre-lock classifier holds a transition claim across them; a control write
	// holding the mirrors and WAITING for a claim closes that cycle exactly.
	//
	// The authority lane is resolved unconditionally. A control write is an
	// administrative write-through: it publishes to a path the caller does not
	// hold open, and resolving the delegated lane would only guarantee an unwind
	// the moment the Create or the Setattr reached beginAuthorityMutation.
	opCtx, cancelOperation := clientcore.WithOperationDeadline(r.Context())
	defer cancelOperation()
	var (
		refreshItemID uint64
		httpStatus    int
		httpMessage   string
	)
	for {
		// ONE READING OF THE PATHNAME'S IDENTITY, USED FOR BOTH HALVES.
		//
		// The reservation is taken against this sample and phase 3 compares the
		// locked target with it — and every authority call in the handler runs
		// through this sample's NodeState. Reading the node separately from the
		// identity is how the two could be about different objects: the registry
		// can replace a record's NodeState while its item and generation stay
		// exactly what they were, and the comparison would then pass over a node
		// nothing in the registry points at any more.
		reserved := a.reservedIdentityForPath(p)
		node := reserved.state
		if node == nil {
			node = clientcore.NewNodeState(0, false)
		}
		// PHASE 1.
		mutCtx, _, settle, err := vol.AdmitWrite(opCtx, p, node, len(data), true)
		if err != nil {
			settle()
			writeHTTPError(
				w,
				httpStatusForErr(creditErrno(err)),
				errMessage("fs/write admission", creditErrno(err)),
			)
			return
		}
		// The item-scoped size token, taken after the lane admission and before
		// the namespace gate, exactly as attach.admitRequest takes it for a
		// kernel frontend request (refreshpin.go). The identity it is taken
		// against travels into phase 3, which compares it with the locked target
		// — and with the authority's own answer — before it mutates anything
		// (see reservedIdentity).
		releaseToken, tokenEno := a.reserveSizeMutation(opCtx, reserved.itemID)
		if tokenEno != 0 {
			settle()
			writeHTTPError(
				w, httpStatusForErr(tokenEno), errMessage("fs/write admission", tokenEno),
			)
			return
		}
		if probe := a.testControlAdmissionProbe; probe != nil {
			probe(mutCtx)
		}
		readmit, status, message, itemID := a.controlWriteLocked(
			mutCtx, vol, p, node, data, reserved,
		)
		if releaseToken != nil {
			releaseToken()
		}
		settle()
		if readmit {
			// PHASE 3 refused to transition under the locks — either the lane it
			// pre-resolved no longer holds, or the name no longer names the
			// identity this attempt reserved — and every lock, the reservation
			// and the lane token are released by now. Re-admit out here, under
			// the SAME deadline, which is what terminates the loop.
			if opCtx.Err() != nil {
				writeHTTPError(
					w,
					httpStatusForErr(creditErrno(opCtx.Err())),
					errMessage("fs/write admission", creditErrno(opCtx.Err())),
				)
				return
			}
			continue
		}
		refreshItemID, httpStatus, httpMessage = itemID, status, message
		break
	}
	if httpStatus != 0 {
		writeHTTPError(w, httpStatus, httpMessage)
		return
	}
	// This write bypassed the kernel entirely. Do not acknowledge it until
	// every live vnode reflects the composed local view; otherwise FSKit can
	// serve pre-write pages after a successful control response.
	refreshCtx, cancelRefresh := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Minute)
	err = a.exactKernelRefresh(refreshCtx, refreshItemID)
	cancelRefresh()
	if err != nil {
		a.failCoherence(err)
		writeHTTPError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// controlGraftWriteOnce is ONE admission-and-mutation attempt of the graft arm.
//
// A GRAFT is machine-local: no delegation covers it, it consumes no stream
// budget, and its mutation path deliberately bypasses the remote Volume
// lifecycle. It needs the namespace gate and nothing else — but it is still a
// frontend, so it takes the item-scoped size token exactly where every other
// frontend does: BEFORE the namespace gate, holding nothing (refreshpin.go).
// Taken under lockExternalNamespaceWrite — which is mount-wide and EXCLUSIVE — a
// wait for a pinned refresh would park the very upcall that refresh needs
// answered in order to release the pin.
//
// readmit reports that the identity this attempt reserved is not the identity
// the name resolves to under the lock. Every lock and the reservation are
// released before it returns, so the caller re-admits holding nothing.
func (a *attach) controlGraftWriteOnce(
	ctx context.Context,
	p, graft string,
	data []byte,
) (readmit bool, httpStatus int, httpMessage string, refreshItemID uint64) {
	reserved := a.reservedIdentityForPath(p)
	releaseToken, tokenEno := a.reserveSizeMutation(ctx, reserved.itemID)
	if tokenEno != 0 {
		return false, httpStatusForErr(tokenEno),
			errMessage("fs/write admission", tokenEno), 0
	}
	releaseGraftToken := func() {
		if releaseToken != nil {
			releaseToken()
			releaseToken = nil
		}
	}
	// The token is given back BEFORE the refresh this write owes the kernel,
	// which the caller issues: the reservation's whole meaning is "a size
	// mutation is on its way to a commit", the commit and its publication are
	// behind this return, and a refresh cannot arm over a reservation that has
	// not been released.
	defer releaseGraftToken()
	if probe := a.testControlAdmissionProbe; probe != nil {
		probe(ctx)
	}
	unlockNamespace := a.lockExternalNamespaceWrite()
	defer unlockNamespace()
	if err := a.controlAdmissionError(); err != nil {
		return false, http.StatusConflict, err.Error(), 0
	}
	// PHASE 3's FIRST QUESTION. writeLocalFile brackets whatever the name
	// resolves to NOW; this attempt reserved whatever it resolved to THEN. If
	// they differ, the bracket and the reservation would be about two different
	// identities, and the reservation would be protecting an item this write
	// never touches (see reservedIdentity).
	if current := a.reservedIdentityForPath(p); current != reserved {
		return true, 0, "", 0
	}
	itemID, eno := a.writeLocalFile(p, graft, data)
	if eno != 0 {
		return false, httpStatusForErr(eno), errMessage("fs/write", eno), 0
	}
	return false, 0, "", itemID
}

// controlWriteLocked is PHASE 2+3 of a control write: it takes the same
// namespace locks a name-mutating kernel request takes for the identical
// authority calls (lockExternalNamespaceMutation) and performs nothing but the
// mutation and its bookkeeping. Every step that can wait UNBOUNDEDLY on the
// uplink — the delegation transition claim and the operand releases — has
// already happened in the caller's phase 1.
//
// The locks are SHARED plus one name stripe, never the mount-wide exclusive
// gate. The authority calls below are real round trips, and pre-lock admission
// does not make them nonblocking; holding an exclusive nsMu across them parked
// every namespace read in the mount behind a writer-preferring RWMutex. The
// kernel frontend runs Create/Open/Write/Setattr under nsMu.RLock plus the one
// name stripe (ops.go), and the control plane is a frontend.
//
// readmit reports that something the caller pre-resolved no longer holds under
// the locks: the delegation lane, or the identity the name is bound to. The
// locks are released before it returns, so the caller re-admits holding nothing
// — the same unwind the two kernel frontends run.
func (a *attach) controlWriteLocked(
	ctx context.Context,
	vol *clientcore.Volume,
	p string,
	node *clientcore.NodeState,
	data []byte,
	reserved reservedIdentity,
) (readmit bool, httpStatus int, httpMessage string, refreshItemID uint64) {
	unlockNamespace := a.lockExternalNamespaceMutation(p)
	defer unlockNamespace()
	if err := a.controlAdmissionError(); err != nil {
		return false, http.StatusConflict, err.Error(), 0
	}
	// PHASE 3's FIRST QUESTION, ASKED BEFORE ANYTHING IS MUTATED OR BRACKETED.
	//
	// The bracket below names the item the name has NOW; the reservation this
	// handler runs under was taken against the item the name had before the
	// gate. A concurrent create or rename-over between the two makes them
	// different identities, and the reservation then protects an item this write
	// never touches while the item it does touch is unprotected — free to be
	// mutated inside a refresh pin. Unwind and re-admit against what is
	// actually there (see reservedIdentity).
	if current := a.reservedIdentityForPath(p); current != reserved {
		return true, 0, "", 0
	}
	// A control write is a write-through with the kernel frontend's exact
	// commit-then-publish shape (vol.Write and vol.Setattr below, registerLocked
	// several steps later), so it owes the refresh fence the same bracket. The
	// item is named from the record the path ALREADY has: a control write that
	// creates the name mints a fresh identity no refresh pass can be carrying a
	// stale sample of, and a zero ID is inert by construction.
	// published starts TRUE: every exit before the size is committed — a lane
	// change, a refused create, a refused write — leaves nothing for the
	// registry to be behind on, and the sequence must close on those paths.
	commit := &setattrCommit{published: true}
	var bracketed uint64
	if existing := a.itemByPath(p); existing != nil {
		bracketed = existing.item.ItemID
		settleMutation := a.beginItemMutation(bracketed)
		defer func() { settleMutation(commit.published) }()
		// EVERY exit below the first committed byte publishes what it committed.
		//
		// A control replacement is TWO mutations — the write, then the truncate
		// that cuts whatever the old contents left behind — and the second one
		// can fail while the first has already landed. Registered after the
		// bracket, this defer therefore runs BEFORE the settle (defers unwind
		// last-in-first-out), which is the only order in which the sequence can
		// close over a registry that has been told about the commit.
		defer a.publishSetattrCommit(ctx, vol, bracketed, commit)
	}
	attr, st := vol.Lookup(ctx, p)
	existed := st == fsproto.OK
	if st == fsproto.ENOENT {
		attr, st = vol.Create(ctx, p, 0o644)
		if clientcore.LaneChanged(st) {
			return true, 0, "", 0
		}
		if st == fsproto.OK {
			a.mu.Lock()
			savedOwner := a.beginReincarnationOwnerLocked(nil)
			created := a.registerCreatedLocked(p, attr)
			ticket := a.endReincarnationOwnerLocked(savedOwner)
			a.mu.Unlock()
			if created == nil {
				return false, http.StatusInternalServerError,
					errMessage("fs/write item identity", darwinEIO), 0
			}
			// The control plane publishes into the same registry the kernel
			// frontend reads, so it owes the same reconciliation: a create that
			// displaced a peer-replaced name leaves that inode's retained
			// aliases stale for every later frontend reply, not just for this
			// HTTP response.
			if eno, _ := ticket.settle(ctx, vol); eno != 0 {
				return false, httpStatusForErr(eno),
					errMessage("fs/write reconcile aliases", eno), 0
			}
		}
	}
	if clientcore.LaneChanged(st) {
		return true, 0, "", 0
	}
	if st != fsproto.OK {
		return false, httpStatusForErr(toDarwinErr(st)),
			errMessage("fs/write", toDarwinErr(st)), 0
	}
	candidateItemID := attr.Ino
	if candidateItemID == 0 {
		candidateItemID = clientcore.InoOf(p)
	}
	if _, ok := fskitItemID(candidateItemID); !ok {
		return false, http.StatusInternalServerError,
			errMessage("fs/write item identity", darwinEIO), 0
	}
	// PHASE 3's LAST QUESTION, AND THE ONLY ONE THE AUTHORITY CAN ANSWER.
	//
	// Everything checked so far — the pre-lock sample, the comparison above —
	// was read out of the LOCAL registry, and nsMu and the name stripes fence
	// only this daemon's frontends. A peer renaming B over p, or a registry
	// merely running behind the authority, leaves all of it consistent while the
	// lookup right above answers B.
	//
	// What used to happen then is the whole of this finding: an unproven
	// NodeState was BOUND to the lookup's inode in passing (and a proven one was
	// compared against nothing at all), and the open, the write and the truncate
	// below ran against B while the reservation, the mutation sequence and the
	// published size all belonged to A. B is then free to be mutated inside B's
	// own outstanding refresh syscall — the exact linearization failure the size
	// token exists to make impossible.
	//
	// So the authority's answer is the final target resolution. If it does not
	// belong to the item this attempt reserved, that is a coherence fact and not
	// an error: REGISTER it, publish the invalidations the identity change owes
	// the kernel, and unwind to pre-lock admission so the next attempt reserves
	// the object that is actually there. Nothing is bound and nothing is mutated
	// on the way out.
	a.mu.RLock()
	proven := a.authorityTargetProvenLocked(p, reserved, attr.Ino)
	a.mu.RUnlock()
	if !proven {
		if eno := a.registerAuthorityTarget(ctx, vol, p, attr); eno != 0 {
			return false, httpStatusForErr(eno),
				errMessage("fs/write item identity", eno), 0
		}
		return true, 0, "", 0
	}
	if attr.Ino != 0 && !node.RecordAuthorityIno(attr.Ino) {
		// Proven above, so this can only be a node the registry replaced between
		// the proof and here. It is never a binding: RecordAuthorityIno is a
		// no-op on an identity it already carries.
		return false, http.StatusInternalServerError,
			errMessage("fs/write item identity", darwinEIO), 0
	}
	if hook := a.testControlWriteAuthorityTarget; hook != nil {
		hook(attr.Ino)
	}
	if st := vol.Open(ctx, p, node, true); st != fsproto.OK {
		return false, httpStatusForErr(toDarwinErr(st)),
			errMessage("fs/write open", toDarwinErr(st)), 0
	}
	defer vol.CloseHandle(p, node)
	// THE FIRST OF THE TWO MUTATIONS, AND ITS PROGRESS IS RECORDED BEFORE ITS
	// STATUS IS INSPECTED.
	//
	// This call used to be the compatibility wrapper, which discards the
	// committing lane's WriteOutcome and reports only a count — so a control
	// write that committed its bytes and then failed at the truncate below
	// recorded NOTHING: commit.published stayed its initial true, the sequence
	// closed over a registry still holding the pre-write size, and the HTTP
	// error skipped the kernel refresh that would otherwise have converged it.
	// A short write with a positive count lost the same way.
	//
	// What the write proves on its own is a FLOOR. The old contents are still
	// past the bytes just written until the truncate cuts them, so the file is
	// at least this long and may be longer; publishing it as exact would shrink
	// a registry that is not wrong. The floor is upgraded to the exact size the
	// moment the truncate commits.
	out, st := vol.WriteCommitted(ctx, p, node, 0, data)
	if out.Count > 0 {
		floor := int64(out.Count)
		if out.SizeKnown {
			floor = out.Size
		}
		commit.recordFloor(floor)
	}
	if st != fsproto.OK {
		if clientcore.LaneChanged(st) {
			return true, 0, "", 0
		}
		return false, httpStatusForErr(toDarwinErr(st)),
			errMessage("fs/write data", toDarwinErr(st)), 0
	}
	// THE COMMITTING CALL'S OWN REPLY IS THE POST-OP STATE.
	//
	// vol.Setattr returns the inode's post-op attributes at the mutation's own
	// ordered apply position (postattrs.go / clientcore.Volume.Setattr), and
	// discarding them was the whole of this path's half of finding 1: the
	// composed size was then only ever published if the OPTIONAL trailing
	// getattr below succeeded, and when it failed the handler registered `attr`
	// — the PRE-write lookup or create attributes — and settled the item's
	// mutation sequence over a registry that still said 0. The next refresh
	// armed on that sample and ftruncated the kernel's vnode back over the bytes
	// this write had just acknowledged to its HTTP caller.
	post, truncated, st := vol.SetattrCommitted(ctx, p, node, clientcore.SetattrRequest{
		Size: int64(len(data)), SetSize: true,
	})
	if truncated.SizeCommitted {
		// The floor becomes exact: the old tail is cut and the file is now
		// precisely this long.
		commit.recordExact(truncated.Size)
	}
	if st != fsproto.OK {
		if clientcore.LaneChanged(st) {
			return true, 0, "", 0
		}
		return false, httpStatusForErr(toDarwinErr(st)),
			errMessage("fs/write truncate", toDarwinErr(st)), 0
	}
	if post.Kind != "" {
		attr = post
	}
	// The trailing getattr is now a REFINEMENT and never the only source of the
	// size: it picks up whatever the authority states about the name after the
	// mutation, and its failure costs nothing the reply needs.
	if a.testControlWriteRefreshFails == nil || !a.testControlWriteRefreshFails() {
		if fresh, st := vol.Getattr(ctx, p, node); st == fsproto.OK {
			attr = fresh
		}
	}
	if attr.Size != int64(len(data)) && post.Kind == "" {
		// No post-op attributes and no successful refresh: the only statement
		// left about this name's size is the one this write committed.
		attr.Size = int64(len(data))
	}
	a.mu.Lock()
	savedOwner := a.beginReincarnationOwnerLocked(nil)
	rec := a.registerLocked(p, attr)
	if rec != nil {
		commit.published = true
	} else if bracketed != 0 {
		// The registration was refused. The bytes are committed anyway, so the
		// item this handler bracketed must not be declared stable over a
		// registry that still holds the pre-write size.
		a.publishItemSizeLocked(bracketed, a.items[bracketed], commit.size, commit.floor)
		commit.published = true
	}
	ticket := a.endReincarnationOwnerLocked(savedOwner)
	if rec == nil {
		a.mu.Unlock()
		return false, http.StatusInternalServerError,
			errMessage("fs/write item identity", darwinEIO), 0
	}
	refreshItemID = rec.item.ItemID
	if !existed {
		a.publishNamespaceInvalidationLocked(p, 0, 0)
	}
	a.publishContentInvalidationLocked(p, 0, 0)
	a.mu.Unlock()
	if eno, _ := ticket.settle(ctx, vol); eno != 0 {
		return false, httpStatusForErr(eno),
			errMessage("fs/write reconcile aliases", eno), 0
	}
	if eno := a.flushBindingDelta(); eno != 0 {
		return false, httpStatusForErr(eno),
			errMessage("fs/write identity journal", eno), 0
	}
	return false, 0, "", refreshItemID
}

func (s *Server) controlFSStat(w http.ResponseWriter, r *http.Request, a *attach) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeHTTPError(w, http.StatusBadRequest, err.Error())
		return
	}
	unlockNamespace := a.lockExternalNamespaceRead()
	defer unlockNamespace()
	if err := a.controlAdmissionError(); err != nil {
		writeHTTPError(w, http.StatusConflict, err.Error())
		return
	}
	p := cleanControlPath(req.Path)
	if graft := a.localDirFor(p); graft != "" {
		attr, eno := a.statLocal(p)
		if eno != 0 {
			writeHTTPError(w, httpStatusForErr(eno), errMessage("fs/stat", eno))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"path": p, "attr": attrJSON(attr)})
		return
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		writeHTTPError(w, httpStatusForErr(eno), errMessage("fs/stat", eno))
		return
	}
	attr, st := vol.Lookup(r.Context(), p)
	if st != fsproto.OK {
		writeHTTPError(w, httpStatusForErr(toDarwinErr(st)), errMessage("fs/stat", toDarwinErr(st)))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": p, "attr": attrJSON(attr)})
}

type pfslocalAttr struct {
	Kind    string `json:"kind"`
	Mode    uint32 `json:"mode"`
	Size    int64  `json:"size"`
	MtimeMs int64  `json:"mtimeMs"`
	CtimeMs int64  `json:"ctimeMs"`
	AtimeMs int64  `json:"atimeMs"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Nlink   uint32 `json:"nlink"`
	Ino     uint64 `json:"ino"`
}

func attrJSON(a fsproto.Attr) pfslocalAttr {
	return pfslocalAttr{
		Kind: a.Kind, Mode: a.Mode, Size: a.Size, MtimeMs: a.MtimeMs, CtimeMs: a.CtimeMs,
		AtimeMs: a.AtimeMs, UID: a.Uid, GID: a.Gid, Nlink: a.Nlink, Ino: a.Ino,
	}
}

func cleanControlPath(p string) string {
	p = strings.TrimPrefix(path.Clean("/"+p), "/")
	if p == "." {
		return ""
	}
	return p
}

func httpStatusForErr(eno int32) int {
	switch eno {
	case darwinENOENT:
		return http.StatusNotFound
	case darwinEEXIST:
		return http.StatusConflict
	case darwinEINVAL:
		return http.StatusBadRequest
	default:
		return http.StatusBadGateway
	}
}
