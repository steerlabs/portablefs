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
			AuthToken     string `json:"authToken"`
			OnlyIfPending bool   `json:"onlyIfPending,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		found, activated, err := s.registry.activate(r.Context(), ref, req.AuthToken, req.OnlyIfPending)
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

	// A GRAFT is machine-local: no delegation covers it, it consumes no stream
	// budget, and its mutation path deliberately bypasses the remote Volume
	// lifecycle. It needs the namespace gate and nothing else.
	if graft := a.localDirFor(p); graft != "" {
		unlockNamespace := a.lockExternalNamespaceWrite()
		if err := a.controlAdmissionError(); err != nil {
			unlockNamespace()
			writeHTTPError(w, http.StatusConflict, err.Error())
			return
		}
		refreshItemID, eno := a.writeLocalFile(p, graft, data)
		unlockNamespace()
		if eno != 0 {
			writeHTTPError(w, httpStatusForErr(eno), errMessage("fs/write", eno))
			return
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
		node := clientcore.NewNodeState(0, false)
		if rec := a.itemByPath(p); rec != nil && rec.state != nil {
			node = rec.state
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
		if probe := a.testControlAdmissionProbe; probe != nil {
			probe(mutCtx)
		}
		laneChanged, status, message, itemID := a.controlWriteLocked(
			mutCtx, vol, p, node, data,
		)
		settle()
		if laneChanged {
			// PHASE 3 refused to transition under the locks, and every lock is
			// released by now. Re-admit out here, under the SAME deadline, which
			// is what terminates the loop.
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
// laneChanged reports that the pre-resolved lane no longer holds. The locks are
// released before it returns, so the caller re-admits holding nothing — the same
// unwind the two kernel frontends run.
func (a *attach) controlWriteLocked(
	ctx context.Context,
	vol *clientcore.Volume,
	p string,
	node *clientcore.NodeState,
	data []byte,
) (laneChanged bool, httpStatus int, httpMessage string, refreshItemID uint64) {
	unlockNamespace := a.lockExternalNamespaceMutation(p)
	defer unlockNamespace()
	if err := a.controlAdmissionError(); err != nil {
		return false, http.StatusConflict, err.Error(), 0
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
			created := a.registerCreatedLocked(p, attr)
			a.mu.Unlock()
			if created == nil {
				return false, http.StatusInternalServerError,
					errMessage("fs/write item identity", darwinEIO), 0
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
	if !node.AuthIno() && attr.Ino != 0 && !node.RecordAuthorityIno(attr.Ino) {
		return false, http.StatusInternalServerError,
			errMessage("fs/write item identity", darwinEIO), 0
	}
	if st := vol.Open(ctx, p, node, true); st != fsproto.OK {
		return false, httpStatusForErr(toDarwinErr(st)),
			errMessage("fs/write open", toDarwinErr(st)), 0
	}
	defer vol.CloseHandle(p, node)
	if _, st := vol.Write(ctx, p, node, 0, data); st != fsproto.OK {
		if clientcore.LaneChanged(st) {
			return true, 0, "", 0
		}
		return false, httpStatusForErr(toDarwinErr(st)),
			errMessage("fs/write data", toDarwinErr(st)), 0
	}
	if _, st := vol.Setattr(ctx, p, node, clientcore.SetattrRequest{
		Size: int64(len(data)), SetSize: true,
	}); st != fsproto.OK {
		if clientcore.LaneChanged(st) {
			return true, 0, "", 0
		}
		return false, httpStatusForErr(toDarwinErr(st)),
			errMessage("fs/write truncate", toDarwinErr(st)), 0
	}
	if fresh, st := vol.Getattr(ctx, p, node); st == fsproto.OK {
		attr = fresh
	}
	a.mu.Lock()
	rec := a.registerLocked(p, attr)
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
