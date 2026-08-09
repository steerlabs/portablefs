package portablefsd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
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
			"attachRef":              a.ref,
			"volumeName":             a.volumeName,
			"authorizationSessionId": a.authorizationSessionID(),
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
			AuthTokenExpiresAtMs int64  `json:"authTokenExpiresAtMs,omitempty"`
			AuthSequence         uint64 `json:"authSequence,omitempty"`
			ClientCertPEM        string `json:"clientCertPem,omitempty"`
			OnlyIfPending        bool   `json:"onlyIfPending,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		found, activated, err := s.registry.activate(r.Context(), ref, req.AuthToken, req.AuthTokenExpiresAtMs, req.AuthSequence, req.ClientCertPEM, req.OnlyIfPending)
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
		if req.AuthSequence != 0 {
			deadline := a.authorizationDeadline()
			if deadline == 0 {
				writeHTTPError(w, http.StatusInternalServerError, "authority did not report the installed authorization deadline")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"authorizationDeadlineUnixMs": deadline,
			})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "bind-root":
		// THE ROOT DESCRIPTOR IS BOUND WHILE THE MOUNT IS PROVEN HEALTHY, and
		// never re-derived afterwards.
		//
		// Every path-based access to an FSKit mount is served by its
		// extension. A repair actuation runs while the extension's publication
		// barrier is closed for that exact repair, so opening the mount root
		// by path AT THAT MOMENT asks the extension to serve a callback for
		// the repair it is itself waiting on — a circular wait that spends the
		// whole repair budget and fences the mount. Binding here breaks the
		// cycle: `portablefs mount` calls this immediately after it has proven
		// the kernel mount present and serving, when nothing is in flight, and
		// the daemon keeps that descriptor for the attach's lifetime.
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := a.bindMountRoot(); err != nil {
			writeHTTPError(w, http.StatusConflict, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "sync":
		// The unmount-class durability barrier, exposed so `portablefs umount`
		// syncs BEFORE the kernel unmount. A v3 attach holds no client-side
		// buffer, so this is exactly the authority's own SyncVolume: success
		// means the authority has made this volume durable, and there is never
		// an unshipped backlog to report.
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		d := a.v3Backend()
		if d == nil {
			writeHTTPError(w, httpStatusForErr(darwinENXIO), errMessage("sync", darwinENXIO))
			return
		}
		if _, eno := d.syncVolume(r.Context()); eno != 0 {
			writeHTTPError(w, httpStatusForErr(eno), errMessage("sync", eno))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"pendingRecords": 0,
			"pendingBytes":   0,
		})
	default:
		writeHTTPError(w, http.StatusNotFound, "unknown attach endpoint")
	}
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
