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

	"github.com/trendup-ai/portablefs/vcs/internal/clientcore"
	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
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
	mux.HandleFunc("/v1/attaches", s.handleAttaches)
	mux.HandleFunc("/v1/attaches/", s.handleAttach)
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
			if _, err := s.registry.delete(r.Context(), ref); err != nil {
				writeHTTPError(w, http.StatusInternalServerError, err.Error())
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	switch strings.Join(parts[1:], "/") {
	case "credential":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			AuthToken string `json:"authToken"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := a.activate(r.Context(), req.AuthToken); err != nil {
			writeHTTPError(w, http.StatusBadGateway, err.Error())
			return
		}
		if eno := a.persistStateOrEIO("credential activation"); eno != 0 {
			writeHTTPError(w, httpStatusForErr(eno), errMessage("credential", eno))
			return
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
	if graft := a.localDirFor(p); graft != "" {
		if eno := a.writeLocalFile(p, graft, data); eno != 0 {
			writeHTTPError(w, httpStatusForErr(eno), errMessage("fs/write", eno))
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
	attr, st := vol.Lookup(r.Context(), p)
	existed := st == fsproto.OK
	if st == fsproto.ENOENT {
		attr, st = vol.Create(r.Context(), p, 0o644)
		if st == fsproto.OK {
			a.mu.Lock()
			a.registerCreatedLocked(p, attr)
			a.mu.Unlock()
		}
	}
	if st != fsproto.OK {
		writeHTTPError(w, httpStatusForErr(toDarwinErr(st)), errMessage("fs/write", toDarwinErr(st)))
		return
	}
	n := clientcore.NewNodeState(attr.Ino, attr.Ino != 0)
	if rec := a.itemByPath(p); rec != nil {
		n = rec.state
	}
	if st := vol.Open(r.Context(), p, n, true); st != fsproto.OK {
		writeHTTPError(w, httpStatusForErr(toDarwinErr(st)), errMessage("fs/write open", toDarwinErr(st)))
		return
	}
	defer vol.CloseHandle(p, n)
	if _, st := vol.Write(r.Context(), p, n, 0, data); st != fsproto.OK {
		writeHTTPError(w, httpStatusForErr(toDarwinErr(st)), errMessage("fs/write data", toDarwinErr(st)))
		return
	}
	if _, st := vol.Setattr(r.Context(), p, n, clientcore.SetattrRequest{Size: int64(len(data)), SetSize: true}); st != fsproto.OK {
		writeHTTPError(w, httpStatusForErr(toDarwinErr(st)), errMessage("fs/write truncate", toDarwinErr(st)))
		return
	}
	if fresh, st := vol.Getattr(r.Context(), p, n); st == fsproto.OK {
		attr = fresh
	}
	a.mu.Lock()
	a.registerLocked(p, attr)
	if !existed {
		a.publishNamespaceInvalidationLocked(p, 0, 0)
	}
	a.publishContentInvalidationLocked(p, 0, 0)
	a.mu.Unlock()
	a.flushBindingDelta()
	// This write bypassed the kernel entirely; refresh any live vnode.
	a.scheduleCoherenceRefresh(p)
	w.WriteHeader(http.StatusNoContent)
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
