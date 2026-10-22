//go:build linux

// Package mountcontrol owns the exact local mount control grammar. Workspace
// controls are paired format 8; real workspace mount handlers remain unavailable.
package mountcontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"io"
	"reflect"
	"unicode/utf8"
)

const MaxIdentityBytes = mountenrollment.MaxClientIdentityBytes
const MaxOrdinaryRequest = (32 << 10) + MaxIdentityBytes + 4096
const MaxOrdinaryResponse = 4096
const MaxWorkspaceRequest = 64 << 10
const MaxWorkspaceResponse = 64 << 10

var ErrGrammar = errors.New("mount control: invalid exact grammar")
var ErrIncarnationTerminal = errors.New("mount control: incarnation terminal")
var ErrPeerRefused = errors.New("workspace peer refused")
var ErrOccupied = errors.New("workspace lane occupied")
var ErrRetired = errors.New("workspace request retired")
var ErrActionConsumed = errors.New("workspace action consumed")
var ErrNotAccepted = errors.New("workspace operation not accepted")
var ErrUnavailable = errors.New("workspace lifecycle unavailable")

type Request struct {
	Operation            string     `json:"operation,omitempty"`
	MountInstanceID      string     `json:"mountInstanceId,omitempty"`
	Capability           string     `json:"capability"`
	ClientCertificatePEM string     `json:"clientCertificatePem"`
	Sequence             uint64     `json:"sequence"`
	Workspace            *Workspace `json:"workspace,omitempty"`
}
type Response struct {
	MountInstanceID             string             `json:"mountInstanceId,omitempty"`
	LossSequence                string             `json:"lossSequence,omitempty"`
	AuthorizationDeadlineUnixMs int64              `json:"authorizationDeadlineUnixMs,omitempty"`
	Error                       string             `json:"error,omitempty"`
	OK                          bool               `json:"ok"`
	Sequence                    uint64             `json:"sequence,omitempty"`
	Workspace                   *WorkspaceResponse `json:"workspace,omitempty"`
}

// strictValue checks exact key spelling as well as duplicates before Go's JSON
// decoder can collapse either. All objects have a finite typed field set.
func strictValue(d *json.Decoder, typ reflect.Type, depth int) error {
	if depth > 16 {
		return ErrGrammar
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return ErrGrammar
	}
	delim, object := token.(json.Delim)
	if !object {
		return nil
	}
	switch delim {
	case '{':
		if typ.Kind() != reflect.Struct {
			return ErrGrammar
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := bytes.Split([]byte(f.Tag.Get("json")), []byte(","))[0]
			fields[string(name)] = f.Type
		}
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return e
			}
			name, ok := key.(string)
			field, known := fields[name]
			if !ok || !known || seen[name] {
				return ErrGrammar
			}
			seen[name] = true
			if err := strictValue(d, field, depth+1); err != nil {
				return err
			}
		}
	case '[':
		if typ.Kind() != reflect.Slice {
			return ErrGrammar
		}
		for d.More() {
			if err := strictValue(d, typ.Elem(), depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrGrammar
	}
	_, err = d.Token()
	return err
}
func StrictJSON(raw []byte, out any, limit int) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return ErrGrammar
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := strictValue(d, reflect.TypeOf(out), 0); err != nil {
		return fmt.Errorf("scan local JSON: %w", err)
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return ErrGrammar
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return fmt.Errorf("decode local JSON: %w", err)
	}
	return nil
}
func DecodeRequest(raw []byte) (Request, error) {
	var r Request
	if err := StrictJSON(raw, &r, MaxOrdinaryRequest); err != nil {
		return r, err
	}
	if r.Workspace != nil || IsWorkspace(r.Operation) {
		if len(raw) > MaxWorkspaceRequest {
			return r, ErrGrammar
		}
		if err := r.ValidateWorkspace(); err != nil {
			return r, err
		}
	}
	return r, nil
}
func DecodeResponse(raw []byte, workspace bool) (Response, error) {
	var r Response
	limit := MaxOrdinaryResponse
	if workspace {
		limit = MaxWorkspaceResponse
	}
	if err := StrictJSON(raw, &r, limit); err != nil {
		return r, err
	}
	if workspace {
		if err := r.ValidateWorkspace(); err != nil {
			return r, err
		}
	} else if r.Workspace != nil {
		return r, ErrGrammar
	}
	return r, nil
}
func EncodeResponse(r Response) ([]byte, error) {
	limit := MaxOrdinaryResponse
	if r.Workspace != nil {
		limit = MaxWorkspaceResponse
		if err := r.ValidateWorkspace(); err != nil {
			return nil, err
		}
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > limit {
		return nil, ErrGrammar
	}
	return raw, nil
}
