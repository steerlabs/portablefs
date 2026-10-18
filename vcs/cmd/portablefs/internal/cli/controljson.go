package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/mountid"
)

func decodeExactJSONObject(data []byte) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	object := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		key, keyOK := token.(string)
		if err != nil || !keyOK {
			return nil, false
		}
		if _, duplicate := object[key]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, false
		}
		object[key] = value
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return nil, false
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	return object, true
}

// The paired operational inventory has one required envelope member. Its
// producer uses either [] or null for an empty slice. Every present identity
// must be complete and unique before absence of a recorded ref is evidence.
func decodeAttachInventory(body []byte) ([]cliAttachStatus, error) {
	envelope, ok := decodeExactJSONObject(body)
	if !ok || len(envelope) != 1 {
		return nil, fmt.Errorf("unreadable exact daemon attach inventory envelope")
	}
	raw, ok := envelope["attaches"]
	if !ok {
		return nil, fmt.Errorf("daemon attach inventory is missing attaches")
	}
	var records []json.RawMessage
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("decode daemon attach inventory: %w", err)
	}
	out := make([]cliAttachStatus, 0, len(records))
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		fields, ok := decodeExactJSONObject(record)
		if !ok {
			return nil, fmt.Errorf("daemon attach inventory contains a malformed record")
		}
		for _, key := range []string{"attachRef", "mountPath", "volumeId"} {
			if bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) || len(fields[key]) == 0 {
				return nil, fmt.Errorf("daemon attach inventory is missing %s", key)
			}
		}
		var status cliAttachStatus
		members := map[string]any{
			"attachRef": &status.AttachRef, "mountPath": &status.MountPath, "volumeId": &status.VolumeID,
			"state": &status.State, "lastError": &status.LastError, "sessionTerminal": &status.SessionTerminal,
			"mountEnrollmentId": &status.MountEnrollmentID, "authorizationDeadlineAtMs": &status.AuthorizationDeadlineAtMs,
			"lastReauthorizationAtMs": &status.LastReauthorizationAtMs, "nextReauthorizationAtMs": &status.NextReauthorizationAtMs,
			"reauthorizationFailures": &status.ReauthorizationFailures, "reauthorizationError": &status.ReauthorizationError,
		}
		// Only exact tokenized keys may populate known members. Go's struct
		// decoder folds case, allowing an alias to overwrite an absence proof.
		for key, raw := range fields {
			member, known := members[key]
			if !known {
				for name := range members {
					if strings.EqualFold(key, name) {
						return nil, fmt.Errorf("daemon attach inventory contains ambiguous member %q", key)
					}
				}
				continue
			}
			if err := json.Unmarshal(raw, member); err != nil {
				return nil, fmt.Errorf("decode daemon attach member %s: %w", key, err)
			}
		}
		if !mountid.ValidAttachRef(status.AttachRef) || !validCanonicalMountPath(status.MountPath) || !validVolumeName(status.VolumeID) || seen[status.AttachRef] {
			return nil, fmt.Errorf("daemon attach inventory contains an incomplete or duplicate identity")
		}
		seen[status.AttachRef] = true
		out = append(out, status)
	}
	return out, nil
}
