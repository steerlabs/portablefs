//go:build linux

package mountcontrol

import (
	"math"
	"reflect"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/mountlog"
)

func TestMetadataSnapshotIsBoundedAndCannotEnterControlProofs(t *testing.T) {
	base := Response{OK: true, MountInstanceID: "mnt_AAAAAAAAAAAAAAAAAAAAAA", LossSequence: "0", Metadata: &mountlog.MetadataStats{PID: 123, ProcessStart: "1234567", FUSEOperations: make([]uint64, mountlog.FUSEOperationSlots)}}
	// Even lifetime counters at their maximum retain the ordinary frame bound.
	fields := reflect.ValueOf(base.Metadata).Elem()
	for i := 0; i < fields.NumField(); i++ {
		if fields.Field(i).Kind() == reflect.Uint64 {
			fields.Field(i).SetUint(math.MaxUint64)
		}
	}
	for i := range base.Metadata.FUSEOperations {
		base.Metadata.FUSEOperations[i] = math.MaxUint64
	}
	base.Metadata.ProcessStart = "18446744073709551615"
	base.LossSequence = "18446744073709551615"
	encoded, err := EncodeResponse(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > MaxOrdinaryResponse {
		t.Fatal("snapshot escaped existing ordinary frame bound")
	}
	decoded, err := DecodeResponse(encoded, false)
	if err != nil || decoded.Metadata == nil || len(decoded.Metadata.FUSEOperations) != mountlog.FUSEOperationSlots {
		t.Fatalf("decode=%v metadata=%+v", err, decoded.Metadata)
	}
	for _, change := range []func(*Response){
		func(r *Response) { r.OK = false }, func(r *Response) { r.Error = "failure" }, func(r *Response) { r.LossSequence = "" },
		func(r *Response) { r.Sequence = 1 }, func(r *Response) { r.AuthorizationDeadlineUnixMs = 1 }, func(r *Response) { r.Workspace = &WorkspaceResponse{} },
	} {
		r := base
		change(&r)
		if _, err := EncodeResponse(r); err == nil {
			t.Fatalf("diagnostic metadata entered a non-loss response: %+v", r)
		}
	}
}
