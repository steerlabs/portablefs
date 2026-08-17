package authorityrpc

import (
	"reflect"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func TestEveryAuthorityRequestBodyHasOneExactTransportClass(t *testing.T) {
	requests := []*authoritypb.Request{
		{Body: &authoritypb.Request_Hello{}}, {Body: &authoritypb.Request_Attach{}},
		{Body: &authoritypb.Request_Resume{}}, {Body: &authoritypb.Request_KeepAlive{}},
		{Body: &authoritypb.Request_Detach{}}, {Body: &authoritypb.Request_Cancel{}},
		{Body: &authoritypb.Request_NextVisibility{}}, {Body: &authoritypb.Request_AckVisibility{}},
		{Body: &authoritypb.Request_Reauthorize{}}, {Body: &authoritypb.Request_Lookup{}},
		{Body: &authoritypb.Request_GetAttr{}}, {Body: &authoritypb.Request_SetAttr{}},
		{Body: &authoritypb.Request_Create{}}, {Body: &authoritypb.Request_Mkdir{}},
		{Body: &authoritypb.Request_Unlink{}}, {Body: &authoritypb.Request_Rename{}},
		{Body: &authoritypb.Request_Link{}}, {Body: &authoritypb.Request_Symlink{}},
		{Body: &authoritypb.Request_Readlink{}}, {Body: &authoritypb.Request_Open{}},
		{Body: &authoritypb.Request_Close{}}, {Body: &authoritypb.Request_Read{}},
		{Body: &authoritypb.Request_WriteTransaction{}}, {Body: &authoritypb.Request_OneShotWrite{}},
		{Body: &authoritypb.Request_Fallocate{}},
		{Body: &authoritypb.Request_CopyFileRange{}}, {Body: &authoritypb.Request_Tmpfile{}}, {Body: &authoritypb.Request_Fsync{}},
		{Body: &authoritypb.Request_ReadDir{}}, {Body: &authoritypb.Request_Reclaim{}},
		{Body: &authoritypb.Request_Flush{}}, {Body: &authoritypb.Request_GetXattr{}},
		{Body: &authoritypb.Request_SetXattr{}}, {Body: &authoritypb.Request_ListXattr{}},
		{Body: &authoritypb.Request_RemoveXattr{}}, {Body: &authoritypb.Request_StatFs{}},
		{Body: &authoritypb.Request_SyncFs{}}, {Body: &authoritypb.Request_GetLock{}},
		{Body: &authoritypb.Request_SetLock{}}, {Body: &authoritypb.Request_ApplyRoutes{}},
		{Body: &authoritypb.Request_Activate{}}, {Body: &authoritypb.Request_AbortAttach{}},
		{Body: &authoritypb.Request_TerminalDeliveryReceipt{}},
	}
	descriptorBodies := (&authoritypb.Request{}).ProtoReflect().Descriptor().Oneofs().ByName("body").Fields().Len()
	if len(requests) != descriptorBodies {
		t.Fatalf("classifier lists %d bodies but schema has %d; every new body must choose one role", len(requests), descriptorBodies)
	}
	seen := make(map[reflect.Type]struct{}, len(requests))
	for _, request := range requests {
		typeOf := reflect.TypeOf(request.GetBody())
		if _, duplicate := seen[typeOf]; duplicate {
			t.Fatalf("duplicate body %v", typeOf)
		}
		seen[typeOf] = struct{}{}
		class, err := classifyTransportRequest(request)
		if err != nil || class == transportRequestInvalid {
			t.Fatalf("%T class=%d err=%v", request.GetBody(), class, err)
		}
	}
}

func TestTransportRoleAllowlistIsStrict(t *testing.T) {
	tests := []struct {
		request *authoritypb.Request
		data    bool
		control bool
	}{
		{request: &authoritypb.Request{Body: &authoritypb.Request_Fallocate{}}, data: true},
		{request: &authoritypb.Request{Body: &authoritypb.Request_OneShotWrite{}}, data: true},
		{request: &authoritypb.Request{Body: &authoritypb.Request_ApplyRoutes{}}, data: true},
		{request: &authoritypb.Request{Body: &authoritypb.Request_NextVisibility{}}, control: true},
		{request: &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{}}, control: true},
		{request: &authoritypb.Request{Body: &authoritypb.Request_Activate{}}, control: true},
		{request: &authoritypb.Request{Body: &authoritypb.Request_TerminalDeliveryReceipt{}}, control: true},
		{request: &authoritypb.Request{Body: &authoritypb.Request_Resume{}}, data: true, control: true},
		{request: &authoritypb.Request{Body: &authoritypb.Request_Cancel{}}, data: true, control: true},
	}
	for _, test := range tests {
		dataErr := requestAllowedOnRole(test.request, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
		controlErr := requestAllowedOnRole(test.request, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
		if (dataErr == nil) != test.data || (controlErr == nil) != test.control {
			t.Fatalf("%T: DATA err=%v CONTROL err=%v", test.request.GetBody(), dataErr, controlErr)
		}
	}
	hello := &authoritypb.Request{Body: &authoritypb.Request_Hello{}}
	if requestAllowedOnRole(hello, authoritypb.TransportRole_TRANSPORT_ROLE_DATA) == nil {
		t.Fatal("second Hello was accepted on DATA")
	}
}
