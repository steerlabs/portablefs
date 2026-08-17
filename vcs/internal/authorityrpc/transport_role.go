package authorityrpc

import (
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type transportRequestClass uint8

const (
	transportRequestInvalid transportRequestClass = iota
	transportRequestHello
	transportRequestEither
	transportRequestData
	transportRequestControl
)

// classifyTransportRequest is the one protocol-5 role allowlist. New request
// bodies fail closed until they are assigned deliberately; neither the client
// nor server may infer a role from traffic size or current load.
func classifyTransportRequest(request *authoritypb.Request) (transportRequestClass, error) {
	if request == nil || request.GetBody() == nil {
		return transportRequestInvalid, fmt.Errorf("%w: request body is required", ErrTransportBinding)
	}
	switch request.GetBody().(type) {
	case *authoritypb.Request_Hello:
		return transportRequestHello, nil
	case *authoritypb.Request_Resume, *authoritypb.Request_Cancel:
		return transportRequestEither, nil
	case *authoritypb.Request_Attach,
		*authoritypb.Request_Lookup, *authoritypb.Request_GetAttr,
		*authoritypb.Request_SetAttr, *authoritypb.Request_Create,
		*authoritypb.Request_Mkdir, *authoritypb.Request_Unlink,
		*authoritypb.Request_Rename, *authoritypb.Request_Link,
		*authoritypb.Request_Symlink, *authoritypb.Request_Readlink,
		*authoritypb.Request_Open, *authoritypb.Request_Close,
		*authoritypb.Request_Read, *authoritypb.Request_WriteTransaction,
		*authoritypb.Request_OneShotWrite,
		*authoritypb.Request_Fallocate, *authoritypb.Request_CopyFileRange,
		*authoritypb.Request_Tmpfile,
		*authoritypb.Request_Fsync, *authoritypb.Request_ReadDir,
		*authoritypb.Request_Reclaim, *authoritypb.Request_Flush,
		*authoritypb.Request_GetXattr, *authoritypb.Request_SetXattr,
		*authoritypb.Request_ListXattr, *authoritypb.Request_RemoveXattr,
		*authoritypb.Request_StatFs, *authoritypb.Request_SyncFs,
		*authoritypb.Request_GetLock, *authoritypb.Request_SetLock,
		*authoritypb.Request_ApplyRoutes:
		return transportRequestData, nil
	case *authoritypb.Request_Activate, *authoritypb.Request_AbortAttach,
		*authoritypb.Request_KeepAlive, *authoritypb.Request_Detach,
		*authoritypb.Request_NextVisibility, *authoritypb.Request_AckVisibility,
		*authoritypb.Request_Reauthorize, *authoritypb.Request_TerminalDeliveryReceipt:
		return transportRequestControl, nil
	default:
		return transportRequestInvalid, fmt.Errorf("%w: unclassified request body %T", ErrTransportBinding, request.GetBody())
	}
}

func requestAllowedOnRole(request *authoritypb.Request, role authoritypb.TransportRole) error {
	class, err := classifyTransportRequest(request)
	if err != nil {
		return err
	}
	switch class {
	case transportRequestEither:
		if validTransportRole(role) {
			return nil
		}
	case transportRequestData:
		if role == authoritypb.TransportRole_TRANSPORT_ROLE_DATA {
			return nil
		}
	case transportRequestControl:
		if role == authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL {
			return nil
		}
	case transportRequestHello:
		return fmt.Errorf("%w: Hello is legal only as the first frame", ErrTransportBinding)
	}
	return fmt.Errorf("%w: request class %d is not legal on role %s", ErrTransportBinding, class, role)
}
