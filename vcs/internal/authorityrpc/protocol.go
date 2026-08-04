package authorityrpc

import (
	"crypto/sha256"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

// ProtocolMajor is intentionally incompatible with every v2 fsproto/pfslocal
// data path. Coordinated v3 peers fail closed instead of emulating old storage.
const ProtocolMajor uint32 = 1

const protocolALPN = "portablefs-authority-v1"

// framePayloadReserve leaves deterministic room for the response envelope,
// handles, attributes, and protobuf length tags around a negotiated data chunk.
const framePayloadReserve uint32 = 1024

var (
	requiredHelloFeatures  = []string{"xfs-current-state", "session-exact-epoch", "direct-write"}
	requiredAttachFeatures = []string{"write-through", "no-history", "no-branches", "direct-io-no-file-mmap", "user-xattr-readonly", "single-principal", "distributed-posix-locks"}
)

func hasFeatures(advertised, required []string) bool {
	set := make(map[string]struct{}, len(advertised))
	for _, feature := range advertised {
		set[feature] = struct{}{}
	}
	for _, feature := range required {
		if _, ok := set[feature]; !ok {
			return false
		}
	}
	return true
}

func canonicalHash(req *authoritypb.Request) (volumeserver.RequestHash, error) {
	clone := proto.Clone(req).(*authoritypb.Request)
	clone.RequestId, clone.Epoch, clone.Session, clone.Mutation = 0, nil, nil, nil
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	return sha256.Sum256(encoded), err
}
