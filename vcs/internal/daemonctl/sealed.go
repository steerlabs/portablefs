package daemonctl

import (
	"encoding/json"
	"fmt"
)

const SealedProtocolsRelativePath = "Contents/Resources/PortableFSProtocol.json"

// SealedProtocols is covered by the service bundle's code signature. Executable
// hashes are computed from the signed executable separately: putting that hash
// in its own signed resources would create a signature/hash cycle.
type SealedProtocols struct {
	IdentitySchema  int    `json:"identitySchema"`
	ControlProtocol int    `json:"controlProtocol"`
	PFSLocalMajor   uint32 `json:"pfslocalMajor"`
	PFSLocalMinor   uint32 `json:"pfslocalMinor"`
}

func (p SealedProtocols) Validate() error {
	if p.IdentitySchema != IdentitySchemaVersion || p.ControlProtocol <= 0 || p.PFSLocalMajor == 0 {
		return fmt.Errorf("invalid sealed daemon protocols")
	}
	return nil
}

func EncodeSealedProtocols(p SealedProtocols) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

func DecodeSealedProtocols(data []byte) (SealedProtocols, error) {
	var p SealedProtocols
	if err := decodeLifecycleObject(data, map[string]any{"identitySchema": &p.IdentitySchema, "controlProtocol": &p.ControlProtocol, "pfslocalMajor": &p.PFSLocalMajor, "pfslocalMinor": &p.PFSLocalMinor}); err != nil {
		return SealedProtocols{}, err
	}
	if err := p.Validate(); err != nil {
		return SealedProtocols{}, err
	}
	return p, nil
}
