// Package fskitidentity holds the one release-stamped identity shared by the
// CLI and portablefsd. The FSKit extension's PFSAppGroupIdentifier and
// entitlement must contain the same value.
package fskitidentity

const IdentitySchemaVersion = 2

// FSType is the filesystem identity published by the FSKit extension. Apple
// requires FSStatFSResult.fileSystemTypeName to match the extension's
// EXAppExtensionAttributes.FSShortName. It is also the kernel-visible boundary
// between OSS PortableFS and products that embed the same filesystem engine.
const FSType = "pfs"

// ResourceScheme is the globally scoped URL scheme that routes generic FSKit
// resources to this product's extension. FSKit selects generic URL providers
// by FSSupportedSchemes, independently of FSType, so this value must not be
// shared with products that embed PortableFS under a different identity.
const ResourceScheme = "dev.portablefs.oss"

// ResourcePrefix is the canonical kernel mount-source prefix.
const ResourcePrefix = ResourceScheme + "://"

// AppGroup is a variable so release builds can stamp the signing team's app
// group with:
//
//	-X github.com/steerlabs/portablefs/vcs/internal/fskitidentity.AppGroup=TEAMID.pfsoss
var AppGroup = "B47U2LLKHW.pfsoss"

// Identity is the complete release-stamped FSKit routing and sandbox
// identity. The CLI, daemon, installer, and extension metadata must agree on
// all three axes.
type Identity struct {
	SchemaVersion  int    `json:"schemaVersion"`
	FSType         string `json:"fsType"`
	ResourceScheme string `json:"resourceScheme"`
	AppGroup       string `json:"appGroup"`
}

func Current() Identity {
	return Identity{
		SchemaVersion:  IdentitySchemaVersion,
		FSType:         FSType,
		ResourceScheme: ResourceScheme,
		AppGroup:       AppGroup,
	}
}
