// Package fskitidentity holds the one release-stamped identity shared by the
// CLI and portablefsd. The FSKit extension's PFSAppGroupIdentifier and
// entitlement must contain the same value.
package fskitidentity

// FSType is the filesystem identity published by the FSKit extension. Apple
// requires FSStatFSResult.fileSystemTypeName to match the extension's
// EXAppExtensionAttributes.FSShortName. It is also the kernel-visible boundary
// between OSS PortableFS and products that embed the same filesystem engine.
const FSType = "pfs"

// AppGroup is a variable so release builds can stamp the signing team's app
// group with:
//
//	-X github.com/steerlabs/portablefs/vcs/internal/fskitidentity.AppGroup=TEAMID.pfsoss
var AppGroup = "B47U2LLKHW.pfsoss"
