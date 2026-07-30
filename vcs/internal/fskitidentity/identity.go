// Package fskitidentity holds the one release-stamped identity shared by the
// CLI and portablefsd. The FSKit extension's PFSAppGroupIdentifier and
// entitlement must contain the same value.
package fskitidentity

// AppGroup is a variable so release builds can stamp the signing team's app
// group with:
//
//	-X github.com/steerlabs/portablefs/vcs/internal/fskitidentity.AppGroup=TEAMID.pfsoss
var AppGroup = "B47U2LLKHW.pfsoss"
