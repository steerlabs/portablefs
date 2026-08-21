// Package tierede2e holds the privileged end-to-end lifecycle proof for
// PortableFS tiered storage: archive -> verify -> destroy -> restore ->
// serve-while-cold -> converge, driven through the real archiver, the real
// hydrator, the real authority, and a real kernel FUSE mount on real XFS with
// project quotas.
//
// The package deliberately contains no production code. It exists as its own
// directory because the flow spans four packages that no existing suite owns
// jointly, and because scripts/xfs-fuse-integration.sh has to be able to name
// it as a required privileged package.
package tierede2e
