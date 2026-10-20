// Package portablefsd owns authority sessions and serves the paired FSKit frontend.
// The daemon retains source publication and metadata cache ownership. FSKit
// exposes no per-reply metadata cache withdrawal or xattr-set forwarding; fixed
// xattr refusal also prevents AppleDouble creation. Real file IDs use the checked
// FSKit successor mapping across UInt64, independently of local item handles.
package portablefsd
