module github.com/steerlabs/portablefs/vcs

go 1.26.6

require (
	github.com/hanwen/go-fuse/v2 v2.10.1
	github.com/klauspost/compress v1.19.1
	github.com/minio/highwayhash v1.0.4
	golang.org/x/sys v0.47.0
	google.golang.org/protobuf v1.36.12
)

// PortableFS requires the post-/dev/fuse-reply publication hook documented in
// third_party/go-fuse/PORTABLEFS_FORK.md. Upstream v2.10.1 has no boundary at
// which a cache-coherent filesystem can learn that the kernel received a raw
// reply.
replace github.com/hanwen/go-fuse/v2 => ./third_party/go-fuse
