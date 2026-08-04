module github.com/steerlabs/portablefs/vcs/spikes/direct-store-writeamp

go 1.26.5

require (
	github.com/steerlabs/portablefs/vcs v0.0.0
	go.etcd.io/bbolt v1.5.0
)

require golang.org/x/sys v0.46.0 // indirect

replace github.com/steerlabs/portablefs/vcs => ../..
