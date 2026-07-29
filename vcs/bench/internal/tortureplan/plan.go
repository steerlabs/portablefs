// Package tortureplan is the deterministic storm plan shared by the torture
// driver (pfstorture) and its client-kill child (pfsbench wbstorm): both
// derive the identical paths and payloads from one seed, so the parent can
// verify byte-exactness against the authority knowing only which plan steps
// the child acknowledged before the kill.
package tortureplan

import "math/rand"

// File is one create+write step.
type File struct {
	Path    string
	Content []byte
}

// Plan is the full deterministic storm for one seed.
type Plan struct {
	Dirs        []string
	Files       []File
	AppendPath  string
	AppendChunk []byte
	// AppendEvery inserts one append after every Nth file.
	AppendEvery int
}

// New derives the storm plan for a seed. It mirrors the W2 shape of the
// authority-kill storm: a directory fan-out, small-file create+write pairs,
// and periodic appends to one log.
func New(seed int64) Plan {
	rng := rand.New(rand.NewSource(seed))
	const nDirs = 8
	nFiles := 120 + rng.Intn(180)
	payload := make([]byte, 16*1024)
	rng.Read(payload)

	p := Plan{
		AppendPath:  "torture/append.log",
		AppendChunk: append([]byte(nil), payload[:512]...),
		AppendEvery: 5,
	}
	for d := 0; d < nDirs; d++ {
		p.Dirs = append(p.Dirs, dirName(d))
	}
	for f := 0; f < nFiles; f++ {
		size := 1024 + rng.Intn(15*1024)
		p.Files = append(p.Files, File{
			Path:    fileName(f%nDirs, f),
			Content: append([]byte(nil), payload[:size]...),
		})
	}
	return p
}

func dirName(d int) string { return "torture/d" + two(d) }

func fileName(d, f int) string {
	return dirName(d) + "/f" + four(f) + ".bin"
}

func two(n int) string  { return string([]byte{'0' + byte(n/10%10), '0' + byte(n%10)}) }
func four(n int) string {
	return string([]byte{'0' + byte(n/1000%10), '0' + byte(n/100%10), '0' + byte(n/10%10), '0' + byte(n%10)})
}
