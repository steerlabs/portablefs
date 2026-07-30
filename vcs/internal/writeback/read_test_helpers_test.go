package writeback

import "context"

// The production overlay surface is intentionally available only through a
// ReadPermit. These helpers preserve concise same-package white-box tests
// while making every non-test caller prove that it joined the handoff.
func (e *Engine) Lookup(path string) (Entry, LookupResult) {
	p, err := e.BeginRead(context.Background(), path)
	if err != nil {
		return Entry{}, LookupUndecided
	}
	defer p.Close()
	return p.Lookup(path)
}

func (e *Engine) Readdir(dir string) ([]Entry, bool) {
	p, err := e.BeginRead(context.Background(), dir)
	if err != nil {
		return nil, false
	}
	defer p.Close()
	return p.Readdir(dir)
}

func (e *Engine) MergeReaddir(dir string, authority []Entry) []Entry {
	p, err := e.BeginRead(context.Background(), dir)
	if err != nil {
		return authority
	}
	defer p.Close()
	return p.MergeReaddir(dir, authority)
}

func (e *Engine) ReadAt(path string, dst []byte, off int64, base BaseReader) (int, bool, error) {
	p, err := e.BeginRead(context.Background(), path)
	if err != nil {
		return 0, false, err
	}
	defer p.Close()
	return p.ReadAt(path, dst, off, base)
}

func (e *Engine) Readlink(path string) (string, string, bool) {
	p, err := e.BeginRead(context.Background(), path)
	if err != nil {
		return "", "", false
	}
	defer p.Close()
	return p.Readlink(path)
}

func (e *Engine) Getxattr(path, name string) ([]byte, LookupResult) {
	p, err := e.BeginRead(context.Background(), path)
	if err != nil {
		return nil, LookupUndecided
	}
	defer p.Close()
	return p.Getxattr(path, name)
}

func (e *Engine) Listxattr(path string) ([]string, bool) {
	p, err := e.BeginRead(context.Background(), path)
	if err != nil {
		return nil, false
	}
	defer p.Close()
	return p.Listxattr(path)
}
