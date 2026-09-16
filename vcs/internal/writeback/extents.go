package writeback

// The AVL tree contains disjoint intervals. A nil data slice denotes a zero
// mask left by truncation. Nodes come from the mount arena, so splitting a
// range does not allocate. Each operation introduces at most two boundaries.
type extent struct {
	lo, hi               int64
	data                 []byte
	left, right          *extent
	height               int
	end                  int64
	owner                *record
	prevOwned, nextOwned *extent
}

type extentMap struct {
	root *extent
	pool *extentPool
}
type extentPool struct {
	nodes []extent
	free  *extent
}

func newExtentPool(n int) extentPool {
	p := extentPool{nodes: make([]extent, n)}
	for i := range p.nodes {
		p.nodes[i].left = p.free
		p.free = &p.nodes[i]
	}
	return p
}
func (p *extentPool) get(lo, hi int64, data []byte, owner ...*record) *extent {
	n := p.free
	if n == nil {
		panic("writeback: extent arena exhausted")
	}
	p.free = n.left
	*n = extent{lo: lo, hi: hi, data: data, height: 1}
	if data != nil {
		n.end = hi
	}
	if len(owner) > 0 && owner[0] != nil {
		n.owner = owner[0]
		n.nextOwned = n.owner.extents
		if n.nextOwned != nil {
			n.nextOwned.prevOwned = n
		}
		n.owner.extents = n
	}
	return n
}
func (p *extentPool) put(n *extent) {
	if n.owner != nil {
		if n.prevOwned != nil {
			n.prevOwned.nextOwned = n.nextOwned
		} else {
			n.owner.extents = n.nextOwned
		}
		if n.nextOwned != nil {
			n.nextOwned.prevOwned = n.prevOwned
		}
	}
	*n = extent{left: p.free}
	p.free = n
}
func height(n *extent) int {
	if n == nil {
		return 0
	}
	return n.height
}
func extentEnd(n *extent) int64 {
	if n == nil {
		return 0
	}
	return n.end
}
func fix(n *extent) {
	n.height = 1 + max(height(n.left), height(n.right))
	n.end = max(extentEnd(n.left), extentEnd(n.right))
	if n.data != nil {
		n.end = max(n.end, n.hi)
	}
}
func rotateLeft(n *extent) *extent {
	r := n.right
	n.right = r.left
	r.left = n
	fix(n)
	fix(r)
	return r
}
func rotateRight(n *extent) *extent {
	l := n.left
	n.left = l.right
	l.right = n
	fix(n)
	fix(l)
	return l
}
func balance(n *extent) *extent {
	if n == nil {
		return nil
	}
	fix(n)
	if height(n.left)-height(n.right) > 1 {
		if height(n.left.left) < height(n.left.right) {
			n.left = rotateLeft(n.left)
		}
		return rotateRight(n)
	}
	if height(n.right)-height(n.left) > 1 {
		if height(n.right.right) < height(n.right.left) {
			n.right = rotateRight(n.right)
		}
		return rotateLeft(n)
	}
	return n
}
func insert(root, n *extent) *extent {
	if root == nil {
		return n
	}
	if n.lo < root.lo {
		root.left = insert(root.left, n)
	} else {
		root.right = insert(root.right, n)
	}
	return balance(root)
}
func remove(root *extent, lo int64) (*extent, *extent) {
	if lo < root.lo {
		var old *extent
		root.left, old = remove(root.left, lo)
		return balance(root), old
	}
	if lo > root.lo {
		var old *extent
		root.right, old = remove(root.right, lo)
		return balance(root), old
	}
	if root.left == nil {
		return root.right, root
	}
	if root.right == nil {
		return root.left, root
	}
	next := root.right
	for next.left != nil {
		next = next.left
	}
	right, _ := remove(root.right, next.lo)
	next.left = root.left
	next.right = right
	return balance(next), root
}
func (m *extentMap) overlap(lo, hi int64) *extent {
	n := m.root
	for n != nil {
		if n.hi <= lo {
			n = n.right
		} else if n.lo >= hi {
			n = n.left
		} else {
			return n
		}
	}
	return nil
}
func sub(data []byte, lo, hi int64) []byte {
	if data == nil {
		return nil
	}
	return data[lo:hi]
}
func (m *extentMap) set(lo, hi int64, data []byte, owner ...*record) {
	for {
		n := m.overlap(lo, hi)
		if n == nil {
			break
		}
		old := *n
		m.root, _ = remove(m.root, n.lo)
		m.pool.put(n)
		if old.lo < lo {
			m.root = insert(m.root, m.pool.get(old.lo, lo, sub(old.data, 0, lo-old.lo), old.owner))
		}
		if old.hi > hi {
			m.root = insert(m.root, m.pool.get(hi, old.hi, sub(old.data, hi-old.lo, old.hi-old.lo), old.owner))
		}
	}
	m.root = insert(m.root, m.pool.get(lo, hi, data, owner...))
}
func (m *extentMap) clear() {
	var walk func(*extent)
	walk = func(n *extent) {
		if n == nil {
			return
		}
		walk(n.left)
		walk(n.right)
		m.pool.put(n)
	}
	walk(m.root)
	m.root = nil
}

type span struct {
	lo, hi int64
	data   []byte
}

func spans(n *extent, lo, hi int64, out *[]span) {
	if n == nil {
		return
	}
	if n.lo > lo {
		spans(n.left, lo, hi, out)
	}
	if n.lo < hi && n.hi > lo {
		a, z := max(lo, n.lo), min(hi, n.hi)
		*out = append(*out, span{a, z, sub(n.data, a-n.lo, z-n.lo)})
	}
	if n.hi < hi {
		spans(n.right, lo, hi, out)
	}
}

func (m *extentMap) retire(r *record) {
	for r.extents != nil {
		n := r.extents
		m.root, _ = remove(m.root, n.lo)
		m.pool.put(n)
	}
}
