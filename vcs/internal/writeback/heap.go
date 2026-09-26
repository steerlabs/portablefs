package writeback

// Indexed heaps make cumulative notifications proportional to the entries
// they advance. Drop removes its records before arena slots can be reused.
type recordHeap []*record

func (h *recordHeap) swap(i, j int) {
	(*h)[i], (*h)[j] = (*h)[j], (*h)[i]
	(*h)[i].heapIndex = i
	(*h)[j].heapIndex = j
}
func (h *recordHeap) up(i int) int {
	for i > 0 {
		p := (i - 1) / 2
		if (*h)[p].applied <= (*h)[i].applied {
			break
		}
		h.swap(i, p)
		i = p
	}
	return i
}
func (h *recordHeap) down(i int) {
	for {
		j := 2*i + 1
		if j >= len(*h) {
			return
		}
		if j+1 < len(*h) && (*h)[j+1].applied < (*h)[j].applied {
			j++
		}
		if (*h)[i].applied <= (*h)[j].applied {
			return
		}
		h.swap(i, j)
		i = j
	}
}
func (h *recordHeap) push(r *record) { r.heapIndex = len(*h); *h = append(*h, r); h.up(r.heapIndex) }
func (h *recordHeap) remove(i int) *record {
	r := (*h)[i]
	last := len(*h) - 1
	h.swap(i, last)
	(*h)[last] = nil
	*h = (*h)[:last]
	if i < last {
		i = h.up(i)
		h.down(i)
	}
	return r
}
